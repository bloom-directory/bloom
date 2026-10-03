//! Iroh peer-review lifecycle and its filesystem-native projection.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bloom_peer::{
    DecisionVerdict, EnrolledPeer, InboundReviewHandler, PeerIdentity, PeerNodeBuilder,
    PeerRegistry, ReplayStore, ReviewDecision, ReviewRequest, now_ms, payload_digest,
};
use bloom_petals::{DispatchResponse, PetalRunner};
use bloom_proto::{CoordinationConfig, CoordinationIrohMode, HomeDir};
use bloom_vfs::{Entry, Handler, HandlerError, VfsPath};
use iroh::{EndpointAddr, EndpointId};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
pub struct CoordinationStatus {
    pub enabled: bool,
    pub online: bool,
    pub endpoint_id: Option<String>,
    pub endpoint_addr: Option<EndpointAddr>,
    pub enrolled_peers: usize,
    pub last_error: Option<String>,
}

impl Default for CoordinationStatus {
    fn default() -> Self {
        Self {
            enabled: true,
            online: false,
            endpoint_id: None,
            endpoint_addr: None,
            enrolled_peers: 0,
            last_error: None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ReviewRecord {
    pub request: ReviewRequest,
    pub peer_endpoint: String,
    pub state: String,
    pub decision: Option<ReviewDecision>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OutboundReview {
    pub peer_endpoint: String,
    #[serde(flatten)]
    pub request: ReviewRequest,
}

struct ReviewCommand {
    peer: EndpointId,
    request: ReviewRequest,
    response: oneshot::Sender<Result<ReviewDecision, String>>,
}

#[derive(Clone)]
pub struct CoordinationService {
    home: HomeDir,
    config: CoordinationConfig,
    petals: PetalRunner,
    command_tx: mpsc::Sender<ReviewCommand>,
    command_rx: Arc<Mutex<Option<mpsc::Receiver<ReviewCommand>>>>,
    status: Arc<RwLock<CoordinationStatus>>,
    records: Arc<RwLock<BTreeMap<Uuid, ReviewRecord>>>,
}

impl CoordinationService {
    pub fn new(home: HomeDir, config: CoordinationConfig, petals: PetalRunner) -> Result<Self> {
        for evaluator in config
            .evaluators
            .values()
            .filter(|evaluator| evaluator.auto_run)
        {
            petals
                .validate_zero_authority_evaluator(
                    &evaluator.petal,
                    &evaluator.route,
                    &evaluator.package_hash,
                )
                .context("invalid auto-run coordination evaluator")?;
        }
        let (command_tx, command_rx) = mpsc::channel(config.max_concurrent_connections.max(1));
        Ok(Self {
            home,
            config,
            petals,
            command_tx,
            command_rx: Arc::new(Mutex::new(Some(command_rx))),
            status: Arc::new(RwLock::new(CoordinationStatus::default())),
            records: Arc::new(RwLock::new(BTreeMap::new())),
        })
    }

    pub fn status(&self) -> CoordinationStatus {
        self.status.read().clone()
    }
    pub fn records(&self) -> Vec<ReviewRecord> {
        self.records.read().values().cloned().collect()
    }

    pub async fn request_review(
        &self,
        peer: EndpointId,
        request: ReviewRequest,
    ) -> Result<ReviewDecision> {
        let (response, receive) = oneshot::channel();
        self.records.write().insert(
            request.request_id,
            ReviewRecord {
                request: request.clone(),
                peer_endpoint: peer.to_string(),
                state: "queued".into(),
                decision: None,
                error: None,
            },
        );
        self.command_tx
            .send(ReviewCommand {
                peer,
                request: request.clone(),
                response,
            })
            .await
            .context("coordination runtime is not running")?;
        match receive.await.context("coordination runtime stopped")? {
            Ok(decision) => {
                if let Some(record) = self.records.write().get_mut(&request.request_id) {
                    record.state = "completed".into();
                    record.decision = Some(decision.clone());
                }
                Ok(decision)
            }
            Err(error) => {
                if let Some(record) = self.records.write().get_mut(&request.request_id) {
                    record.state = "failed".into();
                    record.error = Some(error.clone());
                }
                bail!(error)
            }
        }
    }

    pub fn spawn(&self) -> Result<CoordinationTasks> {
        let receiver = self
            .command_rx
            .lock()
            .take()
            .context("coordination runtime already started")?;
        let (shutdown, shutdown_rx) = watch::channel(false);
        let service = self.clone();
        let handle = tokio::spawn(async move {
            if let Err(error) = service.run(receiver, shutdown_rx).await {
                let message = error.to_string();
                let mut status = service.status.write();
                status.online = false;
                status.last_error = Some(message.clone());
                tracing::error!(%message, "coordination runtime stopped");
            }
        });
        Ok(CoordinationTasks {
            shutdown,
            handle: Some(handle),
        })
    }

    async fn run(
        &self,
        mut commands: mpsc::Receiver<ReviewCommand>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let root = self.home.coordination_dir();
        let identity = PeerIdentity::load_or_create(&root.join("identity.key"))?;
        let registry = PeerRegistry::open(root.join("peers.json"));
        let peers = registry.list()?;
        let replay = ReplayStore::open(&root.join("state.db"))?;
        let mut builder = PeerNodeBuilder::new(identity, replay)
            .use_n0(self.config.iroh.mode == CoordinationIrohMode::N0)
            .config(bloom_peer::PeerNodeConfig {
                max_envelope_bytes: self.config.max_envelope_bytes,
                max_concurrent_connections: self.config.max_concurrent_connections,
                max_message_ttl: Duration::from_secs(self.config.request_ttl_secs),
                ..Default::default()
            });
        for peer in &peers {
            builder = builder.allow_peer(peer.endpoint_addr.id);
        }
        let node = builder.bind().await?;
        {
            let mut status = self.status.write();
            status.online = true;
            status.endpoint_id = Some(node.endpoint_id().to_string());
            status.endpoint_addr = Some(node.endpoint_addr());
            status.enrolled_peers = peers.len();
            status.last_error = None;
        }
        let server = if self.config.listen {
            let handler = EvaluatorHandler {
                config: self.config.clone(),
                petals: self.petals.clone(),
                peers: Arc::new(peers.clone()),
                request_times: Arc::new(Mutex::new(BTreeMap::new())),
            };
            Some(node.serve(Arc::new(handler)))
        } else {
            None
        };

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { break; }
                }
                command = commands.recv() => {
                    let Some(command) = command else { break; };
                    let result = peers.iter()
                        .find(|peer| peer.endpoint_addr.id == command.peer && peer.allow_outbound_review)
                        .cloned();
                    let result = match result {
                        Some(peer) => node.request_review(peer.endpoint_addr, &command.request).await.map_err(|e| e.to_string()),
                        None => Err("peer is not enrolled for outbound review".into()),
                    };
                    let _ = command.response.send(result);
                }
            }
        }
        if let Some(server) = server {
            server.shutdown().await;
        }
        node.close().await;
        self.status.write().online = false;
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum EvaluatorOutput {
    Detailed {
        verdict: DecisionVerdict,
        #[serde(default)]
        reason_codes: Vec<String>,
        #[serde(default)]
        conditions: Vec<serde_json::Value>,
    },
    Verdict(DecisionVerdict),
}

impl EvaluatorOutput {
    fn into_parts(self) -> (DecisionVerdict, Vec<String>, Vec<serde_json::Value>) {
        match self {
            Self::Detailed {
                verdict,
                reason_codes,
                conditions,
            } => (verdict, reason_codes, conditions),
            Self::Verdict(verdict) => (verdict, Vec::new(), Vec::new()),
        }
    }
}

struct EvaluatorHandler {
    config: CoordinationConfig,
    petals: PetalRunner,
    peers: Arc<Vec<EnrolledPeer>>,
    request_times: Arc<Mutex<BTreeMap<EndpointId, VecDeque<u64>>>>,
}

impl InboundReviewHandler for EvaluatorHandler {
    fn review(&self, peer: EndpointId, request: ReviewRequest) -> bloom_peer::HandlerFuture {
        let config = self.config.clone();
        let petals = self.petals.clone();
        let request_times = self.request_times.clone();
        let enrolled = self
            .peers
            .iter()
            .find(|candidate| candidate.endpoint_addr.id == peer)
            .cloned();
        Box::pin(async move {
            let enrolled = enrolled.context("peer is not enrolled")?;
            if !enrolled.allow_inbound_review {
                bail!("peer is not allowed inbound review");
            }
            if !config.auto_evaluate {
                bail!("automatic evaluation is disabled");
            }
            if !enrolled
                .allowed_evaluators
                .iter()
                .any(|alias| alias == &request.evaluator_alias)
            {
                bail!("evaluator is not allowlisted for this peer");
            }
            {
                let current = now_ms();
                let mut rates = request_times.lock();
                let samples = rates.entry(peer).or_default();
                while samples
                    .front()
                    .is_some_and(|seen| current.saturating_sub(*seen) >= 60_000)
                {
                    samples.pop_front();
                }
                if samples.len() >= config.max_requests_per_minute as usize {
                    bail!("peer review rate limit exceeded");
                }
                samples.push_back(current);
            }
            let evaluator = config
                .evaluators
                .get(&request.evaluator_alias)
                .context("unknown evaluator alias")?;
            if !evaluator.auto_run {
                bail!("evaluator auto-run is disabled");
            }
            if request.schema != evaluator.input_schema
                || request.requested_output_schema != evaluator.output_schema
            {
                bail!("review schema is not allowlisted");
            }
            petals.validate_zero_authority_evaluator(
                &evaluator.petal,
                &evaluator.route,
                &evaluator.package_hash,
            )?;
            let input = serde_json::to_vec(&request)?;
            let output = tokio::time::timeout(
                Duration::from_millis(evaluator.timeout_ms),
                petals.dispatch_zero_authority_evaluator(
                    &evaluator.petal,
                    &evaluator.route,
                    input,
                    evaluator.fuel,
                    evaluator.memory_pages,
                ),
            )
            .await
            .context("evaluator timed out")??;
            let DispatchResponse::Read(bytes) = output.response else {
                bail!("evaluator must return a read response");
            };
            if bytes.len() > 8 * 1024 {
                bail!("evaluator output exceeds 8192 bytes");
            }
            let verdict: EvaluatorOutput =
                serde_json::from_slice(&bytes).context("invalid evaluator output schema")?;
            let (verdict, reason_codes, conditions) = verdict.into_parts();
            Ok(ReviewDecision {
                schema: evaluator.output_schema.clone(),
                request_id: request.request_id,
                request_digest: payload_digest(&request)?,
                evaluator_alias: request.evaluator_alias,
                verdict,
                reason_codes,
                conditions,
                valid_until_ms: request.expires_at_ms.min(now_ms().saturating_add(30_000)),
                advisory_only: true,
            })
        })
    }
}

pub struct CoordinationTasks {
    shutdown: watch::Sender<bool>,
    handle: Option<JoinHandle<()>>,
}

impl CoordinationTasks {
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for CoordinationTasks {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

#[derive(Clone)]
pub struct CoordinationHandler {
    service: CoordinationService,
}

impl CoordinationHandler {
    pub fn new(service: CoordinationService) -> Self {
        Self { service }
    }
}

#[async_trait]
impl Handler for CoordinationHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segments = path.segments();
        match segments {
            [] => Ok(Entry::dir("")),
            [name]
                if matches!(
                    name.as_str(),
                    "status.json" | "identity.json" | "peers.json"
                ) =>
            {
                Ok(Entry::file(name))
            }
            [name] if name == "requests" => Ok(Entry::dir(name)),
            [a, b] if a == "requests" && b == "new" => Ok(Entry::writable_file(b)),
            [a, id]
                if a == "requests"
                    && self.service.records.read().contains_key(&parse_uuid(id)?) =>
            {
                Ok(Entry::dir(id))
            }
            [a, id, file]
                if a == "requests"
                    && matches!(
                        file.as_str(),
                        "request.json" | "status.json" | "decision.json"
                    )
                    && self.service.records.read().contains_key(&parse_uuid(id)?) =>
            {
                Ok(Entry::file(file))
            }
            _ => Err(HandlerError::NotFound(path.to_string_path())),
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        match path.segments() {
            [] => Ok(vec![
                Entry::file("identity.json"),
                Entry::file("status.json"),
                Entry::file("peers.json"),
                Entry::dir("requests"),
            ]),
            [name] if name == "requests" => {
                let mut entries = vec![Entry::writable_file("new")];
                entries.extend(
                    self.service
                        .records
                        .read()
                        .keys()
                        .map(|id| Entry::dir(&id.to_string())),
                );
                Ok(entries)
            }
            [a, id]
                if a == "requests"
                    && self.service.records.read().contains_key(&parse_uuid(id)?) =>
            {
                Ok(vec![
                    Entry::file("request.json"),
                    Entry::file("status.json"),
                    Entry::file("decision.json"),
                ])
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let bytes: Result<Vec<u8>, HandlerError> = match path.segments() {
            [name] if name == "status.json" => serde_json::to_vec_pretty(&self.service.status())
                .map_err(|e| HandlerError::Backend(e.to_string())),
            [name] if name == "identity.json" => serde_json::to_vec_pretty(
                &serde_json::json!({"endpoint_id": self.service.status().endpoint_id}),
            )
            .map_err(|e| HandlerError::Backend(e.to_string())),
            [name] if name == "peers.json" => {
                PeerRegistry::open(self.service.home.coordination_dir().join("peers.json"))
                    .list()
                    .map_err(|e| HandlerError::Backend(e.to_string()))
                    .and_then(|peers| {
                        serde_json::to_vec_pretty(&peers)
                            .map_err(|e| HandlerError::Backend(e.to_string()))
                    })
            }
            [a, id, file] if a == "requests" => {
                let id = parse_uuid(id)?;
                let records = self.service.records.read();
                let record = records
                    .get(&id)
                    .ok_or_else(|| HandlerError::NotFound(path.to_string_path()))?;
                match file.as_str() {
                    "request.json" => serde_json::to_vec_pretty(&record.request)
                        .map_err(|e| HandlerError::Backend(e.to_string())),
                    "status.json" => serde_json::to_vec_pretty(
                        &serde_json::json!({"state": record.state, "error": record.error}),
                    )
                    .map_err(|e| HandlerError::Backend(e.to_string())),
                    "decision.json" => record
                        .decision
                        .as_ref()
                        .ok_or_else(|| HandlerError::NotFound(path.to_string_path()))
                        .and_then(|decision| {
                            serde_json::to_vec_pretty(decision)
                                .map_err(|e| HandlerError::Backend(e.to_string()))
                        }),
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                }
            }
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        };
        bytes
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        if path.segments() != ["requests", "new"] {
            return Err(HandlerError::PermissionDenied);
        }
        let outbound: OutboundReview =
            serde_json::from_slice(data).map_err(|e| HandlerError::Invalid(e.to_string()))?;
        let peer: EndpointId = outbound
            .peer_endpoint
            .parse()
            .map_err(|e| HandlerError::Invalid(format!("peer endpoint: {e}")))?;
        let service = self.service.clone();
        tokio::spawn(async move {
            let _ = service.request_review(peer, outbound.request).await;
        });
        Ok(())
    }

    fn is_async_write_command(&self, path: &VfsPath) -> bool {
        path.segments() == ["requests", "new"]
    }
}

fn parse_uuid(value: &str) -> Result<Uuid, HandlerError> {
    Uuid::parse_str(value).map_err(|_| HandlerError::NotFound(value.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_peer::TradeIntent;
    use bloom_petals::{NameRegistry, PetalStore, PetalVm};
    use bloom_proto::{CoordinationEvaluatorConfig, CoordinationIrohConfig};

    #[tokio::test]
    async fn iroh_request_runs_dummy_zero_authority_petal_and_returns_advisory_decision() {
        let directory = tempfile::tempdir().unwrap();
        let store = PetalStore::open(directory.path().join("store")).unwrap();
        let registry = Arc::new(NameRegistry::open(directory.path().join("registry")).unwrap());
        let runner = PetalRunner::new(store.clone(), registry, PetalVm::new().unwrap());

        let package = directory.path().join("dummy-reviewer");
        std::fs::create_dir_all(package.join("petal/dummy-reviewer")).unwrap();
        std::fs::write(
            package.join("petal.toml"),
            br#"schema = "bloom.petal.package.v1"
name = "dummy-reviewer"
"#,
        )
        .unwrap();
        std::fs::write(package.join("README.md"), b"# dummy reviewer").unwrap();
        std::fs::write(package.join("AGENTS.md"), b"# dummy reviewer agents").unwrap();
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../bloom-petals/tests/fixtures/route_component_no_imports.wasm");
        let mut component = std::fs::read(fixture).unwrap();
        let marker = b"not a dircomponentread only";
        let marker_at = component
            .windows(marker.len())
            .position(|window| window == marker)
            .unwrap();
        let value_at = marker_at + b"not a dir".len();
        component[value_at..value_at + b"component".len()].copy_from_slice(br#""abstain""#);
        std::fs::write(
            package.join("petal/dummy-reviewer/review.json.wasm"),
            component,
        )
        .unwrap();
        let (_, meta, _) = store.install_petal_package_dir(&package).unwrap();

        let requester_identity = PeerIdentity::generate();
        let requester = requester_identity.endpoint_id();
        let evaluator_identity = PeerIdentity::generate();
        let evaluator = evaluator_identity.endpoint_id();
        let config = CoordinationConfig {
            enabled: true,
            listen: true,
            auto_evaluate: true,
            request_ttl_secs: 30,
            max_envelope_bytes: 64 * 1024,
            max_concurrent_connections: 4,
            max_requests_per_minute: 10,
            iroh: CoordinationIrohConfig::default(),
            evaluators: BTreeMap::from([(
                "dummy-risk".into(),
                CoordinationEvaluatorConfig {
                    petal: "dummy-reviewer".into(),
                    package_hash: meta.hash,
                    route: "review.json".into(),
                    input_schema: "bloom.trade-review-request/v1".into(),
                    output_schema: "bloom.trade-review-decision/v1".into(),
                    auto_run: true,
                    timeout_ms: 3_000,
                    fuel: 5_000_000,
                    memory_pages: 128,
                },
            )]),
        };
        let handler = EvaluatorHandler {
            config,
            petals: runner,
            peers: Arc::new(vec![EnrolledPeer {
                endpoint_addr: EndpointAddr::new(requester),
                allowed_evaluators: vec!["dummy-risk".into()],
                allow_inbound_review: true,
                allow_outbound_review: true,
                enrolled_at_ms: now_ms(),
            }]),
            request_times: Arc::new(Mutex::new(BTreeMap::new())),
        };
        let request = ReviewRequest {
            schema: "bloom.trade-review-request/v1".into(),
            request_id: Uuid::new_v4(),
            evaluator_alias: "dummy-risk".into(),
            intent: TradeIntent {
                venue: "hyperliquid".into(),
                instrument: "BTC".into(),
                side: "buy".into(),
                order_type: "limit".into(),
                quantity: "0.01".into(),
                limit_price: Some("62000".into()),
            },
            facts: serde_json::json!({"dummy": true}),
            requested_output_schema: "bloom.trade-review-decision/v1".into(),
            expires_at_ms: now_ms() + 30_000,
        };
        let requester_node =
            PeerNodeBuilder::new(requester_identity, ReplayStore::memory().unwrap())
                .allow_peer(evaluator)
                .bind()
                .await
                .unwrap();
        let evaluator_node =
            PeerNodeBuilder::new(evaluator_identity, ReplayStore::memory().unwrap())
                .allow_peer(requester)
                .bind()
                .await
                .unwrap();
        let server = evaluator_node.serve(Arc::new(handler));

        let decision = requester_node
            .request_review(evaluator_node.endpoint_addr(), &request)
            .await
            .unwrap();
        assert_eq!(decision.verdict, DecisionVerdict::Abstain);
        assert!(decision.advisory_only);
        assert_eq!(decision.request_id, request.request_id);
        assert_eq!(decision.request_digest, payload_digest(&request).unwrap());

        server.shutdown().await;
        requester_node.close().await;
    }
}
