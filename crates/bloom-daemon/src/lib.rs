//! Daemon library — wires public projections, chain, transaction, and VFS into a
//! single runtime that can serve VFS calls. The actual NFS mount lives
//! in `bloom-mount` and is feature-gated; this library always exposes the
//! VFS via [`Daemon`] for in-process consumers like the CLI.

#![forbid(unsafe_code)]

pub mod ipc;

mod ens_resolver;
mod price_oracle;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, U256};
use alloy::rpc::types::eth::TransactionRequest;
use bloom_evm::{ChainClient, ChainRegistry};

use bloom_ens::EnsClient;
use bloom_etherscan::EtherscanClient;
use bloom_machine_client::MachineJournalHeadProvider;
use bloom_machine_client::{
    CachedWalletProjectionReader, FileProjectionStore, MachineBrokerClient,
    TrustedPetalSignRequest, WalletProjectionReader,
};
use bloom_paid_http::PaidHttpChainRpcResolver;
use bloom_petals::abi::{
    ApprovalRequired, ChainRequest, ChainResponse, EvmOutboxInspection, EvmOutboxOutcome,
    EvmTransactionRequest, PetalRouteContext,
};
use bloom_petals::{
    ApprovalPending, HostError, HostVfsEntry, HttpRequest, HttpResponse, LateVfsHost, NameRegistry,
    NetPolicy, PayloadBatchSignOutcome, PayloadBatchSignRequest, PayloadSignRequest, PetalHost,
    PetalRouter, PetalRunner, PetalStore, PetalVm, SignOutcome,
};
use bloom_prices::PricesClient;
use bloom_proto::audit::AuditRecord;
use bloom_proto::petal_identity::PETAL_ID_PREFIX;
use bloom_proto::{
    AddressBook, AuditIdentity, AuditLog, ChainSpec, Config, GasStrategy, HomeDir, HomeWritePermit,
    RawIntent, RawIntentBody, intent_hash_of,
};
use bloom_revert::{
    AbiSource, BuiltinDecoder, DecoderChain, EtherscanAbiDecoder, EtherscanAbiSource,
    OpenchainDecoder, boxed,
};
use bloom_tx::DynPriceOracle;
use bloom_tx::outbox::{CentralActionIdentity, CentralOutboxProjection, Outbox, OutboxState};
use bloom_tx::tx_engine::{
    ConfirmBatchResult, ConfirmBatchTarget, Eip1559FeeOverrides, TxEngine, TxEngineError,
};
use bloom_vfs::handlers::outbox::StagedPetalIdentity;
use bloom_vfs::handlers::status::{MempoolBackendStatus, PrivateRpcBackendStatus};
use bloom_vfs::handlers::{
    AddressBookHandler, CentralOutbox, ChainsHandler, DocsHandler, EnsHandler, OutboxHandler,
    PETAL_SIGNING_STATE_SCHEMA, PetalKeyRequestsHandler, PetalSigningRequestProjection,
    PetalSigningRequestsHandler, PricesHandler, RequestsHandler, SimulateHandler, StatusHandler,
    ToolsHandler, WalletsHandler, WatchHandler,
};
use bloom_vfs::{
    BrokerExactPayloadSigner, FileOperationIndex, OperationIndex, PathCache, Vfs, VfsPath,
};
use bloom_watch::{WatchExecutor, WatchRegistry};
use futures::StreamExt;
use sha2::Digest as _;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

const WALLET_PROJECTION_LIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// §20 production background-effect inventory. Security-relevant network
/// decisions and durable projections are journaled; purely observational
/// availability caches are intentionally non-authorizing.
pub const BACKGROUND_EFFECT_AUDIT_MATRIX: &[(&str, &str)] = &[
    (
        "Broker wallet projection boot refresh",
        "signed intent/result before Broker read and durable cache replacement",
    ),
    ("tx receipt/trace reconciliation", "signed intent/result"),
    (
        "receipt.json mined-result projection",
        "signed intent/result",
    ),
    ("basefee bump advisory input/output", "signed intent/result"),
    (
        "expired outbox durable state moves",
        "signed intent/result before moving staged entries to expired",
    ),
    (
        "mempool subscription cache",
        "ephemeral non-authorizing observation; no durable authority result",
    ),
    (
        "watch polling and durable live/history rotation",
        "signed intent/result around externally derived watch network calls and projections",
    ),
    (
        "bloom-rpc endpoint health probe loop",
        "volatile transport scoring only; cannot authorize effects or create durable projections",
    ),
    (
        "private RPC health probe",
        "in-memory availability status only; cannot select or authorize submission",
    ),
    (
        "update checker",
        "advisory release metadata only; never installs or executes updates",
    ),
];

const PETAL_HTTP_MAX_REDIRECTS: usize = 5;

/// Concrete adapter that bridges the Machine-owned central outbox and
/// purpose-specific operation index for the EVM tx-engine outbox.
struct EvmOutboxProjection {
    central: CentralOutbox,
    operations: Arc<dyn OperationIndex>,
}

impl EvmOutboxProjection {
    fn new(central: CentralOutbox, operations: Arc<dyn OperationIndex>) -> Self {
        Self {
            central,
            operations,
        }
    }
}

impl CentralOutboxProjection for EvmOutboxProjection {
    fn allocate_action_id(
        &self,
        surface: &str,
        venue_local_id: &str,
        wallet: &str,
        staged_at_ms: u64,
    ) -> Result<String, String> {
        self.operations
            .allocate(surface, venue_local_id, wallet, staged_at_ms)
    }

    fn stage_action(
        &self,
        action_id: &str,
        intent_json: &[u8],
        plan_md: &str,
        policy_check_json: &[u8],
        identity: CentralActionIdentity<'_>,
    ) -> Result<(), String> {
        let intent_hash = intent_hash_of(intent_json);
        self.central
            .stage_with_identity(
                action_id,
                intent_json,
                &intent_hash,
                plan_md,
                policy_check_json,
                &StagedPetalIdentity {
                    petal_id: identity.petal_id.to_string(),
                    petal_digest: identity.petal_digest.to_string(),
                    petal_version: identity.petal_version.to_string(),
                },
            )
            .map_err(|e| e.to_string())
    }

    fn transition_action(&self, action_id: &str, from: &str, to: &str) -> Result<(), String> {
        self.central
            .transition(action_id, from, to)
            .map_err(|e| e.to_string())
    }

    fn write_action_file(
        &self,
        action_id: &str,
        state: &str,
        file: &str,
        data: &[u8],
    ) -> Result<(), String> {
        self.central
            .write_action_file(action_id, state, file, data)
            .map_err(|e| e.to_string())
    }

    fn read_action_file(
        &self,
        action_id: &str,
        state: &str,
        file: &str,
    ) -> Result<Vec<u8>, String> {
        self.central
            .read_action_file(action_id, state, file)
            .map_err(|e| e.to_string())
    }
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("home: {0}")]
    Home(#[from] bloom_proto::HomeError),
    #[error("config: {0}")]
    Config(#[from] bloom_proto::ConfigError),
    #[error("chain: {0}")]
    Chain(#[from] bloom_evm::ChainError),
    #[error("outbox: {0}")]
    Outbox(String),
    #[error("audit: {0}")]
    Audit(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("watch: {0}")]
    Watch(String),
}

struct DaemonPetalHost {
    vfs: Arc<LateVfsHost>,
    http: reqwest::Client,
    audit: Arc<AuditLog>,
    http_audit_lock: tokio::sync::Mutex<()>,
    tx_outbox: Option<PetalTxOutbox>,
    tx_stage_lock: tokio::sync::Mutex<()>,
    broker: Option<MachineBrokerClient>,
    provenance_catalog: Option<bloom_broker_api::ProvenanceCatalog>,
    petal_key_state_root: Option<PathBuf>,
    petal_key_lock: tokio::sync::Mutex<()>,
    petal_signing_state_root: Option<PathBuf>,
    petal_signing_lock: tokio::sync::Mutex<()>,
}

const PETAL_KEY_STATE_SCHEMA: &str = "bloom.machine.petal-key-request.v2";
const PETAL_KEY_INPUT_CLASS: &str = "petal-key-scope-v2";

/// Machine-owned public reconciliation record. The ceremony URL is retained
/// here for an owner-readable status projection, but is never returned across
/// the Petal host boundary.
#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PetalKeyRequestState {
    schema: String,
    key_slot: String,
    scope: bloom_broker_api::PetalKeyScope,
    scope_digest: bloom_broker_api::Digest32,
    /// Digest of the installer-signed provenance record that Broker will
    /// independently require for a Petal-scoped Sealed Approval. This is
    /// public authorization metadata, not a capability or secret.
    provenance_digest: Option<bloom_broker_api::Digest32>,
    status: String,
    ceremony_url: Option<String>,
    ceremony_expires_at_ms: bloom_broker_api::DecimalU64,
    public_key: Option<bloom_broker_api::KeyPublic>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reusable_approval_id: Option<bloom_broker_api::Digest32>,
}

impl PetalKeyRequestState {
    fn guest_outcome(&self) -> Result<bloom_petals::PetalKeyOutcome, HostError> {
        let operation_id = self.scope.custody_operation_id.as_str().to_string();
        let scope_digest = self.scope_digest.as_str().to_string();
        match (&self.status[..], &self.public_key) {
            ("succeeded", Some(key)) => Ok(bloom_petals::PetalKeyOutcome::Ready {
                operation_id,
                scope_digest,
                key_ref_jcs: serde_jcs::to_vec(&key.key_ref).map_err(|error| {
                    HostError::Backend(format!("canonicalize public Petal KeyRef: {error}"))
                })?,
                addresses: key.addresses.clone(),
            }),
            _ => Ok(bloom_petals::PetalKeyOutcome::Pending {
                operation_id,
                scope_digest,
            }),
        }
    }
}

#[derive(Clone)]
struct PetalTxOutbox {
    tx_engine: TxEngine,
    chains: ChainRegistry,
    wallet_projections: Arc<dyn WalletProjectionReader>,
    address_book: Arc<AddressBook>,
    write_permit: Option<Arc<HomeWritePermit>>,
}

impl DaemonPetalHost {
    fn authorize_guest_vfs_path(path: &str) -> Result<(), HostError> {
        let parsed = VfsPath::parse(path)
            .map_err(|error| HostError::Invalid(format!("Petal VFS path: {error}")))?;
        if matches!(
            parsed.first(),
            Some("petal-key-requests" | "petal-signing-requests")
        ) {
            return Err(HostError::Denied(
                "Petal ceremony request projections are owner-only".into(),
            ));
        }
        let segments = parsed.segments();
        let owner_wallet_ceremony_projection = segments.first().map(String::as_str)
            == Some("wallets")
            && ((segments.len() == 2 && segments[1] == "new")
                || (segments.len() >= 2 && segments[1] == "registrations")
                || (segments.len() == 4
                    && segments[2] == "sealed-approvals"
                    && segments[3] == "new.json")
                || (segments.len() == 5
                    && segments[2] == "sealed-approvals"
                    && segments[4] == "renew")
                || (segments.len() == 5
                    && segments[2] == "policy-updates"
                    && segments[3] == "latest"
                    && matches!(
                        segments[4].as_str(),
                        "approval_challenge.json" | "status.json"
                    ))
                || (segments.len() == 6
                    && segments[2] == "policy-updates"
                    && segments[3] == "pending"
                    && matches!(
                        segments[5].as_str(),
                        "approval_challenge.json" | "status.json"
                    )));
        if owner_wallet_ceremony_projection {
            return Err(HostError::Denied(
                "wallet ceremony launch projections are owner-only".into(),
            ));
        }
        Ok(())
    }

    fn new(vfs: Arc<LateVfsHost>, audit: Arc<AuditLog>) -> Self {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .build()
            .expect("daemon petal http client must build");
        Self {
            vfs,
            http,
            audit,
            http_audit_lock: tokio::sync::Mutex::new(()),
            tx_outbox: None,
            tx_stage_lock: tokio::sync::Mutex::new(()),
            broker: None,
            provenance_catalog: None,
            petal_key_state_root: None,
            petal_key_lock: tokio::sync::Mutex::new(()),
            petal_signing_state_root: None,
            petal_signing_lock: tokio::sync::Mutex::new(()),
        }
    }

    fn with_tx_outbox(mut self, tx_outbox: PetalTxOutbox) -> Self {
        self.tx_outbox = Some(tx_outbox);
        self
    }

    fn with_broker(mut self, broker: Option<MachineBrokerClient>) -> Self {
        self.broker = broker;
        self
    }

    fn with_provenance_catalog(
        mut self,
        provenance_catalog: Option<bloom_broker_api::ProvenanceCatalog>,
    ) -> Self {
        self.provenance_catalog = provenance_catalog;
        self
    }

    fn with_petal_key_state_root(mut self, root: PathBuf) -> Self {
        self.petal_key_state_root = Some(root);
        self
    }

    fn with_petal_signing_state_root(mut self, root: PathBuf) -> Self {
        self.petal_signing_state_root = Some(root);
        self
    }

    fn petal_key_state_path(&self, lineage_id: &str, key_slot: &str) -> Result<PathBuf, HostError> {
        let root = self.petal_key_state_root.as_ref().ok_or_else(|| {
            HostError::Backend("Petal key request state is not configured".into())
        })?;
        let identity = blake3::hash(
            format!(
                "bloom-petal-key-request-state/v2\0{}\0{}",
                lineage_id, key_slot
            )
            .as_bytes(),
        );
        Ok(root.join(format!("{}.json", identity.to_hex())))
    }

    fn read_petal_key_state(path: &Path) -> Result<Option<PetalKeyRequestState>, HostError> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|error| HostError::Denied(format!("Petal key state is invalid: {error}"))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(HostError::Backend(format!(
                "read Petal key state {}: {error}",
                path.display()
            ))),
        }
    }

    fn write_petal_key_state(path: &Path, state: &PetalKeyRequestState) -> Result<(), HostError> {
        let parent = path.parent().ok_or_else(|| {
            HostError::Backend("Petal key state path has no parent directory".into())
        })?;
        std::fs::create_dir_all(parent).map_err(|error| {
            HostError::Backend(format!(
                "create Petal key state directory {}: {error}",
                parent.display()
            ))
        })?;
        let temporary = path.with_extension("json.tmp");
        let bytes = serde_jcs::to_vec(state)
            .map_err(|error| HostError::Backend(format!("encode Petal key state: {error}")))?;
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|error| {
            HostError::Backend(format!(
                "open Petal key state {}: {error}",
                temporary.display()
            ))
        })?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| {
                HostError::Backend(format!(
                    "write Petal key state {}: {error}",
                    temporary.display()
                ))
            })?;
        std::fs::rename(&temporary, path).map_err(|error| {
            HostError::Backend(format!(
                "commit Petal key state {}: {error}",
                path.display()
            ))
        })?;
        Ok(())
    }

    async fn prepare_petal_key_reusable_approval(
        &self,
        broker: &MachineBrokerClient,
        wallet: &bloom_broker_api::WalletPublic,
        scope: &bloom_broker_api::PetalKeyScope,
        key_ref: &bloom_broker_api::KeyRef,
        provenance_digest: bloom_broker_api::Digest32,
    ) -> Result<bloom_broker_api::SealedApprovalPrepareResponse, HostError> {
        let catalog = self.provenance_catalog.as_ref().ok_or_else(|| {
            HostError::Backend("installer provenance catalog is not configured".into())
        })?;
        let mut routes = scope.allowed_routes.clone();
        routes.sort();
        routes.dedup();
        let mut route_grants = Vec::with_capacity(routes.len());
        for route in routes {
            let subject = bloom_broker_api::ProvenanceSubject::Petal {
                package_hash: scope.package_hash.clone(),
                route: route.clone(),
            };
            let record = catalog.record(&subject).ok_or_else(|| {
                HostError::Denied(format!(
                    "Petal reusable approval route {route:?} is absent from installer provenance"
                ))
            })?;
            let mut allowed_operation_classes = record
                .operation_classes
                .iter()
                .filter(|entry| {
                    scope
                        .allowed_operation_classes
                        .contains(&entry.operation_class)
                })
                .map(|entry| entry.operation_class.clone())
                .collect::<Vec<_>>();
            allowed_operation_classes.sort_by(|left, right| left.as_str().cmp(right.as_str()));
            if allowed_operation_classes.is_empty() {
                return Err(HostError::Denied(format!(
                    "Petal reusable approval route {route:?} has no scoped provenance class"
                )));
            }
            route_grants.push(bloom_broker_api::PetalRouteGrant {
                route,
                allowed_operation_classes,
                provenance_digest: record.digest().map_err(|error| {
                    HostError::Denied(format!("digest route provenance: {error}"))
                })?,
            });
        }
        let subject_classes = route_grants
            .iter()
            .find(|grant| grant.route == scope.route)
            .map(|grant| grant.allowed_operation_classes.clone())
            .ok_or_else(|| HostError::Denied("derived-key origin route is not granted".into()))?;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .map_err(|error| HostError::Backend(format!("read system time: {error}")))?;
        let lifetime_ms = scope.maximum_lifetime_ms.get();
        let approval_lifetime_ms = if lifetime_ms > 120_000 {
            lifetime_ms - 60_000
        } else {
            lifetime_ms / 2
        };
        if approval_lifetime_ms == 0 {
            return Err(HostError::Denied(
                "derived-key lifetime is too short for reusable approval".into(),
            ));
        }
        let scope_digest = scope
            .digest()
            .map_err(|error| HostError::Invalid(error.to_string()))?;
        let operation_digest = blake3::hash(
            [
                b"bloom-petal-reusable-approval-operation/v1\0".as_slice(),
                scope_digest.as_str().as_bytes(),
                key_ref.public_key_fingerprint.as_str().as_bytes(),
            ]
            .concat()
            .as_slice(),
        );
        let operation_id = bloom_broker_api::OperationId::from_bytes(*operation_digest.as_bytes());
        let request_nonce_hex = hex::encode(sha2::Sha256::digest(
            [
                b"bloom-petal-reusable-approval-nonce/v1\0".as_slice(),
                operation_id.as_str().as_bytes(),
            ]
            .concat(),
        ));
        let request_nonce = bloom_broker_api::RequestNonce::new(&request_nonce_hex[..32])
            .map_err(|error| HostError::Invalid(error.to_string()))?;
        let terms = bloom_broker_api::SealedApprovalTerms {
            subject: bloom_broker_api::ApprovalSubject::Petal {
                package_hash: scope.package_hash.clone(),
                route: scope.route.clone(),
                agent_id: Some(scope.key_slot.as_str().into()),
            },
            wallet_id: scope.wallet_id.clone(),
            key_ref: key_ref.clone(),
            allowed_crypto_suites: scope.allowed_crypto_suites.clone(),
            selector: bloom_broker_api::ApprovalSelector::Petal {
                package_hash: scope.package_hash.clone(),
                route: scope.route.clone(),
                allowed_operation_classes: subject_classes,
                route_grants,
                required_claim_assurance: bloom_broker_api::ClaimAssuranceLevel::MachineAsserted,
            },
            limits: bloom_broker_api::ApprovalLimits {
                max_operations: bloom_broker_api::DecimalU64::new(256),
                max_signatures: bloom_broker_api::DecimalU64::new(256),
                operation_rate_limits: Vec::new(),
                signature_rate_limits: Vec::new(),
                value_limits: Vec::new(),
            },
            activation_mode: if key_ref.backend.as_str() == "local" {
                bloom_broker_api::ActivationMode::BootBound
            } else {
                bloom_broker_api::ActivationMode::BackendManaged
            },
            wallet_revocation_epoch: wallet.wallet_revocation_epoch.clone(),
            policy_version: wallet.policy_version.clone(),
            policy_digest: wallet.policy_digest.clone(),
            provenance_digest,
            request_nonce,
            issued_at_ms: bloom_broker_api::DecimalU64::new(now_ms),
            not_before_ms: bloom_broker_api::DecimalU64::new(now_ms),
            expires_at_ms: bloom_broker_api::DecimalU64::new(
                now_ms.saturating_add(approval_lifetime_ms),
            ),
            renewal_of: None,
        };
        let plan = serde_json::json!({
            "schema": "bloom.machine.petal-key-reusable-approval-facts.v1",
            "wallet_id": &scope.wallet_id,
            "package_hash": &scope.package_hash,
            "key_slot": &scope.key_slot,
            "key_ref": key_ref,
            "selector": &terms.selector,
            "limits": &terms.limits,
            "expires_at_ms": &terms.expires_at_ms,
        });
        let plan_digest = bloom_broker_api::Digest32::from_bytes(
            sha2::Sha256::digest(serde_jcs::to_vec(&plan).map_err(|error| {
                HostError::Invalid(format!("canonicalize approval plan: {error}"))
            })?)
            .into(),
        );
        broker
            .prepare_approval(bloom_broker_api::ApprovalPrepareRequest {
                operation_id,
                terms,
                canonical_plan_facts_digest: plan_digest,
            })
            .await
            .map_err(|error| {
                HostError::Denied(format!("{}: {}", error.code.as_str(), error.message))
            })
    }

    fn reusable_approval_for_key(
        &self,
        key_ref: &bloom_broker_api::KeyRef,
    ) -> Result<Option<bloom_broker_api::Digest32>, HostError> {
        let Some(root) = &self.petal_key_state_root else {
            return Ok(None);
        };
        let entries = match std::fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(HostError::Backend(format!(
                    "list Petal key approval state: {error}"
                )));
            }
        };
        let mut matched = None;
        for entry in entries.take(1024) {
            let path = entry
                .map_err(|error| {
                    HostError::Backend(format!("read Petal key state entry: {error}"))
                })?
                .path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let Some(state) = Self::read_petal_key_state(&path)? else {
                continue;
            };
            if state.status == "succeeded"
                && state
                    .public_key
                    .as_ref()
                    .is_some_and(|public| &public.key_ref == key_ref)
            {
                let approval_id = state.reusable_approval_id.ok_or_else(|| {
                    HostError::Denied("Petal key has no reusable approval binding".into())
                })?;
                if matched.replace(approval_id).is_some() {
                    return Err(HostError::Denied(
                        "multiple reusable approvals match the selected Petal key".into(),
                    ));
                }
            }
        }
        Ok(matched)
    }

    fn petal_signing_paths(
        &self,
        context: &PetalRouteContext,
        wallet: &str,
        operation_class: &str,
        claimed_hash: &[u8; 32],
        canonical_claim: &[u8],
    ) -> Result<(String, PathBuf, PathBuf), HostError> {
        let root = self.petal_signing_state_root.as_ref().ok_or_else(|| {
            HostError::Backend("Petal exact signing state is not configured".into())
        })?;
        let mut identity = blake3::Hasher::new();
        identity.update(b"bloom-petal-exact-signing/v1\0");
        for part in [
            context.package_hash.as_bytes(),
            context.route_id.as_bytes(),
            wallet.as_bytes(),
            operation_class.as_bytes(),
            claimed_hash,
            canonical_claim,
        ] {
            identity.update(&(part.len() as u64).to_be_bytes());
            identity.update(part);
        }
        let request_id = identity.finalize().to_hex().to_string();
        Ok((
            request_id.clone(),
            root.join(".state").join(format!("{request_id}.json")),
            root.join(format!("{request_id}.json")),
        ))
    }

    fn petal_reusable_signing_paths(
        &self,
        context: &PetalRouteContext,
        wallet: &str,
        operation_class: &str,
        signature_count: usize,
    ) -> Result<(String, PathBuf, PathBuf), HostError> {
        let root = self
            .petal_signing_state_root
            .as_ref()
            .ok_or_else(|| HostError::Backend("Petal signing state is not configured".into()))?;
        let mut identity = blake3::Hasher::new();
        identity.update(b"bloom-petal-reusable-batch-signing/v1\0");
        let signature_count = (signature_count as u64).to_be_bytes();
        for part in [
            context.package_hash.as_bytes(),
            context.route_id.as_bytes(),
            wallet.as_bytes(),
            operation_class.as_bytes(),
            signature_count.as_slice(),
        ] {
            identity.update(&(part.len() as u64).to_be_bytes());
            identity.update(part);
        }
        let request_id = identity.finalize().to_hex().to_string();
        Ok((
            request_id.clone(),
            root.join(".state").join(format!("{request_id}.json")),
            root.join(format!("{request_id}.json")),
        ))
    }

    fn write_petal_signing_projection(
        path: &Path,
        state: &PetalSigningRequestProjection,
    ) -> Result<(), HostError> {
        let parent = path.parent().ok_or_else(|| {
            HostError::Backend("Petal signing projection has no parent directory".into())
        })?;
        std::fs::create_dir_all(parent).map_err(|error| {
            HostError::Backend(format!(
                "create Petal signing projection directory {}: {error}",
                parent.display()
            ))
        })?;
        let bytes = serde_json::to_vec_pretty(state).map_err(|error| {
            HostError::Backend(format!("encode Petal signing projection: {error}"))
        })?;
        let temporary = path.with_extension("json.tmp");
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|error| {
            HostError::Backend(format!(
                "open Petal signing projection {}: {error}",
                temporary.display()
            ))
        })?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| {
                HostError::Backend(format!(
                    "write Petal signing projection {}: {error}",
                    temporary.display()
                ))
            })?;
        std::fs::rename(&temporary, path).map_err(|error| {
            HostError::Backend(format!(
                "commit Petal signing projection {}: {error}",
                path.display()
            ))
        })
    }

    fn petal_execution_origin(
        context: &PetalRouteContext,
    ) -> Result<bloom_proto::plan::ExecutionOrigin, HostError> {
        if context.petal_root.trim().is_empty()
            || context.route_id.trim().is_empty()
            || !bloom_petals::store::is_valid_hex_hash(&context.package_hash)
            || !matches!(context.op.as_str(), "lookup" | "list" | "read" | "write")
        {
            return Err(HostError::Invalid(
                "trusted Petal route context is incomplete or has an invalid package hash".into(),
            ));
        }
        Ok(bloom_proto::plan::ExecutionOrigin {
            petal_id: format!("{PETAL_ID_PREFIX}{}", context.petal_root),
            petal_digest: context.package_hash.clone(),
            petal_version: "v1-package".into(),
        })
    }

    fn audit_http_intent(&self, method: &str, url: &str, body: &[u8]) -> Result<String, HostError> {
        let payload_hash = bloom_tools::sha256_hex(body);
        let operation_id = bloom_tools::sha256_hex(
            format!(
                "bloom-machine-petal-http/v1\0{method}\0{}\0{payload_hash}\0{}",
                audit_http_target(url),
                body.len()
            )
            .as_bytes(),
        );
        let correlation_id = format!("{operation_id}:{}", self.audit.sequence() + 1);
        self.audit
            .append(AuditRecord {
                ts_ms: 0,
                kind: "machine.effect.intent".into(),
                wallet: None,
                chain: None,
                data: serde_json::json!({
                    "operation": "petal.http_fetch",
                    "operation_id": operation_id,
                    "correlation_id": correlation_id,
                    "method": method,
                    "target": audit_http_target(url),
                    "payload_sha256": payload_hash,
                    "payload_size": body.len(),
                }),
                prev: String::new(),
                digest: String::new(),
            })
            .map_err(|error| HostError::Backend(format!("Machine audit unavailable: {error}")))?;
        Ok(correlation_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn audit_http_fetch(
        &self,
        correlation_id: &str,
        method: &str,
        url: &str,
        outcome: &str,
        status: Option<u16>,
        body_len: Option<usize>,
        error: Option<&str>,
    ) -> Result<(), HostError> {
        let mut data = serde_json::json!({
            "method": method,
            "target": audit_http_target(url),
            "outcome": outcome,
        });
        if let Some(status) = status {
            data["status"] = serde_json::json!(status);
        }
        if let Some(body_len) = body_len {
            data["body_len"] = serde_json::json!(body_len);
        }
        if let Some(error) = error {
            data["error"] = serde_json::json!(error);
        }
        self.audit
            .append(AuditRecord {
                ts_ms: 0,
                kind: "machine.effect.result".into(),
                wallet: None,
                chain: None,
                data: serde_json::json!({
                    "operation": "petal.http_fetch",
                    "correlation_id": correlation_id,
                    "outcome": outcome,
                    "result": data,
                }),
                prev: String::new(),
                digest: String::new(),
            })
            .map(|_| ())
            .map_err(|error| HostError::Backend(format!("Machine audit unavailable: {error}")))
    }

    #[allow(clippy::too_many_arguments)]
    fn audited_http_error(
        &self,
        correlation_id: &str,
        method: &str,
        url: &str,
        outcome: &str,
        status: Option<u16>,
        body_len: Option<usize>,
        error: HostError,
    ) -> HostError {
        self.audit_http_fetch(
            correlation_id,
            method,
            url,
            outcome,
            status,
            body_len,
            Some(&error.to_string()),
        )
        .err()
        .unwrap_or(error)
    }
}

#[async_trait::async_trait]
impl PetalHost for DaemonPetalHost {
    async fn vfs_lookup(&self, path: &str) -> Result<HostVfsEntry, HostError> {
        Self::authorize_guest_vfs_path(path)?;
        self.vfs.vfs_lookup(path).await
    }

    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
        Self::authorize_guest_vfs_path(path)?;
        self.vfs.vfs_read(path).await
    }

    async fn vfs_list(&self, path: &str) -> Result<Vec<HostVfsEntry>, HostError> {
        Self::authorize_guest_vfs_path(path)?;
        self.vfs.vfs_list(path).await
    }

    async fn vfs_write(&self, path: &str, bytes: &[u8]) -> Result<(), HostError> {
        Self::authorize_guest_vfs_path(path)?;
        self.vfs.vfs_write(path, bytes).await
    }

    async fn petal_key_request(
        &self,
        req: bloom_petals::PetalKeyRequest,
    ) -> Result<bloom_petals::PetalKeyOutcome, HostError> {
        let _guard = self.petal_key_lock.lock().await;
        let broker = self.broker.as_ref().ok_or_else(|| {
            HostError::Backend("SERVICE_UNAVAILABLE: Broker client is not configured".into())
        })?;
        let context = req.context.as_ref().ok_or_else(|| {
            HostError::Denied("Petal key request requires trusted route provenance".into())
        })?;
        Self::petal_execution_origin(context)?;
        let wallet_id = bloom_broker_api::Token::new(req.wallet_id.clone())
            .map_err(|error| HostError::Invalid(error.to_string()))?;
        let key_slot = bloom_broker_api::Token::new(req.key_slot.clone())
            .map_err(|error| HostError::Invalid(error.to_string()))?;
        let allowed_operation_classes = req
            .allowed_operation_classes
            .iter()
            .map(|class| bloom_broker_api::Token::new(class.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| HostError::Invalid(error.to_string()))?;
        if req.maximum_lifetime_ms == 0 {
            return Err(HostError::Invalid(
                "Petal key maximum_lifetime_ms must be greater than zero".into(),
            ));
        }
        let suites = req
            .allowed_crypto_suites
            .iter()
            .map(|suite| {
                serde_json::from_value::<bloom_broker_api::CryptoSuite>(serde_json::Value::String(
                    suite.clone(),
                ))
                .map_err(|_| HostError::Invalid(format!("unsupported crypto suite {suite:?}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if suites.is_empty() {
            return Err(HostError::Invalid(
                "Petal key request requires at least one crypto suite".into(),
            ));
        }

        let wallet = broker.wallet(wallet_id.clone()).await.map_err(|error| {
            HostError::Denied(format!("{}: {}", error.code.as_str(), error.message))
        })?;
        let eligible_parents = wallet
            .key_refs
            .iter()
            .filter(|key| {
                key.derivation.is_none()
                    && suites.iter().all(|suite| suite.key_spec() == key.key_spec)
            })
            .cloned()
            .collect::<Vec<_>>();
        let [parent_key_ref] = eligible_parents.as_slice() else {
            return Err(HostError::Denied(
                "wallet must expose exactly one parent KeyRef compatible with the requested suites"
                    .into(),
            ));
        };
        let provenance_subject = bloom_broker_api::ProvenanceSubject::Petal {
            package_hash: bloom_broker_api::Digest32::new(context.package_hash.clone())
                .map_err(|error| HostError::Invalid(error.to_string()))?,
            route: context.route_id.clone(),
        };
        let provenance_record = self
            .provenance_catalog
            .as_ref()
            .and_then(|catalog| catalog.record(&provenance_subject))
            .ok_or_else(|| {
                HostError::Denied("Petal route is absent from installer provenance".into())
            })?;
        let lineage = provenance_record
            .petal_lineage
            .as_ref()
            .filter(|entry| entry.active)
            .ok_or_else(|| {
                HostError::Denied("Petal package has no active lineage membership".into())
            })?;
        if !req.allowed_routes.contains(&context.route_id) {
            return Err(HostError::Denied(
                "executing route is outside the requested Petal key scope".into(),
            ));
        }
        let operation_hash = blake3::hash(
            format!(
                "bloom-petal-key-custody-operation/v2\0{}\0{}\0{}",
                wallet_id.as_str(),
                lineage.lineage_id,
                key_slot.as_str()
            )
            .as_bytes(),
        );
        let custody_operation_id =
            bloom_broker_api::OperationId::from_bytes(*operation_hash.as_bytes());
        let scope = bloom_broker_api::PetalKeyScope {
            wallet_id: wallet_id.clone(),
            parent_key_ref: parent_key_ref.clone(),
            package_hash: bloom_broker_api::Digest32::new(context.package_hash.clone())
                .map_err(|error| HostError::Invalid(error.to_string()))?,
            route: context.route_id.clone(),
            lineage_id: lineage.lineage_id.clone(),
            key_slot: key_slot.clone(),
            allowed_routes: req.allowed_routes.clone(),
            allowed_operation_classes,
            allowed_crypto_suites: suites,
            maximum_lifetime_ms: bloom_broker_api::DecimalU64::new(req.maximum_lifetime_ms),
            custody_operation_id: custody_operation_id.clone(),
        };
        let scope_digest = scope
            .digest()
            .map_err(|error| HostError::Invalid(error.to_string()))?;
        let provenance_digest = Some(
            provenance_record
                .digest()
                .map_err(|error| HostError::Denied(error.to_string()))?,
        );
        let path = self.petal_key_state_path(&lineage.lineage_id, key_slot.as_str())?;

        if let Some(mut stored) = Self::read_petal_key_state(&path)? {
            if stored.schema != PETAL_KEY_STATE_SCHEMA
                || stored.key_slot != req.key_slot
                || stored
                    .scope
                    .digest()
                    .map_err(|error| HostError::Denied(error.to_string()))?
                    != scope_digest
                || stored.scope_digest != scope_digest
                || stored.provenance_digest != provenance_digest
                || !matches!(
                    (
                        stored.status.as_str(),
                        stored.public_key.is_some(),
                        stored.ceremony_url.is_some()
                    ),
                    ("awaiting_user", false, true)
                        | ("awaiting_user", true, true)
                        | ("succeeded", true, false)
                )
            {
                return Err(HostError::Denied(
                    "Petal key request_id was already used with different terms".into(),
                ));
            }
            if let Some(public) = stored.public_key.as_ref() {
                if stored.reusable_approval_id.is_none() {
                    let reusable = self
                        .prepare_petal_key_reusable_approval(
                            broker,
                            &wallet,
                            &scope,
                            &public.key_ref,
                            provenance_digest.clone().ok_or_else(|| {
                                HostError::Denied("Petal provenance digest is missing".into())
                            })?,
                        )
                        .await?;
                    stored.reusable_approval_id = Some(reusable.approval_id);
                    stored.status = "awaiting_user".into();
                    stored.ceremony_url = Some(reusable.ceremony_url);
                    stored.ceremony_expires_at_ms = reusable.ceremony_expires_at_ms;
                    Self::write_petal_key_state(&path, &stored)?;
                    return stored.guest_outcome();
                }
                let approval_id = stored
                    .reusable_approval_id
                    .clone()
                    .expect("checked reusable approval id");
                let approval = broker.approval_status(approval_id).await.map_err(|error| {
                    HostError::Denied(format!("{}: {}", error.code.as_str(), error.message))
                })?;
                return match approval.state {
                    bloom_broker_api::ApprovalLifecycleState::Active => {
                        stored.status = "succeeded".into();
                        stored.ceremony_url = None;
                        Self::write_petal_key_state(&path, &stored)?;
                        stored.guest_outcome()
                    }
                    bloom_broker_api::ApprovalLifecycleState::Prepared
                    | bloom_broker_api::ApprovalLifecycleState::AwaitingCeremony => {
                        stored.guest_outcome()
                    }
                    state => Err(HostError::Denied(format!(
                        "Petal reusable approval is not active: {state:?}"
                    ))),
                };
            }
            match broker
                .custody_result(bloom_broker_api::OperationRequest {
                    operation_id: custody_operation_id.clone(),
                })
                .await
            {
                Ok(result) => {
                    if result.ceremony_kind != bloom_broker_api::CeremonyKind::KeyDerive
                        || result.custody_operation_id != custody_operation_id
                        || result.wallet_id.as_ref() != Some(&wallet_id)
                        || result.encrypted_browser_result.is_some()
                    {
                        return Err(HostError::Denied(
                            "Broker returned a custody result outside the requested Petal scope"
                                .into(),
                        ));
                    }
                    let [derived_key_ref] = result.public_key_refs.as_slice() else {
                        return Err(HostError::Denied(
                            "Petal custody result must contain exactly one public KeyRef".into(),
                        ));
                    };
                    let public = broker
                        .key(bloom_broker_api::KeyRequest {
                            key_ref: derived_key_ref.clone(),
                        })
                        .await
                        .map_err(|error| {
                            HostError::Denied(format!("{}: {}", error.code.as_str(), error.message))
                        })?;
                    if public.key_ref != *derived_key_ref
                        || !scope
                            .allowed_crypto_suites
                            .iter()
                            .all(|suite| public.supported_crypto_suites.contains(suite))
                    {
                        return Err(HostError::Denied(
                            "Broker returned public key metadata outside the Petal scope".into(),
                        ));
                    }
                    if stored
                        .public_key
                        .as_ref()
                        .is_some_and(|previous| previous != &public)
                    {
                        return Err(HostError::Denied(
                            "persisted Petal public key conflicts with Broker custody result"
                                .into(),
                        ));
                    }
                    let reusable = self
                        .prepare_petal_key_reusable_approval(
                            broker,
                            &wallet,
                            &scope,
                            &public.key_ref,
                            provenance_digest.clone().ok_or_else(|| {
                                HostError::Denied("Petal provenance digest is missing".into())
                            })?,
                        )
                        .await?;
                    stored.public_key = Some(public);
                    stored.reusable_approval_id = Some(reusable.approval_id);
                    stored.status = "awaiting_user".into();
                    stored.ceremony_url = Some(reusable.ceremony_url);
                    stored.ceremony_expires_at_ms = reusable.ceremony_expires_at_ms;
                    Self::write_petal_key_state(&path, &stored)?;
                    return stored.guest_outcome();
                }
                Err(error)
                    if error.code == bloom_broker_api::ProtocolErrorCode::ApprovalNotFound =>
                {
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|duration| duration.as_millis() as u64)
                        .unwrap_or(0);
                    if stored.ceremony_expires_at_ms.get() <= now_ms {
                        return Err(HostError::Denied(
                            "Petal key custody ceremony expired before completion".into(),
                        ));
                    }
                    return stored.guest_outcome();
                }
                Err(error) => {
                    return Err(HostError::Denied(format!(
                        "{}: {}",
                        error.code.as_str(),
                        error.message
                    )));
                }
            }
        }

        let prepared = broker
            .prepare_custody(
                bloom_machine_client::CustodyPrepareMethod::KeyDerive,
                bloom_broker_api::CustodyPrepareRequest {
                    ceremony_kind: bloom_broker_api::CeremonyKind::KeyDerive,
                    custody_operation_id: custody_operation_id.clone(),
                    wallet_id: Some(wallet_id),
                    key_ref: Some(parent_key_ref.clone()),
                    exact_terms_digest: scope
                        .request_digest()
                        .map_err(|error| HostError::Invalid(error.to_string()))?,
                    expected_input_class: bloom_broker_api::Token::new(PETAL_KEY_INPUT_CLASS)
                        .expect("static Petal key input class is valid"),
                    browser_output_recipient_key: None,
                    petal_key_scope: Some(scope.clone()),
                    legacy_passkey_migration: None,
                },
            )
            .await
            .map_err(|error| {
                HostError::Denied(format!("{}: {}", error.code.as_str(), error.message))
            })?;
        if prepared.ceremony_kind != bloom_broker_api::CeremonyKind::KeyDerive
            || prepared.custody_operation_id != custody_operation_id
        {
            return Err(HostError::Denied(
                "Broker returned a mismatched Petal custody preparation".into(),
            ));
        }
        let stored = PetalKeyRequestState {
            schema: PETAL_KEY_STATE_SCHEMA.into(),
            key_slot: req.key_slot,
            scope,
            scope_digest,
            provenance_digest,
            status: "awaiting_user".into(),
            ceremony_url: Some(prepared.ceremony_url),
            ceremony_expires_at_ms: prepared.ceremony_expires_at_ms,
            public_key: None,
            reusable_approval_id: None,
        };
        Self::write_petal_key_state(&path, &stored)?;
        stored.guest_outcome()
    }

    async fn http_fetch(
        &self,
        req: HttpRequest,
        policy: NetPolicy,
        max_response_bytes: usize,
    ) -> Result<HttpResponse, HostError> {
        // Keep each network intent/result pair adjacent. The audit journal
        // itself supports multiple outstanding correlations, but serializing
        // Petal HTTP makes crash reconciliation and operator diagnosis exact.
        let _audit_guard = self.http_audit_lock.lock().await;
        let mut method = req.method;
        let mut url = req.url;
        let mut body = req.body;
        let mut headers = req.headers;
        for redirect_count in 0..=PETAL_HTTP_MAX_REDIRECTS {
            let correlation_id = self.audit_http_intent(&method, &url, &body)?;
            if let Err(e) = policy.check(&method, &url) {
                return Err(self.audited_http_error(
                    &correlation_id,
                    &method,
                    &url,
                    "denied",
                    None,
                    None,
                    e,
                ));
            }
            let reqwest_method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| {
                let err = HostError::Invalid(format!("http method: {e}"));
                self.audited_http_error(&correlation_id, &method, &url, "error", None, None, err)
            })?;
            let mut builder = self.http.request(reqwest_method, &url);
            for (name, value) in &headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            let resp = builder.body(body.clone()).send().await.map_err(|e| {
                let err = HostError::Backend(format!("http_fetch send: {e}"));
                self.audited_http_error(&correlation_id, &method, &url, "error", None, None, err)
            })?;
            let status = resp.status().as_u16();
            if resp.status().is_redirection() {
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                let Some(location) = location else {
                    let err = HostError::Backend("http redirect missing Location".into());
                    return Err(self.audited_http_error(
                        &correlation_id,
                        &method,
                        &url,
                        "error",
                        Some(status),
                        None,
                        err,
                    ));
                };
                if redirect_count == PETAL_HTTP_MAX_REDIRECTS {
                    let err = HostError::Backend("http redirect limit exceeded".into());
                    return Err(self.audited_http_error(
                        &correlation_id,
                        &method,
                        &url,
                        "error",
                        Some(status),
                        None,
                        err,
                    ));
                }
                let next_url = match resolve_redirect_target(&url, &location) {
                    Ok(url) => url,
                    Err(e) => {
                        return Err(self.audited_http_error(
                            &correlation_id,
                            &method,
                            &url,
                            "error",
                            Some(status),
                            None,
                            e,
                        ));
                    }
                };
                let next_method = redirect_method(&method, status);
                if let Err(e) = policy.check(&next_method, &next_url) {
                    return Err(self.audited_http_error(
                        &correlation_id,
                        &method,
                        &url,
                        "denied_redirect",
                        Some(status),
                        None,
                        e,
                    ));
                }
                if let Err(e) =
                    prepare_redirect_request(&url, &next_url, &next_method, &mut headers, &mut body)
                {
                    return Err(self.audited_http_error(
                        &correlation_id,
                        &method,
                        &url,
                        "denied_redirect",
                        Some(status),
                        None,
                        e,
                    ));
                }
                self.audit_http_fetch(
                    &correlation_id,
                    &method,
                    &url,
                    "redirect",
                    Some(status),
                    None,
                    None,
                )?;
                method = next_method;
                url = next_url;
                continue;
            }
            let headers = resp
                .headers()
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_string(),
                        value.to_str().unwrap_or_default().to_string(),
                    )
                })
                .collect();
            if resp.content_length().is_some_and(|len| {
                usize::try_from(len)
                    .map(|len| len > max_response_bytes)
                    .unwrap_or(true)
            }) {
                let err = HostError::Backend("http response too large".into());
                return Err(self.audited_http_error(
                    &correlation_id,
                    &method,
                    &url,
                    "error",
                    Some(status),
                    None,
                    err,
                ));
            }
            let mut body = Vec::new();
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| {
                    let err = HostError::Backend(format!("http_fetch body: {e}"));
                    self.audited_http_error(
                        &correlation_id,
                        &method,
                        &url,
                        "error",
                        Some(status),
                        Some(body.len()),
                        err,
                    )
                })?;
                if body.len().saturating_add(chunk.len()) > max_response_bytes {
                    let err = HostError::Backend("http response too large".into());
                    return Err(self.audited_http_error(
                        &correlation_id,
                        &method,
                        &url,
                        "error",
                        Some(status),
                        Some(body.len().saturating_add(chunk.len())),
                        err,
                    ));
                }
                body.extend_from_slice(&chunk);
            }
            self.audit_http_fetch(
                &correlation_id,
                &method,
                &url,
                "ok",
                Some(status),
                Some(body.len()),
                None,
            )?;
            return Ok(HttpResponse {
                status,
                headers,
                body,
            });
        }
        unreachable!("bounded redirect loop returns before exhausting iterator")
    }

    async fn sign_payload_outcome(
        &self,
        req: PayloadSignRequest,
    ) -> Result<SignOutcome, HostError> {
        let broker = self.broker.as_ref().ok_or_else(|| {
            HostError::Backend("SERVICE_UNAVAILABLE: Broker client is not configured".into())
        })?;
        let context = req.context.as_ref().ok_or_else(|| {
            warn!(
                wallet = %req.wallet,
                operation_class = %req.operation_class,
                reason = "request carried no trusted Petal route context",
                "petal.sign_payload_denied"
            );
            HostError::Denied("payload signing requires trusted Petal route provenance".into())
        })?;
        let crypto_suite = match req.signature_algorithm.as_str() {
            "secp256k1-keccak256-recoverable" => {
                bloom_broker_api::CryptoSuite::Secp256k1Keccak256Recoverable
            }
            "secp256k1-sha256-recoverable" => {
                bloom_broker_api::CryptoSuite::Secp256k1Sha256Recoverable
            }
            "ed25519-message" => bloom_broker_api::CryptoSuite::Ed25519Message,
            _ => {
                return Err(HostError::Invalid(format!(
                    "unsupported signature algorithm {:?}",
                    req.signature_algorithm
                )));
            }
        };
        let claim: bloom_broker_api::PetalUseClaim =
            serde_json::from_slice(&req.petal_use_claim_jcs)
                .map_err(|error| HostError::Invalid(format!("decode PetalUseClaim: {error}")))?;
        let canonical_claim = serde_jcs::to_vec(&claim)
            .map_err(|error| HostError::Invalid(format!("canonicalize PetalUseClaim: {error}")))?;
        if canonical_claim != req.petal_use_claim_jcs {
            return Err(HostError::Invalid(
                "PetalUseClaim must use exact RFC 8785 canonical JSON".into(),
            ));
        }
        let trusted_package_hash = bloom_broker_api::Digest32::new(context.package_hash.clone())
            .map_err(|error| HostError::Invalid(error.to_string()))?;
        if req.selector == bloom_broker_api::PetalSignSelector::Exact {
            if req.key_ref.is_some() {
                warn!(
                    wallet = %req.wallet,
                    operation_class = %req.operation_class,
                    package_hash = %context.package_hash,
                    route = %context.route_id,
                    reason = "exact Petal signing supplied a key reference",
                    "petal.sign_payload_denied"
                );
                return Err(HostError::Denied(
                    "exact Petal signing uses Machine-owned root selection and approval state"
                        .into(),
                ));
            }
            let trusted_subject = bloom_broker_api::ProvenanceSubject::Petal {
                package_hash: trusted_package_hash.clone(),
                route: context.route_id.clone(),
            };
            let (request_id, exact_state_path, owner_projection_path) = self.petal_signing_paths(
                context,
                &req.wallet,
                &req.operation_class,
                &req.claimed_hash,
                &canonical_claim,
            )?;
            if req
                .approval_hint
                .as_deref()
                .is_some_and(|hint| hint != request_id)
            {
                warn!(
                    wallet = %req.wallet,
                    operation_class = %req.operation_class,
                    package_hash = %context.package_hash,
                    route = %context.route_id,
                    request_id = %request_id,
                    reason = "approval hint does not match the derived request id",
                    "petal.sign_payload_denied"
                );
                return Err(HostError::Denied(
                    "approval artifact does not match the exact Petal operation".into(),
                ));
            }
            let payload_digest =
                bloom_broker_api::Digest32::from_bytes(sha2::Sha256::digest(&req.preimage).into());
            let canonical_facts = serde_json::json!({
                "schema": "bloom.machine.petal-exact-facts.v1",
                "request_id": request_id,
                "package_hash": context.package_hash,
                "route": context.route_id,
                "wallet": req.wallet,
                "operation_class": req.operation_class,
                "crypto_suite": crypto_suite,
                "payload_digest": payload_digest,
                "claimed_hash": hex::encode(req.claimed_hash),
                "petal_use_claim_digest": bloom_broker_api::Digest32::from_bytes(
                    sha2::Sha256::digest(&canonical_claim).into()
                ),
                "claim_assurance_evidence_digest": req.claim_assurance_evidence.as_ref()
                    .map(|bytes| hex::encode(sha2::Sha256::digest(bytes))),
                "action_digest": req.action.as_ref().map(|bytes| hex::encode(sha2::Sha256::digest(bytes))),
                "advisory_digest": req.advisory.as_ref().map(|bytes| hex::encode(sha2::Sha256::digest(bytes))),
            });
            let catalog = self.provenance_catalog.clone().ok_or_else(|| {
                HostError::Backend("installer provenance catalog is not configured".into())
            })?;
            let signer = BrokerExactPayloadSigner::new(broker.clone(), catalog);
            let _guard = self.petal_signing_lock.lock().await;
            let outcome = signer
                .sign_or_prepare_petal(
                    &exact_state_path,
                    &request_id,
                    &req.wallet,
                    &req.operation_class,
                    &req.preimage,
                    bloom_broker_api::Digest32::from_bytes(req.claimed_hash),
                    crypto_suite,
                    &canonical_facts,
                    &trusted_subject,
                    &claim,
                    req.claim_assurance_evidence.as_deref(),
                )
                .await
                .map_err(|reason| {
                    // Host-side only. The Petal guest and the mount both
                    // collapse this to an unqualified permission error, so
                    // without this line an operator cannot tell which
                    // condition refused the signature. Machine logs never
                    // enter an evaluated agent's container, so recording the
                    // reason here does not widen what the guest can observe.
                    warn!(
                        wallet = %req.wallet,
                        operation_class = %req.operation_class,
                        package_hash = %context.package_hash,
                        route = %context.route_id,
                        request_id = %request_id,
                        reason = %reason,
                        "petal.sign_payload_denied"
                    );
                    HostError::Denied(reason)
                })?;
            return match outcome {
                bloom_vfs::ExactPayloadOutcome::ApprovalRequired {
                    approval_id,
                    ceremony_url,
                    ceremony_expires_at_ms,
                } => {
                    Self::write_petal_signing_projection(
                        &owner_projection_path,
                        &PetalSigningRequestProjection {
                            schema: PETAL_SIGNING_STATE_SCHEMA.into(),
                            request_id: request_id.clone(),
                            package_hash: context.package_hash.clone(),
                            route_id: context.route_id.clone(),
                            wallet: req.wallet.clone(),
                            operation_class: req.operation_class.clone(),
                            payload_digest: payload_digest.as_str().into(),
                            approval_id: Some(approval_id.as_str().into()),
                            status: "awaiting_owner_approval".into(),
                            ceremony_url: Some(ceremony_url),
                            ceremony_expires_at_ms: Some(ceremony_expires_at_ms),
                        },
                    )?;
                    Ok(SignOutcome::ApprovalPending(ApprovalPending {
                        action_id: request_id,
                        expires_ms: ceremony_expires_at_ms,
                    }))
                }
                bloom_vfs::ExactPayloadOutcome::Signed(bytes) => {
                    Self::write_petal_signing_projection(
                        &owner_projection_path,
                        &PetalSigningRequestProjection {
                            schema: PETAL_SIGNING_STATE_SCHEMA.into(),
                            request_id,
                            package_hash: context.package_hash.clone(),
                            route_id: context.route_id.clone(),
                            wallet: req.wallet.clone(),
                            operation_class: req.operation_class.clone(),
                            payload_digest: payload_digest.as_str().into(),
                            approval_id: None,
                            status: "signed".into(),
                            ceremony_url: None,
                            ceremony_expires_at_ms: None,
                        },
                    )?;
                    Ok(SignOutcome::Signature(bytes))
                }
            };
        }
        let selected_key_ref = req.key_ref;
        let approval_hint = match (req.approval_hint, selected_key_ref.as_ref()) {
            (Some(hint), _) => Some(hint),
            (None, Some(key_ref)) => self
                .reusable_approval_for_key(key_ref)?
                .map(|approval_id| approval_id.as_str().to_owned()),
            (None, None) => None,
        };
        let approval_id = approval_hint
            .map(bloom_broker_api::Digest32::new)
            .transpose()
            .map_err(|error| HostError::Invalid(error.to_string()))?;
        let trusted_request = TrustedPetalSignRequest {
            wallet_id: bloom_broker_api::Token::new(req.wallet)
                .map_err(|error| HostError::Invalid(error.to_string()))?,
            preimage: req.preimage,
            claimed_hash: bloom_broker_api::Digest32::from_bytes(req.claimed_hash),
            crypto_suite,
            operation_class: bloom_broker_api::Token::new(req.operation_class)
                .map_err(|error| HostError::Invalid(error.to_string()))?,
            selector: req.selector,
            claim,
            claim_assurance_evidence: req.claim_assurance_evidence,
            approval_id,
            trusted_provenance: bloom_broker_api::ProvenanceSubject::Petal {
                package_hash: trusted_package_hash,
                route: context.route_id.clone(),
            },
            frozen_action: req.action,
            frozen_advisory: req.advisory,
        };
        let result = match selected_key_ref {
            Some(key_ref) => {
                broker
                    .sign_petal_payload_with_key(trusted_request, key_ref)
                    .await
            }
            None => broker.sign_petal_payload(trusted_request).await,
        }
        .map_err(|error| {
            warn!(
                package_hash = %context.package_hash,
                route = %context.route_id,
                reason = %error,
                "petal.sign_payload_denied"
            );
            HostError::Denied(format!("{}: {}", error.code.as_str(), error.message))
        })?;
        let [signature] = result.signatures.as_slice() else {
            return Err(HostError::Backend(
                "Broker returned an invalid signature count".into(),
            ));
        };
        let bytes = signature.bytes.decode();
        match signature.crypto_suite.signature_encoding() {
            bloom_broker_api::SignatureEncoding::Secp256k1Recoverable65 if bytes.len() == 65 => {}
            bloom_broker_api::SignatureEncoding::Ed25519Raw64 if bytes.len() == 64 => {}
            _ => {
                return Err(HostError::Backend(
                    "Broker returned an invalid normalized signature".into(),
                ));
            }
        }
        Ok(SignOutcome::Signature(bytes))
    }

    async fn sign_payload_batch_outcome(
        &self,
        req: PayloadBatchSignRequest,
    ) -> Result<PayloadBatchSignOutcome, HostError> {
        if req.key_ref.is_some() {
            return Err(HostError::Denied(
                "Petal payload batches require Machine-owned approval and root selection".into(),
            ));
        }
        let broker = self.broker.as_ref().ok_or_else(|| {
            HostError::Backend("SERVICE_UNAVAILABLE: Broker client is not configured".into())
        })?;
        let context = req.context.as_ref().ok_or_else(|| {
            HostError::Denied("payload batch signing requires trusted Petal provenance".into())
        })?;
        let crypto_suite = match req.signature_algorithm.as_str() {
            "secp256k1-keccak256-recoverable" => {
                bloom_broker_api::CryptoSuite::Secp256k1Keccak256Recoverable
            }
            "secp256k1-sha256-recoverable" => {
                bloom_broker_api::CryptoSuite::Secp256k1Sha256Recoverable
            }
            "ed25519-message" => bloom_broker_api::CryptoSuite::Ed25519Message,
            _ => {
                return Err(HostError::Invalid(format!(
                    "unsupported signature algorithm {:?}",
                    req.signature_algorithm
                )));
            }
        };
        let claim: bloom_broker_api::PetalUseClaim =
            serde_json::from_slice(&req.petal_use_claim_jcs)
                .map_err(|error| HostError::Invalid(format!("decode PetalUseClaim: {error}")))?;
        let canonical_claim = serde_jcs::to_vec(&claim)
            .map_err(|error| HostError::Invalid(format!("canonicalize PetalUseClaim: {error}")))?;
        if canonical_claim != req.petal_use_claim_jcs {
            return Err(HostError::Invalid(
                "PetalUseClaim must use exact RFC 8785 canonical JSON".into(),
            ));
        }
        let preimages = req
            .payloads
            .iter()
            .map(|item| item.preimage.clone())
            .collect::<Vec<_>>();
        let claimed_hashes = req
            .payloads
            .iter()
            .map(|item| bloom_broker_api::Digest32::from_bytes(item.claimed_hash))
            .collect::<Vec<_>>();
        let recomputed_hashes = preimages
            .iter()
            .map(|payload| match crypto_suite {
                bloom_broker_api::CryptoSuite::Secp256k1Keccak256Recoverable => {
                    bloom_broker_api::Digest32::from_bytes(
                        alloy::primitives::keccak256(payload).into(),
                    )
                }
                bloom_broker_api::CryptoSuite::Secp256k1Sha256Recoverable
                | bloom_broker_api::CryptoSuite::Ed25519Message => {
                    bloom_broker_api::Digest32::from_bytes(sha2::Sha256::digest(payload).into())
                }
            })
            .collect::<Vec<_>>();
        if claimed_hashes != recomputed_hashes {
            return Err(HostError::Denied(
                "payload batch claimed hashes do not match exact payload bytes".into(),
            ));
        }
        let mut batch_hasher = sha2::Sha256::new();
        batch_hasher.update(b"bloom.petal.payload-batch.v1\0");
        batch_hasher.update((preimages.len() as u64).to_be_bytes());
        for payload in &preimages {
            batch_hasher.update((payload.len() as u64).to_be_bytes());
            batch_hasher.update(payload);
        }
        let batch_digest_bytes: [u8; 32] = batch_hasher.finalize().into();
        let batch_digest = bloom_broker_api::Digest32::from_bytes(batch_digest_bytes);
        let trusted_package_hash = bloom_broker_api::Digest32::new(context.package_hash.clone())
            .map_err(|error| HostError::Invalid(error.to_string()))?;
        if claim.package_hash != trusted_package_hash
            || claim.route != context.route_id
            || claim.operation_class.as_str() != req.operation_class
            || claim.crypto_suite != crypto_suite
            || claim.payload_digest != batch_digest
            || claim.ordered_hashes != recomputed_hashes
        {
            return Err(HostError::Denied(
                "payload batch claim does not match trusted route or exact ordered payloads".into(),
            ));
        }
        let trusted_subject = bloom_broker_api::ProvenanceSubject::Petal {
            package_hash: trusted_package_hash,
            route: context.route_id.clone(),
        };
        let (request_id, exact_state_path, owner_projection_path) = match req.selector {
            bloom_broker_api::PetalSignSelector::Exact => self.petal_signing_paths(
                context,
                &req.wallet,
                &req.operation_class,
                &batch_digest_bytes,
                &canonical_claim,
            )?,
            bloom_broker_api::PetalSignSelector::Reusable => self.petal_reusable_signing_paths(
                context,
                &req.wallet,
                &req.operation_class,
                preimages.len(),
            )?,
        };
        if req
            .approval_hint
            .as_deref()
            .is_some_and(|hint| hint != request_id)
        {
            return Err(HostError::Denied(
                "approval artifact does not match the Petal batch authorization".into(),
            ));
        }
        let payload_digests = preimages
            .iter()
            .map(|payload| {
                bloom_broker_api::Digest32::from_bytes(sha2::Sha256::digest(payload).into())
            })
            .collect::<Vec<_>>();
        let canonical_facts = match req.selector {
            bloom_broker_api::PetalSignSelector::Exact => serde_json::json!({
                "schema": "bloom.machine.petal-exact-batch-facts.v1",
                "request_id": request_id,
                "package_hash": context.package_hash,
                "route": context.route_id,
                "wallet": req.wallet,
                "operation_class": req.operation_class,
                "crypto_suite": crypto_suite,
                "batch_payload_digest": batch_digest,
                "ordered_payload_digests": payload_digests,
                "ordered_hashes": recomputed_hashes,
                "petal_use_claim_digest": bloom_broker_api::Digest32::from_bytes(
                    sha2::Sha256::digest(&canonical_claim).into()
                ),
                "claim_assurance_evidence_digest": req.claim_assurance_evidence.as_ref()
                    .map(|bytes| hex::encode(sha2::Sha256::digest(bytes))),
                "action_digest": req.action.as_ref().map(|bytes| hex::encode(sha2::Sha256::digest(bytes))),
                "advisory_digest": req.advisory.as_ref().map(|bytes| hex::encode(sha2::Sha256::digest(bytes))),
            }),
            bloom_broker_api::PetalSignSelector::Reusable => serde_json::json!({
                "schema": "bloom.machine.petal-reusable-batch-facts.v1",
                "request_id": request_id,
                "package_hash": context.package_hash,
                "route": context.route_id,
                "wallet": req.wallet,
                "operation_class": req.operation_class,
                "crypto_suite": crypto_suite,
                "max_operations": 1,
                "max_signatures": preimages.len(),
                "required_claim_assurance": claim.claim_assurance.level(),
            }),
        };
        let catalog = self.provenance_catalog.clone().ok_or_else(|| {
            HostError::Backend("installer provenance catalog is not configured".into())
        })?;
        let signer = BrokerExactPayloadSigner::new(broker.clone(), catalog);
        let _guard = self.petal_signing_lock.lock().await;
        let outcome = if req.selector == bloom_broker_api::PetalSignSelector::Reusable {
            signer
                .sign_or_prepare_reusable_petal_batch(
                    &exact_state_path,
                    &request_id,
                    &req.wallet,
                    &req.operation_class,
                    &preimages,
                    &claimed_hashes,
                    crypto_suite,
                    &canonical_facts,
                    &trusted_subject,
                    &claim,
                    req.claim_assurance_evidence.as_deref(),
                )
                .await
        } else {
            signer
                .sign_or_prepare_petal_batch(
                    &exact_state_path,
                    &request_id,
                    &req.wallet,
                    &req.operation_class,
                    &preimages,
                    &claimed_hashes,
                    crypto_suite,
                    &canonical_facts,
                    &trusted_subject,
                    &claim,
                    req.claim_assurance_evidence.as_deref(),
                )
                .await
        }
        .map_err(HostError::Denied)?;
        match outcome {
            bloom_vfs::ExactPayloadBatchOutcome::ApprovalRequired {
                approval_id,
                ceremony_url,
                ceremony_expires_at_ms,
            } => {
                Self::write_petal_signing_projection(
                    &owner_projection_path,
                    &PetalSigningRequestProjection {
                        schema: PETAL_SIGNING_STATE_SCHEMA.into(),
                        request_id: request_id.clone(),
                        package_hash: context.package_hash.clone(),
                        route_id: context.route_id.clone(),
                        wallet: req.wallet,
                        operation_class: req.operation_class,
                        payload_digest: batch_digest.as_str().into(),
                        approval_id: Some(approval_id.as_str().into()),
                        status: "awaiting_owner_approval".into(),
                        ceremony_url: Some(ceremony_url),
                        ceremony_expires_at_ms: Some(ceremony_expires_at_ms),
                    },
                )?;
                Ok(PayloadBatchSignOutcome::ApprovalPending(ApprovalPending {
                    action_id: request_id,
                    expires_ms: ceremony_expires_at_ms,
                }))
            }
            bloom_vfs::ExactPayloadBatchOutcome::Signed(signatures) => {
                Self::write_petal_signing_projection(
                    &owner_projection_path,
                    &PetalSigningRequestProjection {
                        schema: PETAL_SIGNING_STATE_SCHEMA.into(),
                        request_id,
                        package_hash: context.package_hash.clone(),
                        route_id: context.route_id.clone(),
                        wallet: req.wallet,
                        operation_class: req.operation_class,
                        payload_digest: batch_digest.as_str().into(),
                        approval_id: None,
                        status: "signed".into(),
                        ceremony_url: None,
                        ceremony_expires_at_ms: None,
                    },
                )?;
                Ok(PayloadBatchSignOutcome::Signatures(signatures))
            }
        }
    }

    async fn evm_tx_stage(
        &self,
        req: EvmTransactionRequest,
    ) -> Result<EvmOutboxOutcome, HostError> {
        let context = req.context.as_ref().ok_or_else(|| {
            HostError::Denied("Petal EVM outbox requires trusted Petal route context".into())
        })?;
        let origin = Self::petal_execution_origin(context)?;
        let service = self
            .tx_outbox
            .as_ref()
            .ok_or_else(|| HostError::Denied("EVM outbox is unavailable".into()))?;
        let permit = service
            .write_permit
            .as_deref()
            .ok_or_else(|| HostError::Denied("EVM outbox requires daemon write permit".into()))?;
        if req.value_wei.is_empty() || !req.value_wei.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(HostError::Invalid(
                "value-wei must be an unsigned decimal integer".into(),
            ));
        }
        if !req.data_hex.starts_with("0x")
            || !req.data_hex.len().is_multiple_of(2)
            || req.data_hex != req.data_hex.to_ascii_lowercase()
            || hex::decode(&req.data_hex[2..]).is_err()
        {
            return Err(HostError::Invalid(
                "data-hex must be canonical 0x-prefixed hex".into(),
            ));
        }
        let wallet_id = bloom_broker_api::Token::new(req.wallet.clone())
            .map_err(|error| HostError::Invalid(format!("wallet: {error}")))?;
        let wallet_projection = service
            .wallet_projections
            .get_wallet(&wallet_id)
            .await
            .map_err(|error| HostError::Invalid(format!("wallet: {error}")))?;
        let wallet_address = wallet_projection
            .primary_address()
            .map_err(|error| HostError::Invalid(format!("wallet: {error}")))?
            .parse::<Address>()
            .map_err(|error| HostError::Invalid(format!("wallet address: {error}")))?;
        let wallet_policy = bloom_vfs::advisory_evm_policy(&wallet_projection, &req.chain)
            .map_err(|error| HostError::Invalid(format!("wallet policy: {error}")))?;
        let chain = service
            .chains
            .get(&req.chain)
            .ok_or_else(|| HostError::NotFound(format!("chain {}", req.chain)))?;
        let fee_overrides = Eip1559FeeOverrides::from_decimal_pair(
            req.max_fee_per_gas.as_deref(),
            req.max_priority_fee_per_gas.as_deref(),
            chain.spec().legacy_tx,
        )
        .map_err(|error| HostError::Invalid(error.to_string()))?;
        let requested_to = req
            .to
            .parse::<Address>()
            .map_err(|error| HostError::Invalid(format!("to address: {error}")))?;
        let requested_value = req
            .value_wei
            .parse::<U256>()
            .map_err(|error| HostError::Invalid(format!("value-wei: {error}")))?;
        // Keep pending-action reuse and staging atomic within the daemon. Without
        // this guard, concurrent retries can both miss the pending scan.
        let _stage_guard = self.tx_stage_lock.lock().await;
        for pending_id in service
            .tx_engine
            .outbox
            .list(&req.wallet, &req.chain, OutboxState::Pending)
            .map_err(|error| HostError::Backend(format!("list pending EVM outbox: {error}")))?
        {
            let entry = service
                .tx_engine
                .outbox
                .read_in_state(&req.wallet, &req.chain, &pending_id, OutboxState::Pending)
                .map_err(|error| HostError::Backend(format!("read pending EVM outbox: {error}")))?;
            if petal_pending_request_matches(
                &entry.staged,
                &req,
                &origin,
                requested_to,
                requested_value,
            ) {
                return petal_outbox_outcome(
                    &service.tx_engine,
                    &req.wallet,
                    &req.chain,
                    &pending_id,
                    None,
                );
            }
        }
        let staged = service
            .tx_engine
            .stage_with_execution_origin_and_fee_overrides(
                permit,
                &req.wallet,
                wallet_address,
                RawIntent {
                    body: RawIntentBody::Raw {
                        to: req.to,
                        value: format!("{} wei", req.value_wei),
                        data: req.data_hex,
                    },
                    chain: Some(req.chain.clone()),
                    gas: GasStrategy::Auto,
                    nonce: req.nonce,
                    gas_limit_hint: None,
                    usd_value_hint: None,
                },
                &chain,
                &wallet_policy,
                Some(service.address_book.as_ref()),
                Some(origin),
                fee_overrides,
            )
            .await
            .map_err(|e| HostError::Backend(format!("stage EVM outbox: {e}")))?;
        petal_outbox_outcome(
            &service.tx_engine,
            &req.wallet,
            &req.chain,
            &staged.id,
            None,
        )
    }

    async fn evm_tx_confirm(
        &self,
        wallet: String,
        chain_name: String,
        outbox_id: String,
        acknowledge_warnings: bool,
        context: Option<PetalRouteContext>,
    ) -> Result<EvmOutboxOutcome, HostError> {
        let context = context.as_ref().ok_or_else(|| {
            HostError::Denied("Petal EVM outbox requires trusted Petal route context".into())
        })?;
        let origin = Self::petal_execution_origin(context)?;
        let service = self
            .tx_outbox
            .as_ref()
            .ok_or_else(|| HostError::Denied("EVM outbox is unavailable".into()))?;
        let permit = service
            .write_permit
            .as_deref()
            .ok_or_else(|| HostError::Denied("EVM outbox requires daemon write permit".into()))?;
        let entry = service
            .tx_engine
            .outbox
            .read(&wallet, &chain_name, &outbox_id)
            .map_err(|e| HostError::NotFound(format!("outbox {outbox_id}: {e}")))?;
        if entry.staged.resolved_execution_origin() != origin {
            return Err(HostError::Denied(
                "outbox entry was not staged by this trusted Petal".into(),
            ));
        }
        let wallet_id = bloom_broker_api::Token::new(wallet.clone())
            .map_err(|error| HostError::Invalid(format!("wallet: {error}")))?;
        let wallet_projection = service
            .wallet_projections
            .get_wallet(&wallet_id)
            .await
            .map_err(|error| HostError::Invalid(format!("wallet: {error}")))?;
        let wallet_policy = bloom_vfs::advisory_evm_policy(&wallet_projection, &chain_name)
            .map_err(|error| HostError::Invalid(format!("wallet policy: {error}")))?;
        let chain = service
            .chains
            .get(&chain_name)
            .ok_or_else(|| HostError::NotFound(format!("chain {chain_name}")))?;
        match service
            .tx_engine
            .confirm_with_warning_override(
                permit,
                &wallet,
                &chain_name,
                &outbox_id,
                &chain,
                &wallet_policy,
                acknowledge_warnings,
            )
            .await
        {
            Ok(_) => {
                petal_outbox_outcome(&service.tx_engine, &wallet, &chain_name, &outbox_id, None)
            }
            Err(bloom_tx::TxEngineError::ApprovalRequired(requirement)) => petal_outbox_outcome(
                &service.tx_engine,
                &wallet,
                &chain_name,
                &outbox_id,
                Some(requirement),
            ),
            Err(error) => Err(HostError::Backend(format!("confirm EVM outbox: {error}"))),
        }
    }

    async fn evm_tx_inspect(
        &self,
        wallet: String,
        chain_name: String,
        outbox_id: String,
        context: Option<PetalRouteContext>,
    ) -> Result<EvmOutboxInspection, HostError> {
        let context = context.as_ref().ok_or_else(|| {
            HostError::Denied("Petal EVM outbox requires trusted Petal route context".into())
        })?;
        let origin = Self::petal_execution_origin(context)?;
        let service = self
            .tx_outbox
            .as_ref()
            .ok_or_else(|| HostError::Denied("EVM outbox is unavailable".into()))?;
        let entry = service
            .tx_engine
            .outbox
            .read(&wallet, &chain_name, &outbox_id)
            .map_err(|e| HostError::NotFound(format!("outbox {outbox_id}: {e}")))?;
        if entry.staged.resolved_execution_origin() != origin {
            return Err(HostError::Denied(
                "outbox entry was not staged by this trusted Petal".into(),
            ));
        }
        let receipt = service
            .tx_engine
            .outbox
            .read_receipt(&wallet, &chain_name, &outbox_id)
            .map_err(|e| HostError::Backend(format!("read EVM outbox receipt: {e}")))?;
        let state = receipt
            .as_ref()
            .map(|receipt| receipt.outcome.clone())
            .unwrap_or_else(|| entry.staged.status.to_string());
        let receipt_json = receipt
            .map(|receipt| serde_json::to_string(&receipt))
            .transpose()
            .map_err(|e| HostError::Backend(format!("encode EVM outbox receipt: {e}")))?;
        Ok(EvmOutboxInspection {
            outbox_id,
            state,
            tx_hash: entry.staged.tx_hash,
            receipt_json,
        })
    }

    async fn chain_read(&self, req: ChainRequest) -> Result<ChainResponse, HostError> {
        let context = req.context.as_ref().ok_or_else(|| {
            HostError::Denied("Petal chain read requires trusted Petal route context".into())
        })?;
        Self::petal_execution_origin(context)?;
        let service = self
            .tx_outbox
            .as_ref()
            .ok_or_else(|| HostError::Denied("chain reads are unavailable".into()))?;
        let chain = service
            .chains
            .get(&req.chain)
            .ok_or_else(|| HostError::NotFound(format!("chain {}", req.chain)))?;
        let result_json = daemon_petal_chain_read(&chain, &req.method, &req.params_json).await?;
        Ok(ChainResponse { result_json })
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PetalEthCall {
    to: String,
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    input: Option<String>,
}

async fn daemon_petal_chain_read(
    chain: &ChainClient,
    method: &str,
    params_json: &str,
) -> Result<String, HostError> {
    let params: Vec<serde_json::Value> = serde_json::from_str(params_json)
        .map_err(|e| HostError::Invalid(format!("chain params-json must be an array: {e}")))?;
    let result = match method {
        "eth_chainId" if params.is_empty() => format!(
            "0x{:x}",
            chain
                .chain_id()
                .await
                .map_err(|e| HostError::Backend(format!("chain id: {e}")))?
        ),
        "eth_getBalance" if matches!(params.len(), 1 | 2) => {
            require_latest_block_param(&params, 1)?;
            let address = parse_petal_address(&params[0], "eth_getBalance address")?;
            let balance = chain
                .balance(address)
                .await
                .map_err(|e| HostError::Backend(format!("native balance: {e}")))?;
            format!("{balance:#x}")
        }
        "eth_getCode" if matches!(params.len(), 1 | 2) => {
            require_latest_block_param(&params, 1)?;
            let address = parse_petal_address(&params[0], "eth_getCode address")?;
            let code = chain
                .code(address)
                .await
                .map_err(|e| HostError::Backend(format!("contract code: {e}")))?;
            format!("0x{}", hex::encode(code))
        }
        "eth_call" if matches!(params.len(), 1 | 2) => {
            require_latest_block_param(&params, 1)?;
            let call: PetalEthCall = serde_json::from_value(params[0].clone())
                .map_err(|e| HostError::Invalid(format!("invalid eth_call request: {e}")))?;
            if call.data.is_some() && call.input.is_some() {
                return Err(HostError::Invalid(
                    "eth_call must not supply both data and input".into(),
                ));
            }
            let to = call
                .to
                .parse::<Address>()
                .map_err(|e| HostError::Invalid(format!("eth_call to address: {e}")))?;
            let mut tx = TransactionRequest::default().with_to(to);
            if let Some(from) = call.from {
                tx = tx.with_from(
                    from.parse::<Address>()
                        .map_err(|e| HostError::Invalid(format!("eth_call from address: {e}")))?,
                );
            }
            if let Some(value) = call.value {
                tx = tx.with_value(parse_petal_hex_quantity(&value, "eth_call value")?);
            }
            let input = call.data.or(call.input).unwrap_or_else(|| "0x".into());
            tx = tx.with_input(Bytes::from(parse_petal_hex_bytes(&input, "eth_call data")?));
            let bytes = chain
                .eth_call_at_block(tx, Some("latest"))
                .await
                .map_err(|e| HostError::Backend(format!("eth_call: {e}")))?;
            format!("0x{}", hex::encode(bytes))
        }
        "eth_chainId" | "eth_getBalance" | "eth_getCode" | "eth_call" => {
            return Err(HostError::Invalid(format!(
                "invalid {method} parameters; only latest-block reads are allowed"
            )));
        }
        _ => {
            return Err(HostError::Denied(format!(
                "chain method {method} is not in the read-only allowlist"
            )));
        }
    };
    serde_json::to_string(&result)
        .map_err(|e| HostError::Backend(format!("encode chain response: {e}")))
}

fn require_latest_block_param(params: &[serde_json::Value], index: usize) -> Result<(), HostError> {
    if let Some(block) = params.get(index)
        && block.as_str() != Some("latest")
    {
        return Err(HostError::Denied(
            "only latest-block chain reads are allowed".into(),
        ));
    }
    Ok(())
}

fn parse_petal_address(value: &serde_json::Value, field: &str) -> Result<Address, HostError> {
    value
        .as_str()
        .ok_or_else(|| HostError::Invalid(format!("{field} must be a string")))?
        .parse::<Address>()
        .map_err(|e| HostError::Invalid(format!("{field}: {e}")))
}

fn parse_petal_hex_quantity(value: &str, field: &str) -> Result<U256, HostError> {
    if !value.starts_with("0x") || value.len() < 3 {
        return Err(HostError::Invalid(format!(
            "{field} must be a 0x-prefixed hex quantity"
        )));
    }
    value
        .parse::<U256>()
        .map_err(|e| HostError::Invalid(format!("{field}: {e}")))
}

fn parse_petal_hex_bytes(value: &str, field: &str) -> Result<Vec<u8>, HostError> {
    let Some(value) = value.strip_prefix("0x") else {
        return Err(HostError::Invalid(format!(
            "{field} must be canonical 0x-prefixed hex"
        )));
    };
    if !value.len().is_multiple_of(2) {
        return Err(HostError::Invalid(format!(
            "{field} must have an even number of hex digits"
        )));
    }
    hex::decode(value).map_err(|e| HostError::Invalid(format!("{field}: {e}")))
}

fn petal_pending_request_matches(
    staged: &bloom_proto::StagedTx,
    request: &EvmTransactionRequest,
    origin: &bloom_proto::plan::ExecutionOrigin,
    requested_to: Address,
    requested_value: U256,
) -> bool {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(u128::MAX);
    staged.expires_ms > now_ms
        && staged.resolved_execution_origin() == *origin
        && staged.to.parse::<Address>().ok() == Some(requested_to)
        && staged.value_wei.parse::<U256>().ok() == Some(requested_value)
        && staged.data_hex == request.data_hex
        && request.nonce.is_none_or(|nonce| staged.nonce == nonce)
        && request
            .max_fee_per_gas
            .as_ref()
            .is_none_or(|fee| decimal_strings_equal(staged.max_fee_per_gas.as_deref(), fee))
        && request.max_priority_fee_per_gas.as_ref().is_none_or(|fee| {
            decimal_strings_equal(staged.max_priority_fee_per_gas.as_deref(), fee)
        })
}

fn decimal_strings_equal(stored: Option<&str>, requested: &str) -> bool {
    match (
        stored.and_then(|value| value.parse::<U256>().ok()),
        requested.parse::<U256>().ok(),
    ) {
        (Some(stored), Some(requested)) => stored == requested,
        _ => false,
    }
}

fn petal_outbox_outcome(
    tx_engine: &TxEngine,
    wallet: &str,
    chain: &str,
    outbox_id: &str,
    approval_requirement: Option<bloom_tx::ApprovalRequirement>,
) -> Result<EvmOutboxOutcome, HostError> {
    let entry = tx_engine
        .outbox
        .read(wallet, chain, outbox_id)
        .map_err(|e| HostError::Backend(format!("read staged EVM outbox: {e}")))?;
    let plan_md = std::fs::read_to_string(entry.dir.join("plan.md"))
        .map_err(|e| HostError::Backend(format!("read staged EVM plan: {e}")))?;
    let approval_required = approval_requirement.map(|requirement| ApprovalRequired {
        action_id: requirement.action_id,
        ceremony_url: requirement.ceremony_url,
        expires_ms: requirement.expires_ms,
    });
    Ok(EvmOutboxOutcome {
        outbox_id: outbox_id.into(),
        plan_md,
        approval_required,
    })
}

fn resolve_redirect_target(current_url: &str, location: &str) -> Result<String, HostError> {
    let base = url::Url::parse(current_url).map_err(|e| HostError::Invalid(format!("url: {e}")))?;
    base.join(location)
        .map(|url| url.to_string())
        .map_err(|e| HostError::Invalid(format!("redirect location: {e}")))
}

fn redirect_method(method: &str, status: u16) -> String {
    let upper = method.to_ascii_uppercase();
    if matches!(status, 301..=303) && upper != "GET" && upper != "HEAD" {
        "GET".into()
    } else {
        upper
    }
}

fn prepare_redirect_request(
    current_url: &str,
    next_url: &str,
    next_method: &str,
    headers: &mut Vec<(String, String)>,
    body: &mut Vec<u8>,
) -> Result<(), HostError> {
    let same_origin = same_origin(current_url, next_url)?;
    let bodyless = matches!(next_method, "GET" | "HEAD");
    if !same_origin {
        headers.clear();
        if !bodyless && !body.is_empty() {
            return Err(HostError::Denied(
                "cross-origin redirect would replay request body".into(),
            ));
        }
    }
    if bodyless {
        body.clear();
    }
    Ok(())
}

fn same_origin(a: &str, b: &str) -> Result<bool, HostError> {
    let a = url::Url::parse(a).map_err(|e| HostError::Invalid(format!("url: {e}")))?;
    let b = url::Url::parse(b).map_err(|e| HostError::Invalid(format!("url: {e}")))?;
    Ok(a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default())
}

fn audit_http_target(raw: &str) -> serde_json::Value {
    match url::Url::parse(raw) {
        Ok(url) => serde_json::json!({
            "scheme": url.scheme(),
            "host": url.host_str(),
            "port": url.port(),
            "path": url.path(),
        }),
        Err(_) => serde_json::json!({ "invalid": true }),
    }
}

fn default_machine_audit_history_path() -> PathBuf {
    let uid = rustix::process::geteuid().as_raw();
    #[cfg(target_os = "macos")]
    {
        PathBuf::from(format!(
            "/Library/Application Support/BloomTriad/config/{uid}/machine-audit-history.json"
        ))
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::from(format!("/etc/bloom/{uid}/machine-audit-history.json"))
    }
}

fn default_machine_checkpoint_path() -> PathBuf {
    if let Some(path) = std::env::var_os("BLOOM_MACHINE_AUDIT_CHECKPOINT_DIR") {
        return PathBuf::from(path);
    }
    let uid = rustix::process::geteuid().as_raw();
    #[cfg(target_os = "macos")]
    return PathBuf::from(format!(
        "/private/var/db/bloom/{uid}/machine/audit-checkpoints"
    ));
    #[cfg(not(target_os = "macos"))]
    PathBuf::from(format!("/var/lib/bloom/{uid}/machine/audit-checkpoints"))
}

fn default_authority_edge_history_path() -> PathBuf {
    if let Some(path) = std::env::var_os("BLOOM_AUTHORITY_EDGE_HISTORY") {
        return PathBuf::from(path);
    }
    let uid = rustix::process::geteuid().as_raw();
    #[cfg(target_os = "macos")]
    return PathBuf::from(format!(
        "/Library/Application Support/BloomTriad/config/{uid}/authority-edge-history.json"
    ));
    #[cfg(not(target_os = "macos"))]
    PathBuf::from(format!("/etc/bloom/{uid}/authority-edge-history.json"))
}

struct MachineAuditHeadProvider(Arc<AuditLog>);

impl MachineJournalHeadProvider for MachineAuditHeadProvider {
    fn verified_head(
        &self,
    ) -> Result<(u64, bloom_broker_api::Digest32), bloom_broker_api::ProtocolError> {
        if let Some(reason) = self.0.mutation_degradation() {
            return Err(bloom_broker_api::ProtocolError::new(
                bloom_broker_api::ProtocolErrorCode::ServiceUnavailable,
                format!("Machine audit journal is degraded: {reason}"),
            ));
        }
        let hash = self.0.head_hash();
        let hash = if hash.is_empty() {
            "00".repeat(32)
        } else {
            hash
        };
        Ok((self.0.sequence(), bloom_broker_api::Digest32::new(hash)?))
    }

    fn latch_mutations(&self, reason: String) {
        self.0.latch_mutations(reason);
    }
}

#[derive(Clone)]
struct CanonicalBatchConfirmation {
    tx_engine: TxEngine,
    home_write_permit: Arc<HomeWritePermit>,
    chains: ChainRegistry,
    wallet_projections: Arc<dyn WalletProjectionReader>,
    audit: Arc<AuditLog>,
}

fn batch_confirmation_result_json(
    result: Result<ConfirmBatchResult, TxEngineError>,
) -> Result<serde_json::Value, String> {
    match result {
        Ok(result) => Ok(serde_json::json!({
            "status": "succeeded",
            "operation_id": result.operation_id,
            "signer_receipt_digest": result.signer_receipt_digest,
            "broker_receipt_digest": result.broker_receipt_digest,
            "transactions": result.transactions.iter().map(|transaction| serde_json::json!({
                "chain": transaction.chain,
                "id": transaction.id,
                "status": transaction.status,
                "tx_hash": transaction.tx_hash,
            })).collect::<Vec<_>>(),
        })),
        Err(TxEngineError::ApprovalRequired(requirement)) => Ok(serde_json::json!({
            "status": "awaiting_ceremony",
            "action_id": requirement.action_id,
            "ceremony_url": requirement.ceremony_url,
            "ceremony_expires_at": requirement.expires_ms,
            "reason": requirement.reason,
        })),
        Err(error) => Err(error.to_string()),
    }
}

impl ipc::BatchConfirmationService for CanonicalBatchConfirmation {
    fn confirm_batch<'a>(
        &'a self,
        request: ipc::BatchConfirmIpcRequest,
    ) -> ipc::BatchConfirmFuture<'a> {
        Box::pin(async move {
            if !(1..=32).contains(&request.txs.len()) {
                return Err("transaction batch must contain 1 to 32 children".into());
            }
            let wallet_id = bloom_broker_api::Token::new(request.wallet.clone())
                .map_err(|error| format!("invalid wallet ID: {error}"))?;
            let projection = self
                .wallet_projections
                .get_wallet(&wallet_id)
                .await
                .map_err(|error| format!("load public wallet projection: {error}"))?;
            let mut targets = Vec::with_capacity(request.txs.len());
            for reference in &request.txs {
                let (chain_name, id) = reference
                    .split_once(':')
                    .ok_or_else(|| format!("tx ref '{reference}' must be chain:id"))?;
                let chain_name = chain_name.trim();
                let id = id.trim();
                if chain_name.is_empty() || id.is_empty() {
                    return Err(format!(
                        "tx ref '{reference}' must include non-empty chain and id"
                    ));
                }
                let chain = self
                    .chains
                    .get(chain_name)
                    .ok_or_else(|| format!("chain '{chain_name}' is not configured"))?;
                let policy = bloom_vfs::advisory_evm_policy(&projection, chain_name)
                    .map_err(|error| format!("derive key-free advisory policy: {error}"))?;
                targets.push(ConfirmBatchTarget {
                    chain_name: chain_name.to_owned(),
                    id: id.to_owned(),
                    chain,
                    policy,
                });
            }
            let override_warnings = targets.iter().all(|target| {
                request
                    .text
                    .trim()
                    .eq_ignore_ascii_case(target.policy.override_sentinel())
            });
            let request_bytes = serde_jcs::to_vec(&request)
                .map_err(|error| format!("canonicalize batch execution intent: {error}"))?;
            let payload_digest = bloom_tools::sha256_hex(&request_bytes);
            let operation_id = bloom_tools::sha256_hex(
                format!(
                    "bloom-machine-batch-confirm/v1\0{payload_digest}\0{}",
                    request_bytes.len()
                )
                .as_bytes(),
            );
            let correlation_id = format!("{operation_id}:{}", self.audit.sequence() + 1);
            self.audit
                .append(AuditRecord {
                    ts_ms: 0,
                    kind: "machine.effect.intent".into(),
                    wallet: Some(request.wallet.clone()),
                    chain: None,
                    data: serde_json::json!({
                        "operation": "tx.confirm_batch",
                        "operation_id": operation_id,
                        "correlation_id": correlation_id.clone(),
                        "payload_sha256": payload_digest,
                        "payload_size": request_bytes.len(),
                        "ordered_tx_refs": request.txs.clone(),
                    }),
                    prev: String::new(),
                    digest: String::new(),
                })
                .map_err(|error| {
                    format!("Machine audit unavailable before batch dispatch: {error}")
                })?;
            let result = self
                .tx_engine
                .confirm_batch(
                    &self.home_write_permit,
                    &request.wallet,
                    targets,
                    override_warnings,
                )
                .await;
            let projected = batch_confirmation_result_json(result);
            let (outcome, result_data) = match &projected {
                Ok(value) => ("ok", value.clone()),
                Err(error) => ("error", serde_json::json!({"error": error})),
            };
            self.audit
                .append(AuditRecord {
                    ts_ms: 0,
                    kind: "machine.effect.result".into(),
                    wallet: Some(request.wallet),
                    chain: None,
                    data: serde_json::json!({
                        "operation": "tx.confirm_batch",
                        "correlation_id": correlation_id,
                        "outcome": outcome,
                        "result": result_data,
                    }),
                    prev: String::new(),
                    digest: String::new(),
                })
                .map_err(|error| {
                    format!("Machine audit unavailable after batch dispatch: {error}")
                })?;
            projected
        })
    }
}

/// All wired-up state the daemon owns. Cheap to clone (everything is
/// behind Arc/clone-safe inner types).
#[derive(Clone)]
pub struct Daemon {
    pub home: HomeDir,
    pub config: Config,
    pub chains: ChainRegistry,
    pub tx_engine: TxEngine,
    pub home_write_permit: Option<Arc<HomeWritePermit>>,
    pub address_book: Arc<AddressBook>,
    pub audit: Arc<AuditLog>,
    pub wallet_projections: Arc<dyn WalletProjectionReader>,
    pub vfs: Vfs,
    pub petals: PetalRunner,
    pub watch_registry: Arc<WatchRegistry>,
    pub watch_executor: Arc<WatchExecutor>,
    /// Update checker for newer GitHub releases. Construction loads its
    /// cached snapshot without making a network request; the 5-minute
    /// refresher starts only with [`Self::spawn_background_tasks`].
    pub update_checker: Arc<bloom_update::UpdateChecker>,
    /// Shutdown handles for spawned mempool subscription tasks. Dropping
    /// these signals each task to exit at its next iteration.
    pub mempool_shutdown: Arc<parking_lot::Mutex<Vec<tokio::sync::oneshot::Sender<()>>>>,
    /// Shutdown handles for the bump scanner and the backends probe task.
    /// Sent on shutdown; safe even when no scanner / probe was spawned.
    pub bump_shutdown: Arc<parking_lot::Mutex<Vec<tokio::sync::oneshot::Sender<()>>>>,
    pub probe_shutdown: Arc<parking_lot::Mutex<Vec<tokio::sync::oneshot::Sender<()>>>>,
    /// Shutdown handle for the update-checker background refresher.
    /// `Daemon::shutdown` drains this alongside the other
    /// background-task shutdown channels.
    pub update_shutdown: Arc<parking_lot::Mutex<Vec<tokio::sync::oneshot::Sender<()>>>>,
    /// Shared one-shot latch preventing duplicate audited boot refreshes when
    /// background task startup is requested more than once.
    pub wallet_projection_refresh_started: Arc<AtomicBool>,
}

impl Daemon {
    /// Build the narrow Machine-local batch execution service used by the CLI
    /// IPC endpoint. No custody, approval verifier, or private signing object
    /// is captured; final bytes can only flow through `TxEngine`'s configured
    /// Broker batch route.
    pub fn batch_confirmation_service(
        &self,
    ) -> Result<Arc<dyn ipc::BatchConfirmationService>, String> {
        let home_write_permit = self.home_write_permit.clone().ok_or_else(|| {
            "batch confirmation is unavailable without the Machine home write permit".to_owned()
        })?;
        Ok(Arc::new(CanonicalBatchConfirmation {
            tx_engine: self.tx_engine.clone(),
            home_write_permit,
            chains: self.chains.clone(),
            wallet_projections: self.wallet_projections.clone(),
            audit: self.audit.clone(),
        }))
    }

    /// Build a fully-wired daemon from the home directory, materialising
    /// any missing subdirs as needed.
    #[cfg(any(test, debug_assertions, feature = "unsigned-audit-test-seam"))]
    pub fn from_home(home: HomeDir) -> Result<Self, DaemonError> {
        Self::from_home_inner(home, None, None, None)
    }

    /// Build a daemon with a held home write permit. VFS write surfaces use
    /// this permit for TxEngine mutations; callers that omit it get a daemon
    /// suitable for reads/tests but not outbox writes.
    #[cfg(any(test, debug_assertions, feature = "unsigned-audit-test-seam"))]
    pub fn from_home_with_permit(
        home: HomeDir,
        permit: Arc<HomeWritePermit>,
    ) -> Result<Self, DaemonError> {
        Self::from_home_inner(home, Some(permit), None, None)
    }

    /// Explicit key-free developer composition used by the debug CLI when an
    /// installed triad is absent. Release builds do not compile this entry
    /// point. It has no Broker client, signing path, custody path, legacy
    /// keystore, or legacy approval store.
    #[cfg(debug_assertions)]
    pub fn from_home_without_broker_for_debug(home: HomeDir) -> Result<Self, DaemonError> {
        Self::from_home_inner(home, None, None, None)
    }

    /// Write-permitted counterpart to [`Self::from_home_without_broker_for_debug`]
    /// for Machine-owned state such as Petal installation and unsigned staging.
    #[cfg(debug_assertions)]
    pub fn from_home_with_permit_without_broker_for_debug(
        home: HomeDir,
        permit: Arc<HomeWritePermit>,
    ) -> Result<Self, DaemonError> {
        Self::from_home_inner(home, Some(permit), None, None)
    }

    /// Build a Machine daemon whose signing and custody authority is provided
    /// exclusively by the Broker service boundary.
    pub fn from_home_with_broker(
        home: HomeDir,
        broker: MachineBrokerClient,
        provenance_catalog: bloom_broker_api::ProvenanceCatalog,
    ) -> Result<Self, DaemonError> {
        Self::from_home_inner(home, None, Some(broker), Some(provenance_catalog))
    }

    pub fn from_home_with_permit_and_broker(
        home: HomeDir,
        permit: Arc<HomeWritePermit>,
        broker: MachineBrokerClient,
        provenance_catalog: bloom_broker_api::ProvenanceCatalog,
    ) -> Result<Self, DaemonError> {
        Self::from_home_inner(home, Some(permit), Some(broker), Some(provenance_catalog))
    }

    fn from_home_inner(
        home: HomeDir,
        home_write_permit: Option<Arc<HomeWritePermit>>,
        broker: Option<MachineBrokerClient>,
        provenance_catalog: Option<bloom_broker_api::ProvenanceCatalog>,
    ) -> Result<Self, DaemonError> {
        home.ensure()?;
        let config_path = home.config_path();
        let config_existed = config_path.exists();
        let config = Config::load_or_init(&config_path)?;
        if config_existed {
            debug!(path = %config_path.display(), chains = config.chains.len(), default_chain = %config.default_chain, "config.loaded");
        } else {
            debug!(path = %config_path.display(), "config.initialised_default");
        }

        let mut clients: Vec<ChainClient> = Vec::new();
        for spec in config.chains.values() {
            match ChainClient::new(spec.clone()) {
                Ok(c) => clients.push(c),
                Err(e) => warn!(chain = %spec.name, error = %e, "daemon.chain_skipped"),
            }
        }
        let chains = ChainRegistry::default();
        for c in clients {
            chains.add(c);
        }
        let paid_http_rpc_resolver: Arc<dyn PaidHttpChainRpcResolver> =
            Arc::new(ConfigPaidHttpRpcResolver::from_config(&config));
        let wallet_projections: Arc<dyn WalletProjectionReader> = Arc::new(
            CachedWalletProjectionReader::new(
                broker.clone(),
                FileProjectionStore::new(home.cache_dir().join("wallet-projections.json")),
            )
            .map_err(|error| {
                DaemonError::Audit(format!("Machine wallet projection cache: {error}"))
            })?,
        );
        // Build per-chain mempool indexes + handlers from [mempool.<chain>]
        // config. Each entry creates an LRU index, a VFS handler, and
        // spawns a long-lived subscription task. Handles are kept in
        // `mempool_shutdown` and signaled when the daemon's
        // BackgroundTasks is dropped.
        let mut mempool_indexes: std::collections::BTreeMap<
            String,
            Arc<bloom_mempool::PendingTxIndex>,
        > = Default::default();
        let mut mempool_handlers: std::collections::BTreeMap<
            String,
            Arc<bloom_vfs::handlers::MempoolHandler>,
        > = Default::default();
        let mut mempool_shutdown: Vec<tokio::sync::oneshot::Sender<()>> = Vec::new();

        for (chain_name, mc) in &config.mempool {
            // Skip chains not in the registry — we warn but don't fail
            // because a stale config entry shouldn't tank daemon boot.
            if chains.get(chain_name).is_none() {
                warn!(chain = %chain_name, "daemon.mempool_skipped: chain not configured");
                continue;
            }

            // Resolve the provider before allocating any state, so an
            // unknown provider id doesn't leave a half-mounted handler.
            //
            // `generic_eth_subscribe` exists at the crate level but isn't
            // enabled here: it's hash-only, and without tx-body enrichment
            // via `eth_getTransactionByHash` (a follow-up) it would push
            // zeroed `from/nonce/fees/input` records into the index,
            // breaking by-address filtering and nonce-conflict detection.
            // The defensive `delivers_bodies()` check below would refuse
            // it anyway; refusing here at the match keeps the failure
            // mode obvious from the config surface.
            let provider: Arc<dyn bloom_mempool::MempoolProvider> = match mc.provider.as_str() {
                "alchemy" => Arc::new(bloom_mempool::providers::alchemy::AlchemyProvider::new(
                    mc.ws_url.clone(),
                )),
                other => {
                    warn!(
                        chain = %chain_name,
                        provider = %other,
                        "daemon.mempool_skipped: unknown or unsupported provider \
                         (only \"alchemy\" is currently enabled at the daemon layer; \
                         hash-only providers like generic_eth_subscribe are pending \
                         tx-body enrichment)"
                    );
                    continue;
                }
            };

            // Defence in depth: even though the match above only admits
            // body-delivering providers today, this guards against a
            // future provider being added to the match without honouring
            // the `delivers_bodies()` contract. A hash-only provider
            // would push zeroed records into the index and break
            // by-address filtering and nonce-conflict detection.
            if !provider.delivers_bodies() {
                warn!(
                    chain = %chain_name,
                    provider = %mc.provider,
                    "daemon.mempool_skipped: provider does not deliver full tx bodies; \
                     by-address index and nonce-conflict detection would be broken. \
                     Configure a body-delivering provider (e.g. \"alchemy\")."
                );
                continue;
            }

            // Clamp max_index_size = 0 → 1 so PendingTxIndex::new never
            // asserts. A zero value in config is almost certainly a mistake.
            let size = mc.max_index_size.max(1);
            if size != mc.max_index_size {
                warn!(
                    chain = %chain_name,
                    configured = mc.max_index_size,
                    "daemon.mempool_max_index_size_clamped_to_1"
                );
            }
            let idx = bloom_mempool::PendingTxIndex::new(size);
            let handler = Arc::new(bloom_vfs::handlers::MempoolHandler::new(
                chain_name.clone(),
                mc.provider.clone(),
                idx.clone(),
            ));
            mempool_indexes.insert(chain_name.clone(), idx.clone());
            mempool_handlers.insert(chain_name.clone(), handler.clone());

            // Spawning the stream needs a tokio runtime; mirror the
            // watch-executor pattern and only spawn when one is current.
            if tokio::runtime::Handle::try_current().is_ok() {
                let sink: Arc<dyn bloom_mempool::stream::MempoolSink> = handler.clone();
                let shutdown = bloom_mempool::stream::spawn(chain_name.clone(), provider, sink);
                mempool_shutdown.push(shutdown);
                debug!(chain = %chain_name, provider = %mc.provider, "daemon.mempool_spawned");
            } else {
                debug!(chain = %chain_name, "daemon.mempool_spawn_deferred: no tokio runtime");
            }
        }

        // The central outbox's idempotent identity map is Machine state, not
        // approval state. Keep it in a schema that cannot carry grants,
        // challenges, credentials, or signing secrets.
        let operation_index: Arc<dyn OperationIndex> = Arc::new(FileOperationIndex::new(
            home.root().join("operations/index.json"),
        ));
        let central = CentralOutbox::new(home.root().join("central_outbox"));
        let projection: Arc<dyn CentralOutboxProjection> =
            Arc::new(EvmOutboxProjection::new(central, operation_index.clone()));
        let outbox = Outbox::new_with_projection(home.outbox_dir(), projection)
            .map_err(|e| DaemonError::Outbox(e.to_string()))?;
        let mut tx_engine = TxEngine::new(outbox, config.stage_ttl.as_millis());
        match (&broker, &provenance_catalog) {
            (Some(broker), Some(catalog)) => {
                tx_engine = tx_engine
                    .with_triad_signing(broker.clone(), catalog.clone())
                    .map_err(|error| DaemonError::Audit(error.to_string()))?;
            }
            (None, None) => {}
            _ => {
                return Err(DaemonError::Audit(
                    "Broker client and installer provenance catalog must be configured together"
                        .into(),
                ));
            }
        }
        let exact_payload_signer = match (&broker, &provenance_catalog) {
            (Some(broker), Some(catalog)) => Some(BrokerExactPayloadSigner::new(
                broker.clone(),
                catalog.clone(),
            )),
            (None, None) => None,
            _ => unreachable!("Broker/catalog pairing validated above"),
        };
        // Wire ENS resolver into TxEngine when a mainnet-style chain is
        // configured. We pick the first chain with id 1 / 11155111 / 5 /
        // 17000 (the ENS canonical-registry chains) for resolution.
        let ens_client = pick_ens_client(&chains);
        if let Some(c) = ens_client.clone() {
            debug!("daemon.ens_resolver_wired");
            tx_engine = tx_engine.with_resolver(Arc::new(ens_resolver::EnsAdapter::new(c)) as _);
        } else {
            debug!("daemon.ens_resolver_skipped: no ENS-capable chain configured");
        }

        let address_book_path = home.root().join("addressbook.toml");
        let address_book = match AddressBook::load(&address_book_path) {
            Ok(b) => {
                debug!(path = %address_book_path.display(), entries = b.entries.len(), "addressbook.loaded");
                b
            }
            Err(e) => {
                debug!(path = %address_book_path.display(), error = %e, "addressbook.load_failed_using_empty");
                AddressBook::default()
            }
        };
        let address_book_arc = Arc::new(address_book.clone());

        let audit_history_path = std::env::var_os("BLOOM_MACHINE_AUDIT_HISTORY")
            .map(PathBuf::from)
            .unwrap_or_else(default_machine_audit_history_path);
        let (audit_history, audit_history_error) =
            match AuditLog::load_root_trusted_history(&audit_history_path) {
                Ok(history) => (history, None),
                Err(error) => (
                    Vec::new(),
                    Some(format!(
                        "packaging-pinned Machine audit history is invalid: {error}"
                    )),
                ),
            };
        let audit = match broker
            .as_ref()
            .and_then(MachineBrokerClient::local_application_identity)
        {
            Some(identity) => AuditLog::open_signed_with_history(
                home.audit_path(),
                AuditIdentity::new(
                    identity.service_id.as_str(),
                    identity.application_key_id.as_str(),
                    identity.signing_key,
                ),
                &audit_history,
            ),
            None => {
                #[cfg(any(test, debug_assertions, feature = "unsigned-audit-test-seam"))]
                {
                    // Explicit nonproduction seam. Release builds do not
                    // compile an unsigned Machine journal constructor.
                    AuditLog::open(home.audit_path())
                }
                #[cfg(not(any(test, debug_assertions, feature = "unsigned-audit-test-seam")))]
                {
                    return Err(DaemonError::Audit(
                        "production Machine construction requires an authenticated application identity"
                            .to_owned(),
                    ));
                }
            }
        }
        .map_err(|e| DaemonError::Audit(e.to_string()))?;
        if let Some(reason) = audit_history_error {
            audit.latch_mutations(reason);
        }
        let audit_arc = Arc::new(audit.clone());
        if let Some(client) = broker.as_ref()
            && client.local_application_identity().is_some()
        {
            #[cfg(feature = "triad-dev-harness")]
            let history_owner = if std::env::var_os("BLOOM_TRIAD_DEVELOPER_ROOT").is_some() {
                rustix::process::geteuid().as_raw()
            } else {
                0
            };
            #[cfg(not(feature = "triad-dev-harness"))]
            let history_owner = 0;
            let attachment = bloom_machine_client::AuthorityEdgeHistory::load_trusted(
                default_authority_edge_history_path(),
                history_owner,
            )
            .map_err(|error| error.to_string())
            .and_then(|history| {
                client
                    .attach_authority_journal_with_history(
                        Arc::new(MachineAuditHeadProvider(audit_arc.clone())),
                        default_machine_checkpoint_path(),
                        rustix::process::geteuid().as_raw(),
                        history,
                    )
                    .map_err(|error| error.to_string())
            });
            if let Err(error) = attachment {
                audit_arc.latch_mutations(format!(
                    "Machine authority-edge checkpoint/history degradation: {error}"
                ));
            }
        }
        let path_cache = Arc::new(PathCache::new());

        let watch_registry = Arc::new(
            WatchRegistry::new(home.watch_dir()).map_err(|e| DaemonError::Watch(e.to_string()))?,
        );
        let watch_executor = Arc::new(
            WatchExecutor::new(chains.clone(), watch_registry.clone(), home.clone())
                .with_audit(audit_arc.clone()),
        );

        let etherscan = config
            .etherscan
            .as_ref()
            .map(|c| match url::Url::parse(&c.api_url) {
                Ok(url) => {
                    debug!(api_url = %url, "daemon.etherscan_configured");
                    EtherscanClient::with_base_url(c.api_key.clone(), url)
                }
                Err(e) => {
                    warn!(api_url = %c.api_url, error = %e, "daemon.etherscan_url_invalid_using_default");
                    EtherscanClient::new(c.api_key.clone())
                }
            });
        if etherscan.is_none() {
            debug!("daemon.etherscan_skipped: no [etherscan] config");
        }
        let etherscan_arc = etherscan.map(Arc::new);

        let prices = PricesClient::new();

        // Wire the prices client into the policy USD-cap path. The trait
        // lives in bloom-tx; the adapter is in this crate so bloom-tx
        // doesn't pull reqwest+rustls.
        let price_oracle: DynPriceOracle =
            Arc::new(price_oracle::PricesOracle::new(prices.clone()));
        tx_engine = tx_engine.with_price_oracle(price_oracle.clone());

        // Wire mempool indexes into TxEngine (drives nonce-conflict
        // checks + cancel.tx targeting). Done before private-RPC
        // registration so any future ordering invariants hold.
        for (chain_name, idx) in &mempool_indexes {
            tx_engine.set_mempool_index(chain_name.clone(), idx.clone());
        }

        // Build per-chain private RPC providers from [private_rpc.<chain>].
        // We also stash each successfully-registered provider so the
        // backends probe task can call `health()` on them every 60s
        // and publish results into the StatusHandler.
        let mut private_rpc_probes: Vec<(String, Arc<dyn bloom_mempool::PrivateRpcProvider>)> =
            Vec::new();
        for (chain_name, rc) in &config.private_rpc {
            let Some(client) = chains.get(chain_name) else {
                warn!(chain = %chain_name, "daemon.private_rpc_skipped: chain not configured");
                continue;
            };
            let chain_id = client.spec().chain_id;
            if let Some(url) = &rc.mev_blocker_url {
                match bloom_mempool::providers::mev_blocker::MevBlockerProvider::new(url.clone()) {
                    Ok(p) => {
                        let arc_p: Arc<dyn bloom_mempool::PrivateRpcProvider> = Arc::new(p);
                        if let Err(e) = tx_engine.register_private_rpc(chain_id, arc_p.clone()) {
                            warn!(chain = %chain_name, error = %e, "daemon.private_rpc_register_failed");
                        } else {
                            debug!(chain = %chain_name, provider = "mev_blocker", "daemon.private_rpc_registered");
                            private_rpc_probes.push((chain_name.clone(), arc_p));
                        }
                    }
                    Err(e) => {
                        warn!(chain = %chain_name, error = %e, "daemon.mev_blocker_init_failed")
                    }
                }
            }
            if let Some(url) = &rc.flashbots_url {
                match bloom_mempool::providers::flashbots::FlashbotsProvider::new(url.clone()) {
                    Ok(p) => {
                        let arc_p: Arc<dyn bloom_mempool::PrivateRpcProvider> = Arc::new(p);
                        if let Err(e) = tx_engine.register_private_rpc(chain_id, arc_p.clone()) {
                            warn!(chain = %chain_name, error = %e, "daemon.private_rpc_register_failed");
                        } else {
                            debug!(chain = %chain_name, provider = "flashbots", "daemon.private_rpc_registered");
                            private_rpc_probes.push((chain_name.clone(), arc_p));
                        }
                    }
                    Err(e) => {
                        warn!(chain = %chain_name, error = %e, "daemon.flashbots_init_failed")
                    }
                }
            }
        }

        // Build the tiered revert decoder once and share it across every
        // handler that needs to attribute revert returndata. Builtin
        // decoders (Solidity Error/Panic) are always installed; the
        // Etherscan-driven ABI decoder is layered on top when an
        // Etherscan client is configured. Stages 4 and 5 (Openchain,
        // Heimdall) plug in by appending more decoders here.
        let mut decoder_chain = DecoderChain::new().with(boxed(BuiltinDecoder));
        debug!("revert.decoder.builtin_pushed");
        if let Some(es) = etherscan_arc.clone() {
            let abi_source: Arc<dyn AbiSource> = Arc::new(EtherscanAbiSource::new(es));
            decoder_chain = decoder_chain.with(boxed(EtherscanAbiDecoder::new(abi_source)));
            debug!("revert.decoder.etherscan_pushed");
        } else {
            debug!("revert.decoder.etherscan_skipped: no etherscan client");
        }
        decoder_chain = decoder_chain.with(boxed(OpenchainDecoder::default()));
        debug!("revert.decoder.openchain_pushed");
        #[cfg(feature = "bytecode-decompile")]
        {
            let bytecode_source: Arc<dyn bloom_revert::BytecodeSource> = Arc::new(
                bloom_revert::ChainRegistryBytecodeSource::new(chains.clone()),
            );
            let cache_dir = home.cache_dir().join("heimdall");
            decoder_chain = decoder_chain.with(boxed(
                bloom_revert::HeimdallDecompileDecoder::new(bytecode_source)
                    .with_cache_dir(cache_dir),
            ));
            debug!(cache_dir = %home.cache_dir().join("heimdall").display(), "revert.decoder.heimdall_pushed");
        }
        #[cfg(not(feature = "bytecode-decompile"))]
        debug!("revert.decoder.heimdall_skipped: feature 'bytecode-decompile' off");
        let decoder_chain = Arc::new(decoder_chain);

        // Seed initial mempool backend statuses from the handlers we just
        // built. Subsequent live updates come from the probe task below.
        let mut initial_mempool_statuses: std::collections::BTreeMap<String, MempoolBackendStatus> =
            std::collections::BTreeMap::new();
        for (chain_name, handler) in &mempool_handlers {
            initial_mempool_statuses.insert(
                chain_name.clone(),
                MempoolBackendStatus {
                    provider: handler.provider_id().to_string(),
                    subscribed: handler.is_subscribed(),
                    fallback_to: None,
                },
            );
        }

        // Construct the update checker here (before StatusHandler) so
        // the handler can wire its snapshot producer. Construction only
        // loads the on-disk cache; the network refresher is started by
        // `spawn_background_tasks` for long-lived daemon processes.
        let update_checker: Arc<bloom_update::UpdateChecker> = Arc::new(
            bloom_update::UpdateChecker::new(env!("CARGO_PKG_VERSION"), home.cache_dir())
                .map_err(|e| DaemonError::Audit(format!("update checker init: {e}")))?,
        );
        let update_checker_for_vfs = update_checker.clone();

        let status_handler = Arc::new(
            StatusHandler::with_backends(
                chains.clone(),
                tx_engine.clone(),
                audit_arc.clone(),
                Some(prices.clone()),
                Some(home.cache_dir().join("etherscan")),
                config
                    .etherscan
                    .as_ref()
                    .map(|c| !c.api_key.is_empty())
                    .unwrap_or(false),
                config.backends,
                home.root().to_path_buf(),
                SystemTime::now(),
                env!("CARGO_PKG_VERSION"),
                wallet_projections.clone(),
            )
            .with_mempool_statuses(initial_mempool_statuses)
            .with_update_snapshot_fn(Arc::new(move || {
                // Always produce a snapshot. The VFS renders the
                // fields that depend on a successful refresh
                // (latest, available, behind_by, release_url,
                // checked_at) as empty / "unknown" / 0 when the
                // in-memory snapshot is in the `Unknown` state
                // (e.g. fresh daemon, no cache file yet). The
                // `installed` field is always populated because it
                // is baked into the binary at compile time.
                //
                // `bloom_vfs::handlers::status::UpdateAvailable` is a
                // re-export of `bloom_update::UpdateAvailable`, so the
                // `available()` verdict passes through without a
                // three-arm match.
                let s = update_checker_for_vfs.snapshot();
                let available = s.available();
                let behind_by = s.behind_by();
                let bloom_update::UpdateSnapshot {
                    installed,
                    latest,
                    release_url,
                    checked_at,
                    status: _,
                    error_reason: _,
                } = s;
                Some(bloom_vfs::handlers::status::UpdateSnapshot {
                    installed,
                    latest,
                    available,
                    behind_by,
                    checked_at,
                    release_url,
                })
            })),
        );

        // Build the petals runtime: content-addressed store under
        // `~/.bloom/petals/store`, name registry under
        // `~/.bloom/petals/registry`, and a wasmtime engine. Petal
        // packages are exposed under `petals/`.
        let petals_root = home.root().join("petals");
        let petal_store = PetalStore::open(petals_root.join("store"))
            .map_err(|e| DaemonError::Audit(format!("petals store: {e}")))?;
        let petal_registry = Arc::new(
            NameRegistry::open(petals_root.join("registry"))
                .map_err(|e| DaemonError::Audit(format!("petals registry: {e}")))?,
        );
        let petal_vm = PetalVm::new().map_err(|e| DaemonError::Audit(format!("petals vm: {e}")))?;
        let petals = PetalRunner::new(petal_store.clone(), petal_registry.clone(), petal_vm);
        let petal_vfs_host = Arc::new(LateVfsHost::new());
        let petal_app_host = DaemonPetalHost::new(petal_vfs_host.clone(), audit_arc.clone())
            .with_broker(broker.clone())
            .with_provenance_catalog(provenance_catalog.clone())
            .with_petal_key_state_root(home.cache_dir().join("petal-key-requests"))
            .with_petal_signing_state_root(home.cache_dir().join("petal-signing-requests"))
            .with_tx_outbox(PetalTxOutbox {
                tx_engine: tx_engine.clone(),
                chains: chains.clone(),
                wallet_projections: wallet_projections.clone(),
                address_book: address_book_arc.clone(),
                write_permit: home_write_permit.clone(),
            });
        let petal_app_host = Arc::new(petal_app_host);
        debug!(root = %petals_root.display(), "daemon.petals_initialised");
        let petals_for_docs = petals.clone();
        let petals_doc_renderer: Arc<dyn Fn() -> Vec<u8> + Send + Sync> =
            Arc::new(move || render_installed_petals_doc(&petals_for_docs));

        let mut vfs_builder = Vfs::builder()
            .mount(
                "petal-key-requests",
                Arc::new(PetalKeyRequestsHandler::new(
                    home.cache_dir().join("petal-key-requests"),
                )) as _,
            )
            .mount(
                "petal-signing-requests",
                Arc::new(PetalSigningRequestsHandler::new(
                    home.cache_dir().join("petal-signing-requests"),
                    broker.clone(),
                )) as _,
            )
            .mount(
                "petals",
                Arc::new(
                    PetalRouter::new(petals.clone(), petal_app_host)
                        .with_audit(audit_arc.clone())
                        .with_runtime_petals(config.petals.runtime.clone())
                        .map_err(|e| {
                            DaemonError::Audit(format!("petals runtime configuration: {e}"))
                        })?,
                ) as _,
            )
            .mount(
                "chains",
                Arc::new(
                    ChainsHandler::new(chains.clone())
                        .with_etherscan(etherscan_arc.clone())
                        .with_ens(ens_client.clone())
                        .with_backends(config.backends)
                        .with_mempool_handlers(mempool_handlers.clone())
                        .with_revert_decoder(decoder_chain.clone()),
                ) as _,
            );

        let wallets_handler = WalletsHandler::new(
            chains.clone(),
            tx_engine.clone(),
            address_book.clone(),
            wallet_projections.clone(),
            home.root().join("machine-policy-projections"),
        );
        let wallets_handler = wallets_handler
            .with_broker(broker.clone())
            .with_home_write_permit_opt(home_write_permit.clone())
            .with_mempool_indexes(mempool_indexes.clone());

        vfs_builder = vfs_builder
            .mount("wallets", Arc::new(wallets_handler) as _)
            .mount("tools", Arc::new(ToolsHandler::new()) as _)
            .mount(
                "requests",
                Arc::new(
                    RequestsHandler::new_projected(
                        home.root().to_path_buf(),
                        config.default_wallet.clone(),
                        wallet_projections.clone(),
                    )
                    .with_operation_index(operation_index.clone())
                    .with_exact_signer(exact_payload_signer.clone())
                    .with_paid_http_rpc_resolver(paid_http_rpc_resolver.clone()),
                ) as _,
            )
            .mount("status", status_handler.clone() as _)
            .mount(
                "docs",
                Arc::new(DocsHandler::new().with_petals_renderer(petals_doc_renderer)) as _,
            )
            .mount(
                "simulate",
                Arc::new(SimulateHandler::new(
                    chains.clone(),
                    address_book_arc.clone(),
                )) as _,
            )
            .mount(
                "watch",
                Arc::new(WatchHandler::new(
                    watch_registry.clone(),
                    watch_executor.clone(),
                    home.clone(),
                )) as _,
            )
            .mount("ens", Arc::new(EnsHandler::new(ens_client.clone())) as _)
            .mount("prices", Arc::new(PricesHandler::new(prices)) as _)
            .mount(
                "outbox",
                Arc::new(OutboxHandler::new(CentralOutbox::new(
                    home.root().join("central_outbox"),
                ))) as _,
            )
            .mount(
                "addressbook",
                Arc::new(
                    AddressBookHandler::open(&address_book_path)
                        .map_err(|e| DaemonError::Audit(e.to_string()))?,
                ) as _,
            );

        // /next.md — brutally-scoped next-action aggregator for agents.
        // Answers: what wallets need attention, what confirms are pending,
        // what capabilities are active/expired/orphaned, what risk data is stale.
        let next_wallet_projections = wallet_projections.clone();
        vfs_builder = vfs_builder.with_root_dynamic_async("next.md", move || {
            let projections = next_wallet_projections.clone();
            async move { render_next_actions(projections.as_ref()).await }
        });

        let vfs = vfs_builder
            .with_audit(audit_arc.clone())
            .with_cache(path_cache)
            .build();
        petal_vfs_host.set(Arc::new(vfs.clone()));

        // Start the watch executor so any pre-existing specs on disk are
        // sampled and any new ones registered by the WatchHandler get
        // picked up on the next tick. Idempotent so repeat boots are safe.
        //
        // `tokio::spawn` (used internally by `start`) requires an active
        // runtime; the daemon may be constructed from a synchronous test
        // helper, so we only attempt to start if a runtime is currently
        // installed. Production paths (`#[tokio::main]` in the CLI, the
        // mount serve loop) always have one.
        if tokio::runtime::Handle::try_current().is_ok() {
            if let Err(e) = watch_executor.start() {
                warn!(error = %e, "watch.executor.start_failed");
            }
        } else {
            warn!("watch.executor.skipped: no tokio runtime; call Daemon::start_workers later");
        }

        // Spawn the bump scanner if any chain has a mempool index. The
        // scanner walks the outbox every 30s and emits `bump.tx` /
        // `cancel.tx` / `bump_advice.json` artefacts next to stuck txs.
        //
        // The canonical Broker policy has no Machine-local bump tuning.
        // Resolve wallet existence from the public projection and use the
        // scanner's explicit defaults; never reopen Machine-local policy state.
        let mut bump_shutdown: Vec<tokio::sync::oneshot::Sender<()>> = Vec::new();
        if !mempool_indexes.is_empty() && tokio::runtime::Handle::try_current().is_ok() {
            let shared_indexes: bloom_tx::bump_scanner::MempoolIndexes =
                Arc::new(parking_lot::RwLock::new(mempool_indexes.clone()));
            let basefee: Arc<dyn bloom_tx::bump_scanner::BasefeeProvider> =
                Arc::new(ChainBasefeeProvider {
                    chains: chains.clone(),
                });
            let cfg = bloom_tx::bump_scanner::BumpScannerConfig::default();
            let default_stuck_after = cfg.stuck_after;
            let default_overrun = cfg.basefee_overrun_pct;
            let projections_for_lookup = wallet_projections.clone();
            let wallet_policy: bloom_tx::bump_scanner::WalletPolicyLookup =
                Arc::new(move |wallet: &str| {
                    let projections = match projections_for_lookup.cached_wallets() {
                        Ok(projections) => projections,
                        Err(_) => {
                            return bloom_tx::bump_scanner::WalletPolicyProjection::Unavailable;
                        }
                    };
                    let Some(projection) = projections
                        .iter()
                        .find(|projection| projection.wallet.wallet_id.as_str() == wallet)
                    else {
                        return bloom_tx::bump_scanner::WalletPolicyProjection::Unknown;
                    };
                    // The canonical Broker policy intentionally has no
                    // Machine-local bump tuning, so authenticated projections
                    // use the scanner defaults while preserving freshness.
                    match projection.freshness {
                        bloom_machine_client::ProjectionFreshness::Fresh => {
                            bloom_tx::bump_scanner::WalletPolicyProjection::Current(
                                default_stuck_after,
                                default_overrun,
                            )
                        }
                        bloom_machine_client::ProjectionFreshness::Stale => {
                            bloom_tx::bump_scanner::WalletPolicyProjection::Stale(
                                default_stuck_after,
                                default_overrun,
                            )
                        }
                    }
                });
            let scanner = Arc::new(
                bloom_tx::bump_scanner::BumpScanner::new(
                    tx_engine.outbox.clone(),
                    shared_indexes,
                    basefee,
                    cfg,
                )
                .with_wallet_policy(wallet_policy)
                .with_audit(audit_arc.clone()),
            );
            let shutdown = scanner.spawn();
            bump_shutdown.push(shutdown);
            debug!("daemon.bump_scanner_spawned");
        }

        // Spawn the receipt reconciler: every ~15s it walks sent/ entries and
        // records each broadcast tx's mined outcome (success/reverted) as a
        // `receipt.json` sibling. The same-chain dependency gate and the bump
        // scanner read it. Runs regardless of mempool config.
        if tokio::runtime::Handle::try_current().is_ok() {
            let reconciler = Arc::new(bloom_tx::reconcile::Reconciler::new(
                tx_engine.outbox.clone(),
                chains.clone(),
                audit_arc.clone(),
            ));
            bump_shutdown.push(reconciler.spawn());
            debug!("daemon.reconciler_spawned");
        }

        // Spawn the backends probe task. Every 60s it:
        //   * refreshes `status/backends/mempool` from the live handler state
        //   * calls `health()` on each registered private RPC and writes the
        //     result into `status/backends/private_rpc`.
        let mut probe_shutdown: Vec<tokio::sync::oneshot::Sender<()>> = Vec::new();
        let probe_needed = !mempool_handlers.is_empty() || !private_rpc_probes.is_empty();
        if probe_needed && tokio::runtime::Handle::try_current().is_ok() {
            let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
            probe_shutdown.push(tx);
            let status_for_probe = status_handler.clone();
            let mempool_handlers_for_probe = mempool_handlers.clone();
            let probes = private_rpc_probes.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(60));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                // `tokio::time::interval` fires its first `tick()` immediately;
                // consume that initial tick here so the loop body's "do work
                // then await tick" structure doesn't double-fire at boot
                // (probe → immediate-tick-returns → probe again).
                // The first iteration of the loop below still runs the probe
                // at boot — we just don't queue an immediate second pass.
                ticker.tick().await;
                loop {
                    // Refresh mempool snapshot from handler state.
                    let mut mempool_map: std::collections::BTreeMap<String, MempoolBackendStatus> =
                        std::collections::BTreeMap::new();
                    for (chain_name, h) in &mempool_handlers_for_probe {
                        mempool_map.insert(
                            chain_name.clone(),
                            MempoolBackendStatus {
                                provider: h.provider_id().to_string(),
                                subscribed: h.is_subscribed(),
                                fallback_to: None,
                            },
                        );
                    }
                    status_for_probe.replace_mempool_statuses(mempool_map);

                    // Probe private RPC health.
                    let mut health_map: std::collections::BTreeMap<
                        (String, String),
                        PrivateRpcBackendStatus,
                    > = std::collections::BTreeMap::new();
                    for (chain, provider) in &probes {
                        let probed_at = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let status = match provider.health().await {
                            Ok(bloom_mempool::HealthStatus::Healthy) => "healthy".to_string(),
                            Ok(bloom_mempool::HealthStatus::Degraded) => "degraded".to_string(),
                            Ok(bloom_mempool::HealthStatus::Unhealthy) => "unhealthy".to_string(),
                            Err(_) => "unhealthy".to_string(),
                        };
                        health_map.insert(
                            (chain.clone(), provider.id().to_string()),
                            PrivateRpcBackendStatus {
                                last_status: status,
                                last_probed_at: probed_at,
                            },
                        );
                    }
                    status_for_probe.replace_private_rpc_healths(health_map);

                    tokio::select! {
                        _ = &mut rx => return,
                        _ = ticker.tick() => {}
                    }
                }
            });
            debug!("daemon.backends_probe_spawned");
        }

        // `debug!`, not `info!`: the CLI builds a daemon in-process for
        // every `vfs cat`/`ls`, so at default verbosity this line would
        // print before each value and clutter agent/visual output.
        debug!(
            home = %home.root().display(),
            chains = ?config.chains.keys().collect::<Vec<_>>(),
            etherscan = etherscan_arc.is_some(),
            ens_resolver = ens_client.is_some(),
            heimdall = cfg!(feature = "bytecode-decompile"),
            "daemon.built"
        );

        Ok(Self {
            home,
            config,
            chains,
            tx_engine,
            home_write_permit,
            address_book: address_book_arc,
            audit: audit_arc,
            wallet_projections,
            vfs,
            petals,
            watch_registry,
            watch_executor,
            update_checker,
            mempool_shutdown: Arc::new(parking_lot::Mutex::new(mempool_shutdown)),
            bump_shutdown: Arc::new(parking_lot::Mutex::new(bump_shutdown)),
            probe_shutdown: Arc::new(parking_lot::Mutex::new(probe_shutdown)),
            update_shutdown: Arc::new(parking_lot::Mutex::new(Vec::new())),
            wallet_projection_refresh_started: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Idempotent: ensure background workers are running. Already
    /// invoked by [`from_home`] when a tokio runtime is available; call
    /// this after entering an async context if construction happened
    /// outside one.
    pub fn start_workers(&self) {
        if let Err(e) = self.watch_executor.start() {
            warn!(error = %e, "watch.executor.start_failed");
        }
    }

    /// Stop background workers cleanly. Signals all spawned mempool
    /// subscription tasks, the bump scanner, the backends probe, and
    /// the update-checker refresher, then shuts down the watch
    /// executor's polling task. Safe to call multiple times.
    pub async fn shutdown(&self) {
        for s in self.mempool_shutdown.lock().drain(..) {
            let _ = s.send(());
        }
        for s in self.bump_shutdown.lock().drain(..) {
            let _ = s.send(());
        }
        for s in self.probe_shutdown.lock().drain(..) {
            let _ = s.send(());
        }
        for s in self.update_shutdown.lock().drain(..) {
            let _ = s.send(());
        }
        self.watch_executor.stop().await;
    }

    /// Convenience for the default home dir (`~/.bloom`).
    #[cfg(any(test, debug_assertions, feature = "unsigned-audit-test-seam"))]
    pub fn from_default_home() -> Result<Self, DaemonError> {
        let home = HomeDir::resolve("~/.bloom")?;
        Self::from_home(home)
    }

    /// Spawn long-lived background tasks: the update checker and the
    /// outbox expiry sweeper that runs every 60s and moves any pending
    /// entry past its `expires_ms` into `failed/` (fix #3). Caller keeps
    /// the returned [`BackgroundTasks`] alive; dropping it triggers
    /// graceful shutdown of the sweeper.
    ///
    /// Safe to call multiple times — each call spawns a fresh sweeper and
    /// returns its own handle, while the update refresher starts at most
    /// once per daemon. Short-lived CLI commands generally don't need
    /// these tasks; this is primarily for `bloom serve` and the in-process
    /// daemon used by integration tests.
    pub fn spawn_background_tasks(&self) -> BackgroundTasks {
        // Refresh public wallet projections only for a long-lived daemon.
        // The refresh is deliberately best-effort: cached projections and
        // Broker-independent VFS routes remain available while Broker is down.
        let projection_refresh = self
            .wallet_projection_refresh_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| {
                spawn_wallet_projection_refresh(self.wallet_projections.clone(), self.audit.clone())
            });

        // Only long-lived daemons poll GitHub. Most CLI commands construct
        // an in-process Daemon, so starting this in `from_home` would turn
        // every `vfs cat`/`ls` invocation into an immediate API request.
        let mut update_shutdown = self.update_shutdown.lock();
        if update_shutdown.is_empty() && !bloom_update::automatic_checks_disabled() {
            update_shutdown.push(Arc::clone(&self.update_checker).spawn_background());
            debug!("daemon.update_checker_spawned");
        } else if update_shutdown.is_empty() {
            debug!(
                env = bloom_update::DISABLE_AUTO_CHECK_ENV,
                "daemon.update_checker_disabled"
            );
        }
        drop(update_shutdown);

        let outbox = self.tx_engine.outbox.clone();
        let audit = self.audit.clone();
        let (tx, mut rx) = watch::channel(false);
        let interval = Duration::from_secs(60);
        let handle = tokio::spawn(async move {
            // Tick at `interval`, but exit promptly when the cancel
            // channel flips. We use `tokio::select!` so a long sleep
            // doesn't delay shutdown.
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_millis())
                            .unwrap_or(0);
                        match run_expiry_sweep_once(&outbox, &audit, now_ms) {
                            Ok(0) => tracing::trace!("outbox.sweep_expired.empty"),
                            Ok(n) => info!(swept = n, "outbox.sweep_expired"),
                            Err(e) => warn!(error = %e, "outbox.sweep_expired_failed"),
                        }
                    }
                    _ = rx.changed() => {
                        if *rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        BackgroundTasks {
            cancel: tx,
            handle: Some(handle),
            projection_refresh,
        }
    }

    /// Mount this daemon's [`Vfs`] over NFS at `path`.
    ///
    /// Only available with `--features mount` on this crate (which in
    /// turn enables `bloom-mount/mount`). Requires that `path` exists
    /// and is an empty directory; the platform mount command is
    /// invoked synchronously, so on Linux the kernel NFS client must
    /// be available (`nfs-common` package).
    ///
    /// Returns a handle whose `unmount` runs the platform `umount`
    /// command and aborts the embedded server. Drop also triggers a
    /// best-effort cleanup so a panicked test doesn't leak a mount.
    #[cfg(feature = "mount")]
    pub async fn mount(
        &self,
        path: &std::path::Path,
    ) -> Result<bloom_mount::NfsMountHandle, bloom_mount::MountError> {
        bloom_mount::serve_nfs(self.vfs.clone(), path).await
    }
}

async fn render_next_actions(projections: &dyn WalletProjectionReader) -> Vec<u8> {
    render_next_actions_with_timeout(projections, WALLET_PROJECTION_LIVE_TIMEOUT).await
}

async fn render_next_actions_with_timeout(
    projections: &dyn WalletProjectionReader,
    live_timeout: Duration,
) -> Vec<u8> {
    let mut md = String::from("# Next Actions\n\n");
    let live = tokio::time::timeout(live_timeout, projections.list_wallets()).await;
    let (wallets, wallet_projection_unavailable) = match live {
        Ok(Ok(wallets)) => (wallets, false),
        Ok(Err(_)) => (Vec::new(), true),
        Err(_) => match projections.cached_wallets() {
            Ok(wallets) => (wallets, false),
            Err(_) => (Vec::new(), true),
        },
    };

    if wallet_projection_unavailable {
        md.push_str("## Wallet Projections Unavailable\n\n");
        md.push_str(
            "Broker is offline and no cached public wallet projection is available. Authority operations remain fail-closed.\n\n",
        );
    }

    // Stale public projections remain readable but never authorize.
    let stale_wallets: Vec<String> = wallets
        .iter()
        .filter(|projection| {
            projection.freshness == bloom_machine_client::ProjectionFreshness::Stale
        })
        .map(|projection| projection.wallet.wallet_id.as_str().to_owned())
        .collect();
    if !stale_wallets.is_empty() {
        md.push_str("## Stale Wallet Projections\n\n");
        for wallet in &stale_wallets {
            md.push_str(&format!(
                "- `{wallet}`: cached public data is **stale**; signing and custody still require Broker\n"
            ));
        }
        md.push('\n');
    }

    if !wallet_projection_unavailable && stale_wallets.is_empty() {
        md.push_str("No wallets with pending actions.\n\n");
        md.push_str("All policies are signed and no outbox confirms await review.\n");
    }
    md.into_bytes()
}

fn run_expiry_sweep_once(
    outbox: &bloom_tx::outbox::Outbox,
    audit: &AuditLog,
    now_ms: u128,
) -> Result<usize, String> {
    let intent = serde_json::json!({
        "operation": "tx.outbox.sweep_expired",
        "cutoff_ms": now_ms.to_string(),
        "scope": "all_pending_machine_outbox_entries",
    });
    let operation_id =
        bloom_tools::sha256_hex(&serde_jcs::to_vec(&intent).map_err(|error| error.to_string())?);
    let correlation_id = format!("{operation_id}:{}", audit.sequence() + 1);
    audit
        .append(AuditRecord {
            ts_ms: 0,
            kind: "machine.effect.intent".into(),
            wallet: None,
            chain: None,
            data: serde_json::json!({
                "operation_id": operation_id,
                "correlation_id": correlation_id,
                "details": intent,
            }),
            prev: String::new(),
            digest: String::new(),
        })
        .map_err(|error| format!("Machine audit unavailable before expiry sweep: {error}"))?;
    let swept = outbox.sweep_expired(now_ms);
    let result = match &swept {
        Ok(count) => serde_json::json!({"outcome": "completed", "swept": count}),
        Err(error) => serde_json::json!({"outcome": "error", "error": error.to_string()}),
    };
    audit
        .append(AuditRecord {
            ts_ms: 0,
            kind: "machine.effect.result".into(),
            wallet: None,
            chain: None,
            data: serde_json::json!({
                "operation": "tx.outbox.sweep_expired",
                "correlation_id": correlation_id,
                "result": result,
            }),
            prev: String::new(),
            digest: String::new(),
        })
        .map_err(|error| format!("Machine audit unavailable after expiry sweep: {error}"))?;
    swept.map_err(|error| error.to_string())
}

fn spawn_wallet_projection_refresh(
    projections: Arc<dyn WalletProjectionReader>,
    audit: Arc<AuditLog>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(error) = refresh_wallet_projections_once(projections.as_ref(), &audit).await {
            warn!(%error, "Machine wallet projection refresh failed");
        }
    })
}

struct WalletProjectionRefreshAudit<'a> {
    audit: &'a AuditLog,
    correlation_id: String,
    finished: bool,
}

impl WalletProjectionRefreshAudit<'_> {
    fn append_result(&self, result: serde_json::Value) -> Result<(), String> {
        self.audit
            .append(AuditRecord {
                ts_ms: 0,
                kind: "machine.effect.result".into(),
                wallet: None,
                chain: None,
                data: serde_json::json!({
                    "operation": "machine.wallet_projection.boot_refresh",
                    "correlation_id": self.correlation_id,
                    "result": result,
                }),
                prev: String::new(),
                digest: String::new(),
            })
            .map(|_| ())
            .map_err(|error| format!("Machine audit unavailable after wallet refresh: {error}"))
    }

    fn finish(mut self, result: serde_json::Value) -> Result<(), String> {
        // A failed durable result append must remain visible as degradation;
        // do not let Drop disguise it with a second write attempt.
        self.finished = true;
        self.append_result(result)
    }
}

impl Drop for WalletProjectionRefreshAudit<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let result = serde_json::json!({
            "outcome": "cancelled",
            "error": "wallet projection refresh was cancelled before completion",
        });
        if let Err(error) = self.append_result(result) {
            warn!(%error, "Machine wallet projection cancellation audit failed");
        }
    }
}

async fn refresh_wallet_projections_once(
    projections: &dyn WalletProjectionReader,
    audit: &AuditLog,
) -> Result<(), String> {
    refresh_wallet_projections_once_with_timeout(projections, audit, WALLET_PROJECTION_LIVE_TIMEOUT)
        .await
}

async fn refresh_wallet_projections_once_with_timeout(
    projections: &dyn WalletProjectionReader,
    audit: &AuditLog,
    live_timeout: Duration,
) -> Result<(), String> {
    let operation_id = bloom_tools::sha256_hex(b"machine.wallet_projection.boot_refresh/v1");
    let correlation_id = format!("{operation_id}:{}", audit.sequence() + 1);
    audit
        .append(AuditRecord {
            ts_ms: 0,
            kind: "machine.effect.intent".into(),
            wallet: None,
            chain: None,
            data: serde_json::json!({
                "operation_id": operation_id,
                "correlation_id": correlation_id,
                "details": {
                    "operation": "machine.wallet_projection.boot_refresh",
                    "broker_method": "wallet.list_public",
                    "projection": "wallet-projections.json",
                },
            }),
            prev: String::new(),
            digest: String::new(),
        })
        .map_err(|error| format!("Machine audit unavailable before wallet refresh: {error}"))?;
    let refresh_audit = WalletProjectionRefreshAudit {
        audit,
        correlation_id,
        finished: false,
    };
    let refreshed = match tokio::time::timeout(live_timeout, projections.list_wallets()).await {
        Ok(result) => result.map_err(|error| error.to_string()),
        Err(_) => Err(format!(
            "wallet projection live refresh exceeded {}ms",
            live_timeout.as_millis()
        )),
    };
    let result = match &refreshed {
        Ok(wallets) => serde_json::json!({
            "outcome": "refreshed",
            "wallet_count": wallets.len(),
        }),
        Err(error) => serde_json::json!({
            "outcome": "error",
            "error": error.to_string(),
        }),
    };
    refresh_audit.finish(result)?;
    refreshed.map(|_| ())
}

/// Handle to background tasks owned by a running [`Daemon`]. Drop to
/// signal shutdown; the spawned tasks read the watch and exit at the
/// next tick. Holding this past daemon lifetime keeps the sweeper alive.
pub struct BackgroundTasks {
    cancel: watch::Sender<bool>,
    handle: Option<JoinHandle<()>>,
    projection_refresh: Option<JoinHandle<()>>,
}

impl BackgroundTasks {
    /// Trigger graceful shutdown and wait for the sweeper task to exit.
    pub async fn shutdown(mut self) {
        let _ = self.cancel.send(true);
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
        if let Some(h) = self.projection_refresh.take() {
            let _ = h.await;
        }
    }
}

impl Drop for BackgroundTasks {
    fn drop(&mut self) {
        // Best-effort fire-and-forget cancel. If the runtime is still up
        // the task will see the flip and exit; if the runtime is being
        // torn down, abort the join handle to avoid a leak.
        let _ = self.cancel.send(true);
        if let Some(h) = self.handle.take() {
            h.abort();
        }
        // An audited projection refresh may already have written its intent.
        // Detach it instead of aborting so it can still append the matching
        // result while the runtime remains alive. Long-lived callers must use
        // `shutdown` to await completion before tearing the runtime down.
        let _ = self.projection_refresh.take();
    }
}

/// Pick an ENS-capable chain client from the registry. Prefers chain id 1
/// (mainnet); falls back to Sepolia / Goerli / Holesky.
/// Adapter that reads the current basefee for a chain via the
/// registered RPC pool. Used by the bump scanner's stuck-tx trigger.
struct ChainBasefeeProvider {
    chains: ChainRegistry,
}

#[async_trait::async_trait]
impl bloom_tx::bump_scanner::BasefeeProvider for ChainBasefeeProvider {
    async fn basefee_wei(&self, chain: &str) -> Option<u128> {
        let client = self.chains.get(chain)?;
        let fh = client.fee_history(1).await.ok()?;
        fh.base_fee_per_gas.last().copied()
    }
}

#[derive(Debug, Clone)]
struct ConfigPaidHttpRpcResolver {
    by_chain_id: std::collections::BTreeMap<u64, Vec<String>>,
}

impl ConfigPaidHttpRpcResolver {
    fn from_config(config: &Config) -> Self {
        let by_chain_id = config
            .chains
            .values()
            .filter_map(|spec| {
                let urls = http_rpc_urls(spec);
                (!urls.is_empty()).then_some((spec.chain_id, urls))
            })
            .collect();
        Self { by_chain_id }
    }
}

impl PaidHttpChainRpcResolver for ConfigPaidHttpRpcResolver {
    fn http_rpc_urls_for_chain_id(&self, chain_id: u64) -> Vec<String> {
        self.by_chain_id.get(&chain_id).cloned().unwrap_or_default()
    }
}

fn http_rpc_urls(spec: &ChainSpec) -> Vec<String> {
    let mut endpoints = spec.endpoints();
    endpoints.sort_by_key(|endpoint| std::cmp::Reverse(endpoint.weight));
    endpoints
        .into_iter()
        .map(|endpoint| endpoint.url)
        .filter(|url| url.starts_with("http://") || url.starts_with("https://"))
        .collect()
}

fn pick_ens_client(chains: &ChainRegistry) -> Option<EnsClient> {
    for name in chains.list_names() {
        let Some(c) = chains.get(&name) else {
            continue;
        };
        let id = c.spec().chain_id;
        if matches!(id, 1 | 5 | 11155111 | 17000) {
            debug!(chain = %name, chain_id = id, "ens.picker.matched");
            return Some(EnsClient::mainnet(c));
        }
    }
    debug!("ens.picker.no_match: no chain with id 1/5/11155111/17000 configured");
    None
}

fn render_installed_petals_doc(petals: &PetalRunner) -> Vec<u8> {
    match petals.installed_petal_discovery() {
        Ok(installed) => render_petal_discovery_markdown(&installed),
        Err(error) => {
            warn!(error = %error, "daemon.petals_docs_render_failed");
            format!(
                "# Installed Petals\n\n\
                 Bloom could not read the installed Petal manifests: `{error}`\n"
            )
            .into_bytes()
        }
    }
}

fn render_petal_discovery_markdown(installed: &[bloom_petals::package::PetalDiscovery]) -> Vec<u8> {
    let mut markdown = String::from(
        "# Installed Petals\n\n\
         This file is generated from the immutable `petal.toml` manifests of \
         the Petals installed in this Bloom home.\n\n",
    );
    if installed.is_empty() {
        markdown.push_str("No Petals are currently installed.\n");
        return markdown.into_bytes();
    }

    for petal in installed {
        let summary = petal
            .summary
            .as_deref()
            .map(|summary| summary.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|summary| !summary.is_empty())
            .unwrap_or_else(|| "No consent summary was declared.".to_string());
        let capabilities = if petal.capabilities.is_empty() {
            "none".to_string()
        } else {
            petal
                .capabilities
                .iter()
                .map(|capability| format!("`{capability}`"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        markdown.push_str(&format!(
            "## `{name}`\n\n\
             - Directory: `petals/{name}/`\n\
             - Summary: {summary}\n\
             - Declared capabilities: {capabilities}\n\
             - Package documentation: `petals/{name}/README.md`, \
             `petals/{name}/AGENTS.md`\n\n",
            name = petal.name,
        ));
    }
    markdown.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_broker_api::{MachineBrokerRequest, MachineBrokerResponse, MachineBrokerService};
    use bloom_vfs::VfsPath;
    use bloom_vfs::handler::Handler;
    use bloom_vfs::handler::{Entry, HandlerError};

    #[test]
    fn batch_approval_requirement_preserves_owner_launch_fields() {
        let value = batch_confirmation_result_json(Err(TxEngineError::ApprovalRequired(
            bloom_tx::tx_engine::ApprovalRequirement {
                action_id: "transaction-batch:operation".into(),
                ceremony_url: "http://localhost:18734/ceremony/owner-secret".into(),
                expires_ms: 42_000,
                reason: "exact batch approval required".into(),
            },
        )))
        .unwrap();
        assert_eq!(value["status"], "awaiting_ceremony");
        assert_eq!(
            value["ceremony_url"],
            "http://localhost:18734/ceremony/owner-secret"
        );
        assert_eq!(value["ceremony_expires_at"], 42_000);
        assert!(value.get("operation_id").is_none());
        assert!(value.get("signer_receipt_digest").is_none());
    }

    struct GuestWalletProjectionFixture {
        wrote: std::sync::atomic::AtomicBool,
    }

    struct ProjectionRefreshFixture {
        calls: std::sync::atomic::AtomicUsize,
    }

    struct BlockingProjectionRefreshFixture {
        started: tokio::sync::Notify,
        release: tokio::sync::Notify,
        completed: std::sync::atomic::AtomicBool,
    }

    struct NeverCompletingProjectionRefreshFixture {
        cached_calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl WalletProjectionReader for ProjectionRefreshFixture {
        async fn list_wallets(
            &self,
        ) -> Result<Vec<bloom_machine_client::WalletProjection>, bloom_broker_api::ProtocolError>
        {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Vec::new())
        }

        async fn get_wallet(
            &self,
            _wallet_id: &bloom_broker_api::Token,
        ) -> Result<bloom_machine_client::WalletProjection, bloom_broker_api::ProtocolError>
        {
            Err(bloom_broker_api::ProtocolError::new(
                bloom_broker_api::ProtocolErrorCode::ServiceUnavailable,
                "fixture has no wallet",
            ))
        }

        fn cached_wallets(
            &self,
        ) -> Result<Vec<bloom_machine_client::WalletProjection>, bloom_broker_api::ProtocolError>
        {
            Ok(Vec::new())
        }
    }

    #[async_trait::async_trait]
    impl WalletProjectionReader for BlockingProjectionRefreshFixture {
        async fn list_wallets(
            &self,
        ) -> Result<Vec<bloom_machine_client::WalletProjection>, bloom_broker_api::ProtocolError>
        {
            self.started.notify_one();
            self.release.notified().await;
            self.completed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(Vec::new())
        }

        async fn get_wallet(
            &self,
            _wallet_id: &bloom_broker_api::Token,
        ) -> Result<bloom_machine_client::WalletProjection, bloom_broker_api::ProtocolError>
        {
            Err(bloom_broker_api::ProtocolError::new(
                bloom_broker_api::ProtocolErrorCode::ServiceUnavailable,
                "fixture has no wallet",
            ))
        }

        fn cached_wallets(
            &self,
        ) -> Result<Vec<bloom_machine_client::WalletProjection>, bloom_broker_api::ProtocolError>
        {
            Ok(Vec::new())
        }
    }

    #[async_trait::async_trait]
    impl WalletProjectionReader for NeverCompletingProjectionRefreshFixture {
        async fn list_wallets(
            &self,
        ) -> Result<Vec<bloom_machine_client::WalletProjection>, bloom_broker_api::ProtocolError>
        {
            futures::future::pending().await
        }

        async fn get_wallet(
            &self,
            _wallet_id: &bloom_broker_api::Token,
        ) -> Result<bloom_machine_client::WalletProjection, bloom_broker_api::ProtocolError>
        {
            futures::future::pending().await
        }

        fn cached_wallets(
            &self,
        ) -> Result<Vec<bloom_machine_client::WalletProjection>, bloom_broker_api::ProtocolError>
        {
            self.cached_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn next_actions_refreshes_wallet_projections_before_rendering() {
        let projections = ProjectionRefreshFixture {
            calls: std::sync::atomic::AtomicUsize::new(0),
        };

        let rendered = render_next_actions(&projections).await;

        assert_eq!(
            projections.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "/next.md must explicitly request the current wallet projection"
        );
        assert!(
            String::from_utf8(rendered)
                .unwrap()
                .starts_with("# Next Actions\n")
        );
    }

    #[tokio::test]
    async fn next_actions_timeout_falls_back_to_cached_projections() {
        let projections = NeverCompletingProjectionRefreshFixture {
            cached_calls: std::sync::atomic::AtomicUsize::new(0),
        };

        let rendered =
            render_next_actions_with_timeout(&projections, Duration::from_millis(10)).await;

        assert_eq!(
            projections
                .cached_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert!(
            String::from_utf8(rendered)
                .unwrap()
                .contains("No wallets with pending actions.")
        );
    }

    #[async_trait::async_trait]
    impl Handler for GuestWalletProjectionFixture {
        async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
            Ok(Entry::file(
                path.segments().last().map(String::as_str).unwrap_or(""),
            ))
        }

        async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            if path.segments().last().map(String::as_str) == Some("address") {
                Ok(b"0x0000000000000000000000000000000000000001\n".to_vec())
            } else {
                Ok(b"owner-only-launch-token".to_vec())
            }
        }

        async fn list(&self, _path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            Ok(vec![Entry::file("address")])
        }

        async fn write(&self, _path: &VfsPath, _data: &[u8]) -> Result<(), HandlerError> {
            self.wrote.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    struct PetalKeyBrokerFixture {
        completed: std::sync::atomic::AtomicBool,
        approval_active: std::sync::atomic::AtomicBool,
        prepares: std::sync::atomic::AtomicUsize,
        parent: bloom_broker_api::KeyRef,
        child: bloom_broker_api::KeyRef,
    }

    struct PetalExactBrokerFixture {
        active: std::sync::atomic::AtomicBool,
        requests: std::sync::Mutex<Vec<MachineBrokerRequest>>,
        root: bloom_broker_api::KeyRef,
    }

    impl PetalExactBrokerFixture {
        fn new() -> Self {
            Self {
                active: std::sync::atomic::AtomicBool::new(false),
                requests: std::sync::Mutex::new(Vec::new()),
                root: bloom_broker_api::KeyRef {
                    backend: bloom_broker_api::Token::new("local").unwrap(),
                    backend_instance: bloom_broker_api::Token::new("primary").unwrap(),
                    locator: "wallet/primary/root".into(),
                    key_spec: bloom_broker_api::KeySpec::Secp256k1,
                    public_key_fingerprint: bloom_broker_api::Digest32::from_bytes([0x31; 32]),
                    derivation: None,
                },
            }
        }
    }

    impl MachineBrokerService for PetalExactBrokerFixture {
        fn dispatch<'a>(
            &'a self,
            request: MachineBrokerRequest,
        ) -> bloom_broker_api::ServiceFuture<'a, MachineBrokerResponse> {
            Box::pin(async move {
                self.requests.lock().unwrap().push(request.clone());
                match request {
                    MachineBrokerRequest::WalletGetPublic(request) => Ok(
                        MachineBrokerResponse::WalletGetPublic(bloom_broker_api::WalletPublic {
                            wallet_id: request.wallet_id,
                            wallet_kind: bloom_broker_api::Token::new("local").unwrap(),
                            root_key_ref: self.root.clone(),
                            key_refs: vec![self.root.clone()],
                            policy_version: bloom_broker_api::DecimalU64::new(1),
                            policy_digest: bloom_broker_api::Digest32::from_bytes([0x32; 32]),
                            wallet_revocation_epoch: bloom_broker_api::DecimalU64::new(0),
                        }),
                    ),
                    MachineBrokerRequest::KeyGetPublic(request) => {
                        assert_eq!(request.key_ref, self.root);
                        Ok(MachineBrokerResponse::KeyGetPublic(
                            bloom_broker_api::KeyPublic {
                                key_ref: self.root.clone(),
                                role: bloom_broker_api::KeyRole::WalletRoot,
                                canonical_public_key: bloom_broker_api::Base64UrlBytes::from_bytes(
                                    &[0x02; 33],
                                ),
                                addresses: vec![
                                    "0x0000000000000000000000000000000000000001".into(),
                                ],
                                supported_crypto_suites: vec![
                                    bloom_broker_api::CryptoSuite::Secp256k1Sha256Recoverable,
                                ],
                            },
                        ))
                    }
                    MachineBrokerRequest::SealedApprovalPrepare(request) => {
                        Ok(MachineBrokerResponse::SealedApprovalPrepare(
                            bloom_broker_api::SealedApprovalPrepareResponse {
                                approval_id: request.terms.approval_id()?,
                                state: bloom_broker_api::ApprovalPrepareState::AwaitingCeremony,
                                ceremony_url: "http://localhost:18734/ceremony/exact-owner-secret"
                                    .into(),
                                ceremony_expires_at_ms: request.terms.expires_at_ms,
                                review_manifest_digest: bloom_broker_api::Digest32::from_bytes(
                                    [0x33; 32],
                                ),
                            },
                        ))
                    }
                    MachineBrokerRequest::SealedApprovalStatus(request) => {
                        let active = self.active.load(std::sync::atomic::Ordering::SeqCst);
                        Ok(MachineBrokerResponse::SealedApprovalStatus(
                            bloom_broker_api::ApprovalPublicStatus {
                                approval_id: request.id,
                                wallet_id: bloom_broker_api::Token::new("primary").unwrap(),
                                state: if active {
                                    bloom_broker_api::ApprovalLifecycleState::Active
                                } else {
                                    bloom_broker_api::ApprovalLifecycleState::AwaitingCeremony
                                },
                                effective_claim_assurance: None,
                                ceremony_url: (!active).then(|| {
                                    "http://localhost:18734/ceremony/exact-owner-secret".into()
                                }),
                                ceremony_expires_at_ms: (!active)
                                    .then(|| bloom_broker_api::DecimalU64::new(u64::MAX)),
                            },
                        ))
                    }
                    MachineBrokerRequest::SigningSign(request) => {
                        if !self.active.load(std::sync::atomic::Ordering::SeqCst) {
                            return Err(bloom_broker_api::ProtocolError::new(
                                bloom_broker_api::ProtocolErrorCode::ApprovalNotFound,
                                "approval is not active",
                            ));
                        }
                        Ok(MachineBrokerResponse::SigningSign(
                            bloom_broker_api::SigningResult {
                                operation_id: request.operation_id,
                                operation_digest: request.operation_digest,
                                signatures: vec![bloom_broker_api::NormalizedSignature {
                                    crypto_suite: request.crypto_suite,
                                    bytes: bloom_broker_api::Base64UrlBytes::from_bytes(
                                        &[0x34; 65],
                                    ),
                                }],
                                signer_receipt_digest: bloom_broker_api::Digest32::from_bytes(
                                    [0x35; 32],
                                ),
                                broker_receipt_digest: bloom_broker_api::Digest32::from_bytes(
                                    [0x36; 32],
                                ),
                            },
                        ))
                    }
                    MachineBrokerRequest::SigningSignBatch(request) => {
                        if !self.active.load(std::sync::atomic::Ordering::SeqCst) {
                            return Err(bloom_broker_api::ProtocolError::new(
                                bloom_broker_api::ProtocolErrorCode::ApprovalNotFound,
                                "approval is not active",
                            ));
                        }
                        let count = match &request.payloads {
                            bloom_broker_api::SigningPayloads::Batch { children } => children.len(),
                            bloom_broker_api::SigningPayloads::Single { .. } => 1,
                        };
                        Ok(MachineBrokerResponse::SigningSignBatch(
                            bloom_broker_api::SigningResult {
                                operation_id: request.operation_id,
                                operation_digest: request.operation_digest,
                                signatures: (0..count)
                                    .map(|index| bloom_broker_api::NormalizedSignature {
                                        crypto_suite: request.crypto_suite,
                                        bytes: bloom_broker_api::Base64UrlBytes::from_bytes(
                                            &[0x40 + index as u8; 65],
                                        ),
                                    })
                                    .collect(),
                                signer_receipt_digest: bloom_broker_api::Digest32::from_bytes(
                                    [0x35; 32],
                                ),
                                broker_receipt_digest: bloom_broker_api::Digest32::from_bytes(
                                    [0x36; 32],
                                ),
                            },
                        ))
                    }
                    other => panic!("unexpected exact Petal Broker request: {other:?}"),
                }
            })
        }
    }

    impl PetalKeyBrokerFixture {
        fn new() -> Self {
            let key_ref = |locator: &str, fingerprint: u8| bloom_broker_api::KeyRef {
                backend: bloom_broker_api::Token::new("local").unwrap(),
                backend_instance: bloom_broker_api::Token::new("default").unwrap(),
                locator: locator.into(),
                key_spec: bloom_broker_api::KeySpec::Secp256k1,
                public_key_fingerprint: bloom_broker_api::Digest32::from_bytes([fingerprint; 32]),
                derivation: None,
            };
            let mut child = key_ref("wallet/primary/petals/7", 2);
            child.derivation = Some(bloom_broker_api::DerivationRef::Bip32Secp256k1 {
                root_key_id: bloom_broker_api::Token::new("primary-root").unwrap(),
                path: "m/44'/60'/0'/18734/7".into(),
            });
            Self {
                completed: std::sync::atomic::AtomicBool::new(false),
                approval_active: std::sync::atomic::AtomicBool::new(false),
                prepares: std::sync::atomic::AtomicUsize::new(0),
                parent: key_ref("wallet/primary/root", 1),
                child,
            }
        }
    }

    impl MachineBrokerService for PetalKeyBrokerFixture {
        fn dispatch<'a>(
            &'a self,
            request: MachineBrokerRequest,
        ) -> bloom_broker_api::ServiceFuture<'a, MachineBrokerResponse> {
            Box::pin(async move {
                match request {
                    MachineBrokerRequest::WalletGetPublic(request) => {
                        Ok(MachineBrokerResponse::WalletGetPublic(
                            bloom_broker_api::WalletPublic {
                                wallet_id: request.wallet_id,
                                wallet_kind: bloom_broker_api::Token::new("local").unwrap(),
                                root_key_ref: self.parent.clone(),
                                // A previously derived Petal child is also in the public
                                // projection. It must never make root selection ambiguous.
                                key_refs: vec![self.parent.clone(), self.child.clone()],
                                policy_version: bloom_broker_api::DecimalU64::new(1),
                                policy_digest: bloom_broker_api::Digest32::from_bytes([3; 32]),
                                wallet_revocation_epoch: bloom_broker_api::DecimalU64::new(0),
                            },
                        ))
                    }
                    MachineBrokerRequest::KeyDerivePrepare(request) => {
                        self.prepares
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        request.validate_petal_key_scope_binding()?;
                        Ok(MachineBrokerResponse::KeyDerivePrepare(
                            bloom_broker_api::CustodyPrepareResponse {
                                ceremony_kind: bloom_broker_api::CeremonyKind::KeyDerive,
                                custody_operation_id: request.custody_operation_id,
                                state: bloom_broker_api::CustodyPrepareState::AwaitingUser,
                                ceremony_url: "http://127.0.0.1:18734/ceremony/owner-only".into(),
                                ceremony_expires_at_ms: bloom_broker_api::DecimalU64::new(u64::MAX),
                                signer_contribution_digest: bloom_broker_api::Digest32::from_bytes(
                                    [4; 32],
                                ),
                            },
                        ))
                    }
                    MachineBrokerRequest::CustodyResult(request) => {
                        if !self.completed.load(std::sync::atomic::Ordering::SeqCst) {
                            return Err(bloom_broker_api::ProtocolError::new(
                                bloom_broker_api::ProtocolErrorCode::ApprovalNotFound,
                                "custody result not found",
                            ));
                        }
                        Ok(MachineBrokerResponse::CustodyResult(
                            bloom_broker_api::CustodyResult {
                                ceremony_kind: bloom_broker_api::CeremonyKind::KeyDerive,
                                custody_operation_id: request.operation_id,
                                public_status: bloom_broker_api::CeremonyState::Succeeded,
                                wallet_id: Some(bloom_broker_api::Token::new("primary").unwrap()),
                                public_key_refs: vec![self.child.clone()],
                                credential_summaries: Vec::new(),
                                initial_policy: None,
                                receipt_digest: bloom_broker_api::Digest32::from_bytes([5; 32]),
                                encrypted_browser_result: None,
                                signer_key_id: bloom_broker_api::Token::new("signer").unwrap(),
                                signer_signature: bloom_broker_api::Base64UrlBytes::from_bytes(
                                    &[6; 64],
                                ),
                            },
                        ))
                    }
                    MachineBrokerRequest::KeyGetPublic(request)
                        if request.key_ref == self.child =>
                    {
                        Ok(MachineBrokerResponse::KeyGetPublic(
                            bloom_broker_api::KeyPublic {
                                key_ref: self.child.clone(),
                                role: bloom_broker_api::KeyRole::Derived,
                                canonical_public_key: bloom_broker_api::Base64UrlBytes::from_bytes(
                                    &[7; 33],
                                ),
                                addresses: vec![
                                    "0x1111111111111111111111111111111111111111".into(),
                                ],
                                supported_crypto_suites: vec![
                                    bloom_broker_api::CryptoSuite::Secp256k1Keccak256Recoverable,
                                    // Public key capability may be broader than this
                                    // Petal's immutable scope. Signer enforces the
                                    // narrower scope independently on every use.
                                    bloom_broker_api::CryptoSuite::Secp256k1Sha256Recoverable,
                                ],
                            },
                        ))
                    }
                    MachineBrokerRequest::SealedApprovalPrepare(request) => {
                        let bloom_broker_api::ApprovalSelector::Petal { route_grants, .. } =
                            &request.terms.selector
                        else {
                            panic!("derived key must prepare a Petal approval")
                        };
                        assert_eq!(route_grants.len(), 1);
                        assert_eq!(route_grants[0].route, "r000007");
                        let approval_id = request.terms.approval_id()?;
                        Ok(MachineBrokerResponse::SealedApprovalPrepare(
                            bloom_broker_api::SealedApprovalPrepareResponse {
                                approval_id,
                                state: bloom_broker_api::ApprovalPrepareState::AwaitingCeremony,
                                ceremony_url: "http://127.0.0.1:18734/ceremony/reusable-owner-only"
                                    .into(),
                                ceremony_expires_at_ms: bloom_broker_api::DecimalU64::new(u64::MAX),
                                review_manifest_digest: bloom_broker_api::Digest32::from_bytes(
                                    [8; 32],
                                ),
                            },
                        ))
                    }
                    MachineBrokerRequest::SealedApprovalStatus(request) => {
                        let active = self
                            .approval_active
                            .load(std::sync::atomic::Ordering::SeqCst);
                        Ok(MachineBrokerResponse::SealedApprovalStatus(
                            bloom_broker_api::ApprovalPublicStatus {
                                approval_id: request.id,
                                wallet_id: bloom_broker_api::Token::new("primary").unwrap(),
                                state: if active {
                                    bloom_broker_api::ApprovalLifecycleState::Active
                                } else {
                                    bloom_broker_api::ApprovalLifecycleState::AwaitingCeremony
                                },
                                effective_claim_assurance: Some(
                                    bloom_broker_api::ClaimAssuranceLevel::MachineAsserted,
                                ),
                                ceremony_url: None,
                                ceremony_expires_at_ms: None,
                            },
                        ))
                    }
                    other => panic!("unexpected Petal key Broker request: {other:?}"),
                }
            })
        }
    }

    #[test]
    fn approval_error_display_text_cannot_trigger_ceremony_routing() {
        let error = bloom_tx::TxEngineError::ApprovalServiceUnavailable(
            "Sealed Approval is mentioned, but no ceremony can recover this".into(),
        );
        assert!(!matches!(
            error,
            bloom_tx::TxEngineError::ApprovalRequired(_)
        ));

        let requirement = bloom_tx::ApprovalRequirement {
            action_id: "action-1".into(),
            ceremony_url: "http://127.0.0.1/approve/action-1".into(),
            expires_ms: 123,
            reason: "wording is irrelevant".into(),
        };
        assert!(matches!(
            bloom_tx::TxEngineError::ApprovalRequired(requirement),
            bloom_tx::TxEngineError::ApprovalRequired(_)
        ));
    }

    #[tokio::test]
    async fn petal_http_audit_intent_failure_prevents_network_dispatch_and_latches() {
        let directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(directory.path().join("audit.jsonl")).unwrap());
        let host = DaemonPetalHost::new(Arc::new(LateVfsHost::new()), audit.clone());
        audit.fail_next_write_for_test();
        let error = host
            .http_fetch(
                bloom_petals::HttpRequest {
                    method: "GET".into(),
                    url: "http://127.0.0.1:9/must-not-dispatch".into(),
                    headers: Vec::new(),
                    body: Vec::new(),
                },
                bloom_petals::NetPolicy::deny_all(),
                1024,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Machine audit unavailable"));
        assert_eq!(audit.count().unwrap(), 0);
        assert!(audit.mutation_degradation().is_some());
    }

    #[tokio::test]
    async fn denied_petal_network_attempt_has_exact_intent_and_error_result() {
        let directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(directory.path().join("audit.jsonl")).unwrap());
        let host = DaemonPetalHost::new(Arc::new(LateVfsHost::new()), audit.clone());
        let error = host
            .http_fetch(
                bloom_petals::HttpRequest {
                    method: "POST".into(),
                    url: "https://example.invalid/orders?secret=redacted".into(),
                    headers: Vec::new(),
                    body: b"exact-payload".to_vec(),
                },
                bloom_petals::NetPolicy::deny_all(),
                1024,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, HostError::Denied(_)));
        let records = audit.tail(2).unwrap();
        assert_eq!(records[0].kind, "machine.effect.intent");
        assert_eq!(records[0].data["operation"], "petal.http_fetch");
        assert_eq!(records[0].data["method"], "POST");
        assert_eq!(records[0].data["payload_size"], 13);
        assert_eq!(records[1].kind, "machine.effect.result");
        assert_eq!(records[1].data["outcome"], "denied");
        assert_eq!(
            records[0].data["correlation_id"],
            records[1].data["correlation_id"]
        );
        assert!(audit.pending_effect_correlations().unwrap().is_empty());
    }

    #[test]
    fn installed_petal_markdown_exposes_mount_summary_and_capabilities() {
        let markdown = render_petal_discovery_markdown(&[bloom_petals::package::PetalDiscovery {
            name: "enso".into(),
            summary: Some("Request routes,\n simulate, and stage swap transactions.".into()),
            capabilities: vec!["bloom:chain".into(), "bloom:tx.outbox".into()],
        }]);
        let markdown = String::from_utf8(markdown).unwrap();
        assert!(markdown.contains("## `enso`"));
        assert!(markdown.contains("`petals/enso/`"));
        assert!(markdown.contains("Request routes, simulate, and stage swap transactions."));
        assert!(markdown.contains("`bloom:chain`, `bloom:tx.outbox`"));
        assert!(markdown.contains("`petals/enso/README.md`"));
    }

    #[test]
    fn production_background_effect_inventory_has_explicit_audit_or_non_authority_rationale() {
        assert_eq!(BACKGROUND_EFFECT_AUDIT_MATRIX.len(), 10);
        for (effect, treatment) in BACKGROUND_EFFECT_AUDIT_MATRIX {
            assert!(!effect.is_empty());
            assert!(
                treatment.contains("signed intent/result")
                    || treatment.contains("non-authorizing")
                    || treatment.contains("cannot authorize")
                    || treatment.contains("cannot select or authorize")
                    || treatment.contains("never installs"),
                "background effect {effect} lacks an explicit §20 treatment: {treatment}"
            );
        }

        // Keep this tied to the actual production launch sites. Adding a new
        // background route without extending this list makes the release test
        // fail rather than silently relying on a hand-maintained prose table.
        let daemon = include_str!("lib.rs");
        let rpc = include_str!("../../bloom-rpc/src/transport.rs");
        let watch = include_str!("../../bloom-watch/src/executor.rs");
        let update = include_str!("../../bloom-update/src/checker.rs");
        let routes = [
            (
                daemon,
                "spawn_wallet_projection_refresh(",
                "Broker wallet projection boot refresh",
            ),
            (
                daemon,
                "bloom_mempool::stream::spawn",
                "mempool subscription cache",
            ),
            (
                daemon,
                "scanner.spawn()",
                "basefee bump advisory input/output",
            ),
            (
                daemon,
                "reconciler.spawn()",
                "tx receipt/trace reconciliation",
            ),
            (
                daemon,
                "run_expiry_sweep_once(",
                "expired outbox durable state moves",
            ),
            (
                daemon,
                "provider.health().await",
                "private RPC health probe",
            ),
            (
                daemon,
                "watch_executor.start()",
                "watch polling and durable live/history rotation",
            ),
            (daemon, ".spawn_background()", "update checker"),
            (
                rpc,
                "spawn_probe_loop(",
                "bloom-rpc endpoint health probe loop",
            ),
            (
                watch,
                "watch.poll_and_project",
                "watch polling and durable live/history rotation",
            ),
            (update, "tokio::spawn(async move", "update checker"),
        ];
        for (source, launch, effect) in routes {
            assert!(
                source.contains(launch),
                "expected production background launch route disappeared: {launch}"
            );
            assert!(
                BACKGROUND_EFFECT_AUDIT_MATRIX
                    .iter()
                    .any(|(listed, _)| *listed == effect),
                "production background launch {launch} is missing inventory row {effect}"
            );
        }
    }

    #[test]
    fn builds_from_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        let home = HomeDir::at(dir.path());
        let d = Daemon::from_home(home).unwrap();
        assert!(!d.config.chains.is_empty());
        assert!(d.vfs.handler("tools").is_some());
        assert!(d.vfs.handler("wallets").is_some());
        assert!(d.vfs.handler("chains").is_some());
        assert!(d.vfs.handler("simulate").is_some());
        assert!(d.vfs.handler("watch").is_some());
        assert!(d.vfs.handler("prices").is_some());
        assert!(d.vfs.handler("addressbook").is_some());
        assert!(d.vfs.handler("ens").is_some());
        assert!(d.vfs.handler("petals").is_some());
        assert!(
            d.vfs.handler("hyperliquid").is_none(),
            "native Hyperliquid must not be mounted; use petals/hyperliquid"
        );
        assert!(
            d.vfs.handler("polymarket").is_none(),
            "native Polymarket must not be mounted; use petals/polymarket"
        );
    }

    #[tokio::test]
    async fn petal_key_host_reconciles_retry_and_fails_closed_on_changed_or_tampered_state() {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        let fixture = Arc::new(PetalKeyBrokerFixture::new());
        let provenance_record = bloom_broker_api::ProvenanceRecord {
            subject: bloom_broker_api::ProvenanceSubject::Petal {
                package_hash: bloom_broker_api::Digest32::from_bytes([0xaa; 32]),
                route: "r000007".into(),
            },
            publisher: bloom_broker_api::Token::new("fixture-publisher").unwrap(),
            petal_lineage: Some(bloom_broker_api::PetalLineageMembership {
                lineage_id: "pln1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                release_sequence: bloom_broker_api::DecimalU64::new(1),
                predecessor_package_hashes: vec![],
                controller_key_id: bloom_broker_api::Token::new("fixture-controller").unwrap(),
                controller_signature: bloom_broker_api::Base64UrlBytes::from_bytes(&[0x44; 64]),
                active: true,
            }),
            operation_classes: vec![bloom_broker_api::ProvenanceOperationClass {
                operation_class: bloom_broker_api::Token::new("exchange-agent").unwrap(),
                fee_asset: None,
            }],
            installer_key_id: bloom_broker_api::Token::new("fixture-installer").unwrap(),
            installer_signature: bloom_broker_api::Base64UrlBytes::from_bytes(&[0x55; 64]),
        };
        let expected_provenance_digest = provenance_record.digest().unwrap();
        let host = DaemonPetalHost::new(Arc::new(LateVfsHost::new()), audit)
            .with_broker(Some(MachineBrokerClient::new(fixture.clone())))
            .with_provenance_catalog(Some(bloom_broker_api::ProvenanceCatalog {
                schema: bloom_broker_api::PROVENANCE_CATALOG_SCHEMA.into(),
                records: vec![provenance_record],
            }))
            .with_petal_key_state_root(dir.path().join("petal-key-requests"));
        let context = PetalRouteContext {
            petal_root: "exchange".into(),
            package_hash: "aa".repeat(32),
            route_id: "r000007".into(),
            op: "write".into(),
            path: "orders/new".into(),
            params: Vec::new(),
            actor: None,
        };
        let request = bloom_petals::PetalKeyRequest {
            wallet_id: "primary".into(),
            key_slot: "desk-a".into(),
            allowed_routes: vec!["r000007".into()],
            allowed_operation_classes: vec!["exchange-agent".into()],
            allowed_crypto_suites: vec!["secp256k1-keccak256-recoverable".into()],
            maximum_lifetime_ms: 60_000,
            context: Some(context.clone()),
        };

        let pending = host.petal_key_request(request.clone()).await.unwrap();
        let pending_json = serde_json::to_value(&pending).unwrap();
        assert_eq!(pending_json["state"], "pending");
        assert!(pending_json.get("ceremony_url").is_none());
        assert_eq!(
            fixture.prepares.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            host.petal_key_request(request.clone()).await.unwrap(),
            pending
        );
        assert_eq!(
            fixture.prepares.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an exact retry must reconcile the original custody operation"
        );

        let mut changed = request.clone();
        changed.allowed_operation_classes = vec!["payment-key".into()];
        let changed_error = host.petal_key_request(changed).await.unwrap_err();
        assert!(changed_error.to_string().contains("different terms"));

        let state_path = host
            .petal_key_state_path(
                "pln1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                &request.key_slot,
            )
            .unwrap();
        let owner_status: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        assert_eq!(
            owner_status["ceremony_url"],
            "http://127.0.0.1:18734/ceremony/owner-only"
        );
        assert_eq!(owner_status["status"], "awaiting_user");
        assert_eq!(
            owner_status["provenance_digest"],
            expected_provenance_digest.as_str()
        );
        let owner_vfs = Vfs::builder()
            .mount(
                "petal-key-requests",
                Arc::new(PetalKeyRequestsHandler::new(
                    dir.path().join("petal-key-requests"),
                )),
            )
            .build();
        let mounted_path = VfsPath::parse(&format!(
            "petal-key-requests/{}",
            state_path.file_name().unwrap().to_str().unwrap()
        ))
        .unwrap();
        let mounted_status: serde_json::Value =
            serde_json::from_slice(&owner_vfs.read(&mounted_path).await.unwrap()).unwrap();
        assert_eq!(mounted_status["ceremony_url"], owner_status["ceremony_url"]);

        fixture
            .completed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let reusable_pending = host.petal_key_request(request.clone()).await.unwrap();
        assert_eq!(
            serde_json::to_value(&reusable_pending).unwrap()["state"],
            "pending"
        );
        let approval_owner_status: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        assert_eq!(approval_owner_status["status"], "awaiting_user");
        assert_eq!(
            approval_owner_status["ceremony_url"],
            "http://127.0.0.1:18734/ceremony/reusable-owner-only"
        );
        assert!(approval_owner_status["reusable_approval_id"].is_string());

        fixture
            .approval_active
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let ready = host.petal_key_request(request.clone()).await.unwrap();
        let ready_json = serde_json::to_value(&ready).unwrap();
        assert_eq!(ready_json["state"], "ready");
        assert!(ready_json.get("ceremony_url").is_none());
        assert!(ready_json.get("private_key").is_none());
        let completed_owner_status: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        assert_eq!(completed_owner_status["status"], "succeeded");
        assert!(completed_owner_status["ceremony_url"].is_null());

        let mut tampered: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        tampered["scope"]["key_slot"] = serde_json::json!("other-slot");
        std::fs::write(&state_path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        let tamper_error = host.petal_key_request(request).await.unwrap_err();
        assert!(tamper_error.to_string().contains("different terms"));
    }

    #[tokio::test]
    async fn exact_petal_approval_is_owner_only_and_retries_the_frozen_payload_after_activation() {
        let directory = tempfile::tempdir().unwrap();
        let state_root = directory.path().join("petal-signing-requests");
        let broker = Arc::new(PetalExactBrokerFixture::new());
        let machine_broker = MachineBrokerClient::new(broker.clone());
        let late_vfs = Arc::new(LateVfsHost::new());
        let owner_vfs = Arc::new(
            Vfs::builder()
                .mount(
                    "petal-signing-requests",
                    Arc::new(PetalSigningRequestsHandler::new(
                        state_root.clone(),
                        Some(machine_broker.clone()),
                    )),
                )
                .build(),
        );
        late_vfs.set(owner_vfs.clone());
        let subject = bloom_broker_api::ProvenanceSubject::Petal {
            package_hash: bloom_broker_api::Digest32::from_bytes([0xbb; 32]),
            route: "r000009".into(),
        };
        let host = DaemonPetalHost::new(
            late_vfs,
            Arc::new(AuditLog::open(directory.path().join("audit.jsonl")).unwrap()),
        )
        .with_broker(Some(machine_broker))
        .with_provenance_catalog(Some(bloom_broker_api::ProvenanceCatalog {
            schema: bloom_broker_api::PROVENANCE_CATALOG_SCHEMA.into(),
            records: vec![bloom_broker_api::ProvenanceRecord {
                petal_lineage: None,
                subject: subject.clone(),
                publisher: bloom_broker_api::Token::new("fixture-publisher").unwrap(),
                operation_classes: vec![bloom_broker_api::ProvenanceOperationClass {
                    operation_class: bloom_broker_api::Token::new("order.place").unwrap(),
                    fee_asset: None,
                }],
                installer_key_id: bloom_broker_api::Token::new("fixture-installer").unwrap(),
                installer_signature: bloom_broker_api::Base64UrlBytes::from_bytes(&[0x55; 64]),
            }],
        }))
        .with_petal_signing_state_root(state_root.clone());
        let context = PetalRouteContext {
            petal_root: "exchange".into(),
            package_hash: "bb".repeat(32),
            route_id: "r000009".into(),
            op: "write".into(),
            path: "orders/new".into(),
            params: Vec::new(),
            actor: None,
        };
        let payload = b"exact owner order".to_vec();
        let payload_digest =
            bloom_broker_api::Digest32::from_bytes(sha2::Sha256::digest(&payload).into());
        let claim_payload_digest = {
            let mut digest = sha2::Sha256::new();
            digest.update(b"bloom.petal.payload-batch.v1\0");
            digest.update(1_u64.to_be_bytes());
            digest.update((payload.len() as u64).to_be_bytes());
            digest.update(&payload);
            bloom_broker_api::Digest32::from_bytes(digest.finalize().into())
        };
        let claim = bloom_broker_api::PetalUseClaim {
            package_hash: bloom_broker_api::Digest32::from_bytes([0xbb; 32]),
            route: context.route_id.clone(),
            operation_class: bloom_broker_api::Token::new("order.place").unwrap(),
            crypto_suite: bloom_broker_api::CryptoSuite::Secp256k1Sha256Recoverable,
            payload_digest: claim_payload_digest,
            ordered_hashes: vec![payload_digest.clone()],
            declared_debits: Vec::new(),
            declared_destinations: Vec::new(),
            declared_fee: bloom_broker_api::DeclaredFee::None,
            nonce: bloom_broker_api::RequestNonce::from_bytes([0x37; 16]),
            claim_assurance: bloom_broker_api::ClaimAssurance::MachineAsserted,
        };
        let mut request = PayloadSignRequest {
            wallet: "primary".into(),
            preimage: payload.clone(),
            claimed_hash: payload_digest.to_bytes(),
            signature_algorithm: "secp256k1-sha256-recoverable".into(),
            operation_class: "order.place".into(),
            petal_use_claim_jcs: serde_jcs::to_vec(&claim).unwrap(),
            claim_assurance_evidence: Some(b"fixture-assurance".to_vec()),
            approval_hint: None,
            action: Some(b"place BTC order".to_vec()),
            advisory: None,
            selector: bloom_broker_api::PetalSignSelector::Exact,
            key_ref: None,
            context: Some(context),
        };

        let SignOutcome::ApprovalPending(pending) =
            host.sign_payload_outcome(request.clone()).await.unwrap()
        else {
            panic!("first exact attempt must return a safe pending result");
        };
        assert!(!pending.action_id.contains("ceremony"));
        assert!(!pending.action_id.contains("exact-owner-secret"));
        let record = format!("{}.json", pending.action_id);
        let owner_path = VfsPath::parse(&format!("petal-signing-requests/{record}")).unwrap();
        let awaiting: PetalSigningRequestProjection =
            serde_json::from_slice(&owner_vfs.read(&owner_path).await.unwrap()).unwrap();
        assert_eq!(awaiting.status, "awaiting_owner_approval");
        assert_eq!(
            awaiting.ceremony_url.as_deref(),
            Some("http://localhost:18734/ceremony/exact-owner-secret")
        );
        assert_ne!(pending.action_id, awaiting.approval_id.as_deref().unwrap());
        let guest_error = host
            .vfs_read(&format!("petal-signing-requests/{record}"))
            .await
            .unwrap_err();
        assert!(matches!(guest_error, HostError::Denied(_)));

        broker
            .active
            .store(true, std::sync::atomic::Ordering::SeqCst);
        request.approval_hint = Some(pending.action_id);
        let active: PetalSigningRequestProjection =
            serde_json::from_slice(&owner_vfs.read(&owner_path).await.unwrap()).unwrap();
        assert_eq!(active.status, "approved_retry_required");
        assert!(active.ceremony_url.is_none());

        let signed = host.sign_payload_outcome(request).await.unwrap();
        assert_eq!(signed, SignOutcome::Signature(vec![0x34; 65]));
        let completed: PetalSigningRequestProjection =
            serde_json::from_slice(&owner_vfs.read(&owner_path).await.unwrap()).unwrap();
        assert_eq!(completed.status, "signed");
        assert!(completed.ceremony_url.is_none());
        assert!(completed.approval_id.is_none());

        let requests = broker.requests.lock().unwrap();
        let prepared = requests.iter().find_map(|request| match request {
            MachineBrokerRequest::SealedApprovalPrepare(request) => Some(request),
            _ => None,
        });
        let signed = requests.iter().find_map(|request| match request {
            MachineBrokerRequest::SigningSign(request) => Some(request),
            _ => None,
        });
        let (prepared, signed) = (prepared.unwrap(), signed.unwrap());
        assert_eq!(
            prepared.terms.selector,
            bloom_broker_api::ApprovalSelector::Exact {
                ordered_payload_digests: vec![payload_digest.clone()],
                ordered_hashes: vec![payload_digest],
            }
        );
        assert_eq!(
            signed.payloads,
            bloom_broker_api::SigningPayloads::Single {
                payload: bloom_broker_api::Base64UrlBytes::from_bytes(&payload),
            }
        );
        assert_eq!(
            signed.crypto_suite,
            bloom_broker_api::CryptoSuite::Secp256k1Sha256Recoverable
        );
    }

    #[tokio::test]
    async fn exact_petal_batch_is_atomic_and_rejects_an_old_hint_after_reorder() {
        let directory = tempfile::tempdir().unwrap();
        let state_root = directory.path().join("petal-signing-requests");
        let broker = Arc::new(PetalExactBrokerFixture::new());
        let machine_broker = MachineBrokerClient::new(broker.clone());
        let host = DaemonPetalHost::new(
            Arc::new(LateVfsHost::new()),
            Arc::new(AuditLog::open(directory.path().join("audit.jsonl")).unwrap()),
        )
        .with_broker(Some(machine_broker))
        .with_provenance_catalog(Some(bloom_broker_api::ProvenanceCatalog {
            schema: bloom_broker_api::PROVENANCE_CATALOG_SCHEMA.into(),
            records: vec![bloom_broker_api::ProvenanceRecord {
                petal_lineage: None,
                subject: bloom_broker_api::ProvenanceSubject::Petal {
                    package_hash: bloom_broker_api::Digest32::from_bytes([0xbb; 32]),
                    route: "r000010".into(),
                },
                publisher: bloom_broker_api::Token::new("fixture-publisher").unwrap(),
                operation_classes: vec![bloom_broker_api::ProvenanceOperationClass {
                    operation_class: bloom_broker_api::Token::new("order.batch").unwrap(),
                    fee_asset: None,
                }],
                installer_key_id: bloom_broker_api::Token::new("fixture-installer").unwrap(),
                installer_signature: bloom_broker_api::Base64UrlBytes::from_bytes(&[0x55; 64]),
            }],
        }))
        .with_petal_signing_state_root(state_root);
        let context = PetalRouteContext {
            petal_root: "exchange".into(),
            package_hash: "bb".repeat(32),
            route_id: "r000010".into(),
            op: "write".into(),
            path: "orders/batch".into(),
            params: Vec::new(),
            actor: None,
        };
        let preimages = [b"first exact payload".to_vec(), b"second".to_vec()];
        let hashes = preimages
            .iter()
            .map(|payload| {
                bloom_broker_api::Digest32::from_bytes(sha2::Sha256::digest(payload).into())
            })
            .collect::<Vec<_>>();
        let batch_digest = |payloads: &[Vec<u8>]| {
            let mut digest = sha2::Sha256::new();
            digest.update(b"bloom.petal.payload-batch.v1\0");
            digest.update((payloads.len() as u64).to_be_bytes());
            for payload in payloads {
                digest.update((payload.len() as u64).to_be_bytes());
                digest.update(payload);
            }
            bloom_broker_api::Digest32::from_bytes(digest.finalize().into())
        };
        let claim = bloom_broker_api::PetalUseClaim {
            package_hash: bloom_broker_api::Digest32::from_bytes([0xbb; 32]),
            route: context.route_id.clone(),
            operation_class: bloom_broker_api::Token::new("order.batch").unwrap(),
            crypto_suite: bloom_broker_api::CryptoSuite::Secp256k1Sha256Recoverable,
            payload_digest: batch_digest(&preimages),
            ordered_hashes: hashes.clone(),
            declared_debits: Vec::new(),
            declared_destinations: Vec::new(),
            declared_fee: bloom_broker_api::DeclaredFee::None,
            nonce: bloom_broker_api::RequestNonce::from_bytes([0x48; 16]),
            claim_assurance: bloom_broker_api::ClaimAssurance::MachineAsserted,
        };
        let mut request = PayloadBatchSignRequest {
            wallet: "primary".into(),
            payloads: preimages
                .iter()
                .zip(&hashes)
                .map(|(preimage, hash)| bloom_petals::PayloadSignItem {
                    preimage: preimage.clone(),
                    claimed_hash: hash.to_bytes(),
                })
                .collect(),
            signature_algorithm: "secp256k1-sha256-recoverable".into(),
            operation_class: "order.batch".into(),
            petal_use_claim_jcs: serde_jcs::to_vec(&claim).unwrap(),
            claim_assurance_evidence: None,
            approval_hint: None,
            action: Some(b"two exact orders".to_vec()),
            advisory: None,
            selector: bloom_broker_api::PetalSignSelector::Exact,
            key_ref: None,
            context: Some(context),
        };

        let PayloadBatchSignOutcome::ApprovalPending(pending) = host
            .sign_payload_batch_outcome(request.clone())
            .await
            .unwrap()
        else {
            panic!("first batch attempt must return a safe pending result");
        };
        assert!(!pending.action_id.contains("ceremony"));
        request.approval_hint = Some(pending.action_id.clone());
        let mut reordered = request.clone();
        reordered.payloads.swap(0, 1);
        let reordered_preimages = reordered
            .payloads
            .iter()
            .map(|item| item.preimage.clone())
            .collect::<Vec<_>>();
        let mut reordered_claim = claim;
        reordered_claim.payload_digest = batch_digest(&reordered_preimages);
        reordered_claim.ordered_hashes.reverse();
        reordered.petal_use_claim_jcs = serde_jcs::to_vec(&reordered_claim).unwrap();
        let error = host
            .sign_payload_batch_outcome(reordered)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("approval artifact does not match")
        );

        broker
            .active
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let PayloadBatchSignOutcome::Signatures(signatures) =
            host.sign_payload_batch_outcome(request).await.unwrap()
        else {
            panic!("approved retry must return the complete signature batch");
        };
        assert_eq!(signatures, vec![vec![0x40; 65], vec![0x41; 65]]);
        let requests = broker.requests.lock().unwrap();
        let signed = requests.iter().find_map(|request| match request {
            MachineBrokerRequest::SigningSignBatch(request) => Some(request),
            _ => None,
        });
        let bloom_broker_api::SigningPayloads::Batch { children } = &signed.unwrap().payloads
        else {
            panic!("Petal batch must use signing.sign_batch");
        };
        assert_eq!(
            children,
            &preimages
                .iter()
                .map(|payload| bloom_broker_api::Base64UrlBytes::from_bytes(payload))
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn petal_guest_vfs_cannot_reach_owner_only_key_ceremony_projection() {
        let directory = tempfile::tempdir().unwrap();
        let state_root = directory.path().join("petal-key-requests");
        std::fs::create_dir_all(&state_root).unwrap();
        let record = format!("{}.json", "ab".repeat(32));
        let owner_record = br#"{"status":"awaiting_user","ceremony_url":"http://127.0.0.1:18734/ceremony/secret"}"#;
        std::fs::write(state_root.join(&record), owner_record).unwrap();

        let owner_vfs = Arc::new(
            Vfs::builder()
                .mount(
                    "petal-key-requests",
                    Arc::new(PetalKeyRequestsHandler::new(state_root)),
                )
                .build(),
        );
        let owner_path = VfsPath::parse(&format!("petal-key-requests/{record}")).unwrap();
        assert_eq!(owner_vfs.read(&owner_path).await.unwrap(), owner_record);

        let late_vfs = Arc::new(LateVfsHost::new());
        late_vfs.set(owner_vfs);
        let audit = Arc::new(AuditLog::open(directory.path().join("audit.jsonl")).unwrap());
        let guest = DaemonPetalHost::new(late_vfs, audit);

        let operations = [
            guest.vfs_lookup("petal-key-requests").await.map(|_| ()),
            guest.vfs_list("petal-key-requests").await.map(|_| ()),
            guest
                .vfs_read(&format!("petal-key-requests/{record}"))
                .await
                .map(|_| ()),
            guest
                .vfs_write(&format!("petal-key-requests/{record}"), b"replace")
                .await,
            guest
                .vfs_read(&format!("public/../petal-key-requests/{record}"))
                .await
                .map(|_| ()),
        ];
        for result in operations {
            assert!(
                matches!(result, Err(HostError::Denied(ref message)) if message.contains("owner-only"))
            );
        }
        assert_eq!(
            std::fs::read(directory.path().join("petal-key-requests").join(record)).unwrap(),
            owner_record,
            "denied guest write must not modify the owner projection"
        );
    }

    #[tokio::test]
    async fn petal_guest_vfs_denies_normalized_owner_wallet_ceremony_projections() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_projection = Arc::new(GuestWalletProjectionFixture {
            wrote: std::sync::atomic::AtomicBool::new(false),
        });
        let owner_vfs = Arc::new(
            Vfs::builder()
                .mount("wallets", wallet_projection.clone())
                .build(),
        );
        let owner_secret = owner_vfs
            .read(&VfsPath::parse("wallets/alice/sealed-approvals/new.json").unwrap())
            .await
            .unwrap();
        assert_eq!(owner_secret, b"owner-only-launch-token");

        let late_vfs = Arc::new(LateVfsHost::new());
        late_vfs.set(owner_vfs);
        let audit = Arc::new(AuditLog::open(directory.path().join("audit.jsonl")).unwrap());
        let guest = DaemonPetalHost::new(late_vfs, audit);
        let protected = vec![
            "wallets/new".to_string(),
            "wallets/registrations".to_string(),
            format!("wallets/registrations/{}/status.json", "22".repeat(32)),
            format!("wallets/registrations/{}/result.json", "22".repeat(32)),
            format!("wallets/registrations/{}/cancel", "22".repeat(32)),
            "wallets/alice/sealed-approvals/new.json".to_string(),
            format!("wallets/alice/sealed-approvals/{}/renew", "11".repeat(32)),
            "wallets/alice/policy-updates/latest/approval_challenge.json".to_string(),
            "wallets/alice/policy-updates/latest/status.json".to_string(),
            "wallets/alice/policy-updates/pending/policy-update-abc/approval_challenge.json"
                .to_string(),
            "wallets/alice/policy-updates/pending/policy-update-abc/status.json".to_string(),
            "public/../wallets/alice/sealed-approvals/new.json".to_string(),
            "wallets/alice/adjacent/../policy-updates/latest/status.json".to_string(),
        ];
        for path in &protected {
            let operations = [
                guest.vfs_lookup(path).await.map(|_| ()),
                guest.vfs_list(path).await.map(|_| ()),
                guest.vfs_read(path).await.map(|_| ()),
                guest.vfs_write(path, b"replace").await,
            ];
            for result in operations {
                assert!(
                    matches!(result, Err(HostError::Denied(ref message)) if message.contains("owner-only")),
                    "guest operation unexpectedly reached owner projection {path}: {result:?}"
                );
            }
        }
        assert!(
            !wallet_projection
                .wrote
                .load(std::sync::atomic::Ordering::SeqCst),
            "normalized denied writes must never reach WalletsHandler"
        );

        let adjacent = guest.vfs_read("wallets/alice/address").await.unwrap();
        assert_eq!(adjacent, b"0x0000000000000000000000000000000000000001\n");
        assert!(guest.vfs_lookup("wallets/alice/address").await.is_ok());
        assert!(guest.vfs_list("wallets/alice").await.is_ok());
    }

    #[test]
    fn daemon_petal_host_derives_evm_origin_only_from_trusted_route_context() {
        let context = PetalRouteContext {
            petal_root: "polymarket".into(),
            package_hash: "a".repeat(64),
            route_id: "r000001".into(),
            op: "write".into(),
            path: "/fund/alice/one/confirm".into(),
            params: vec![("id".into(), "one".into())],
            actor: Some("agent-1".into()),
        };
        let origin = DaemonPetalHost::petal_execution_origin(&context).unwrap();
        assert_eq!(origin.petal_id, "petal:polymarket");
        assert_eq!(origin.petal_digest, "a".repeat(64));
        assert_eq!(origin.petal_version, "v1-package");

        for mutate in ["route", "operation", "path"] {
            let mut changed = context.clone();
            match mutate {
                "route" => changed.route_id = "r000002".into(),
                "operation" => changed.op = "read".into(),
                "path" => changed.path = "/fund/alice/two/confirm".into(),
                _ => unreachable!(),
            }
            assert_eq!(
                DaemonPetalHost::petal_execution_origin(&changed).unwrap(),
                origin,
                "{mutate} must remain within the package-scoped EVM execution origin"
            );
        }

        let mut root = context.clone();
        root.path.clear();
        assert_eq!(
            DaemonPetalHost::petal_execution_origin(&root).unwrap(),
            origin
        );

        let mut invalid = context;
        invalid.package_hash = "not-a-digest".into();
        assert!(DaemonPetalHost::petal_execution_origin(&invalid).is_err());
    }

    fn test_petal_host(daemon: &Daemon) -> DaemonPetalHost {
        DaemonPetalHost::new(Arc::new(LateVfsHost::new()), daemon.audit.clone()).with_tx_outbox(
            PetalTxOutbox {
                tx_engine: daemon.tx_engine.clone(),
                chains: daemon.chains.clone(),
                wallet_projections: daemon.wallet_projections.clone(),
                address_book: daemon.address_book.clone(),
                write_permit: daemon.home_write_permit.clone(),
            },
        )
    }

    #[tokio::test]
    async fn daemon_petal_chain_read_requires_context_and_rejects_unsafe_rpc_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = Daemon::from_home(HomeDir::at(dir.path())).unwrap();
        let host = test_petal_host(&daemon);
        let context = PetalRouteContext {
            petal_root: "reader".into(),
            package_hash: "a".repeat(64),
            route_id: "r000001".into(),
            op: "read".into(),
            path: "/balance.json".into(),
            params: vec![],
            actor: None,
        };
        let chain_name = daemon.chains.list_names().into_iter().next().unwrap();

        let missing_context = host
            .chain_read(ChainRequest {
                chain: chain_name.clone(),
                method: "eth_chainId".into(),
                params_json: "[]".into(),
                context: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(missing_context, HostError::Denied(_)));

        for (method, params) in [
            ("eth_sendRawTransaction", "[]"),
            ("eth_chainId", "[1]"),
            (
                "eth_getBalance",
                r#"["0x0000000000000000000000000000000000000001","pending"]"#,
            ),
            (
                "eth_getCode",
                r#"["0x0000000000000000000000000000000000000001","pending"]"#,
            ),
            (
                "eth_call",
                r#"[{"to":"0x0000000000000000000000000000000000000001","stateOverride":{}},"latest"]"#,
            ),
        ] {
            let error = host
                .chain_read(ChainRequest {
                    chain: chain_name.clone(),
                    method: method.into(),
                    params_json: params.into(),
                    context: Some(context.clone()),
                })
                .await
                .unwrap_err();
            assert!(
                matches!(error, HostError::Denied(_) | HostError::Invalid(_)),
                "unexpected {method} result: {error}"
            );
        }

        assert!(parse_petal_hex_bytes("0x70a08231", "data").is_ok());
        assert!(parse_petal_hex_bytes("70a08231", "data").is_err());
        assert!(parse_petal_hex_quantity("0x0", "value").is_ok());
        assert!(parse_petal_hex_quantity("0", "value").is_err());
    }

    #[tokio::test]
    async fn daemon_petal_outbox_inspection_is_read_only_and_origin_bound() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = Daemon::from_home(HomeDir::at(dir.path())).unwrap();
        let host = test_petal_host(&daemon);
        let context = PetalRouteContext {
            petal_root: "funding".into(),
            package_hash: "b".repeat(64),
            route_id: "r000002".into(),
            op: "read".into(),
            path: "/fund/alice/one/status.json".into(),
            params: vec![],
            actor: Some("agent-1".into()),
        };
        let tx_hash = format!("0x{}", "ab".repeat(32));
        let staged = bloom_proto::StagedTx {
            id: "petal-inspect".into(),
            wallet: "alice".into(),
            chain: "anvil".into(),
            chain_id: 31337,
            from: "0x0000000000000000000000000000000000000001".into(),
            to: "0x0000000000000000000000000000000000000002".into(),
            value_wei: "0".into(),
            data_hex: "0x".into(),
            gas_limit: 21_000,
            max_fee_per_gas: Some("100".into()),
            max_priority_fee_per_gas: Some("10".into()),
            gas_price: None,
            nonce: 0,
            policy_checks: vec![],
            created_ms: 1,
            expires_ms: u128::MAX,
            status: bloom_proto::TxStatus::Pending,
            action_kind: bloom_proto::TxActionKind::Unknown,
            tx_hash: Some(tx_hash.clone()),
            token: None,
            nft: None,
            usd_value: None,
            valuation: None,
            depends_on: None,
            action_id: None,
            execution_origin: Some(DaemonPetalHost::petal_execution_origin(&context).unwrap()),
        };
        let request = EvmTransactionRequest {
            wallet: "alice".into(),
            chain: "anvil".into(),
            to: staged.to.clone(),
            value_wei: staged.value_wei.clone(),
            data_hex: staged.data_hex.clone(),
            nonce: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            context: Some(context.clone()),
        };
        let origin = staged.resolved_execution_origin();
        assert!(petal_pending_request_matches(
            &staged,
            &request,
            &origin,
            staged.to.parse().unwrap(),
            staged.value_wei.parse().unwrap(),
        ));
        let mut equivalent_fee_request = request.clone();
        equivalent_fee_request.max_fee_per_gas = Some("00100".into());
        equivalent_fee_request.max_priority_fee_per_gas = Some("00010".into());
        assert!(petal_pending_request_matches(
            &staged,
            &equivalent_fee_request,
            &origin,
            staged.to.parse().unwrap(),
            staged.value_wei.parse().unwrap(),
        ));
        let mut changed_request = request;
        changed_request.data_hex = "0x00".into();
        assert!(!petal_pending_request_matches(
            &staged,
            &changed_request,
            &origin,
            staged.to.parse().unwrap(),
            staged.value_wei.parse().unwrap(),
        ));
        let entry_dir = daemon
            .tx_engine
            .outbox
            .write_pending(&staged, "# plan")
            .unwrap();
        let receipt = bloom_tx::outbox::MinedReceipt {
            outcome: "success".into(),
            tx_hash: tx_hash.clone(),
            block_number: Some(42),
            revert_reason: None,
        };
        daemon
            .tx_engine
            .outbox
            .write_artefact(
                &entry_dir,
                bloom_tx::outbox::RECEIPT_FILE,
                &serde_json::to_vec(&receipt).unwrap(),
            )
            .unwrap();

        let inspection = host
            .evm_tx_inspect(
                "alice".into(),
                "anvil".into(),
                staged.id.clone(),
                Some(context.clone()),
            )
            .await
            .unwrap();
        assert_eq!(inspection.state, "success");
        assert_eq!(inspection.tx_hash.as_deref(), Some(tx_hash.as_str()));
        assert!(
            inspection
                .receipt_json
                .unwrap()
                .contains("\"block_number\":42")
        );

        let mut other_route = context.clone();
        other_route.path = "/fund/alice/two/confirm".into();
        host.evm_tx_inspect(
            "alice".into(),
            "anvil".into(),
            staged.id.clone(),
            Some(other_route),
        )
        .await
        .unwrap();

        let mut other_app = context.clone();
        other_app.petal_root = "other".into();
        let denied = host
            .evm_tx_inspect(
                "alice".into(),
                "anvil".into(),
                staged.id.clone(),
                Some(other_app),
            )
            .await
            .unwrap_err();
        assert!(matches!(denied, HostError::Denied(_)));

        let mut other_context = context;
        other_context.package_hash = "c".repeat(64);
        let denied = host
            .evm_tx_inspect(
                "alice".into(),
                "anvil".into(),
                staged.id,
                Some(other_context),
            )
            .await
            .unwrap_err();
        assert!(matches!(denied, HostError::Denied(_)));
    }

    /// A pre-existing watch spec on disk should be loaded into the
    /// registry and the executor should start polling it on boot. We
    /// register an event-style spec (which keys off block number) and
    /// rely on the executor's tick loop creating the per-watch directory
    /// — the easiest deterministic signal in a no-network test. We
    /// can't actually hit RPC here, so we verify the executor is
    /// running and the registry exposes the seeded spec; the live-file
    /// content path is exercised in `crates/bloom-watch/tests/`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watch_executor_starts_with_preexisting_spec() {
        use bloom_watch::{WatchKind, WatchSpec};
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let home = HomeDir::at(dir.path());
        home.ensure().unwrap();

        // Seed a spec on disk *before* daemon construction.
        let registry = Arc::new(WatchRegistry::new(home.watch_dir()).unwrap());
        registry
            .add(WatchSpec {
                id: "w-0001".into(),
                wallet: "alice".into(),
                created_ms: 1,
                kind: WatchKind::Block {
                    chain: "anvil".into(),
                },
                note: None,
            })
            .unwrap();
        drop(registry);

        let d = Daemon::from_home(home.clone()).unwrap();
        // The handler picks up specs scanned at registry construction time.
        let entries = d
            .vfs
            .list(&VfsPath::parse("/watch").unwrap())
            .await
            .unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&"w-0001"),
            "expected pre-seeded spec to appear: {names:?}"
        );

        // Drive a tick directly to prove the executor's loop logic is
        // wired (the auto-spawned task may not hit RPC in this offline
        // test environment, but tick_once fails silently on missing
        // chain). After the tick the executor should still be running;
        // shutdown should stop it cleanly.
        let mut state = bloom_watch::executor::ExecutorState::default();
        let _ = d.watch_executor.tick_once(&mut state).await;
        // shutdown is idempotent and should complete promptly.
        tokio::time::timeout(Duration::from_secs(2), d.shutdown())
            .await
            .expect("shutdown timed out");
    }

    #[test]
    fn daemon_boots_without_mempool_config() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = HomeDir::at(tmp.path());
        let daemon = Daemon::from_home(home).expect("daemon boots");
        assert!(daemon.config.mempool.is_empty());
        assert!(daemon.config.private_rpc.is_empty());
    }

    #[tokio::test]
    async fn daemon_skips_mempool_for_unknown_chain() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = HomeDir::at(tmp.path());
        home.ensure().unwrap();
        // Write a config with a mempool entry pointing at a chain not in [chains.*]
        let config_toml = r#"
default_chain = "ethereum"
[chains.ethereum]
name = "ethereum"
chain_id = 1
rpc_urls = ["http://127.0.0.1:8545"]
native_symbol = "ETH"
native_decimals = 18

[mempool.bogus_chain]
provider = "alchemy"
ws_url = "wss://example.invalid"
"#;
        std::fs::write(home.config_path(), config_toml).unwrap();
        // The chain has no real RPC; daemon still boots because chain
        // creation is best-effort (see existing chain_skipped path).
        let daemon = Daemon::from_home(home).expect("daemon boots");
        // Confirm the config was actually parsed with the bogus_chain entry
        // (so we know the skip path was exercised, not just absent).
        assert!(
            daemon.config.mempool.contains_key("bogus_chain"),
            "expected bogus_chain in parsed config"
        );
        // No mempool shutdown handle: the bogus chain was skipped because
        // it doesn't appear in [chains.*].
        assert!(daemon.mempool_shutdown.lock().is_empty());
    }

    /// Boots a daemon with one valid mempool chain and verifies that the
    /// bump scanner and backends probe tasks were both spawned (their
    /// shutdown senders are non-empty), and that the StatusHandler's
    /// `status/backends/mempool` reads back a non-empty snapshot.
    #[tokio::test]
    async fn daemon_wires_bump_scanner_and_backends_probe_for_mempool_chain() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = HomeDir::at(tmp.path());
        home.ensure().unwrap();
        let config_toml = r#"
default_chain = "ethereum"
[chains.ethereum]
name = "ethereum"
chain_id = 1
rpc_urls = ["http://127.0.0.1:8545"]
native_symbol = "ETH"
native_decimals = 18

[mempool.ethereum]
provider = "alchemy"
ws_url = "wss://example.invalid"
"#;
        std::fs::write(home.config_path(), config_toml).unwrap();
        let daemon = Daemon::from_home(home).expect("daemon boots");

        assert!(
            !daemon.bump_shutdown.lock().is_empty(),
            "bump scanner should be spawned when at least one mempool chain is configured"
        );
        assert!(
            !daemon.probe_shutdown.lock().is_empty(),
            "backends probe should be spawned when at least one mempool chain is configured"
        );

        let path = bloom_vfs::VfsPath::parse("status/backends/mempool").unwrap();
        let body = daemon
            .vfs
            .read(&path)
            .await
            .expect("status/backends/mempool readable");
        let s = std::str::from_utf8(&body).unwrap();
        assert!(
            s.contains("ethereum") && s.contains("alchemy"),
            "expected mempool snapshot to mention ethereum + alchemy; got: {s}"
        );

        tokio::time::timeout(Duration::from_secs(2), daemon.shutdown())
            .await
            .expect("shutdown timed out");
    }

    #[tokio::test]
    async fn daemon_construction_does_not_start_update_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = Daemon::from_home(HomeDir::at(dir.path())).unwrap();

        assert!(
            daemon.update_shutdown.lock().is_empty(),
            "short-lived daemon construction must not start the GitHub update refresher"
        );
    }

    #[test]
    fn daemon_construction_does_not_launch_wallet_projection_refresh() {
        let source = include_str!("lib.rs");
        let constructor_start = source.find("fn from_home_inner(").unwrap();
        let constructor_end = source[constructor_start..]
            .find("\n    pub fn start_workers")
            .map(|offset| constructor_start + offset)
            .unwrap();
        let constructor = &source[constructor_start..constructor_end];

        assert!(
            !constructor.contains("spawn_wallet_projection_refresh("),
            "short-lived daemon construction must not contact Broker to refresh wallet projections"
        );
    }

    #[tokio::test]
    async fn long_lived_background_tasks_launch_wallet_projection_refresh() {
        let directory = tempfile::tempdir().unwrap();
        let mut daemon = Daemon::from_home(HomeDir::at(directory.path())).unwrap();
        let projections = Arc::new(ProjectionRefreshFixture {
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        daemon.wallet_projections = projections.clone();

        let tasks = daemon.spawn_background_tasks();
        tokio::time::timeout(Duration::from_secs(2), async {
            while projections.calls.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("long-lived daemon did not launch wallet projection refresh");
        assert_eq!(
            projections.calls.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        tasks.shutdown().await;
        daemon.shutdown().await;
    }

    #[tokio::test]
    async fn background_task_shutdown_awaits_wallet_projection_refresh() {
        let directory = tempfile::tempdir().unwrap();
        let mut daemon = Daemon::from_home(HomeDir::at(directory.path())).unwrap();
        let projections = Arc::new(BlockingProjectionRefreshFixture {
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            completed: std::sync::atomic::AtomicBool::new(false),
        });
        daemon.wallet_projections = projections.clone();

        let tasks = daemon.spawn_background_tasks();
        projections.started.notified().await;
        let mut shutdown = tokio::spawn(tasks.shutdown());
        tokio::task::yield_now().await;
        assert!(
            !shutdown.is_finished(),
            "graceful shutdown returned while the audited projection refresh was in flight"
        );

        projections.release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), &mut shutdown)
            .await
            .expect("graceful shutdown did not await the projection refresh")
            .unwrap();
        assert!(
            projections
                .completed
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        daemon.shutdown().await;
    }

    #[tokio::test]
    async fn repeated_background_startup_coalesces_wallet_projection_refresh() {
        let directory = tempfile::tempdir().unwrap();
        let mut daemon = Daemon::from_home(HomeDir::at(directory.path())).unwrap();
        let projections = Arc::new(ProjectionRefreshFixture {
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        daemon.wallet_projections = projections.clone();

        let first = daemon.spawn_background_tasks();
        let second = daemon.spawn_background_tasks();
        tokio::time::timeout(Duration::from_secs(2), async {
            while projections.calls.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("long-lived daemon did not launch wallet projection refresh");
        tokio::task::yield_now().await;
        assert_eq!(
            projections.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "repeated background startup must not duplicate the audited boot refresh"
        );

        second.shutdown().await;
        first.shutdown().await;
        daemon.shutdown().await;
    }

    /// Fix #3: the spawned sweeper drops expired pending entries into
    /// `failed/` on its own. We don't wait for the natural 60s tick;
    /// instead the test calls `outbox.sweep_expired` itself to keep
    /// runtime short, but verifies that `spawn_background_tasks` returns
    /// a guard that cleans up cleanly when shut down.
    #[tokio::test]
    async fn sweep_background_task_handles_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let home = HomeDir::at(dir.path());
        let d = Daemon::from_home(home).unwrap();
        let tasks = d.spawn_background_tasks();
        assert_eq!(
            d.update_shutdown.lock().len(),
            1,
            "long-lived background tasks should start one update refresher"
        );
        // Seed an already-expired pending entry; the foreground call
        // exercises the same code the spawned task runs.
        let staged = bloom_proto::StagedTx {
            id: "0001-test".into(),
            wallet: "alice".into(),
            chain: "anvil".into(),
            chain_id: 31337,
            from: "0x0000000000000000000000000000000000000001".into(),
            to: "0x0000000000000000000000000000000000000002".into(),
            value_wei: "0".into(),
            data_hex: "0x".into(),
            gas_limit: 21000,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            gas_price: None,
            nonce: 0,
            policy_checks: vec![],
            created_ms: 0,
            expires_ms: 1,
            status: bloom_proto::TxStatus::Pending,
            action_kind: bloom_proto::TxActionKind::Unknown,
            tx_hash: None,
            token: None,
            nft: None,
            usd_value: None,
            valuation: None,
            depends_on: None,
            action_id: None,
            execution_origin: None,
        };
        d.tx_engine.outbox.write_pending(&staged, "p").unwrap();
        let n = run_expiry_sweep_once(&d.tx_engine.outbox, &d.audit, 2).unwrap();
        assert_eq!(n, 1);
        let records = d.audit.tail(2).unwrap();
        assert_eq!(records[0].kind, "machine.effect.intent");
        assert_eq!(
            records[0].data["details"]["operation"],
            "tx.outbox.sweep_expired"
        );
        assert_eq!(records[1].kind, "machine.effect.result");
        assert_eq!(records[1].data["result"]["swept"], 1);

        // Shutdown completes promptly.
        tokio::time::timeout(std::time::Duration::from_secs(2), tasks.shutdown())
            .await
            .expect("background task did not honour shutdown signal");
    }

    #[test]
    fn expiry_sweep_audit_prewrite_failure_prevents_durable_move() {
        let dir = tempfile::tempdir().unwrap();
        let d = Daemon::from_home(HomeDir::at(dir.path())).unwrap();
        let staged = bloom_proto::StagedTx {
            id: "0001-audit-failure".into(),
            wallet: "alice".into(),
            chain: "anvil".into(),
            chain_id: 31337,
            from: "0x0000000000000000000000000000000000000001".into(),
            to: "0x0000000000000000000000000000000000000002".into(),
            value_wei: "0".into(),
            data_hex: "0x".into(),
            gas_limit: 21_000,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            gas_price: None,
            nonce: 0,
            policy_checks: vec![],
            created_ms: 0,
            expires_ms: 1,
            status: bloom_proto::TxStatus::Pending,
            action_kind: bloom_proto::TxActionKind::Unknown,
            tx_hash: None,
            token: None,
            nft: None,
            usd_value: None,
            valuation: None,
            depends_on: None,
            action_id: None,
            execution_origin: None,
        };
        d.tx_engine.outbox.write_pending(&staged, "p").unwrap();
        d.audit.fail_next_write_for_test();
        assert!(run_expiry_sweep_once(&d.tx_engine.outbox, &d.audit, 2).is_err());
        let entry = d
            .tx_engine
            .outbox
            .read("alice", "anvil", "0001-audit-failure")
            .unwrap();
        assert_eq!(entry.state, bloom_tx::outbox::OutboxState::Pending);
        assert!(d.audit.mutation_degradation().is_some());
    }

    #[tokio::test]
    async fn wallet_projection_boot_refresh_prewrite_failure_prevents_broker_read() {
        let directory = tempfile::tempdir().unwrap();
        let audit = AuditLog::open(directory.path().join("audit.jsonl")).unwrap();
        let projections = ProjectionRefreshFixture {
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        audit.fail_next_write_for_test();
        assert!(
            refresh_wallet_projections_once(&projections, &audit)
                .await
                .is_err()
        );
        assert_eq!(
            projections.calls.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert!(audit.mutation_degradation().is_some());
    }

    #[tokio::test]
    async fn wallet_projection_boot_refresh_result_loss_latches_on_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).unwrap();
        let projections = ProjectionRefreshFixture {
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        audit.fail_after_writes_for_test(1);
        assert!(
            refresh_wallet_projections_once(&projections, &audit)
                .await
                .is_err()
        );
        assert_eq!(
            projections.calls.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        drop(audit);
        let restarted = AuditLog::open(&path).unwrap();
        assert!(restarted.mutation_degradation().is_some());
        assert_eq!(restarted.pending_effect_correlations().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn cancelled_wallet_projection_refresh_closes_its_audit_correlation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        let audit = Arc::new(AuditLog::open(&path).unwrap());
        let projections = Arc::new(BlockingProjectionRefreshFixture {
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            completed: std::sync::atomic::AtomicBool::new(false),
        });

        let refresh = spawn_wallet_projection_refresh(projections.clone(), audit.clone());
        projections.started.notified().await;
        refresh.abort();
        assert!(refresh.await.unwrap_err().is_cancelled());
        drop(audit);

        let restarted = AuditLog::open(&path).unwrap();
        assert!(
            restarted.pending_effect_correlations().unwrap().is_empty(),
            "cancelling an in-flight refresh must append a terminal audit result"
        );
    }

    #[tokio::test]
    async fn wallet_projection_boot_refresh_timeout_closes_its_audit_correlation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).unwrap();
        let projections = NeverCompletingProjectionRefreshFixture {
            cached_calls: std::sync::atomic::AtomicUsize::new(0),
        };

        assert!(
            refresh_wallet_projections_once_with_timeout(
                &projections,
                &audit,
                Duration::from_millis(10),
            )
            .await
            .is_err()
        );
        drop(audit);

        let restarted = AuditLog::open(&path).unwrap();
        assert!(restarted.pending_effect_correlations().unwrap().is_empty());
    }
}
