//! Owner-only status projection for Machine-orchestrated exact Petal signing.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bloom_machine_client::MachineBrokerClient;
use serde::{Deserialize, Serialize};

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

pub const PETAL_SIGNING_STATE_SCHEMA: &str = "bloom.machine.petal-signing-request.v1";

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PetalSigningRequestProjection {
    pub schema: String,
    pub request_id: String,
    pub package_hash: String,
    pub route_id: String,
    pub wallet: String,
    pub operation_class: String,
    pub payload_digest: String,
    pub approval_id: Option<String>,
    pub status: String,
    pub ceremony_url: Option<String>,
    pub ceremony_expires_at_ms: Option<u64>,
}

#[derive(Clone)]
pub struct PetalSigningRequestsHandler {
    root: PathBuf,
    broker: Option<MachineBrokerClient>,
}

impl PetalSigningRequestsHandler {
    pub fn new(root: PathBuf, broker: Option<MachineBrokerClient>) -> Self {
        Self { root, broker }
    }

    fn record_path(&self, path: &VfsPath) -> Result<PathBuf, HandlerError> {
        let [name] = path.segments() else {
            return Err(HandlerError::NotAFile(path.to_string_path()));
        };
        if name.len() != 69
            || !name.ends_with(".json")
            || !name[..64].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(HandlerError::NotFound(path.to_string_path()));
        }
        Ok(self.root.join(name))
    }

    fn regular_metadata(path: &Path) -> Result<std::fs::Metadata, HandlerError> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => Ok(metadata),
            Ok(_) => Err(HandlerError::NotFound(path.display().to_string())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(HandlerError::NotFound(path.display().to_string()))
            }
            Err(error) => Err(error.into()),
        }
    }

    fn write_projection(
        path: &Path,
        projection: &PetalSigningRequestProjection,
    ) -> Result<(), HandlerError> {
        let bytes = serde_json::to_vec_pretty(projection)
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        let temporary = path.with_extension("json.tmp");
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(temporary, path)?;
        Ok(())
    }

    async fn reconciled(&self, path: &Path) -> Result<PetalSigningRequestProjection, HandlerError> {
        Self::regular_metadata(path)?;
        let mut projection: PetalSigningRequestProjection =
            serde_json::from_slice(&std::fs::read(path)?)
                .map_err(|error| HandlerError::backend(error.to_string()))?;
        if projection.schema != PETAL_SIGNING_STATE_SCHEMA
            || path.file_stem().and_then(|value| value.to_str())
                != Some(projection.request_id.as_str())
        {
            return Err(HandlerError::backend(
                "Petal signing projection identity is invalid",
            ));
        }
        if projection.status == "signed" {
            projection.ceremony_url = None;
            projection.ceremony_expires_at_ms = None;
            return Ok(projection);
        }
        let approval_id = projection
            .approval_id
            .as_ref()
            .ok_or_else(|| HandlerError::backend("pending Petal signing has no approval ID"))?;
        let approval_id = bloom_broker_api::Digest32::new(approval_id.clone())
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        let wallet_id = bloom_broker_api::Token::new(projection.wallet.clone())
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        let status = self
            .broker
            .as_ref()
            .ok_or_else(|| HandlerError::backend("Broker is unavailable"))?
            .approval_status(approval_id.clone())
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        if status.approval_id != approval_id || status.wallet_id != wallet_id {
            return Err(HandlerError::backend(
                "Broker returned a mismatched Petal approval status",
            ));
        }
        match status.state {
            bloom_broker_api::ApprovalLifecycleState::AwaitingCeremony => {
                let ceremony_url = status
                    .ceremony_url
                    .filter(|url| !url.trim().is_empty())
                    .ok_or_else(|| {
                        HandlerError::backend(
                            "Broker omitted the actionable Petal approval ceremony URL",
                        )
                    })?;
                let ceremony_expires_at_ms = status
                    .ceremony_expires_at_ms
                    .map(|value| value.get())
                    .ok_or_else(|| {
                        HandlerError::backend("Broker omitted the Petal approval ceremony expiry")
                    })?;
                if ceremony_expires_at_ms <= now_ms()? {
                    return Err(HandlerError::backend(
                        "Broker returned an expired Petal approval ceremony",
                    ));
                }
                projection.status = "awaiting_owner_approval".into();
                projection.ceremony_url = Some(ceremony_url);
                projection.ceremony_expires_at_ms = Some(ceremony_expires_at_ms);
            }
            bloom_broker_api::ApprovalLifecycleState::Active => {
                projection.status = "approved_retry_required".into();
                projection.ceremony_url = None;
                projection.ceremony_expires_at_ms = None;
            }
            terminal => {
                projection.status = format!("{:?}", terminal).to_ascii_lowercase();
                projection.ceremony_url = None;
                projection.ceremony_expires_at_ms = None;
            }
        }
        Self::write_projection(path, &projection)?;
        Ok(projection)
    }
}

fn now_ms() -> Result<u64, HandlerError> {
    bloom_proto::now_ms().map_err(HandlerError::backend)
}

#[async_trait]
impl Handler for PetalSigningRequestsHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let record = self.record_path(path)?;
        let metadata = Self::regular_metadata(&record)?;
        Ok(
            Entry::read_only_file(path.first().expect("record path has one segment"))
                .with_fs_metadata(&metadata),
        )
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let record = self.record_path(path)?;
        let projection = self.reconciled(&record).await?;
        let mut bytes = serde_json::to_vec_pretty(&projection)
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        if !path.is_root() {
            return Err(HandlerError::NotADir(path.to_string_path()));
        }
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut records = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(path) = VfsPath::parse(&name) else {
                continue;
            };
            if let Ok(record) = self.record_path(&path)
                && let Ok(metadata) = Self::regular_metadata(&record)
            {
                records.push(Entry::read_only_file(&name).with_fs_metadata(&metadata));
            }
        }
        records.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use bloom_broker_api::{
        ApprovalLifecycleState, ApprovalPublicStatus, DecimalU64, Digest32, MachineBrokerRequest,
        MachineBrokerResponse, MachineBrokerService, ProtocolError, ProtocolErrorCode,
        ServiceFuture, Token,
    };

    struct StatusBroker {
        state: Mutex<ApprovalLifecycleState>,
        include_launch_fields: Mutex<bool>,
    }

    impl MachineBrokerService for StatusBroker {
        fn dispatch<'a>(
            &'a self,
            request: MachineBrokerRequest,
        ) -> ServiceFuture<'a, MachineBrokerResponse> {
            Box::pin(async move {
                let MachineBrokerRequest::SealedApprovalStatus(request) = request else {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::UnknownMethod,
                        "unexpected owner projection request",
                    ));
                };
                let state = *self.state.lock().unwrap();
                let include_launch_fields = *self.include_launch_fields.lock().unwrap();
                Ok(MachineBrokerResponse::SealedApprovalStatus(
                    ApprovalPublicStatus {
                        approval_id: request.id,
                        wallet_id: Token::new("wallet").unwrap(),
                        state,
                        effective_claim_assurance: None,
                        ceremony_url: include_launch_fields
                            .then(|| "http://localhost:18734/ceremony/owner-secret".into()),
                        ceremony_expires_at_ms: include_launch_fields
                            .then(|| DecimalU64::new(u64::MAX)),
                    },
                ))
            })
        }
    }

    fn projection(request_id: &str, approval_id: &Digest32) -> PetalSigningRequestProjection {
        PetalSigningRequestProjection {
            schema: PETAL_SIGNING_STATE_SCHEMA.into(),
            request_id: request_id.into(),
            package_hash: "11".repeat(32),
            route_id: "orders/place".into(),
            wallet: "wallet".into(),
            operation_class: "order.place".into(),
            payload_digest: "22".repeat(32),
            approval_id: Some(approval_id.as_str().into()),
            status: "awaiting_owner_approval".into(),
            ceremony_url: None,
            ceremony_expires_at_ms: None,
        }
    }

    #[tokio::test]
    async fn owner_sees_actionable_launch_then_activation_durably_clears_it() {
        let temporary = tempfile::tempdir().unwrap();
        let request_id = "ab".repeat(32);
        let approval_id = Digest32::from_bytes([3; 32]);
        let path = temporary.path().join(format!("{request_id}.json"));
        PetalSigningRequestsHandler::write_projection(
            &path,
            &projection(&request_id, &approval_id),
        )
        .unwrap();
        let broker = Arc::new(StatusBroker {
            state: Mutex::new(ApprovalLifecycleState::AwaitingCeremony),
            include_launch_fields: Mutex::new(true),
        });
        let handler = PetalSigningRequestsHandler::new(
            temporary.path().to_path_buf(),
            Some(MachineBrokerClient::new(broker.clone())),
        );
        let record_name = format!("{request_id}.json");
        let vfs_path = VfsPath::parse(&record_name).unwrap();

        let awaiting: PetalSigningRequestProjection =
            serde_json::from_slice(&handler.read(&vfs_path).await.unwrap()).unwrap();
        assert_eq!(awaiting.status, "awaiting_owner_approval");
        assert_eq!(
            awaiting.ceremony_url.as_deref(),
            Some("http://localhost:18734/ceremony/owner-secret")
        );

        *broker.state.lock().unwrap() = ApprovalLifecycleState::Active;
        *broker.include_launch_fields.lock().unwrap() = false;
        let active: PetalSigningRequestProjection =
            serde_json::from_slice(&handler.read(&vfs_path).await.unwrap()).unwrap();
        assert_eq!(active.status, "approved_retry_required");
        assert!(active.ceremony_url.is_none());
        assert!(active.ceremony_expires_at_ms.is_none());
        assert!(
            !String::from_utf8(std::fs::read(path).unwrap())
                .unwrap()
                .contains("owner-secret"),
            "activation must durably remove the launch token"
        );
    }

    #[tokio::test]
    async fn awaiting_projection_without_actionable_launch_fields_fails_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let request_id = "cd".repeat(32);
        let approval_id = Digest32::from_bytes([4; 32]);
        let path = temporary.path().join(format!("{request_id}.json"));
        PetalSigningRequestsHandler::write_projection(
            &path,
            &projection(&request_id, &approval_id),
        )
        .unwrap();
        let broker = Arc::new(StatusBroker {
            state: Mutex::new(ApprovalLifecycleState::AwaitingCeremony),
            include_launch_fields: Mutex::new(false),
        });
        let handler = PetalSigningRequestsHandler::new(
            temporary.path().to_path_buf(),
            Some(MachineBrokerClient::new(broker)),
        );
        let record_name = format!("{request_id}.json");
        let error = handler
            .read(&VfsPath::parse(&record_name).unwrap())
            .await
            .unwrap_err();
        assert!(
            matches!(error, HandlerError::Backend(message) if message.contains("ceremony URL"))
        );
    }
}
