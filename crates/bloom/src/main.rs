//! `bloom` — key-free Bloom Machine CLI and runtime.
//!
//! Machine owns reads, staging, simulation, broadcast, and public projections.
//! Every production custody, approval, and signing operation crosses its
//! authenticated Broker edge; Signer alone owns wallet key material.

#![forbid(unsafe_code)]

mod commands {
    pub mod qr;
}
mod github_source;
mod pf_monitor;
mod session_sentinel;
mod triad_enrollment;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::time::{SystemTime, UNIX_EPOCH};

static UPDATE_EXIT_CODE: AtomicI32 = AtomicI32::new(0);

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bloom_daemon::Daemon;
use bloom_daemon::ipc::{
    IpcCallResult, IpcClient, IpcClientError, IpcOutputEvent, IpcOutputStream, IpcProtocolRange,
    IpcServer, MachineCeremonyAction, MachineCommand, MachineCommandFuture, MachineCommandOutput,
    MachineCommandService, MachineCustodyKind, MachineError, MachineErrorKind,
    MachineOperationAction, default_socket_path,
};
use bloom_machine_client::MachineJournalHeadProvider;
use bloom_proto::{AuditIdentity, AuditLog, HomeDir, HomeWritePermit};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};
use tracing::{debug, info, trace};
use tracing_subscriber::EnvFilter;

#[cfg(target_os = "linux")]
const DEFAULT_MOUNT_PATH: &str = "/bloom";
#[cfg(target_os = "macos")]
const DEFAULT_MOUNT_PATH: &str = "/Volumes/bloom";
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const DEFAULT_MOUNT_PATH: &str = "/bloom";

const ALPHA_DISCLOSURE: &str = "⚠️  Bloom is experimental, unaudited alpha software. Do not use with funds you cannot afford to lose. Review every generated transaction plan before signing.";
#[derive(Debug, Clone)]
struct ResolvedEndpoint {
    socket: PathBuf,
    display: String,
}

impl ResolvedEndpoint {
    fn default_for_home(home: &HomeDir) -> Self {
        let socket = default_socket_path(home.root());
        Self {
            display: format!("unix:{}", socket.display()),
            socket,
        }
    }

    fn explicit(raw: &str) -> Result<Self> {
        let path = parse_unix_endpoint(raw)?;
        Ok(Self {
            display: format!("unix:{}", path.display()),
            socket: path,
        })
    }

    fn explicit_socket(path: PathBuf) -> Self {
        Self {
            display: format!("unix:{}", path.display()),
            socket: path,
        }
    }
}

fn parse_unix_endpoint(raw: &str) -> Result<PathBuf> {
    if let Some(rest) = raw.strip_prefix("unix:") {
        if rest.is_empty() {
            anyhow::bail!("empty unix endpoint path");
        }
        Ok(PathBuf::from(rest))
    } else if raw.starts_with("tcp:") || raw.starts_with("fd:") || raw == "stdio" {
        anyhow::bail!("unsupported Bloom endpoint '{raw}' (only unix:/path is implemented)");
    } else {
        Ok(PathBuf::from(raw))
    }
}

fn resolve_client_endpoint(
    home: &HomeDir,
    connect: Option<&str>,
    ipc_socket: Option<&Path>,
) -> Result<ResolvedEndpoint> {
    if let Some(raw) = connect {
        return ResolvedEndpoint::explicit(raw);
    }
    if let Some(path) = ipc_socket {
        return Ok(ResolvedEndpoint::explicit_socket(path.to_path_buf()));
    }
    Ok(ResolvedEndpoint::default_for_home(home))
}

fn resolve_server_endpoint(home: &HomeDir, endpoint: Option<&str>) -> Result<ResolvedEndpoint> {
    if let Some(raw) = endpoint {
        return ResolvedEndpoint::explicit(raw);
    }
    Ok(ResolvedEndpoint::default_for_home(home))
}

fn configured_broker_client(home: &HomeDir) -> Result<bloom_machine_client::MachineBrokerClient> {
    configured_broker_client_with_activation(home, false)
}

fn validate_wallet_name(name: &str) -> Result<()> {
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name.chars().all(
                |character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            ),
        "wallet name must be 1-64 ASCII alphanumeric, '-' or '_' characters"
    );
    Ok(())
}

fn configured_broker_client_with_activation(
    home: &HomeDir,
    allow_activating: bool,
) -> Result<bloom_machine_client::MachineBrokerClient> {
    let client = configured_raw_broker_client_with_activation(allow_activating)?;
    let identity = client
        .local_application_identity()
        .context("authenticated Machine client did not retain its application identity")?;
    let audit = Arc::new(open_configured_machine_audit_with_activation(
        home,
        identity,
        allow_activating,
    )?);
    let checkpoint_root = configured_machine_checkpoint_path_with_activation(allow_activating)?;
    #[cfg(feature = "triad-dev-harness")]
    let history_owner = if std::env::var_os("BLOOM_TRIAD_DEVELOPER_ROOT").is_some() {
        rustix::process::geteuid().as_raw()
    } else {
        0
    };
    #[cfg(not(feature = "triad-dev-harness"))]
    let history_owner = 0;
    let authority_history = bloom_machine_client::AuthorityEdgeHistory::load_trusted(
        configured_authority_edge_history_path_with_activation(allow_activating)?,
        history_owner,
    )
    .map_err(anyhow::Error::new)
    .context("load packaging-owned authority-edge application-key history")?;
    client
        .attach_authority_journal_with_history(
            Arc::new(ConfiguredMachineAuditHead(audit)),
            checkpoint_root,
            rustix::process::geteuid().as_raw(),
            authority_history,
        )
        .map_err(anyhow::Error::new)
        .context("attach signed Machine authority-edge journal")?;
    Ok(client)
}

fn configured_raw_broker_client_with_activation(
    allow_activating: bool,
) -> Result<bloom_machine_client::MachineBrokerClient> {
    let installed = installed_macos_triad_paths_with_activation(allow_activating)?;
    let broker_socket = std::env::var_os("BLOOM_BROKER_SOCKET")
        .map(std::path::PathBuf::from)
        .or_else(|| installed.as_ref().map(|paths| paths.broker_socket.clone()))
        .unwrap_or_else(|| std::path::PathBuf::from("/var/run/bloom/broker.sock"));
    let machine_identity = std::env::var_os("BLOOM_MACHINE_IDENTITY")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            installed
                .as_ref()
                .map(|paths| paths.machine_identity.clone())
        })
        .unwrap_or_else(|| std::path::PathBuf::from("/var/run/bloom/machine-identity.json"));
    let edge_manifest = std::env::var_os("BLOOM_EDGE_MANIFEST")
        .map(std::path::PathBuf::from)
        .or_else(|| installed.as_ref().map(|paths| paths.edge_manifest.clone()))
        .unwrap_or_else(|| std::path::PathBuf::from("/etc/bloom/edge-manifest.json"));
    #[cfg(feature = "triad-dev-harness")]
    let client = match std::env::var_os("BLOOM_TRIAD_DEVELOPER_ROOT") {
        Some(root) => bloom_machine_client::MachineBrokerClient::connect_unix_from_developer_files(
            root,
            broker_socket.clone(),
            machine_identity.clone(),
            edge_manifest.clone(),
        ),
        None => bloom_machine_client::MachineBrokerClient::connect_unix_from_files(
            broker_socket.clone(),
            machine_identity.clone(),
            edge_manifest.clone(),
        ),
    };
    #[cfg(not(feature = "triad-dev-harness"))]
    let client = bloom_machine_client::MachineBrokerClient::connect_unix_from_files(
        broker_socket,
        machine_identity,
        edge_manifest,
    );
    client.context("load authenticated Machine-to-Broker edge")
}

async fn installed_triad_health_check(expected_build: &str) -> Result<()> {
    use bloom_broker_api::{
        Digest32, Empty, MachineBrokerRequest, MachineBrokerResponse, ReadinessState,
    };

    let expected_build =
        Digest32::new(expected_build.to_owned()).context("parse expected release digest")?;
    let installed = installed_macos_triad_paths_with_activation(true)
        .ok()
        .flatten();
    let home = HomeDir::resolve("~/.bloom").context("resolve Machine home for health check")?;
    let client = configured_broker_client_with_activation(&home, true)
        .map_err(|error| enrich_broker_startup_failure(error, installed.as_ref()))?;
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.request(MachineBrokerRequest::BrokerReadiness(Empty {})),
    )
    .await
    .context("authenticated Broker readiness timed out")
    .map_err(|error| enrich_broker_startup_failure(error, installed.as_ref()))?
    .context("request authenticated Broker readiness")
    .map_err(|error| enrich_broker_startup_failure(error, installed.as_ref()))?;
    let readiness = match response {
        MachineBrokerResponse::BrokerReadiness(readiness) => readiness,
        _ => bail!("Broker returned the wrong response to broker.readiness"),
    };
    if readiness.service_id.as_str() != "bloom-broker"
        || readiness.build_digest != expected_build
        || readiness.state != ReadinessState::Ready
    {
        bail!(
            "Broker/Signer triad is not ready on the exact installed build: service_id={}, observed_build={}, expected_build={}, state={:?}, conditions={}",
            readiness.service_id,
            readiness.build_digest,
            expected_build,
            readiness.state,
            serde_json::to_string(&readiness.conditions)
                .unwrap_or_else(|_| "[\"unreportable\"]".into())
        );
    }
    Ok(())
}

fn configured_broker_connection(
    _home: &HomeDir,
) -> Result<(
    bloom_machine_client::MachineBrokerClient,
    bloom_broker_api::ProvenanceCatalog,
)> {
    // Daemon construction attaches this raw authenticated client to the exact
    // AuditLog instance it owns before any RPC can be dispatched.
    let broker = configured_raw_broker_client_with_activation(false)?;
    let installed = installed_macos_triad_paths()?;
    let provenance_catalog = std::env::var_os("BLOOM_PROVENANCE_CATALOG")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            installed
                .as_ref()
                .map(|paths| paths.provenance_catalog.clone())
        })
        .unwrap_or_else(|| std::path::PathBuf::from("/etc/bloom/provenance-catalog.json"));
    #[cfg(feature = "triad-dev-harness")]
    let catalog = match std::env::var_os("BLOOM_TRIAD_DEVELOPER_ROOT") {
        Some(root) => {
            bloom_machine_client::load_developer_provenance_catalog(root, &provenance_catalog)
        }
        None => bloom_machine_client::load_provenance_catalog(&provenance_catalog),
    }
    .context("load installer-owned provenance catalog")?;
    #[cfg(not(feature = "triad-dev-harness"))]
    let catalog = bloom_machine_client::load_provenance_catalog(provenance_catalog)
        .context("load installer-owned provenance catalog")?;
    Ok((broker, catalog))
}

#[derive(Clone)]
struct InstalledMacosTriadPaths {
    broker_socket: PathBuf,
    machine_identity: PathBuf,
    edge_manifest: PathBuf,
    provenance_catalog: PathBuf,
    machine_audit_history: PathBuf,
    authority_edge_history: PathBuf,
    startup_status: PathBuf,
    broker_uid: u32,
    machine_broker_gid: u32,
}

fn installed_macos_triad_paths() -> Result<Option<InstalledMacosTriadPaths>> {
    installed_macos_triad_paths_with_activation(false)
}

#[cfg(any(target_os = "macos", test))]
fn enrollment_state_is_usable(state: &str, allow_activating: bool) -> bool {
    state == "active" || (allow_activating && state == "activating")
}

fn installed_macos_triad_paths_with_activation(
    allow_activating: bool,
) -> Result<Option<InstalledMacosTriadPaths>> {
    #[cfg(not(target_os = "macos"))]
    let _ = allow_activating;

    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt as _;

        let uid = rustix::process::geteuid().as_raw();
        let enrollment = PathBuf::from(format!(
            "/Library/Application Support/BloomTriad/enrollments/{uid}.json"
        ));
        let metadata = match std::fs::symlink_metadata(&enrollment) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("inspect installed Bloom enrollment"),
        };
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() != 1
        {
            bail!("installed Bloom enrollment has unsafe ownership or type");
        }
        let enrollment_value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&enrollment)?)
                .context("decode installed Bloom enrollment")?;
        if enrollment_value
            .get("schema")
            .and_then(serde_json::Value::as_str)
            != Some("bloom.macos-enrollment.1")
            || enrollment_value
                .get("login_uid")
                .and_then(serde_json::Value::as_u64)
                != Some(u64::from(uid))
        {
            bail!("installed Bloom enrollment identity does not match this login");
        }
        let state = enrollment_value
            .get("state")
            .and_then(serde_json::Value::as_str)
            .context("installed Bloom enrollment has no state")?;
        if !enrollment_state_is_usable(state, allow_activating) {
            bail!("installed Bloom enrollment is not active");
        }
        let broker_uid = u32::try_from(
            enrollment_value
                .get("broker_uid")
                .and_then(serde_json::Value::as_u64)
                .context("installed Bloom enrollment has no Broker UID")?,
        )
        .context("installed Bloom Broker UID is outside the platform range")?;
        let machine_broker_gid = u32::try_from(
            enrollment_value
                .get("machine_broker_gid")
                .and_then(serde_json::Value::as_u64)
                .context("installed Bloom enrollment has no Machine-Broker GID")?,
        )
        .context("installed Bloom Machine-Broker GID is outside the platform range")?;
        let config = PathBuf::from(format!(
            "/Library/Application Support/BloomTriad/config/{uid}"
        ));
        Ok(Some(InstalledMacosTriadPaths {
            broker_socket: PathBuf::from(format!(
                "/private/var/run/bloom/{uid}/machine-broker/broker.sock"
            )),
            machine_identity: config.join("machine/identity.json"),
            edge_manifest: config.join("edge-manifest.json"),
            provenance_catalog: config.join("provenance-catalog.json"),
            machine_audit_history: config.join("machine-audit-history.json"),
            authority_edge_history: config.join("authority-edge-history.json"),
            startup_status: PathBuf::from(format!(
                "/private/var/run/bloom/{uid}/status/broker-startup.json"
            )),
            broker_uid,
            machine_broker_gid,
        }))
    }
    #[cfg(not(target_os = "macos"))]
    Ok(None)
}

fn enrich_broker_startup_failure(
    error: anyhow::Error,
    installed: Option<&InstalledMacosTriadPaths>,
) -> anyhow::Error {
    let Some(diagnostic) = installed.and_then(read_broker_startup_failure) else {
        return error;
    };
    anyhow::anyhow!("{diagnostic}; authenticated Broker readiness failed: {error:#}")
}

fn read_broker_startup_failure(paths: &InstalledMacosTriadPaths) -> Option<String> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::symlink_metadata(&paths.startup_status).ok()?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != paths.broker_uid
        || metadata.gid() != paths.machine_broker_gid
        || metadata.mode() & 0o777 != 0o640
        || metadata.nlink() != 1
        || metadata.len() > 1024
    {
        return None;
    }
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&paths.startup_status).ok()?).ok()?;
    if value.as_object().map(serde_json::Map::len) != Some(6)
        || value.get("schema").and_then(serde_json::Value::as_str) != Some("bloom.broker-startup.1")
        || value.get("state").and_then(serde_json::Value::as_str) != Some("fatal")
        || value.get("address").and_then(serde_json::Value::as_str) != Some("127.0.0.1:18734")
        || value
            .get("observed_at_ms")
            .and_then(serde_json::Value::as_u64)
            .is_none()
    {
        return None;
    }
    let incident = value.get("incident").and_then(serde_json::Value::as_str)?;
    let expected_message = match incident {
        "another_login_session" => "another login session owns the Bloom ceremony listener",
        "foreign_or_unverifiable_process" => {
            "a foreign or unverifiable process owns the Bloom ceremony listener"
        }
        _ => return None,
    };
    if value.get("message").and_then(serde_json::Value::as_str) != Some(expected_message) {
        return None;
    }
    Some(format!("Bloom Broker startup failed: {expected_message}"))
}

#[cfg(test)]
mod broker_startup_failure_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    fn installed_paths(startup_status: PathBuf) -> InstalledMacosTriadPaths {
        let metadata = std::fs::symlink_metadata(
            startup_status
                .parent()
                .expect("startup status has a parent"),
        )
        .expect("status parent metadata");
        InstalledMacosTriadPaths {
            broker_socket: PathBuf::new(),
            machine_identity: PathBuf::new(),
            edge_manifest: PathBuf::new(),
            provenance_catalog: PathBuf::new(),
            machine_audit_history: PathBuf::new(),
            authority_edge_history: PathBuf::new(),
            startup_status,
            broker_uid: metadata.uid(),
            machine_broker_gid: metadata.gid(),
        }
    }

    #[test]
    fn machine_reports_only_an_exact_authenticated_startup_diagnostic() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("broker-startup.json");
        std::fs::write(
            &path,
            br#"{"schema":"bloom.broker-startup.1","state":"fatal","incident":"another_login_session","address":"127.0.0.1:18734","message":"another login session owns the Bloom ceremony listener","observed_at_ms":1}"#,
        )
        .expect("write startup diagnostic");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("set startup diagnostic permissions");
        let installed = installed_paths(path.clone());

        assert_eq!(
            read_broker_startup_failure(&installed).as_deref(),
            Some(
                "Bloom Broker startup failed: another login session owns the Bloom ceremony listener"
            )
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("weaken startup diagnostic permissions");
        assert!(read_broker_startup_failure(&installed).is_none());
    }
}

fn build_write_daemon(home: HomeDir) -> Result<(Arc<HomeWritePermit>, Daemon)> {
    let permit = Arc::new(HomeWritePermit::acquire(&home)?);
    // Loading the authenticated edge is local and does not connect to Broker.
    // Production Machine must retain that application identity even while the
    // Broker process is down so its own audit journal never falls back to an
    // unsigned/best-effort mode.
    let daemon = match configured_broker_connection(&home) {
        Ok((broker, catalog)) => {
            Daemon::from_home_with_permit_and_broker(home, permit.clone(), broker, catalog)
                .context("build daemon")?
        }
        Err(error) => {
            #[cfg(debug_assertions)]
            {
                debug!(error = %error, "authenticated Broker edge absent; using key-free debug Machine composition");
                Daemon::from_home_with_permit_without_broker_for_debug(home, permit.clone())
                    .context("build key-free debug daemon")?
            }
            #[cfg(not(debug_assertions))]
            {
                return Err(error).context("load authenticated Machine identity and Broker edge");
            }
        }
    };
    Ok((permit, daemon))
}

fn machine_audit_status(audit: &AuditLog) -> serde_json::Value {
    let (pending, pending_read_error) = match audit.pending_effect_correlations() {
        Ok(pending) => (pending, None),
        Err(error) => (Vec::new(), Some(error.to_string())),
    };
    let degradation = audit
        .mutation_degradation()
        .or_else(|| pending_read_error.clone());
    let first_pending = pending.first().cloned();
    serde_json::json!({
        "service_id": "bloom-machine",
        "sequence": audit.sequence(),
        "head": audit.head_hash(),
        "mutation_degradation": degradation,
        "pending_effect_correlation": first_pending,
        "pending_effect_correlations": pending,
        "pending_effect_read_error": pending_read_error,
        "required_confirmation": first_pending.as_ref().map(|correlation| {
            serde_json::json!({
                "committed": format!("RECONCILE MACHINE AUDIT {correlation} AS COMMITTED"),
                "aborted": format!("RECONCILE MACHINE AUDIT {correlation} AS ABORTED"),
            })
        }),
    })
}

fn machine_audit_status_output(audit: &AuditLog) -> Result<String> {
    Ok(serde_json::to_string_pretty(&machine_audit_status(audit))?)
}

fn execute_audit_command(command: &AuditCmd, audit: &AuditLog) -> Result<String> {
    match command {
        AuditCmd::Status => machine_audit_status_output(audit),
        AuditCmd::Reconcile {
            correlation_id,
            outcome,
            confirm,
        } => Ok(serde_json::to_string_pretty(
            &audit.reconcile_pending_effect(correlation_id, outcome, confirm)?,
        )?),
    }
}

fn open_configured_machine_audit_with_activation(
    home: &HomeDir,
    identity: bloom_triad_local_transport::LocalIdentity,
    allow_activating: bool,
) -> Result<AuditLog> {
    let history_path = configured_machine_audit_history_path_with_activation(allow_activating)?;
    open_machine_audit_with_history(home, identity, &history_path)
}

fn open_machine_audit_with_history(
    home: &HomeDir,
    identity: bloom_triad_local_transport::LocalIdentity,
    history_path: &Path,
) -> Result<AuditLog> {
    let (history, history_error) = match AuditLog::load_root_trusted_history(history_path) {
        Ok(history) => (history, None),
        Err(error) => (
            Vec::new(),
            Some(format!(
                "packaging-pinned Machine audit history is invalid: {error}"
            )),
        ),
    };
    let audit = AuditLog::open_signed_with_history(
        home.audit_path(),
        AuditIdentity::new(
            identity.service_id.as_str(),
            identity.application_key_id.as_str(),
            identity.signing_key,
        ),
        &history,
    )
    .context("open signed Machine audit journal")?;
    if let Some(reason) = history_error {
        audit.latch_mutations(reason);
    }
    Ok(audit)
}

struct ConfiguredMachineAuditHead(Arc<AuditLog>);

impl MachineJournalHeadProvider for ConfiguredMachineAuditHead {
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

fn configured_machine_checkpoint_path_with_activation(allow_activating: bool) -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("BLOOM_MACHINE_AUDIT_CHECKPOINT_DIR") {
        return Ok(PathBuf::from(path));
    }
    let uid = rustix::process::geteuid().as_raw();
    if installed_macos_triad_paths_with_activation(allow_activating)?.is_some() {
        return Ok(PathBuf::from(format!(
            "/private/var/db/bloom/{uid}/machine/audit-checkpoints"
        )));
    }
    Ok(PathBuf::from(format!(
        "/var/lib/bloom/{uid}/machine/audit-checkpoints"
    )))
}

fn configured_authority_edge_history_path_with_activation(
    allow_activating: bool,
) -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("BLOOM_AUTHORITY_EDGE_HISTORY") {
        return Ok(PathBuf::from(path));
    }
    if let Some(installed) = installed_macos_triad_paths_with_activation(allow_activating)? {
        return Ok(installed.authority_edge_history);
    }
    let uid = rustix::process::geteuid().as_raw();
    Ok(PathBuf::from(format!(
        "/etc/bloom/{uid}/authority-edge-history.json"
    )))
}

fn configured_machine_audit_history_path_with_activation(
    allow_activating: bool,
) -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("BLOOM_MACHINE_AUDIT_HISTORY") {
        return Ok(PathBuf::from(path));
    }
    if let Some(installed) = installed_macos_triad_paths_with_activation(allow_activating)? {
        return Ok(installed.machine_audit_history);
    }
    #[cfg(unix)]
    let uid = rustix::process::geteuid().as_raw();
    #[cfg(not(unix))]
    let uid = 0_u32;
    Ok(PathBuf::from(format!(
        "/etc/bloom/{uid}/machine-audit-history.json"
    )))
}

async fn launch_custody_ceremony(
    home: &HomeDir,
    requested_name: &str,
    method: bloom_machine_client::CustodyPrepareMethod,
    ceremony_kind: bloom_broker_api::CeremonyKind,
    wallet_id: Option<bloom_broker_api::Token>,
    expected_input_class: &str,
    legacy_migration: Option<LegacyMigrationLaunch>,
) -> Result<String> {
    use rand::RngCore as _;
    use sha2::Digest as _;

    validate_wallet_name(requested_name).map_err(|error| {
        machine_error(
            MachineErrorKind::InvalidParams,
            format!("requested wallet name must be a safe single path segment: {error:#}"),
        )
    })?;
    let requested_wallet_id =
        bloom_broker_api::Token::new(requested_name.to_owned()).map_err(|error| {
            machine_error(
                MachineErrorKind::InvalidParams,
                format!("requested wallet name must be a protocol token: {error}"),
            )
        })?;
    let client = configured_broker_client(home).map_err(|error| {
        machine_error(
            MachineErrorKind::Unavailable,
            format!("custody requires the authenticated Machine-to-Broker edge: {error:#}"),
        )
    })?;
    let (operation_id, exact_terms_digest, legacy_passkey_migration) =
        if let Some(migration) = legacy_migration {
            (
                migration.operation_id,
                migration.exact_terms_digest,
                Some(migration.public_terms),
            )
        } else {
            let mut operation_bytes = [0_u8; 32];
            rand::thread_rng().fill_bytes(&mut operation_bytes);
            let operation_id = bloom_broker_api::OperationId::from_bytes(operation_bytes);
            let effective_wallet_id = wallet_id
                .clone()
                .unwrap_or_else(|| requested_wallet_id.clone());
            let reviewed_terms = serde_jcs::to_vec(&serde_json::json!({
                "ceremony_kind": ceremony_kind,
                "wallet_id": effective_wallet_id,
            }))
            .context("canonicalize custody launch terms")?;
            (
                operation_id,
                bloom_broker_api::Digest32::from_bytes(sha2::Sha256::digest(reviewed_terms).into()),
                None,
            )
        };
    let response = client
        .prepare_custody(
            method,
            bloom_broker_api::CustodyPrepareRequest {
                ceremony_kind,
                custody_operation_id: operation_id,
                wallet_id: legacy_passkey_migration
                    .is_none()
                    .then_some(requested_wallet_id)
                    .or(wallet_id),
                key_ref: None,
                exact_terms_digest,
                expected_input_class: bloom_broker_api::Token::new(expected_input_class)
                    .context("custody input class")?,
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration,
            },
        )
        .await
        .map_err(anyhow::Error::new)
        .context("prepare Broker custody ceremony")?;
    let projection = bloom_machine_client::CeremonyProjection::from_custody_prepare(
        &response,
        current_unix_ms(),
    )
    .map_err(anyhow::Error::new)
    .context("construct Machine custody projection")?;
    let projection_path = persist_ceremony_projection(home, &projection)?;
    Ok(format!(
        "operation_id: {}\nceremony_kind: {:?}\nceremony_url: {}\nceremony_expires_at_ms: {}\nprojection: {}\n",
        response.custody_operation_id,
        response.ceremony_kind,
        response.ceremony_url,
        response.ceremony_expires_at_ms.get(),
        projection_path.display(),
    ))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletRegistrationLaunchProjection {
    schema: String,
    requested_name: String,
    operation_id: bloom_broker_api::OperationId,
    ceremony_kind: bloom_broker_api::CeremonyKind,
    ceremony_state: bloom_broker_api::CeremonyState,
    ceremony_url: Option<String>,
    ceremony_expires_at_ms: Option<bloom_broker_api::DecimalU64>,
    signer_contribution_digest: bloom_broker_api::Digest32,
}

async fn launch_wallet_registration_via_vfs(
    vfs: &bloom_vfs::Vfs,
    requested_name: &str,
) -> Result<String> {
    validate_wallet_name(requested_name).map_err(|error| {
        machine_error(
            MachineErrorKind::InvalidParams,
            format!("requested wallet name must be a safe single path segment: {error:#}"),
        )
    })?;
    let write_path = bloom_vfs::VfsPath::parse("/wallets/new")?;
    bloom_vfs::Handler::write(vfs, &write_path, requested_name.as_bytes()).await?;

    let projection_path = format!("/wallets/registrations/{requested_name}/status.json");
    let projection_path_parsed = bloom_vfs::VfsPath::parse(&projection_path)?;
    let projection: WalletRegistrationLaunchProjection =
        serde_json::from_slice(&bloom_vfs::Handler::read(vfs, &projection_path_parsed).await?)
            .context("decode mounted wallet registration projection")?;
    let _ = &projection.signer_contribution_digest;
    if projection.schema != "bloom.machine-wallet-registration-projection.1"
        || projection.requested_name != requested_name
        || projection.ceremony_kind != bloom_broker_api::CeremonyKind::WalletRegistration
        || projection.ceremony_state != bloom_broker_api::CeremonyState::AwaitingUser
    {
        return Err(machine_error(
            MachineErrorKind::Internal,
            "mounted wallet registration returned a mismatched or non-actionable projection",
        )
        .into());
    }
    let ceremony_url = projection.ceremony_url.ok_or_else(|| {
        machine_error(
            MachineErrorKind::Internal,
            "mounted wallet registration omitted its ceremony URL",
        )
    })?;
    let ceremony_expires_at_ms = projection.ceremony_expires_at_ms.ok_or_else(|| {
        machine_error(
            MachineErrorKind::Internal,
            "mounted wallet registration omitted its ceremony expiry",
        )
    })?;
    Ok(format!(
        "operation_id: {}\nceremony_kind: {:?}\nceremony_url: {}\nceremony_expires_at_ms: {}\nprojection: {}\n",
        projection.operation_id,
        projection.ceremony_kind,
        ceremony_url,
        ceremony_expires_at_ms.get(),
        projection_path,
    ))
}

struct LegacyMigrationLaunch {
    operation_id: bloom_broker_api::OperationId,
    exact_terms_digest: bloom_broker_api::Digest32,
    public_terms: bloom_broker_api::LegacyPasskeyMigrationPublic,
}

#[derive(Clone)]
struct DaemonMachineCommands {
    home: HomeDir,
    daemon: Daemon,
}

impl MachineCommandService for DaemonMachineCommands {
    fn execute(&self, command: MachineCommand) -> MachineCommandFuture<'_> {
        Box::pin(async move {
            execute_machine_command(&self.home, &self.daemon, command)
                .await
                .map_err(machine_error_from_anyhow)
        })
    }
}

fn machine_error_from_anyhow(error: anyhow::Error) -> MachineError {
    let message = format!("{error:#}");
    for cause in error.chain() {
        if let Some(error) = cause.downcast_ref::<MachineError>() {
            return MachineError::new(error.kind, error.code.clone(), message);
        }
        if let Some(error) = cause.downcast_ref::<bloom_broker_api::ProtocolError>() {
            return machine_error_from_protocol(error, message);
        }
        if let Some(error) = cause.downcast_ref::<bloom_vfs::HandlerError>() {
            return machine_error_from_handler(error, message);
        }
        if cause.downcast_ref::<bloom_vfs::path::PathError>().is_some() {
            return machine_error(MachineErrorKind::InvalidParams, message);
        }
        if let Some(error) = cause.downcast_ref::<std::io::Error>() {
            return machine_error_from_io(error, message);
        }
    }
    machine_error(MachineErrorKind::Internal, message)
}

fn machine_error_from_protocol(
    error: &bloom_broker_api::ProtocolError,
    message: String,
) -> MachineError {
    use bloom_broker_api::ProtocolErrorCode as Code;
    let kind = match error.code {
        Code::MalformedFrame
        | Code::LimitExceededFrame
        | Code::UnknownField
        | Code::UnknownMethod
        | Code::UnsupportedVersion
        | Code::BackendInvalidRequest => MachineErrorKind::InvalidParams,
        Code::ApprovalNotFound => MachineErrorKind::NotFound,
        Code::OperationIdConflict | Code::PolicyBaselineStale | Code::CeremonyReplay => {
            MachineErrorKind::Conflict
        }
        Code::ServiceUnavailable
        | Code::AssuranceUnavailable
        | Code::ClockUntrusted
        | Code::ClockRollback
        | Code::BackendUnsupported => MachineErrorKind::Unavailable,
        Code::AmbiguousProviderEffect => MachineErrorKind::Internal,
        Code::UnauthenticatedPeer
        | Code::ApprovalExpired
        | Code::ApprovalRevoked
        | Code::ApprovalRearmRequired
        | Code::RevocationEpochUnreconciled
        | Code::SelectorMismatch
        | Code::SuiteNotAllowed
        | Code::KeyrefMismatch
        | Code::LimitExceededOperations
        | Code::LimitExceededSignatures
        | Code::LimitExceededValue
        | Code::LimitExceededRate
        | Code::SignerRateBackstopDenied
        | Code::ClaimInvalid
        | Code::ProvenanceMismatch
        | Code::CeremonyRateLimited
        | Code::CeremonyKindMismatch
        | Code::QuotaExceeded => MachineErrorKind::PermissionDenied,
    };
    machine_error(kind, message)
}

fn machine_wallet_lookup_error(error: bloom_broker_api::ProtocolError) -> MachineError {
    use bloom_broker_api::ProtocolErrorCode as Code;
    let message = error.to_string();
    match error.code {
        // The projection reader currently uses BackendInvalidRequest for a
        // well-formed wallet identifier absent from the authoritative list.
        // At this operation boundary that is a missing resource, not malformed
        // command input.
        Code::BackendInvalidRequest => machine_error(MachineErrorKind::NotFound, message),
        _ => machine_error_from_protocol(&error, message),
    }
}

fn machine_error_from_handler(error: &bloom_vfs::HandlerError, message: String) -> MachineError {
    let kind = match error {
        bloom_vfs::HandlerError::NotFound(_) => MachineErrorKind::NotFound,
        bloom_vfs::HandlerError::PermissionDenied
        | bloom_vfs::HandlerError::OperationNotPermitted => MachineErrorKind::PermissionDenied,
        bloom_vfs::HandlerError::Invalid(_)
        | bloom_vfs::HandlerError::NotADir(_)
        | bloom_vfs::HandlerError::NotAFile(_)
        | bloom_vfs::HandlerError::Unsupported(_) => MachineErrorKind::InvalidParams,
        bloom_vfs::HandlerError::Backend(_) => MachineErrorKind::Internal,
        bloom_vfs::HandlerError::Io(error) => return machine_error_from_io(error, message),
    };
    machine_error(kind, message)
}

fn machine_error_from_io(error: &std::io::Error, message: String) -> MachineError {
    let kind = match error.kind() {
        std::io::ErrorKind::NotFound => MachineErrorKind::NotFound,
        std::io::ErrorKind::PermissionDenied => MachineErrorKind::PermissionDenied,
        std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::WouldBlock => {
            MachineErrorKind::Conflict
        }
        std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::NotConnected
        | std::io::ErrorKind::TimedOut
        | std::io::ErrorKind::BrokenPipe => MachineErrorKind::Unavailable,
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => {
            MachineErrorKind::InvalidParams
        }
        _ => MachineErrorKind::Internal,
    };
    machine_error(kind, message)
}

fn machine_error(kind: MachineErrorKind, message: impl Into<String>) -> MachineError {
    let code = match kind {
        MachineErrorKind::InvalidParams => "INVALID_ARGUMENT",
        MachineErrorKind::PermissionDenied => "PERMISSION_DENIED",
        MachineErrorKind::Unavailable => "UNAVAILABLE",
        MachineErrorKind::Conflict => "CONFLICT",
        MachineErrorKind::NotFound => "NOT_FOUND",
        MachineErrorKind::Internal => "INTERNAL",
    };
    MachineError::new(kind, code, message)
}

async fn execute_machine_command(
    home: &HomeDir,
    daemon: &Daemon,
    command: MachineCommand,
) -> Result<MachineCommandOutput> {
    let output = match command {
        MachineCommand::Status => {
            let wallets = match daemon.wallet_projections.list_wallets().await {
                Ok(wallets) => Some(wallets),
                Err(error)
                    if error.code == bloom_broker_api::ProtocolErrorCode::ServiceUnavailable =>
                {
                    None
                }
                Err(error) => return Err(error.into()),
            };
            let mut output = format!(
                "version: {}\nhome: {}\nchains: {:?}\ndefault_chain: {}\ndefault_wallet: {}\ntry: bloom vfs ls /\n",
                env!("CARGO_PKG_VERSION"),
                home.root().display(),
                daemon.chains.list_names(),
                daemon.config.default_chain,
                daemon.config.default_wallet.as_deref().unwrap_or("<none>"),
            );
            match wallets {
                Some(wallets) if wallets.is_empty() => output.push_str("no wallets yet — create one with bloom wallet new main\n"),
                Some(_) => output.push_str("deposit: bloom wallet address <wallet> --qr\nagent workflow: browse the mounted VFS or use bloom vfs cat/ls/write\n"),
                None => output.push_str("wallets: unavailable (Broker offline and no cached public projection)\n"),
            }
            let mut stderr = String::new();
            let checker =
                bloom_update::UpdateChecker::new(env!("CARGO_PKG_VERSION"), home.cache_dir())?;
            if let Some(snapshot) = checker.quick_check_cached() {
                let latest = snapshot.latest.as_deref().unwrap_or("?");
                let available = match snapshot.available() {
                    bloom_update::UpdateAvailable::OutOfDate => "out_of_date",
                    bloom_update::UpdateAvailable::UpToDate => "up_to_date",
                    bloom_update::UpdateAvailable::Unknown => "unknown",
                };
                output.push_str(&format!(
                    "latest_release: {latest}\nupdate_available: {available}\n"
                ));
                if matches!(
                    snapshot.available(),
                    bloom_update::UpdateAvailable::OutOfDate
                ) {
                    let latest_display = latest.strip_prefix('v').unwrap_or(latest);
                    stderr.push_str(&format!(
                        "hint: bloom v{latest_display} is available (you have v{}); see /status/update\n",
                        env!("CARGO_PKG_VERSION")
                    ));
                }
            }
            return Ok(MachineCommandOutput {
                stdout: output,
                stderr,
                exit_code: 0,
            });
        }
        MachineCommand::AuditStatus => {
            format!("{}\n", machine_audit_status_output(daemon.audit.as_ref())?)
        }
        MachineCommand::AuditReconcile {
            correlation_id,
            outcome,
            confirm,
        } => format!(
            "{}\n",
            execute_audit_command(
                &AuditCmd::Reconcile {
                    correlation_id,
                    outcome,
                    confirm,
                },
                daemon.audit.as_ref(),
            )?
        ),
        MachineCommand::WalletList => {
            let mut output = String::new();
            for projection in daemon.wallet_projections.list_wallets().await? {
                output.push_str(&format!(
                    "{}\t{}\t{}\n",
                    projection.wallet.wallet_id,
                    projection.primary_address()?,
                    projection.wallet.wallet_kind
                ));
            }
            output
        }
        MachineCommand::WalletProjection { name } => {
            let wallet_id = bloom_broker_api::Token::new(name)?;
            let projection = daemon
                .wallet_projections
                .get_wallet(&wallet_id)
                .await
                .map_err(machine_wallet_lookup_error)?;
            format!("{}\n", serde_json::to_string_pretty(&projection)?)
        }
        MachineCommand::WalletAddress { name } => {
            let wallet_id = bloom_broker_api::Token::new(name)?;
            let projection = daemon
                .wallet_projections
                .get_wallet(&wallet_id)
                .await
                .map_err(machine_wallet_lookup_error)?;
            let address: alloy::primitives::Address = projection.primary_address()?.parse()?;
            bloom_proto::checksum_address(&address)
        }
        MachineCommand::WalletUnlock { name } => {
            return Err(machine_error(
                MachineErrorKind::PermissionDenied,
                format!(
                    "wallet unlock for '{}' is fail-closed: §17.1 defines wallet.unlock_prepare but §13.1 has no wallet_unlock ceremony_kind",
                    name
                ),
            )
            .into());
        }
        MachineCommand::WalletCustody { name, kind } => {
            if kind == MachineCustodyKind::New {
                launch_wallet_registration_via_vfs(&daemon.vfs, &name).await?
            } else {
                let (method, ceremony_kind, wallet_id, input_class) = match kind {
                    MachineCustodyKind::New => {
                        unreachable!("wallet registration uses the VFS adapter")
                    }
                    MachineCustodyKind::Import => (
                        bloom_machine_client::CustodyPrepareMethod::WalletImport,
                        bloom_broker_api::CeremonyKind::WalletImport,
                        None,
                        "raw-wallet-import",
                    ),
                    MachineCustodyKind::Rebind => (
                        bloom_machine_client::CustodyPrepareMethod::CredentialReplace,
                        bloom_broker_api::CeremonyKind::CredentialReplace,
                        Some(bloom_broker_api::Token::new(name.clone())?),
                        "credential-prf",
                    ),
                    MachineCustodyKind::Delete => (
                        bloom_machine_client::CustodyPrepareMethod::WalletDelete,
                        bloom_broker_api::CeremonyKind::WalletDelete,
                        Some(bloom_broker_api::Token::new(name.clone())?),
                        "none",
                    ),
                };
                launch_custody_ceremony(
                    home,
                    &name,
                    method,
                    ceremony_kind,
                    wallet_id,
                    input_class,
                    None,
                )
                .await?
            }
        }
        MachineCommand::WalletMigrate { receipt } => {
            let receipt: LegacyMigrationReceiptFile =
                serde_json::from_value(serde_json::to_value(receipt)?)?;
            let (name, migration) = receipt.into_launch()?;
            launch_custody_ceremony(
                home,
                &name,
                bloom_machine_client::CustodyPrepareMethod::WalletImport,
                bloom_broker_api::CeremonyKind::WalletImport,
                None,
                "legacy_passkey_v1_prf",
                Some(migration),
            )
            .await?
        }
        MachineCommand::WalletPolicyPrepare {
            name,
            policy,
            assurance_level,
        } => prepare_policy_update(home, &name, &policy, &assurance_level).await?,
        MachineCommand::WalletPolicyCommit { operation_id } => {
            commit_policy_update(home, operation_id).await?
        }
        MachineCommand::WalletOutboxCancel {
            wallet,
            chain,
            id,
            text,
        } => {
            execute_wallet_outbox_action(
                &daemon.vfs,
                &wallet,
                &chain,
                &id,
                "cancel",
                text.as_bytes(),
            )
            .await?;
            format!("cancel submitted for {id}\n")
        }
        MachineCommand::WalletOutboxReplace {
            wallet,
            chain,
            id,
            intent,
        } => {
            execute_wallet_outbox_action(
                &daemon.vfs,
                &wallet,
                &chain,
                &id,
                "replace",
                intent.as_bytes(),
            )
            .await?;
            format!("replacement submitted for {id}\n")
        }
        MachineCommand::Ceremony {
            action,
            operation_id,
        } => {
            let command = match action {
                MachineCeremonyAction::Status => CeremonyCmd::Status { operation_id },
                MachineCeremonyAction::Cancel => CeremonyCmd::Cancel { operation_id },
                MachineCeremonyAction::Result => CeremonyCmd::Result { operation_id },
            };
            handle_ceremony(home, command).await?
        }
        MachineCommand::Operation {
            action,
            operation_id,
        } => {
            let command = match action {
                MachineOperationAction::Status => OperationCmd::Status { operation_id },
                MachineOperationAction::Cancel => OperationCmd::Cancel { operation_id },
            };
            handle_operation(home, command).await?
        }
        MachineCommand::UpdateStatus => handle_update(home, UpdateCmd::Status).await?.0,
        MachineCommand::UpdateCheck => {
            let (output, code) = handle_update(home, UpdateCmd::Check).await?;
            return Ok(MachineCommandOutput {
                stdout: output,
                stderr: String::new(),
                exit_code: code,
            });
        }
        MachineCommand::Completions { shell } => {
            let shell: Shell = shell
                .parse()
                .map_err(|_| machine_error(MachineErrorKind::InvalidParams, "invalid shell"))?;
            let mut bytes = Vec::new();
            generate(shell, &mut Cli::command(), "bloom", &mut bytes);
            String::from_utf8(bytes)?
        }
    };
    Ok(MachineCommandOutput {
        stdout: output,
        stderr: String::new(),
        exit_code: 0,
    })
}

async fn execute_wallet_outbox_action(
    vfs: &bloom_vfs::Vfs,
    wallet: &str,
    chain: &str,
    id: &str,
    action: &str,
    body: &[u8],
) -> Result<()> {
    for (label, value) in [("wallet", wallet), ("chain", chain), ("id", id)] {
        if value.is_empty()
            || value == "."
            || value == ".."
            || value
                .chars()
                .any(|character| matches!(character, '/' | '\\' | '\0'))
        {
            return Err(machine_error(
                MachineErrorKind::InvalidParams,
                format!("invalid wallet outbox {label}"),
            )
            .into());
        }
    }
    let path = bloom_vfs::VfsPath::parse(&format!(
        "/wallets/{wallet}/chains/{chain}/outbox/pending/{id}/{action}"
    ))?;
    bloom_vfs::Handler::write(vfs, &path, body).await?;
    Ok(())
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyMigrationReceiptFile {
    schema: String,
    operation_id: bloom_broker_api::OperationId,
    wallet_name: bloom_broker_api::Token,
    address: String,
    public_key_fingerprint: bloom_broker_api::Digest32,
    credential_id_fingerprint: bloom_broker_api::Digest32,
    legacy_format_version: u8,
    bundle_digest: bloom_broker_api::Digest32,
    policy_mode: String,
    exact_terms_digest: bloom_broker_api::Digest32,
}

impl LegacyMigrationReceiptFile {
    fn into_launch(self) -> Result<(String, LegacyMigrationLaunch)> {
        let public_terms = bloom_broker_api::LegacyPasskeyMigrationPublic {
            schema: bloom_broker_api::Token::new(self.schema)
                .context("legacy migration receipt schema")?,
            wallet_name: self.wallet_name.clone(),
            address: self.address,
            public_key_fingerprint: self.public_key_fingerprint,
            credential_id_fingerprint: self.credential_id_fingerprint,
            legacy_format_version: self.legacy_format_version,
            bundle_digest: self.bundle_digest,
            policy_mode: bloom_broker_api::Token::new(self.policy_mode)
                .context("legacy migration receipt policy mode")?,
        };
        let computed = public_terms
            .terms_digest(&self.operation_id)
            .map_err(anyhow::Error::new)
            .context("validate legacy migration receipt terms")?;
        if computed != self.exact_terms_digest {
            anyhow::bail!("legacy migration receipt terms digest does not match its contents");
        }
        Ok((
            self.wallet_name.as_str().to_owned(),
            LegacyMigrationLaunch {
                operation_id: self.operation_id,
                exact_terms_digest: self.exact_terms_digest,
                public_terms,
            },
        ))
    }
}

const MAX_POLICY_DOCUMENT_BYTES: u64 = 1024 * 1024;

async fn prepare_policy_update(
    home: &HomeDir,
    requested_name: &str,
    input: &[u8],
    assurance_level: &str,
) -> Result<String> {
    use rand::RngCore as _;
    use sha2::Digest as _;

    validate_wallet_name(requested_name).map_err(|error| {
        machine_error(
            MachineErrorKind::InvalidParams,
            format!("wallet name must be a safe single path segment: {error:#}"),
        )
    })?;
    let wallet_id = bloom_broker_api::Token::new(requested_name.to_owned())
        .context("wallet name must be a protocol token")?;
    let assurance_level = bloom_broker_api::Token::new(assurance_level.to_owned())
        .context("assurance level must be a protocol token")?;
    if input.len() as u64 > MAX_POLICY_DOCUMENT_BYTES {
        return Err(machine_error(
            MachineErrorKind::InvalidParams,
            format!(
                "proposed policy must be a regular file no larger than {MAX_POLICY_DOCUMENT_BYTES} bytes"
            ),
        )
        .into());
    }
    let proposed: bloom_broker_api::CanonicalWalletPolicy =
        serde_json::from_slice(input).map_err(|error| {
            machine_error(
                MachineErrorKind::InvalidParams,
                format!("parse proposed policy as canonical policy JSON: {error}"),
            )
        })?;
    if proposed.wallet_id != wallet_id {
        return Err(machine_error(
            MachineErrorKind::InvalidParams,
            "proposed policy wallet_id does not match requested wallet",
        )
        .into());
    }
    let proposed_bytes =
        serde_jcs::to_vec(&proposed).context("canonicalize proposed policy document")?;

    let client = configured_broker_client(home).map_err(|error| {
        machine_error(
            MachineErrorKind::Unavailable,
            format!("policy update requires the authenticated Machine-to-Broker edge: {error:#}"),
        )
    })?;
    let baseline = client
        .policy(wallet_id.clone())
        .await
        .map_err(anyhow::Error::new)
        .context("read Signer-authenticated policy baseline from Broker")?;
    let baseline_bytes = baseline.canonical_policy.decode();
    anyhow::ensure!(
        bloom_broker_api::Digest32::from_bytes(sha2::Sha256::digest(&baseline_bytes).into())
            == baseline.policy_digest,
        "Broker policy baseline digest does not match its canonical bytes"
    );
    let baseline_policy: bloom_broker_api::CanonicalWalletPolicy =
        serde_json::from_slice(&baseline_bytes).context("parse Broker policy baseline")?;
    anyhow::ensure!(
        serde_jcs::to_vec(&baseline_policy).context("canonicalize Broker policy baseline")?
            == baseline_bytes,
        "Broker policy baseline is not canonical"
    );
    anyhow::ensure!(
        baseline_policy.wallet_id == wallet_id,
        "Broker policy baseline names another wallet"
    );

    let authority_diff_digest =
        bloom_machine_client::claimed_policy_authority_diff_digest(&baseline_policy, &proposed)
            .map_err(anyhow::Error::new)
            .context("digest claimed policy authority diff")?;
    let mut operation_bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut operation_bytes);
    let operation_id = bloom_broker_api::OperationId::from_bytes(operation_bytes);
    let request = bloom_broker_api::PolicyUpdateRequest {
        operation_id,
        wallet_id,
        baseline_version: baseline.version,
        baseline_digest: baseline.policy_digest,
        proposed_canonical_policy: bloom_broker_api::Base64UrlBytes::from_bytes(&proposed_bytes),
        proposed_policy_digest: bloom_broker_api::Digest32::from_bytes(
            sha2::Sha256::digest(&proposed_bytes).into(),
        ),
        authority_diff_digest,
        assurance_level,
    };
    let response = client
        .validate_policy_update(request)
        .await
        .map_err(anyhow::Error::new)
        .context("validate policy update and prepare Broker-originated custody ceremony")?;
    let projection =
        bloom_machine_client::CeremonyProjection::from_policy_prepare(&response, current_unix_ms())
            .map_err(anyhow::Error::new)
            .context("construct Machine policy-update projection")?;
    let projection_path = persist_ceremony_projection(home, &projection)?;
    Ok(format!(
        "operation_id: {}\nceremony_kind: {:?}\nreview_manifest_digest: {}\nceremony_url: {}\nceremony_expires_at_ms: {}\nprojection: {}\n",
        response.operation_id,
        response.ceremony_kind,
        response.review_manifest_digest,
        response.ceremony_url,
        response.ceremony_expires_at_ms.get(),
        projection_path.display(),
    ))
}

async fn commit_policy_update(home: &HomeDir, operation_id: String) -> Result<String> {
    let operation_id = bloom_broker_api::OperationId::new(operation_id)
        .context("operation ID must be 64 lowercase hexadecimal characters")?;
    let client = configured_broker_client(home).map_err(|error| {
        machine_error(
            MachineErrorKind::Unavailable,
            format!("policy commit requires the authenticated Machine-to-Broker edge: {error:#}"),
        )
    })?;
    let ceremony_receipt = client
        .custody_result(bloom_broker_api::OperationRequest {
            operation_id: operation_id.clone(),
        })
        .await
        .map_err(anyhow::Error::new)
        .context("retrieve completed policy-update ceremony receipt")?;
    anyhow::ensure!(
        is_completed_policy_update_receipt(&ceremony_receipt, &operation_id),
        "policy commit requires the matching completed policy_update ceremony receipt"
    );

    let receipt = client
        .commit_policy_update(bloom_broker_api::PolicyCommitUpdateRequest {
            operation_id: operation_id.clone(),
            ceremony_receipt,
        })
        .await
        .map_err(anyhow::Error::new)
        .context("commit policy update through Broker and Signer compare-and-swap")?;
    anyhow::ensure!(
        receipt.operation_id == operation_id,
        "Broker policy commit receipt operation identity mismatch"
    );

    if let Ok(status) = client.ceremony_status(operation_id.clone()).await {
        let now_ms = current_unix_ms();
        let mut projection = match load_ceremony_projection(home, &operation_id)? {
            Some(mut projection) => {
                projection
                    .reconcile_custody(&status, now_ms)
                    .map_err(anyhow::Error::new)
                    .context("reconcile committed policy-update projection")?;
                projection
            }
            None => bloom_machine_client::CeremonyProjection::from_custody_status(&status, now_ms)
                .map_err(anyhow::Error::new)
                .context("rebuild committed policy-update projection")?,
        };
        projection.expire_launch_secret(now_ms);
        persist_ceremony_projection(home, &projection)?;
    }

    Ok(format!(
        "{}\n",
        serde_json::to_string_pretty(&receipt).context("encode policy commit receipt")?
    ))
}

fn is_completed_policy_update_receipt(
    receipt: &bloom_broker_api::CustodyResult,
    operation_id: &bloom_broker_api::OperationId,
) -> bool {
    receipt.custody_operation_id == *operation_id
        && receipt.ceremony_kind == bloom_broker_api::CeremonyKind::PolicyUpdate
        && receipt.public_status == bloom_broker_api::CeremonyState::Succeeded
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn ceremony_projection_path(home: &HomeDir, operation_id: &str) -> PathBuf {
    home.root()
        .join("triad")
        .join("ceremonies")
        .join(format!("{operation_id}.json"))
}

fn persist_ceremony_projection(
    home: &HomeDir,
    projection: &bloom_machine_client::CeremonyProjection,
) -> Result<PathBuf> {
    use std::io::Write as _;

    let operation_id = projection
        .operation_id()
        .context("custody projection is missing operation identity")?;
    let path = ceremony_projection_path(home, operation_id.as_str());
    let parent = path.parent().context("ceremony projection parent")?;
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("protect {}", parent.display()))?;
    }
    let mut suffix = [0_u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut suffix);
    let temp_path = parent.join(format!(
        ".{}.{}.tmp",
        operation_id.as_str(),
        hex::encode(suffix)
    ));
    let bytes = serde_json::to_vec_pretty(projection).context("encode ceremony projection")?;
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp_path)
        .with_context(|| format!("create {}", temp_path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("write {}", temp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", temp_path.display()))?;
    std::fs::rename(&temp_path, &path).with_context(|| format!("publish {}", path.display()))?;
    Ok(path)
}

fn load_ceremony_projection(
    home: &HomeDir,
    operation_id: &bloom_broker_api::OperationId,
) -> Result<Option<bloom_machine_client::CeremonyProjection>> {
    let path = ceremony_projection_path(home, operation_id.as_str());
    match std::fs::read(&path) {
        Ok(bytes) => {
            let projection = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse {}", path.display()))?;
            Ok(Some(projection))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

async fn handle_ceremony(home: &HomeDir, command: CeremonyCmd) -> Result<String> {
    let (operation_id, action) = match command {
        CeremonyCmd::Status { operation_id } => (operation_id, "status"),
        CeremonyCmd::Cancel { operation_id } => (operation_id, "cancel"),
        CeremonyCmd::Result { operation_id } => (operation_id, "result"),
    };
    let operation_id = bloom_broker_api::OperationId::new(operation_id)
        .context("operation ID must be 64 lowercase hexadecimal characters")?;
    let client = configured_broker_client(home).map_err(|error| {
        machine_error(
            MachineErrorKind::Unavailable,
            format!(
                "ceremony operations require the authenticated Machine-to-Broker edge: {error:#}"
            ),
        )
    })?;
    if action == "result" {
        let result = client
            .custody_result(bloom_broker_api::OperationRequest {
                operation_id: operation_id.clone(),
            })
            .await
            .map_err(anyhow::Error::new)
            .context("retrieve Broker custody result")?;
        anyhow::ensure!(
            result.custody_operation_id == operation_id,
            "Broker custody result operation identity mismatch"
        );
        return Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(&serde_json::json!({
                "ceremony_kind": result.ceremony_kind,
                "operation_id": result.custody_operation_id,
                "state": result.public_status,
                "wallet_id": result.wallet_id,
                "public_key_refs": result.public_key_refs,
                "credential_summaries": result.credential_summaries,
                "receipt_digest": result.receipt_digest,
                "has_encrypted_browser_result": result.encrypted_browser_result.is_some(),
            }))
            .context("encode public custody result")?
        ));
    }

    let status = if action == "cancel" {
        client
            .cancel_ceremony(operation_id.clone())
            .await
            .map_err(anyhow::Error::new)
            .context("cancel Broker ceremony")?
    } else {
        client
            .ceremony_status(operation_id.clone())
            .await
            .map_err(anyhow::Error::new)
            .context("read Broker ceremony status")?
    };
    anyhow::ensure!(
        status.operation_id == operation_id,
        "Broker ceremony status operation identity mismatch"
    );
    let now_ms = current_unix_ms();
    let mut projection = match load_ceremony_projection(home, &operation_id)? {
        Some(mut projection) => {
            projection
                .reconcile_custody(&status, now_ms)
                .map_err(anyhow::Error::new)
                .context("reconcile durable Machine ceremony projection")?;
            projection
        }
        None => bloom_machine_client::CeremonyProjection::from_custody_status(&status, now_ms)
            .map_err(anyhow::Error::new)
            .context("rebuild Machine ceremony projection from Broker")?,
    };
    projection.expire_launch_secret(now_ms);
    let path = persist_ceremony_projection(home, &projection)?;
    Ok(format!(
        "{}\nprojection: {}\n",
        serde_json::to_string_pretty(&projection).context("encode ceremony projection")?,
        path.display(),
    ))
}

async fn handle_operation(home: &HomeDir, command: OperationCmd) -> Result<String> {
    let (raw_operation_id, cancel) = match command {
        OperationCmd::Status { operation_id } => (operation_id, false),
        OperationCmd::Cancel { operation_id } => (operation_id, true),
    };
    let operation_id = bloom_broker_api::OperationId::new(raw_operation_id)
        .context("operation ID must be 64 lowercase hexadecimal characters")?;
    let client = configured_broker_client(home).map_err(|error| {
        machine_error(
            MachineErrorKind::Unavailable,
            format!(
                "operation lifecycle requires the authenticated Machine-to-Broker edge: {error:#}"
            ),
        )
    })?;
    let status = if cancel {
        client
            .cancel_operation(operation_id.clone())
            .await
            .map_err(anyhow::Error::new)
            .context("cancel Broker operation before downstream acceptance")?
    } else {
        client
            .operation_status(operation_id.clone())
            .await
            .map_err(anyhow::Error::new)
            .context("read Broker operation status")?
    };
    anyhow::ensure!(
        status.operation_id == operation_id,
        "Broker operation status identity mismatch"
    );
    Ok(format!(
        "{}\n",
        serde_json::to_string_pretty(&status).context("encode Broker operation status")?
    ))
}

#[derive(Parser, Debug)]
#[command(
    name = "bloom",
    disable_version_flag = true,
    arg_required_else_help = true,
    about = "Bloom — an agentic Ethereum wallet as a virtual filesystem",
    long_about = "Bloom mounts an agentic Ethereum wallet as a directory for agents. EXPERIMENTAL / UNAUDITED ALPHA: do not use with funds you cannot afford to lose, and review every generated transaction plan before signing. Read balances, contracts, ENS, prices, and status with cat/ls; stage wallet actions by writing intents into an outbox; confirm only after reviewing the generated plan. New agents should read https://bloom.directory/SKILL.md, then run bloom init and bloom serve --mount ~/bloom. Use bloom vfs only as a fallback when mounting is unavailable."
)]
struct Cli {
    /// Show CLI, daemon, and negotiated IPC protocol versions.
    #[arg(long)]
    version: bool,

    /// Override home directory (default: ~/.bloom).
    #[arg(long, env = "BLOOM_HOME")]
    home: Option<PathBuf>,

    /// Connect to an explicit Bloom IPC endpoint.
    ///
    /// Currently only Unix socket endpoints are supported:
    /// `unix:/path/to/bloom.sock`. A bare path is accepted as a
    /// compatibility shorthand.
    #[arg(long, value_name = "ENDPOINT")]
    connect: Option<String>,

    /// Compatibility alias for `--connect unix:<path>`.
    #[arg(long, value_name = "PATH")]
    ipc_socket: Option<PathBuf>,

    /// Suppress daemon/diagnostic logs on stderr (values still print on
    /// stdout). `RUST_LOG` overrides this when set.
    #[arg(long, short, global = true)]
    quiet: bool,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum InitInternal {
    #[cfg(feature = "triad-dev-harness")]
    #[command(name = "triad-render-developer-enrollment", hide = true)]
    TriadRenderDeveloperEnrollment {
        template_dir: PathBuf,
        output_dir: PathBuf,
        release_digest: String,
    },
    #[cfg(feature = "triad-dev-harness")]
    #[command(name = "triad-enroll-developer-petal-provenance", hide = true)]
    TriadEnrollDeveloperPetalProvenance {
        config_dir: PathBuf,
        petal_dir: PathBuf,
    },
    #[command(name = "triad-render-macos-enrollment", hide = true)]
    TriadRenderMacosEnrollment {
        template_dir: PathBuf,
        output_dir: PathBuf,
        login_uid: u32,
        broker_uid: u32,
        signer_uid: u32,
        session_socket_gid: u32,
        release_digest: String,
    },
    #[command(name = "triad-render-macos-identity-rotation", hide = true)]
    TriadRenderMacosIdentityRotation {
        current_identity: PathBuf,
        replacement_identity: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum ServeInternal {
    #[command(name = "triad-health-check", hide = true)]
    TriadHealthCheck { expected_build: String },
    #[command(name = "triad-pf-monitor-once", hide = true)]
    TriadPfMonitorOnce,
    #[command(name = "session-sentinel", hide = true)]
    SessionSentinel,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Show daemon status (chains configured, version, uptime).
    Status,
    /// Inspect or explicitly reconcile the Machine-owned audit journal.
    #[command(subcommand)]
    Audit(AuditCmd),
    /// VFS path operations (no NFS mount required).
    #[command(subcommand)]
    Vfs(VfsCmd),
    /// Wallet management.
    #[command(subcommand)]
    Wallet(WalletCmd),
    /// Inspect or cancel a Broker-owned custody ceremony by operation ID.
    #[command(subcommand)]
    Ceremony(CeremonyCmd),
    /// Inspect or cancel a Broker operation before downstream acceptance.
    #[command(subcommand)]
    Operation(OperationCmd),
    /// Paid/free HTTP requests via the `/requests` VFS surface.
    #[command(subcommand)]
    Request(RequestCmd),
    /// Run the daemon as a long-lived process.
    Serve {
        /// IPC endpoint to bind.
        ///
        /// Currently only Unix socket endpoints are supported:
        /// `unix:/path/to/bloom.sock`. A bare path is accepted as a
        /// compatibility shorthand.
        #[arg(long, value_name = "ENDPOINT")]
        endpoint: Option<String>,

        /// Mount the VFS for the lifetime of the daemon.
        ///
        /// With no PATH, defaults to /bloom on Linux and /Volumes/bloom on macOS.
        #[arg(
            long,
            value_name = "PATH",
            num_args = 0..=1,
            default_missing_value = DEFAULT_MOUNT_PATH
        )]
        mount: Option<PathBuf>,

        #[command(subcommand)]
        internal: Option<ServeInternal>,
    },
    /// Talk to a running `bloom serve` over its UDS JSON-RPC socket.
    #[command(subcommand)]
    Ipc(IpcCmd),
    /// Manage wasm petals: install, app, list, uninstall.
    #[command(subcommand, visible_alias = "petal")]
    Petals(PetalsCmd),
    /// Check for newer bloom releases on GitHub and inspect the
    /// current update-checker state.
    #[command(subcommand)]
    Update(UpdateCmd),
    /// Initialise ~/.bloom with default config + dirs.
    Init {
        #[command(subcommand)]
        internal: Option<InitInternal>,
    },

    /// Print a shell completion script.
    Completions { shell: Shell },
}

#[derive(Subcommand, Debug)]
enum AuditCmd {
    /// Print signed-journal health without performing a mutation.
    Status,
    /// Close an unmatched durable intent without redispatching its effect.
    Reconcile {
        correlation_id: String,
        #[arg(long, value_parser = ["committed", "aborted"])]
        outcome: String,
        /// Exact confirmation printed by `bloom audit status`.
        #[arg(long)]
        confirm: String,
    },
}

#[derive(Subcommand, Debug)]
enum IpcCmd {
    /// Send a raw JSON-RPC call. `params` is a JSON literal (default: null).
    Call {
        method: String,
        #[arg(long)]
        params: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum CeremonyCmd {
    /// Refresh and print the durable Machine projection from Broker status.
    Status { operation_id: String },
    /// Cancel a ceremony before its atomic commit marker.
    Cancel { operation_id: String },
    /// Retrieve the signed public custody result. Encrypted Browser output is
    /// never printed by Machine.
    Result { operation_id: String },
}

#[derive(Subcommand, Debug)]
enum OperationCmd {
    /// Read the Broker's durable public operation state.
    Status { operation_id: String },
    /// Cancel only if Broker proves no downstream/backend acceptance occurred.
    Cancel { operation_id: String },
}

#[derive(Subcommand, Debug)]
enum VfsCmd {
    /// `cat /bloom/<path>` — read a file via the VFS.
    Cat { path: String },
    /// `ls /bloom/<path>` — list a directory via the VFS.
    Ls {
        #[arg(default_value = "/")]
        path: String,
    },
    /// `stat /bloom/<path>` — inspect VFS metadata without a kernel mount.
    Stat { path: String },
    /// Write data to a writable VFS path. Reads from stdin if `--data` is omitted.
    Write {
        path: String,
        #[arg(long)]
        data: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum PetalsCmd {
    /// Install a Petal package directory, `.petal.tar`, or trusted GitHub source repository.
    Install {
        /// Path to a package directory, `.petal.tar`, or trusted GitHub source repository URL.
        path: String,
        /// Git tag, branch, or commit SHA to install from a GitHub source repository.
        #[arg(long = "ref", value_name = "TAG_OR_SHA")]
        ref_: Option<String>,
    },
    /// Validate a Petal package directory and optionally emit a deterministic `.petal.tar`.
    Build {
        /// Package directory containing petal.toml, README.md, AGENTS.md, and petal/<name>/.
        package_dir: String,
        /// Write a deterministic `.petal.tar` archive.
        #[arg(long, value_name = "ARCHIVE")]
        out: Option<String>,
    },
    /// List installed petals.
    Ls,
    /// Remove an installed petal (and any petname pointing at it).
    Uninstall {
        /// Content hash of the petal to remove: full 64-char hex, a
        /// unique prefix of at least 12 chars (as printed by `ls`),
        /// a Petal name, or a petname.
        target: String,
    },
}

#[derive(Subcommand, Debug)]
enum PetalAppCmd {
    /// Validate a v2 package directory and optionally emit a deterministic `.petal.tar`.
    Build {
        /// Package directory containing petal.toml, README.md, AGENTS.md, and app/<name>/.
        package_dir: String,
        /// Write a deterministic `.petal.tar` archive.
        #[arg(long, value_name = "ARCHIVE")]
        out: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum RequestCmd {
    /// Create a request from one-line, TOML, or HTTP-message-like input.
    New {
        /// Request text, e.g. `GET https://example.com/data`.
        request: String,
        /// Paying wallet. If omitted, config.default_wallet or the only wallet is used.
        #[arg(long)]
        wallet: Option<String>,
        /// Stage/probe only; never spends or signs.
        #[arg(long)]
        dry_run: bool,
    },
    /// Show the staged payment plan for an id or `latest`.
    Plan { id: String },
    /// Confirm a pending paid request.
    Confirm {
        id: String,
        /// Confirmation text: `y`/`yes`/`confirm`, or the wallet's policy override
        /// sentinel to bypass soft limits. Defaults to `confirm`.
        #[arg(long, default_value = "confirm")]
        text: String,
    },
    /// Print response body for an id or `latest`.
    Body { id: String },
    /// Print receipt JSON for an id or `latest`.
    Receipt { id: String },
}

/// Subcommands for `bloom update`.
#[derive(Subcommand, Debug)]
enum UpdateCmd {
    /// Force a refresh against GitHub and print the result as JSON.
    /// Exits 0 if up to date, 1 if behind, 2 if unknown/error.
    Check,
    /// Print the cached snapshot without making a network call.
    Status,
}

#[derive(Subcommand, Debug)]
enum WalletCmd {
    /// Start a Broker-hosted wallet registration ceremony.
    New { name: String },
    /// Start a Broker-hosted wallet import ceremony. The private key is entered
    /// only in the ceremony browser and never crosses the Machine process.
    Import { name: String },
    /// Convert a staged v1 passkey wallet into Signer-owned Triad custody.
    /// The receipt contains public binding data only; Machine never opens the
    /// legacy wallet directory.
    MigratePasskey { receipt: PathBuf },
    /// List configured wallets.
    List,
    /// Print the authenticated, key-free Broker projection for a wallet.
    /// This contains public keys, public credential descriptors, and the
    /// signed policy snapshot; it never contains custody material.
    Projection { name: String },
    /// Print a wallet's deposit address. Default output is the bare checksummed
    /// address (one line, scriptable); `--qr` adds a scannable QR block above it,
    /// and `--qr-out <path>` writes a scannable SVG of the address to a file.
    Address {
        name: String,
        #[arg(long)]
        qr: bool,
        /// Write a scannable SVG QR of the deposit address to this path.
        #[arg(long, value_name = "PATH")]
        qr_out: Option<PathBuf>,
    },
    /// Request wallet re-arming. This is currently fail-closed because the
    /// normative ceremony-kind inventory has no wallet-unlock kind.
    Unlock { name: String },
    /// Stage a tx by writing an intent file. Convenience for the
    /// outbox flow.
    Stage {
        wallet: String,
        chain: String,
        /// Intent body (JSON, TOML, or shell-style). If omitted, read
        /// from stdin.
        #[arg(long)]
        intent: Option<String>,
    },
    /// Submit confirmation of a staged transaction through the Machine VFS.
    Confirm {
        wallet: String,
        chain: String,
        id: String,
        /// Confirmation text (default "y"; "override" bypasses soft
        /// policy warnings).
        #[arg(long, default_value = "y")]
        text: String,
    },
    /// Submit a same-nonce self-send replacement request for a staged tx.
    Cancel {
        wallet: String,
        chain: String,
        id: String,
        /// Confirmation text. Must be non-empty.
        #[arg(long, default_value = "y")]
        text: String,
    },
    /// Submit a same-nonce replacement request from a new intent body.
    Replace {
        wallet: String,
        chain: String,
        id: String,
        /// Replacement intent body (JSON, TOML, or shell-style). If omitted, read stdin.
        #[arg(long)]
        intent: Option<String>,
    },
    /// Sign an ordered batch atomically, then broadcast each transaction in order.
    ///
    /// Each TX is `chain:id`, for example `base:0001-abc`.
    ConfirmBatch {
        wallet: String,
        /// Staged tx references in the exact order to broadcast.
        txs: Vec<String>,
        /// Confirmation text for each tx.
        #[arg(long, default_value = "y")]
        text: String,
    },
    /// Validate a proposed policy and prepare its Broker-originated review
    /// ceremony. The input is JSON and is canonicalized before submission.
    UpdatePolicy {
        name: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long, default_value = "user_verified")]
        assurance_level: String,
    },
    /// Commit a policy update using its completed policy_update ceremony
    /// receipt. This never provides a direct commit path.
    CommitPolicy { operation_id: String },
    /// Replace a wallet credential through a Broker-originated custody
    /// ceremony. Signer authenticates the current credential, registers the
    /// replacement, and updates its credential registry without exposing key
    /// material to Machine. The wallet address does not change.
    ///
    /// Use this to rotate authenticators (e.g. new YubiKey or new device)
    /// without moving funds. Ceremony status and public results are projected
    /// from Broker.
    RebindPasskey { name: String },
    /// Permanently delete a wallet through a Broker-originated custody
    /// ceremony. Signer deletes custody state after owner authorization;
    /// Machine removes only its public projection. This cannot be undone.
    Delete { name: String },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // RUST_LOG wins when set; otherwise default to `info`, or `error`
    // under `--quiet` so `vfs cat`/`ls` output stays clean.
    let default_level = if cli.quiet { "error" } else { "info" };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level)),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();

    match run(cli).await {
        Ok(()) => {
            let code = UPDATE_EXIT_CODE.load(std::sync::atomic::Ordering::SeqCst);
            if code != 0 {
                return ExitCode::from(code as u8);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

/// Calls the configured daemon endpoint. A missing daemon is always an error:
/// `init` and `serve` are the only CLI commands allowed to execute without the
/// long-running Machine process.
async fn try_ipc(
    client: &IpcClient,
    endpoint: &ResolvedEndpoint,
    method: &str,
    params: serde_json::Value,
) -> std::io::Result<serde_json::Value> {
    match client.call(method, params).await {
        Ok(v) => Ok(v),
        Err(error) => Err(map_ipc_client_error(endpoint, error)),
    }
}

async fn try_ipc_streaming<F>(
    client: &IpcClient,
    endpoint: &ResolvedEndpoint,
    method: &str,
    params: serde_json::Value,
    on_output: F,
) -> std::io::Result<IpcCallResult>
where
    F: FnMut(IpcOutputEvent) -> std::io::Result<()>,
{
    client
        .call_streaming(method, params, on_output)
        .await
        .map_err(|error| map_ipc_client_error(endpoint, error))
}

fn map_ipc_client_error(endpoint: &ResolvedEndpoint, error: IpcClientError) -> std::io::Error {
    match error {
        IpcClientError::Rpc(error) => std::io::Error::other(error),
        IpcClientError::Transport(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::io::Error::new(
                e.kind(),
                format!(
                    "Bloom daemon endpoint {} is not available: {e}; start it with 'bloom serve'",
                    endpoint.display
                ),
            )
        }
        IpcClientError::Transport(e) if is_endpoint_permission_denial(&e) => {
            endpoint_connection_error(&endpoint.display, e)
        }
        IpcClientError::Transport(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            std::io::Error::other(format!(
                "Bloom daemon endpoint {} is not responding: {e}; start it with 'bloom serve'",
                endpoint.display,
            ))
        }
        IpcClientError::Transport(e) => endpoint_connection_error(&endpoint.display, e),
        IpcClientError::Protocol(message) => std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Bloom daemon endpoint {} returned {message}",
                endpoint.display
            ),
        ),
        IpcClientError::EndpointSecurity(message) => std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "Bloom daemon endpoint {} is insecure: {message}",
                endpoint.display
            ),
        ),
        error @ IpcClientError::Incompatible { .. } => std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "Bloom daemon endpoint {} rejected: {error}",
                endpoint.display
            ),
        ),
    }
}

fn is_endpoint_permission_denial(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1)
}

fn endpoint_connection_error(endpoint: &str, error: std::io::Error) -> std::io::Error {
    std::io::Error::new(
        error.kind(),
        format!("Bloom daemon endpoint {endpoint} failed: {error}; start it with 'bloom serve'"),
    )
}

fn system_time_to_unix_ms(time: SystemTime) -> u128 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn unix_ms_to_system_time(ms: u128) -> SystemTime {
    let ms = ms.min(u64::MAX as u128) as u64;
    UNIX_EPOCH + std::time::Duration::from_millis(ms)
}

fn print_vfs_stat(
    path: &str,
    name: &str,
    kind: &str,
    mode: u32,
    size: u64,
    link_target: Option<&str>,
    modified: Option<SystemTime>,
) {
    let (modified, modified_source) = match modified {
        Some(t) => (t, "artifact"),
        None => (SystemTime::now(), "synthetic_now"),
    };
    let modified_ms = system_time_to_unix_ms(modified);
    println!("path: {path}");
    println!("name: {name}");
    println!("kind: {kind}");
    println!("mode: {:04o}", mode & 0o7777);
    println!("size: {size}");
    println!("modified_ms: {modified_ms}");
    println!("modified: {}", humantime::format_rfc3339(modified));
    println!("modified_source: {modified_source}");
    if let Some(target) = link_target {
        println!("link_target: {target}");
    }
}

fn print_vfs_stat_json(path: &str, entry: &serde_json::Value) -> Result<()> {
    let name = entry
        .get("name")
        .and_then(|v| v.as_str())
        .context("ipc lookup: missing name")?;
    let kind = entry
        .get("kind")
        .and_then(|v| v.as_str())
        .context("ipc lookup: missing kind")?;
    let mode = entry
        .get("mode")
        .and_then(|v| v.as_u64())
        .context("ipc lookup: missing mode")? as u32;
    let size = entry
        .get("size")
        .and_then(|v| v.as_u64())
        .context("ipc lookup: missing size")?;
    let link_target = entry.get("link_target").and_then(|v| v.as_str());
    let modified = entry
        .get("modified_ms")
        .and_then(|v| v.as_u64())
        .map(|ms| unix_ms_to_system_time(ms as u128));
    print_vfs_stat(path, name, kind, mode, size, link_target, modified);
    Ok(())
}

async fn ipc_read(endpoint: &ResolvedEndpoint, path: &str) -> Result<Vec<u8>> {
    let mut streamed = Vec::new();
    let reply = try_ipc_streaming(
        &IpcClient::new(&endpoint.socket),
        endpoint,
        "read",
        serde_json::json!({ "path": path }),
        |event| match event.stream {
            IpcOutputStream::Data => {
                streamed.extend_from_slice(&event.bytes);
                Ok(())
            }
            IpcOutputStream::Stdout | IpcOutputStream::Stderr => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "IPC read returned command output",
            )),
        },
    )
    .await
    .with_context(|| format!("ipc read {path} via {}", endpoint.display))?;
    let result = reply.result;
    if result.get("streamed").and_then(serde_json::Value::as_bool) == Some(true) {
        let expected = result
            .get("len")
            .and_then(serde_json::Value::as_u64)
            .context("ipc read: streamed response is missing len")?;
        anyhow::ensure!(
            streamed.len() as u64 == expected,
            "ipc read: streamed byte count mismatch (expected {expected}, received {})",
            streamed.len()
        );
        return Ok(streamed);
    }
    anyhow::ensure!(streamed.is_empty(), "ipc read: unexpected streamed data");
    let encoded = result
        .get("bytes_b64")
        .and_then(|value| value.as_str())
        .context("ipc read: missing bytes_b64")?;
    B64.decode(encoded).context("ipc read: bad base64")
}

async fn ipc_read_to_stdout(endpoint: &ResolvedEndpoint, path: &str, context: &str) -> Result<()> {
    let bytes = ipc_read(endpoint, path)
        .await
        .with_context(|| context.to_owned())?;
    std::io::Write::write_all(&mut std::io::stdout(), &bytes)?;
    Ok(())
}

async fn machine_command(
    endpoint: &ResolvedEndpoint,
    command: MachineCommand,
) -> Result<MachineCommandOutput> {
    let result = try_ipc(
        &IpcClient::new(&endpoint.socket),
        endpoint,
        "machine.execute",
        serde_json::to_value(command)?,
    )
    .await?;
    serde_json::from_value(result).context("decode daemon Machine command response")
}

async fn call_machine_command(endpoint: &ResolvedEndpoint, command: MachineCommand) -> Result<()> {
    let output = machine_command(endpoint, command).await?;
    std::io::Write::write_all(&mut std::io::stdout(), output.stdout.as_bytes())?;
    std::io::Write::write_all(&mut std::io::stderr(), output.stderr.as_bytes())?;
    if output.exit_code != 0 {
        UPDATE_EXIT_CODE.store(output.exit_code, std::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

async fn run(cli: Cli) -> Result<()> {
    anyhow::ensure!(
        !cli.version || cli.cmd.is_none(),
        "--version cannot be combined with a command"
    );
    let lifecycle_command = matches!(cli.cmd.as_ref(), Some(Cmd::Init { .. } | Cmd::Serve { .. }));
    let (connect, ipc_socket) = if lifecycle_command {
        (None, None)
    } else if cli.connect.is_some() {
        (cli.connect, None)
    } else if cli.ipc_socket.is_some() {
        (None, cli.ipc_socket)
    } else if let Ok(endpoint) = std::env::var("BLOOM_RPC_ENDPOINT") {
        (Some(endpoint), None)
    } else {
        (
            None,
            std::env::var_os("BLOOM_IPC_SOCKET").map(PathBuf::from),
        )
    };
    let home = match cli.home {
        Some(p) => {
            debug!(path = %p.display(), "cli.home.override");
            HomeDir::at(p)
        }
        None => HomeDir::resolve("~/.bloom").context("resolving home dir")?,
    };
    let client_endpoint = if lifecycle_command {
        ResolvedEndpoint::default_for_home(&home)
    } else {
        resolve_client_endpoint(&home, connect.as_deref(), ipc_socket.as_deref())
            .context("resolve Bloom endpoint")?
    };
    trace!(cmd = ?cli.cmd, home = %home.root().display(), "cli.dispatch");

    if cli.version {
        let client_protocol = IpcProtocolRange::supported();
        println!("bloom {}", env!("CARGO_PKG_VERSION"));
        match IpcClient::new(&client_endpoint.socket)
            .call_with_protocol("version", serde_json::Value::Null)
            .await
        {
            Ok(reply) => {
                let daemon_version = reply
                    .result
                    .as_str()
                    .context("daemon version response is not a string")?;
                println!("bloom-daemon {daemon_version}");
                println!(
                    "bloom-ipc {} (compatible; cli {}, daemon {})",
                    reply.negotiated_protocol, client_protocol, reply.daemon_protocol
                );
            }
            Err(IpcClientError::Transport(_)) => {
                println!("bloom-daemon unavailable");
                println!("bloom-ipc {client_protocol} (not negotiated)");
            }
            Err(IpcClientError::Incompatible { client, daemon }) => {
                println!("bloom-daemon incompatible");
                println!("bloom-ipc incompatible (cli {client}, daemon {daemon})");
            }
            Err(error) => {
                println!("bloom-daemon incompatible");
                println!("bloom-ipc {client_protocol} (not negotiated: {error})");
            }
        }
        return Ok(());
    }

    match cli.cmd.context("a command is required")? {
        Cmd::Init { internal } => {
            if let Some(internal) = internal {
                return match internal {
                    #[cfg(feature = "triad-dev-harness")]
                    InitInternal::TriadRenderDeveloperEnrollment {
                        template_dir,
                        output_dir,
                        release_digest,
                    } => {
                        triad_enrollment::run_developer(&template_dir, &output_dir, release_digest)
                            .context("Bloom developer triad enrollment generation failed")
                    }
                    #[cfg(feature = "triad-dev-harness")]
                    InitInternal::TriadEnrollDeveloperPetalProvenance {
                        config_dir,
                        petal_dir,
                    } => triad_enrollment::run_developer_petal_provenance(&config_dir, &petal_dir)
                        .context("Bloom developer Petal provenance enrollment failed"),
                    InitInternal::TriadRenderMacosEnrollment {
                        template_dir,
                        output_dir,
                        login_uid,
                        broker_uid,
                        signer_uid,
                        session_socket_gid,
                        release_digest,
                    } => triad_enrollment::run(
                        template_dir,
                        output_dir,
                        login_uid,
                        broker_uid,
                        signer_uid,
                        session_socket_gid,
                        release_digest,
                    )
                    .context("Bloom macOS enrollment generation failed"),
                    InitInternal::TriadRenderMacosIdentityRotation {
                        current_identity,
                        replacement_identity,
                    } => triad_enrollment::run_identity_rotation(
                        &current_identity,
                        &replacement_identity,
                    )
                    .context("Bloom macOS identity rotation generation failed"),
                };
            }
            eprintln!("{ALPHA_DISCLOSURE}");
            let (_home_permit, d) = build_write_daemon(home.clone()).context("init daemon")?;
            let preinstalled = github_source::ensure_preinstalled_petals(&home, &d)
                .context("provision configured pre-installed Petals")?;
            println!("home: {}", d.home.root().display());
            println!("config: {}", d.home.config_path().display());
            println!("chains: {:?}", d.chains.list_names());
            println!("preinstalled_petals: {preinstalled:?}");
            println!("next: bloom wallet new main");
            println!("then: bloom wallet address main --qr");
            println!("mount: mkdir -p ~/bloom && bloom serve --mount ~/bloom");
            println!("fallback: bloom vfs cat /docs/README.md");
            println!("agent setup: https://bloom.directory/SKILL.md");
            Ok(())
        }
        Cmd::Status => call_machine_command(&client_endpoint, MachineCommand::Status).await,
        Cmd::Audit(command) => {
            let command = match command {
                AuditCmd::Status => MachineCommand::AuditStatus,
                AuditCmd::Reconcile {
                    correlation_id,
                    outcome,
                    confirm,
                } => MachineCommand::AuditReconcile {
                    correlation_id,
                    outcome,
                    confirm,
                },
            };
            call_machine_command(&client_endpoint, command).await
        }
        Cmd::Vfs(VfsCmd::Cat { path }) => {
            let client = IpcClient::new(&client_endpoint.socket);
            let res = try_ipc(
                &client,
                &client_endpoint,
                "read",
                serde_json::json!({ "path": path }),
            )
            .await
            .with_context(|| format!("ipc read via {}", client_endpoint.display))?;
            debug!(endpoint = %client_endpoint.display, "cli.vfs.cat.via_ipc");
            let b64 = res
                .get("bytes_b64")
                .and_then(|v| v.as_str())
                .context("ipc read: missing bytes_b64")?;
            let bytes = B64.decode(b64).context("ipc read: bad base64")?;
            std::io::Write::write_all(&mut std::io::stdout(), &bytes)?;
            Ok(())
        }
        Cmd::Vfs(VfsCmd::Ls { path }) => {
            let client = IpcClient::new(&client_endpoint.socket);
            let res = try_ipc(
                &client,
                &client_endpoint,
                "list",
                serde_json::json!({ "path": path }),
            )
            .await
            .with_context(|| format!("ipc list via {}", client_endpoint.display))?;
            debug!(endpoint = %client_endpoint.display, "cli.vfs.ls.via_ipc");
            let arr = res.as_array().context("ipc list: expected array")?;
            for e in arr {
                let name = e.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let kind = match e.get("kind").and_then(|v| v.as_str()).unwrap_or("file") {
                    "dir" => "Dir",
                    "symlink" => "Symlink",
                    _ => "File",
                };
                println!("{}\t{}", name, kind);
            }
            Ok(())
        }
        Cmd::Vfs(VfsCmd::Stat { path }) => {
            let client = IpcClient::new(&client_endpoint.socket);
            let res = try_ipc(
                &client,
                &client_endpoint,
                "lookup",
                serde_json::json!({ "path": path }),
            )
            .await
            .with_context(|| format!("ipc lookup via {}", client_endpoint.display))?;
            debug!(endpoint = %client_endpoint.display, "cli.vfs.stat.via_ipc");
            print_vfs_stat_json(&path, &res)?;
            Ok(())
        }
        Cmd::Vfs(VfsCmd::Write { path, data }) => {
            let body = match data {
                Some(s) => s.into_bytes(),
                None => {
                    let mut buf = Vec::new();
                    std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)?;
                    buf
                }
            };
            let client = IpcClient::new(&client_endpoint.socket);
            try_ipc(
                &client,
                &client_endpoint,
                "write",
                serde_json::json!({ "path": path, "bytes_b64": B64.encode(&body) }),
            )
            .await
            .with_context(|| format!("ipc write via {}", client_endpoint.display))?;
            debug!(endpoint = %client_endpoint.display, "cli.vfs.write.via_ipc");
            Ok(())
        }
        Cmd::Request(RequestCmd::New {
            request,
            wallet,
            dry_run,
        }) => {
            let body = request_body_with_wallet(request, wallet.as_deref());
            let path = if dry_run {
                "/requests/new.dry-run"
            } else {
                "/requests/new"
            };
            let client = IpcClient::new(&client_endpoint.socket);
            try_ipc(
                &client,
                &client_endpoint,
                "write_with_lookup",
                serde_json::json!({
                    "path": path,
                    "bytes_b64": B64.encode(body.as_bytes()),
                    "projection_path": "/requests/latest",
                }),
            )
            .await
            .with_context(|| format!("ipc request new via {}", client_endpoint.display))
            .and_then(|entry| {
                let target = entry
                    .get("link_target")
                    .and_then(serde_json::Value::as_str)
                    .context("ipc request new: latest projection is missing link_target")?;
                println!("request: {target}");
                Ok(entry)
            })?;
            debug!(endpoint = %client_endpoint.display, "cli.request.new.via_ipc");
            if dry_run {
                println!("dry_run: true (unpaid probe/staging only; no spend/signing)");
            }
            Ok(())
        }
        Cmd::Request(RequestCmd::Plan { id }) => {
            ipc_read_to_stdout(
                &client_endpoint,
                &format!("/requests/{id}/plan.md"),
                "request plan",
            )
            .await?;
            Ok(())
        }
        Cmd::Request(RequestCmd::Confirm { id, text }) => {
            let path = format!("/requests/{id}/confirm");
            let body = text.into_bytes();
            let client = IpcClient::new(&client_endpoint.socket);
            // Confirmation uses the ordinary Machine VFS lane. Any signing
            // requirement must be satisfied through Broker; the CLI never
            // accepts an unlock secret or hosts a ceremony.
            let confirm_params = serde_json::json!({
                "path": path,
                "bytes_b64": B64.encode(&body),
            });
            try_ipc(&client, &client_endpoint, "write", confirm_params)
                .await
                .with_context(|| format!("ipc request confirm via {}", client_endpoint.display))?;
            debug!(endpoint = %client_endpoint.display, "cli.request.confirm.via_ipc");
            Ok(())
        }
        Cmd::Request(RequestCmd::Body { id }) => {
            ipc_read_to_stdout(
                &client_endpoint,
                &format!("/requests/{id}/response/body"),
                "request body",
            )
            .await?;
            Ok(())
        }
        Cmd::Request(RequestCmd::Receipt { id }) => {
            ipc_read_to_stdout(
                &client_endpoint,
                &format!("/requests/{id}/receipt.json"),
                "request receipt",
            )
            .await?;
            Ok(())
        }
        Cmd::Wallet(WalletCmd::New { name }) => {
            call_machine_command(
                &client_endpoint,
                MachineCommand::WalletCustody {
                    name,
                    kind: MachineCustodyKind::New,
                },
            )
            .await
        }
        Cmd::Wallet(WalletCmd::Import { name }) => {
            call_machine_command(
                &client_endpoint,
                MachineCommand::WalletCustody {
                    name,
                    kind: MachineCustodyKind::Import,
                },
            )
            .await
        }
        Cmd::Wallet(WalletCmd::MigratePasskey { receipt }) => {
            use std::io::Read as _;

            let descriptor = rustix::fs::open(
                &receipt,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )
            .with_context(|| format!("open migration receipt {}", receipt.display()))?;
            let mut file = std::fs::File::from(descriptor);
            let metadata = file
                .metadata()
                .with_context(|| format!("inspect migration receipt {}", receipt.display()))?;
            if !metadata.file_type().is_file() || metadata.len() > 64 * 1024 {
                anyhow::bail!("migration receipt must be a regular file no larger than 64 KiB");
            }
            let mut encoded = Vec::with_capacity(metadata.len() as usize);
            (&mut file)
                .take(64 * 1024 + 1)
                .read_to_end(&mut encoded)
                .with_context(|| format!("read migration receipt {}", receipt.display()))?;
            if encoded.len() > 64 * 1024 {
                anyhow::bail!("migration receipt exceeds 64 KiB");
            }
            let receipt: LegacyMigrationReceiptFile =
                serde_json::from_slice(&encoded).context("parse legacy migration receipt")?;
            call_machine_command(
                &client_endpoint,
                MachineCommand::WalletMigrate {
                    receipt: serde_json::from_value(serde_json::to_value(receipt)?)?,
                },
            )
            .await
        }
        Cmd::Wallet(WalletCmd::List) => {
            call_machine_command(&client_endpoint, MachineCommand::WalletList).await
        }
        Cmd::Wallet(WalletCmd::Projection { name }) => {
            call_machine_command(&client_endpoint, MachineCommand::WalletProjection { name }).await
        }
        Cmd::Wallet(WalletCmd::Address { name, qr, qr_out }) => {
            let result =
                machine_command(&client_endpoint, MachineCommand::WalletAddress { name }).await?;
            let address = result.stdout;
            if let Some(path) = qr_out {
                match commands::qr::render_qr_svg(&address) {
                    Some(svg) => {
                        std::fs::write(&path, svg)
                            .with_context(|| format!("write QR SVG to {}", path.display()))?;
                        eprintln!("wrote deposit QR SVG: {}", path.display());
                    }
                    None => anyhow::bail!("address too large to encode as a QR code"),
                }
            }
            if qr && let Some(code) = commands::qr::render_qr(&address) {
                println!("{code}");
            }
            println!("{address}");
            Ok(())
        }
        Cmd::Wallet(WalletCmd::Unlock { name }) => {
            call_machine_command(&client_endpoint, MachineCommand::WalletUnlock { name }).await
        }
        Cmd::Wallet(WalletCmd::UpdatePolicy {
            name,
            file,
            assurance_level,
        }) => {
            let metadata = std::fs::metadata(&file)
                .with_context(|| format!("inspect proposed policy {}", file.display()))?;
            anyhow::ensure!(
                metadata.is_file() && metadata.len() <= MAX_POLICY_DOCUMENT_BYTES,
                "proposed policy must be a regular file no larger than {MAX_POLICY_DOCUMENT_BYTES} bytes"
            );
            let policy = std::fs::read(&file)
                .with_context(|| format!("read proposed policy {}", file.display()))?;
            call_machine_command(
                &client_endpoint,
                MachineCommand::WalletPolicyPrepare {
                    name,
                    policy,
                    assurance_level,
                },
            )
            .await
        }
        Cmd::Wallet(WalletCmd::CommitPolicy { operation_id }) => {
            call_machine_command(
                &client_endpoint,
                MachineCommand::WalletPolicyCommit { operation_id },
            )
            .await
        }
        Cmd::Wallet(WalletCmd::RebindPasskey { name }) => {
            call_machine_command(
                &client_endpoint,
                MachineCommand::WalletCustody {
                    name,
                    kind: MachineCustodyKind::Rebind,
                },
            )
            .await
        }
        Cmd::Wallet(WalletCmd::Delete { name }) => {
            call_machine_command(
                &client_endpoint,
                MachineCommand::WalletCustody {
                    name,
                    kind: MachineCustodyKind::Delete,
                },
            )
            .await
        }
        Cmd::Wallet(WalletCmd::Stage {
            wallet,
            chain,
            intent,
        }) => {
            let body = match intent {
                Some(s) => s,
                None => {
                    let mut buf = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
                    buf
                }
            };
            let path = format!("/wallets/{wallet}/chains/{chain}/outbox/new.tx");
            let client = IpcClient::new(&client_endpoint.socket);
            let projection = try_ipc(
                &client,
                &client_endpoint,
                "write_with_lookup",
                serde_json::json!({
                    "path": path,
                    "bytes_b64": B64.encode(body.as_bytes()),
                    "projection_path": format!("/wallets/{wallet}/chains/{chain}/outbox/latest"),
                }),
            )
            .await
            .with_context(|| format!("ipc wallet stage via {}", client_endpoint.display))?;
            debug!(endpoint = %client_endpoint.display, "cli.wallet.stage.via_ipc");
            let target = projection
                .get("link_target")
                .and_then(serde_json::Value::as_str)
                .context("ipc wallet stage: latest projection is missing link_target")?;
            let id = target
                .strip_prefix("pending/")
                .context("ipc wallet stage: invalid latest target")?;
            println!("{id}");
            Ok(())
        }
        Cmd::Wallet(WalletCmd::Confirm {
            wallet,
            chain,
            id,
            text,
        }) => {
            let path = format!("/wallets/{wallet}/chains/{chain}/outbox/pending/{id}/confirm");
            let body = text.into_bytes();
            let client = IpcClient::new(&client_endpoint.socket);
            try_ipc(
                &client,
                &client_endpoint,
                "write",
                serde_json::json!({
                    "path": path,
                    "bytes_b64": B64.encode(&body),
                }),
            )
            .await
            .with_context(|| format!("ipc wallet confirm via {}", client_endpoint.display))?;
            debug!(endpoint = %client_endpoint.display, "cli.wallet.confirm.via_ipc");
            Ok(())
        }
        Cmd::Wallet(WalletCmd::Cancel {
            wallet,
            chain,
            id,
            text,
        }) => {
            call_machine_command(
                &client_endpoint,
                MachineCommand::WalletOutboxCancel {
                    wallet,
                    chain,
                    id,
                    text,
                },
            )
            .await
        }
        Cmd::Wallet(WalletCmd::Replace {
            wallet,
            chain,
            id,
            intent,
        }) => {
            let body = match intent {
                Some(s) => s,
                None => {
                    let mut buf = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
                    buf
                }
            };
            call_machine_command(
                &client_endpoint,
                MachineCommand::WalletOutboxReplace {
                    wallet,
                    chain,
                    id,
                    intent: body,
                },
            )
            .await
        }
        Cmd::Wallet(WalletCmd::ConfirmBatch { wallet, txs, text }) => {
            if txs.is_empty() {
                bail!("confirm-batch needs at least one tx ref like base:0001-abc");
            }
            for tx in &txs {
                let _ = parse_batch_tx_ref(tx)?;
            }
            let request = bloom_daemon::ipc::BatchConfirmIpcRequest { wallet, txs, text };
            let client = IpcClient::new(&client_endpoint.socket);
            let result = try_ipc(
                &client,
                &client_endpoint,
                "confirm_batch",
                serde_json::to_value(&request)?,
            )
            .await
            .with_context(|| format!("ipc wallet confirm-batch via {}", client_endpoint.display))?;
            debug!(endpoint = %client_endpoint.display, "cli.wallet.confirm_batch.via_ipc");
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        Cmd::Ceremony(command) => {
            let (action, operation_id) = match command {
                CeremonyCmd::Status { operation_id } => {
                    (MachineCeremonyAction::Status, operation_id)
                }
                CeremonyCmd::Cancel { operation_id } => {
                    (MachineCeremonyAction::Cancel, operation_id)
                }
                CeremonyCmd::Result { operation_id } => {
                    (MachineCeremonyAction::Result, operation_id)
                }
            };
            call_machine_command(
                &client_endpoint,
                MachineCommand::Ceremony {
                    action,
                    operation_id,
                },
            )
            .await
        }
        Cmd::Operation(command) => {
            let (action, operation_id) = match command {
                OperationCmd::Status { operation_id } => {
                    (MachineOperationAction::Status, operation_id)
                }
                OperationCmd::Cancel { operation_id } => {
                    (MachineOperationAction::Cancel, operation_id)
                }
            };
            call_machine_command(
                &client_endpoint,
                MachineCommand::Operation {
                    action,
                    operation_id,
                },
            )
            .await
        }
        Cmd::Serve {
            endpoint,
            mount,
            internal,
        } => {
            if let Some(internal) = internal {
                return match internal {
                    ServeInternal::TriadHealthCheck { expected_build } => {
                        installed_triad_health_check(&expected_build)
                            .await
                            .context("Bloom triad health check failed")
                    }
                    ServeInternal::TriadPfMonitorOnce => {
                        pf_monitor::run_once().context("Bloom packet-filter monitor failed")
                    }
                    ServeInternal::SessionSentinel => session_sentinel::run()
                        .await
                        .context("Bloom session sentinel failed"),
                };
            }
            eprintln!("{ALPHA_DISCLOSURE}");
            let (_home_permit, d) = build_write_daemon(home.clone())?;
            github_source::ensure_preinstalled_petals(&home, &d)
                .context("provision configured pre-installed Petals before serving")?;
            let mount_handle = mount_bloom(&d, mount.as_deref()).await?;
            let chains: Vec<String> = d.chains.list_names();
            println!(
                "bloom serve: home={} chains={:?}",
                d.home.root().display(),
                chains
            );
            if let Some(mount_path) = mount.as_deref() {
                println!("mount: {}", mount_path.display());
            }
            let endpoint = resolve_server_endpoint(&d.home, endpoint.as_deref())
                .context("resolve serve endpoint")?;
            let socket = endpoint.socket.clone();
            println!("ipc endpoint: {}", endpoint.display);
            println!("ipc socket: {}", socket.display());
            info!(home = %d.home.root().display(), chains = ?chains, endpoint = %endpoint.display, socket = %socket.display(), mount = ?mount, "cli.serve.starting");
            let server = IpcServer::new(d.vfs.clone(), env!("CARGO_PKG_VERSION"), chains)
                .with_petals(d.petals.clone())
                .with_petal_runtime_endpoints(
                    d.config
                        .petals
                        .runtime
                        .iter()
                        .map(|(name, runtime)| (name.clone(), runtime.endpoints.clone()))
                        .collect(),
                )
                .with_petal_source_installer(Arc::new(CanonicalPetalSourceInstaller {
                    home: home.clone(),
                    daemon: d.clone(),
                }))
                .with_batch_confirmation(
                    d.batch_confirmation_service().map_err(anyhow::Error::msg)?,
                )
                .with_machine_commands(Arc::new(DaemonMachineCommands {
                    home: home.clone(),
                    daemon: d.clone(),
                }));
            // Start audited and durable background effects only after every
            // fallible serve setup step has succeeded. The handle is shut
            // down and awaited before the runtime can return.
            let sweeper = d.spawn_background_tasks();
            let server2 = server.clone();
            // Trigger graceful shutdown on Ctrl-C or SIGTERM.
            let shutdown = tokio::spawn(async move {
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{SignalKind, signal};
                    let mut sigterm = signal(SignalKind::terminate())
                        .expect("SIGTERM handler registration failed");
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => info!("cli.serve.ctrl_c_received"),
                        _ = sigterm.recv() => info!("cli.serve.sigterm_received"),
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = tokio::signal::ctrl_c().await;
                    info!("cli.serve.ctrl_c_received");
                }
                server2.trigger_shutdown();
            });
            let serve_result = server.serve(&socket).await.context("ipc serve");
            shutdown.abort();
            // Stop the outbox expiry sweeper (fix #3) and any other
            // daemon-owned workers (watch executor, etc., fix #6).
            let unmount_result = unmount_bloom(mount_handle).await;
            sweeper.shutdown().await;
            d.shutdown().await;
            serve_result?;
            unmount_result?;
            info!("cli.serve.shutdown_complete");
            println!("shutting down");
            Ok(())
        }
        Cmd::Update(cmd) => {
            let command = match cmd {
                UpdateCmd::Status => MachineCommand::UpdateStatus,
                UpdateCmd::Check => MachineCommand::UpdateCheck,
            };
            call_machine_command(&client_endpoint, command).await
        }
        Cmd::Petals(cmd) => run_petals(&client_endpoint, cmd).await,

        Cmd::Completions { shell } => {
            call_machine_command(
                &client_endpoint,
                MachineCommand::Completions {
                    shell: shell.to_string(),
                },
            )
            .await
        }
        Cmd::Ipc(IpcCmd::Call { method, params }) => {
            let endpoint = client_endpoint;
            if !endpoint.socket.exists() {
                debug!(endpoint = %endpoint.display, "cli.ipc.call.no_socket: daemon may not be running");
            }
            let client = IpcClient::new(&endpoint.socket);
            let v: serde_json::Value = match params {
                Some(s) => serde_json::from_str(&s).context("parse params JSON")?,
                None => serde_json::Value::Null,
            };
            debug!(%method, endpoint = %endpoint.display, "cli.ipc.call");
            let result = try_ipc(&client, &endpoint, &method, v).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
    }
}

#[derive(Clone)]
struct CanonicalPetalSourceInstaller {
    home: HomeDir,
    daemon: Daemon,
}

impl bloom_daemon::ipc::PetalSourceInstallService for CanonicalPetalSourceInstaller {
    fn install_source(
        &self,
        params: serde_json::Value,
        context: bloom_daemon::ipc::IpcOperationContext,
    ) -> Result<serde_json::Value, String> {
        let path = params
            .get("path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "missing 'path'".to_owned())?;
        let requested_ref = params.get("ref").and_then(serde_json::Value::as_str);
        let repo = github_source::parse_github_install_url(path)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| {
                "trusted source installer requires a GitHub repository URL".to_owned()
            })?;
        let installed = match github_source::install_github_source_streaming(
            &self.home,
            &self.daemon,
            &repo,
            requested_ref,
            &context,
        ) {
            Ok(installed) => installed,
            Err(error) => {
                if let Some(failure) = github_source::source_install_failure(&error) {
                    return Ok(serde_json::json!({
                        "progress_lines": failure.progress,
                        "build_stdout_b64": B64.encode(&failure.stdout),
                        "build_stderr_b64": B64.encode(&failure.stderr),
                        "completion_progress_lines": failure.completion_progress,
                        "operation_error": failure.message,
                    }));
                }
                return Err(format!("{error:#}"));
            }
        };
        let selected = installed
            .provenance
            .selected_tag
            .as_deref()
            .unwrap_or(&installed.provenance.requested_ref);
        Ok(serde_json::json!({
            "hash": installed.result.hash,
            "mode": "petal",
            "size": installed.result.size,
            "already_present": installed.result.already_present,
            "petal_mount": installed.meta.petal.as_ref().map(|petal| format!("petals/{}/", petal.name)),
            "routes": installed.index.routes.len(),
            "source": format!("{}/{}@{}", installed.provenance.owner, installed.provenance.repo, selected),
            "resolved_commit": installed.provenance.resolved_commit,
            "progress_lines": installed.progress,
            "build_stdout_b64": B64.encode(&installed.build_stdout),
            "build_stderr_b64": B64.encode(&installed.build_stderr),
            "completion_progress_lines": installed.completion_progress,
            "consent_lines": petal_consent_lines(&installed.consent),
        }))
    }
}

fn required_petal_string<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .with_context(|| format!("ipc petals response: missing {field}"))
}

fn required_petal_u64(value: &serde_json::Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .with_context(|| format!("ipc petals response: missing {field}"))
}

fn print_ipc_lines(value: &serde_json::Value, field: &str) -> Result<()> {
    for line in value
        .get(field)
        .and_then(serde_json::Value::as_array)
        .with_context(|| format!("ipc petals response: missing {field}"))?
    {
        println!(
            "{}",
            line.as_str()
                .with_context(|| format!("ipc petals response: non-string {field}"))?
        );
    }
    Ok(())
}

fn print_ipc_captured_build_output(value: &serde_json::Value) -> Result<()> {
    if let Some(stdout) = value
        .get("build_stdout_b64")
        .and_then(serde_json::Value::as_str)
    {
        let bytes = B64.decode(stdout).context("decode captured build stdout")?;
        std::io::Write::write_all(&mut std::io::stdout(), &bytes)?;
        std::io::Write::flush(&mut std::io::stdout())?;
    }
    if let Some(stderr) = value
        .get("build_stderr_b64")
        .and_then(serde_json::Value::as_str)
    {
        let bytes = B64.decode(stderr).context("decode captured build stderr")?;
        std::io::Write::write_all(&mut std::io::stderr(), &bytes)?;
        std::io::Write::flush(&mut std::io::stderr())?;
    }
    Ok(())
}

fn write_ipc_output_event(event: IpcOutputEvent) -> std::io::Result<()> {
    match event.stream {
        IpcOutputStream::Stdout => {
            std::io::Write::write_all(&mut std::io::stdout(), &event.bytes)?;
            std::io::Write::flush(&mut std::io::stdout())
        }
        IpcOutputStream::Stderr => {
            std::io::Write::write_all(&mut std::io::stderr(), &event.bytes)?;
            std::io::Write::flush(&mut std::io::stderr())
        }
        IpcOutputStream::Data => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "command emitted an unexpected IPC data stream",
        )),
    }
}

fn absolute_cli_path(path: &str) -> Result<PathBuf> {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()
            .context("resolve CLI working directory")?
            .join(path))
    }
}

fn validate_petal_archive_output(package_dir: &str, out: &str) -> Result<()> {
    let package_dir = std::fs::canonicalize(package_dir)
        .with_context(|| format!("resolve Petal package directory {package_dir}"))?;
    let out_path = Path::new(out);
    let parent = out_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let output = std::fs::canonicalize(parent)
        .with_context(|| format!("resolve Petal archive parent {}", parent.display()))?
        .join(
            out_path
                .file_name()
                .context("Petal archive path has no file name")?,
        );
    anyhow::ensure!(
        !output.starts_with(package_dir),
        "--out must be outside the package directory so archives are not packaged into future builds"
    );
    Ok(())
}

async fn run_petals(endpoint: &ResolvedEndpoint, cmd: PetalsCmd) -> Result<()> {
    let client = IpcClient::new(&endpoint.socket);
    match cmd {
        PetalsCmd::Install { path, ref_ } => {
            let params = if path.contains("://") || path.starts_with("git@github.com:") {
                serde_json::json!({ "path": path, "ref": ref_ })
            } else {
                anyhow::ensure!(
                    ref_.is_none(),
                    "--ref is only supported for trusted GitHub source installs"
                );
                let local = absolute_cli_path(&path)?;
                serde_json::json!({ "path": local, "ref": null })
            };
            let reply = try_ipc_streaming(
                &client,
                endpoint,
                "petals.install",
                params,
                write_ipc_output_event,
            )
            .await
            .with_context(|| format!("ipc petals install via {}", endpoint.display))?;
            let result = reply.result;
            if reply.output_events == 0 && result.get("progress_lines").is_some() {
                print_ipc_lines(&result, "progress_lines")?;
            }
            if reply.output_events == 0 {
                print_ipc_captured_build_output(&result)?;
            }
            if reply.output_events == 0 && result.get("completion_progress_lines").is_some() {
                print_ipc_lines(&result, "completion_progress_lines")?;
            }
            if let Some(error) = result
                .get("operation_error")
                .and_then(serde_json::Value::as_str)
            {
                bail!("{error}");
            }
            println!("hash: {}", required_petal_string(&result, "hash")?);
            println!("mode: petal");
            println!("size: {} bytes", required_petal_u64(&result, "size")?);
            if result["already_present"].as_bool() == Some(true) {
                println!("note: already installed");
            }
            if let Some(mount) = result["petal_mount"].as_str() {
                println!("petal_mount: {mount}");
            }
            println!("routes: {}", required_petal_u64(&result, "routes")?);
            if let Some(source) = result["source"].as_str() {
                println!("source: {source}");
            }
            if let Some(commit) = result["resolved_commit"].as_str() {
                println!("resolved_commit: {commit}");
            }
            print_ipc_lines(&result, "consent_lines")?;
            Ok(())
        }
        PetalsCmd::Build { package_dir, out } => {
            if let Some(out) = out.as_deref() {
                validate_petal_archive_output(&package_dir, out)?;
            }
            let rpc_package_dir = absolute_cli_path(&package_dir)?;
            let rpc_out = out.as_deref().map(absolute_cli_path).transpose()?;
            let result = try_ipc(
                &client,
                endpoint,
                "petals.build",
                serde_json::json!({ "package_dir": rpc_package_dir, "out": rpc_out }),
            )
            .await
            .with_context(|| format!("ipc petals build via {}", endpoint.display))?;
            for field in ["hash", "contract", "wit_digest", "petal_mount", "routes"] {
                let value = result
                    .get(field)
                    .context("ipc petals build: missing response field")?;
                println!(
                    "{field}: {}",
                    value
                        .as_str()
                        .map_or_else(|| value.to_string(), str::to_owned)
                );
            }
            println!("artifacts: {package_dir}/artifacts");
            print_ipc_lines(&result, "consent_lines")?;
            if let Some(archive) = out {
                println!("archive: {archive}");
            }
            Ok(())
        }
        PetalsCmd::Ls => {
            let result = try_ipc(&client, endpoint, "petals.list", serde_json::Value::Null)
                .await
                .with_context(|| format!("ipc petals list via {}", endpoint.display))?;
            let entries = result
                .as_array()
                .context("ipc petals list: expected array")?;
            if entries.is_empty() {
                println!("(no petals installed)");
                return Ok(());
            }
            for entry in entries {
                let hash = required_petal_string(entry, "hash")?;
                let app = entry["petal_mount"]
                    .as_str()
                    .map(|mount| format!("  app={mount}"))
                    .unwrap_or_default();
                let source = entry["source"]
                    .as_object()
                    .map_or_else(String::new, |source| {
                        let selected = source
                            .get("selected_tag")
                            .and_then(|v| v.as_str())
                            .or_else(|| source.get("requested_ref").and_then(|v| v.as_str()))
                            .unwrap_or("?");
                        format!(
                            "  source={}/{}@{}",
                            source.get("owner").and_then(|v| v.as_str()).unwrap_or("?"),
                            source.get("repo").and_then(|v| v.as_str()).unwrap_or("?"),
                            selected
                        )
                    });
                println!(
                    "{}  {:<7}  {:>7}  caps=[]  name=-{}{}",
                    &hash[..bloom_petals::store::HASH_PREFIX_LEN.min(hash.len())],
                    "app",
                    required_petal_u64(entry, "size")?,
                    app,
                    source
                );
            }
            Ok(())
        }
        PetalsCmd::Uninstall { target } => {
            let result = try_ipc(
                &client,
                endpoint,
                "petals.uninstall",
                serde_json::json!({ "hash": target }),
            )
            .await
            .with_context(|| format!("ipc petals uninstall via {}", endpoint.display))?;
            let removed = result["removed"]
                .as_bool()
                .context("ipc petals uninstall: missing removed")?;
            if removed {
                println!("removed {target}");
            } else {
                println!("not installed: {target}");
            }
            Ok(())
        }
    }
}

fn petal_consent_lines(summary: &bloom_petals::package::PetalConsentSummary) -> Vec<String> {
    let mut lines = vec!["consent:".to_owned()];
    if let Some(package_summary) = &summary.package_summary {
        lines.push(format!("  summary: {package_summary}"));
    }
    lines.push(format!("  docs: {}", summary.docs.join(", ")));
    if !summary.capabilities.is_empty() {
        lines.push(format!(
            "  capabilities: {}",
            summary.capabilities.join(", ")
        ));
    }
    if !summary.network.is_empty() {
        lines.push("  network:".to_owned());
        for rule in &summary.network {
            lines.push(format_petal_consent_net_rule(rule));
        }
    }
    if !summary.sign_intents.is_empty() {
        lines.push(format!(
            "  signing_intents: {}",
            summary.sign_intents.join(", ")
        ));
    }
    if !summary.store_namespaces.is_empty() {
        lines.push("  private_store:".to_owned());
        for ns in &summary.store_namespaces {
            let visibility = if ns.secret { "secret" } else { "private" };
            lines.push(format!("    - {} {}", ns.namespace, visibility));
        }
    }
    if !summary.routes.is_empty() {
        lines.push("  routes:".to_owned());
        for route in &summary.routes {
            let ops = route
                .ops
                .iter()
                .map(|op| format!("{op:?}").to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join(",");
            let mut flags = Vec::new();
            if route.side_effecting_read {
                flags.push("side_effecting_read".to_string());
            }
            if route.write_async {
                flags.push("write_async".to_string());
            }
            if let Some(ttl) = route.cache_ttl_ms {
                flags.push(format!("cache_ttl_ms={ttl}"));
            }
            let caps = if route.required_caps.is_empty() {
                "-".to_string()
            } else {
                route.required_caps.join(",")
            };
            if flags.is_empty() {
                lines.push(format!(
                    "    - {} ops=[{}] caps=[{}]",
                    route.path, ops, caps
                ));
            } else {
                lines.push(format!(
                    "    - {} ops=[{}] caps=[{}] flags=[{}]",
                    route.path,
                    ops,
                    caps,
                    flags.join(",")
                ));
            }
        }
    }
    lines
}

fn format_petal_consent_net_rule(rule: &bloom_petals::package::PetalConsentNetRule) -> String {
    let binding = rule
        .binding
        .as_deref()
        .map(|binding| format!(" binding={binding}"))
        .unwrap_or_default();
    let effective = rule
        .effective_origin
        .as_deref()
        .map(|origin| format!(" effective_origin={origin}"))
        .unwrap_or_default();
    format!(
        "    - declared_host={}{}{} methods=[{}] paths=[{}]",
        rule.host,
        binding,
        effective,
        rule.methods.join(","),
        rule.paths.join(",")
    )
}

#[cfg(feature = "mount")]
async fn mount_bloom(
    daemon: &Daemon,
    mount: Option<&std::path::Path>,
) -> Result<Option<bloom_mount::NfsMountHandle>> {
    match mount {
        Some(path) => daemon
            .mount(path)
            .await
            .map(Some)
            .with_context(|| format!("mount bloom vfs at {}", path.display())),
        None => Ok(None),
    }
}

fn request_body_with_wallet(mut request: String, wallet: Option<&str>) -> String {
    let Some(wallet) = wallet else {
        return request;
    };
    if let Ok(mut value) = request.parse::<toml::Value>()
        && value.get("url").is_some()
        && let Some(table) = value.as_table_mut()
    {
        table.insert("wallet".into(), toml::Value::String(wallet.to_string()));
        return toml::to_string_pretty(&value).unwrap_or_else(|_| {
            let mut fallback = request.clone();
            fallback.push('\n');
            fallback.push_str(&format!("wallet = \"{wallet}\""));
            fallback
        });
    }
    let Some(first_newline) = request.find('\n') else {
        request.push(' ');
        request.push_str(&format!("wallet={wallet}"));
        return request;
    };
    request.insert_str(first_newline, &format!(" wallet={wallet}"));
    request
}

fn parse_batch_tx_ref(s: &str) -> Result<(String, String)> {
    let (chain, id) = s
        .split_once(':')
        .with_context(|| format!("tx ref '{s}' must be chain:id"))?;
    let chain = chain.trim();
    let id = id.trim();
    if chain.is_empty() || id.is_empty() {
        bail!("tx ref '{s}' must include non-empty chain and id");
    }
    Ok((chain.to_string(), id.to_string()))
}

async fn handle_update(home: &HomeDir, cmd: UpdateCmd) -> Result<(String, i32)> {
    match cmd {
        UpdateCmd::Status => {
            let installed = env!("CARGO_PKG_VERSION");
            let snap = bloom_update::read_cache_only(installed, &home.cache_dir());
            let json = serde_json::to_string_pretty(&snap).context("serialise update snapshot")?;
            Ok((format!("{json}\n"), 0))
        }
        UpdateCmd::Check => {
            // An explicit check needs only a checker; avoid constructing
            // the full daemon and its unrelated VFS/transaction services.
            let checker =
                bloom_update::UpdateChecker::new(env!("CARGO_PKG_VERSION"), home.cache_dir())
                    .context("build update checker")?;
            let snap = checker.refresh().await;
            let json = serde_json::to_string_pretty(&snap).context("serialise update snapshot")?;
            let code = match snap.available() {
                bloom_update::UpdateAvailable::OutOfDate => 1,
                bloom_update::UpdateAvailable::UpToDate => 0,
                bloom_update::UpdateAvailable::Unknown => 2,
            };
            Ok((format!("{json}\n"), code))
        }
    }
}

#[cfg(not(feature = "mount"))]
async fn mount_bloom(daemon: &Daemon, mount: Option<&std::path::Path>) -> Result<Option<()>> {
    let _ = daemon;
    match mount {
        Some(path) => anyhow::bail!(
            "mount support is not enabled in this build; rebuild with --features mount (release binaries are built with --all-features): {}",
            path.display()
        ),
        None => Ok(None),
    }
}

#[cfg(feature = "mount")]
async fn unmount_bloom(handle: Option<bloom_mount::NfsMountHandle>) -> Result<()> {
    if let Some(handle) = handle {
        bloom_mount::MountHandle::unmount(&handle)
            .await
            .context("unmount bloom vfs")?;
    }
    Ok(())
}

#[cfg(not(feature = "mount"))]
async fn unmount_bloom(handle: Option<()>) -> Result<()> {
    let _ = handle;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use clap::Parser as _;

    use super::{
        Cli, Cmd, LegacyMigrationReceiptFile, WalletCmd, ceremony_projection_path,
        endpoint_connection_error, enrollment_state_is_usable, execute_audit_command,
        execute_wallet_outbox_action, format_petal_consent_net_rule,
        is_completed_policy_update_receipt, launch_wallet_registration_via_vfs,
        load_ceremony_projection, machine_error_from_anyhow, machine_wallet_lookup_error,
        open_machine_audit_with_history, persist_ceremony_projection, request_body_with_wallet,
    };

    #[derive(Default)]
    struct RecordingOutboxHandler(Mutex<Vec<(String, Vec<u8>)>>);

    #[derive(Default)]
    struct RecordingRegistrationHandler(Mutex<Vec<(String, Vec<u8>)>>);

    #[async_trait]
    impl bloom_vfs::Handler for RecordingRegistrationHandler {
        async fn lookup(
            &self,
            path: &bloom_vfs::VfsPath,
        ) -> Result<bloom_vfs::Entry, bloom_vfs::HandlerError> {
            match path.segments() {
                [name] if name == "new" => Ok(bloom_vfs::Entry::writable_file("new")),
                [_, _, leaf] if leaf == "status.json" => Ok(bloom_vfs::Entry::file("status.json")),
                _ => Err(bloom_vfs::HandlerError::NotFound(path.to_string_path())),
            }
        }

        async fn read(
            &self,
            path: &bloom_vfs::VfsPath,
        ) -> Result<Vec<u8>, bloom_vfs::HandlerError> {
            if path.to_string_path() != "/registrations/gavin/status.json" {
                return Err(bloom_vfs::HandlerError::NotFound(path.to_string_path()));
            }
            Ok(serde_json::to_vec(&serde_json::json!({
                "schema": "bloom.machine-wallet-registration-projection.1",
                "requested_name": "gavin",
                "operation_id": "11".repeat(32),
                "ceremony_kind": "wallet_registration",
                "ceremony_state": "AWAITING_USER",
                "ceremony_url": "http://localhost:18734/ceremony/test-token",
                "ceremony_expires_at_ms": u64::MAX.to_string(),
                "signer_contribution_digest": "22".repeat(32),
            }))
            .unwrap())
        }

        async fn write(
            &self,
            path: &bloom_vfs::VfsPath,
            data: &[u8],
        ) -> Result<(), bloom_vfs::HandlerError> {
            self.0
                .lock()
                .unwrap()
                .push((path.to_string_path(), data.to_vec()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn wallet_new_machine_command_uses_the_mounted_registration_projection() {
        let handler = std::sync::Arc::new(RecordingRegistrationHandler::default());
        let vfs = bloom_vfs::Vfs::builder()
            .mount("wallets", handler.clone())
            .build();

        let output = launch_wallet_registration_via_vfs(&vfs, "gavin")
            .await
            .unwrap();

        assert_eq!(
            *handler.0.lock().unwrap(),
            vec![("/new".into(), b"gavin".to_vec())]
        );
        assert!(output.contains("operation_id: "));
        assert!(output.contains("ceremony_url: http://localhost:18734/ceremony/test-token\n"));
        assert!(output.contains("projection: /wallets/registrations/gavin/status.json\n"));
    }

    #[async_trait]
    impl bloom_vfs::Handler for RecordingOutboxHandler {
        async fn lookup(
            &self,
            path: &bloom_vfs::VfsPath,
        ) -> Result<bloom_vfs::Entry, bloom_vfs::HandlerError> {
            Ok(bloom_vfs::Entry::writable_file(
                path.segments().last().map(String::as_str).unwrap_or(""),
            ))
        }

        async fn write(
            &self,
            path: &bloom_vfs::VfsPath,
            data: &[u8],
        ) -> Result<(), bloom_vfs::HandlerError> {
            self.0
                .lock()
                .unwrap()
                .push((path.to_string_path(), data.to_vec()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn daemon_owned_wallet_outbox_actions_use_the_canonical_vfs_handler() {
        let handler = std::sync::Arc::new(RecordingOutboxHandler::default());
        let vfs = bloom_vfs::Vfs::builder()
            .mount("wallets", handler.clone())
            .build();

        execute_wallet_outbox_action(&vfs, "alice", "base", "tx-1", "cancel", b"approve")
            .await
            .unwrap();
        execute_wallet_outbox_action(
            &vfs,
            "alice",
            "base",
            "tx-1",
            "replace",
            b"replacement intent",
        )
        .await
        .unwrap();

        assert_eq!(
            *handler.0.lock().unwrap(),
            vec![
                (
                    "/alice/chains/base/outbox/pending/tx-1/cancel".into(),
                    b"approve".to_vec(),
                ),
                (
                    "/alice/chains/base/outbox/pending/tx-1/replace".into(),
                    b"replacement intent".to_vec(),
                ),
            ]
        );
    }

    #[tokio::test]
    async fn daemon_owned_wallet_outbox_actions_reject_path_shaping_params() {
        let vfs = bloom_vfs::Vfs::new();
        for invalid in ["bad/segment", "bad\\segment", "bad\0segment"] {
            for (wallet, chain, id) in [
                (invalid, "base", "tx-1"),
                ("alice", invalid, "tx-1"),
                ("alice", "base", invalid),
            ] {
                let error =
                    execute_wallet_outbox_action(&vfs, wallet, chain, id, "cancel", b"approve")
                        .await
                        .unwrap_err();
                let error = error
                    .downcast_ref::<bloom_daemon::ipc::MachineError>()
                    .unwrap();
                assert_eq!(
                    error.kind,
                    bloom_daemon::ipc::MachineErrorKind::InvalidParams,
                    "{wallet:?} {chain:?} {id:?}"
                );
                assert_eq!(error.code, "INVALID_ARGUMENT");
            }
        }
    }

    #[test]
    fn machine_error_mapping_uses_concrete_causes_not_context_words() {
        use bloom_broker_api::ProtocolErrorCode as Code;
        use bloom_daemon::ipc::MachineErrorKind as Kind;

        let cases = [
            (Code::MalformedFrame, Kind::InvalidParams),
            (Code::UnauthenticatedPeer, Kind::PermissionDenied),
            (Code::OperationIdConflict, Kind::Conflict),
            (Code::ServiceUnavailable, Kind::Unavailable),
        ];
        for (code, expected) in cases {
            let source = bloom_broker_api::ProtocolError::new(code, "typed cause");
            let mapped = machine_error_from_anyhow(anyhow::Error::new(source));
            assert_eq!(mapped.kind, expected, "{code:?}");
        }

        let missing = machine_wallet_lookup_error(bloom_broker_api::ProtocolError::new(
            Code::BackendInvalidRequest,
            "wallet absent",
        ));
        assert_eq!(missing.kind, Kind::NotFound);

        let refused = machine_error_from_anyhow(anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "Broker socket refused",
        )));
        assert_eq!(refused.kind, Kind::Unavailable);

        let misleading = anyhow::Error::new(bloom_broker_api::ProtocolError::new(
            Code::ServiceUnavailable,
            "Broker socket refused",
        ))
        .context("permission denied and invalid words in outer context");
        assert_eq!(
            machine_error_from_anyhow(misleading).kind,
            Kind::Unavailable
        );

        let unexpected = machine_error_from_anyhow(anyhow::anyhow!("unexpected failure"));
        assert_eq!(unexpected.kind, Kind::Internal);

        let invalid_path = machine_error_from_anyhow(anyhow::Error::new(
            bloom_vfs::path::PathError::InvalidSegment("bad\\segment".into()),
        ));
        assert_eq!(invalid_path.kind, Kind::InvalidParams);
        assert_eq!(invalid_path.code, "INVALID_ARGUMENT");
    }

    #[test]
    fn legacy_migration_receipt_is_digest_bound_and_cli_is_explicit() {
        let operation_id = bloom_broker_api::OperationId::from_bytes([81; 32]);
        let public = bloom_broker_api::LegacyPasskeyMigrationPublic {
            schema: bloom_broker_api::Token::new("bloom.legacy_passkey_migration_receipt.v1")
                .unwrap(),
            wallet_name: bloom_broker_api::Token::new("wallet").unwrap(),
            address: "0x1111111111111111111111111111111111111111".into(),
            public_key_fingerprint: bloom_broker_api::Digest32::from_bytes([82; 32]),
            credential_id_fingerprint: bloom_broker_api::Digest32::from_bytes([83; 32]),
            legacy_format_version: 1,
            bundle_digest: bloom_broker_api::Digest32::from_bytes([84; 32]),
            policy_mode: bloom_broker_api::Token::new("restrictive_current_policy").unwrap(),
        };
        let exact_terms_digest = public.terms_digest(&operation_id).unwrap();
        let receipt = LegacyMigrationReceiptFile {
            schema: public.schema.as_str().into(),
            operation_id: operation_id.clone(),
            wallet_name: public.wallet_name.clone(),
            address: public.address.clone(),
            public_key_fingerprint: public.public_key_fingerprint.clone(),
            credential_id_fingerprint: public.credential_id_fingerprint.clone(),
            legacy_format_version: public.legacy_format_version,
            bundle_digest: public.bundle_digest.clone(),
            policy_mode: public.policy_mode.as_str().into(),
            exact_terms_digest,
        };
        let (wallet_name, launch) = receipt.into_launch().unwrap();
        assert_eq!(wallet_name, "wallet");
        assert_eq!(launch.operation_id, operation_id);

        let tampered = LegacyMigrationReceiptFile {
            schema: public.schema.as_str().into(),
            operation_id: launch.operation_id,
            wallet_name: public.wallet_name,
            address: public.address,
            public_key_fingerprint: public.public_key_fingerprint,
            credential_id_fingerprint: public.credential_id_fingerprint,
            legacy_format_version: 2,
            bundle_digest: public.bundle_digest,
            policy_mode: public.policy_mode.as_str().into(),
            exact_terms_digest: launch.exact_terms_digest,
        };
        assert!(tampered.into_launch().is_err());

        let cli =
            Cli::try_parse_from(["bloom", "wallet", "migrate-passkey", "receipt.json"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Some(Cmd::Wallet(WalletCmd::MigratePasskey { receipt }))
                if receipt.as_os_str() == "receipt.json"
        ));
    }

    #[test]
    fn activating_enrollment_is_usable_only_for_installer_health() {
        assert!(enrollment_state_is_usable("active", false));
        assert!(enrollment_state_is_usable("active", true));
        assert!(enrollment_state_is_usable("activating", true));
        assert!(!enrollment_state_is_usable("activating", false));
        assert!(!enrollment_state_is_usable("pending", true));
    }

    #[test]
    fn audit_status_reports_malformed_evidence_as_degradation() {
        use std::io::Write as _;

        let temp = tempfile::tempdir().unwrap();
        let home = bloom_proto::HomeDir::at(temp.path());
        let path = home.audit_path();
        let identity = bloom_triad_local_transport::LocalIdentity {
            service_id: bloom_broker_api::Token::new("bloom-machine").unwrap(),
            boot_epoch: bloom_broker_api::BootEpoch::from_bytes([7; 16]),
            application_key_id: bloom_broker_api::Token::new("machine-app").unwrap(),
            signing_key: std::sync::Arc::new(ed25519_dalek::SigningKey::from_bytes(&[7; 32])),
        };
        let audit = open_machine_audit_with_history(
            &home,
            identity,
            &temp.path().join("missing-packaging-history.json"),
        )
        .unwrap();
        audit
            .append(bloom_proto::AuditRecord {
                ts_ms: 0,
                kind: "test.valid".into(),
                wallet: None,
                chain: None,
                data: serde_json::json!({}),
                prev: String::new(),
                digest: String::new(),
            })
            .unwrap();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "not-json-evidence").unwrap();
        file.sync_all().unwrap();

        let cli = Cli::try_parse_from(["bloom", "audit", "status"]).unwrap();
        let Some(Cmd::Audit(command)) = cli.cmd else {
            panic!("audit status must parse to the audit command handler");
        };
        let output = execute_audit_command(&command, &audit).unwrap();
        let status: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(status["mutation_degradation"].is_string());
        assert!(status["pending_effect_read_error"].is_string());
        assert_eq!(status["pending_effect_correlations"], serde_json::json!([]));
    }

    #[test]
    fn petal_consent_network_line_includes_named_binding() {
        let line = format_petal_consent_net_rule(&bloom_petals::package::PetalConsentNetRule {
            binding: Some("clob".into()),
            host: "clob.polymarket.com".into(),
            effective_origin: Some("https://clob.internal.example".into()),
            methods: vec!["POST".into()],
            paths: vec!["/order".into()],
        });
        assert_eq!(
            line,
            "    - declared_host=clob.polymarket.com binding=clob effective_origin=https://clob.internal.example methods=[POST] paths=[/order]"
        );
    }

    #[test]
    fn request_wallet_injection_preserves_http_message_body() {
        let input = concat!(
            "POST https://api.example.com/data\n",
            "content-type: application/json\n",
            "\n",
            "{\"ok\":true}"
        )
        .to_string();
        let output = request_body_with_wallet(input, Some("gavin"));
        assert!(output.starts_with("POST https://api.example.com/data wallet=gavin\n"));
        assert!(output.ends_with("\n\n{\"ok\":true}"));
    }

    #[test]
    fn custody_projection_persists_atomically_and_without_secret_world_access() {
        let temp = tempfile::tempdir().unwrap();
        let home = bloom_proto::HomeDir::at(temp.path());
        let operation_id = bloom_broker_api::OperationId::from_bytes([61; 32]);
        let status = bloom_broker_api::CeremonyPublicStatus {
            ceremony_id: bloom_broker_api::Digest32::from_bytes([62; 32]),
            ceremony_kind: bloom_broker_api::CeremonyKind::WalletImport,
            operation_id: operation_id.clone(),
            state: bloom_broker_api::CeremonyState::AwaitingUser,
            expires_at_ms: bloom_broker_api::DecimalU64::new(u64::MAX),
            ceremony_url: Some("http://localhost:18734/ceremony/owner-readable-secret".into()),
            receipt_digest: None,
        };
        let projection =
            bloom_machine_client::CeremonyProjection::from_custody_status(&status, 1).unwrap();
        let path = persist_ceremony_projection(&home, &projection).unwrap();
        assert_eq!(path, ceremony_projection_path(&home, operation_id.as_str()));
        assert_eq!(
            load_ceremony_projection(&home, &operation_id)
                .unwrap()
                .unwrap(),
            projection
        );
        assert!(
            std::fs::read_dir(path.parent().unwrap())
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".tmp"))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn ac26_every_custody_kind_exposes_launch_data_only_while_awaiting() {
        use bloom_broker_api::{
            CeremonyKind, CeremonyPublicStatus, CeremonyState, CustodyPrepareResponse, DecimalU64,
            Digest32, OperationId,
        };

        let custody_kinds = [
            CeremonyKind::WalletRegistration,
            CeremonyKind::WalletImport,
            CeremonyKind::WalletExport,
            CeremonyKind::WalletDelete,
            CeremonyKind::WalletRecovery,
            CeremonyKind::CredentialAdd,
            CeremonyKind::CredentialReplace,
            CeremonyKind::CredentialRemove,
            CeremonyKind::BackendEnrollment,
            CeremonyKind::KeyDerive,
            CeremonyKind::PolicyUpdate,
        ];
        let non_actionable_states = [
            CeremonyState::Prepared,
            CeremonyState::Verifying,
            CeremonyState::WalletCommitted,
            CeremonyState::AwaitingRecoveryAck,
            CeremonyState::Completed,
            CeremonyState::ApprovingRootChange,
            CeremonyState::CreatingCredential,
            CeremonyState::Committing,
            CeremonyState::Succeeded,
            CeremonyState::Cancelled,
            CeremonyState::Expired,
            CeremonyState::Failed,
        ];

        for (ordinal, kind) in custody_kinds.into_iter().enumerate() {
            let operation_id = OperationId::from_bytes([ordinal as u8 + 1; 32]);
            let expected_url = format!(
                "http://localhost:18734/ceremony/ac26-{}",
                operation_id.as_str()
            );
            let prepared = CustodyPrepareResponse {
                ceremony_kind: kind,
                custody_operation_id: operation_id.clone(),
                state: bloom_broker_api::CustodyPrepareState::AwaitingUser,
                ceremony_url: expected_url.clone(),
                ceremony_expires_at_ms: DecimalU64::new(10_000),
                signer_contribution_digest: Digest32::from_bytes([ordinal as u8 + 32; 32]),
            };
            let awaiting =
                bloom_machine_client::CeremonyProjection::from_custody_prepare(&prepared, 1_000)
                    .unwrap();
            assert_eq!(
                awaiting.ceremony_url(),
                Some(expected_url.as_str()),
                "{kind:?}"
            );
            assert_eq!(awaiting.expires_at_ms(), Some(10_000), "{kind:?}");
            let awaiting_json = serde_json::to_value(&awaiting).unwrap();
            assert_eq!(awaiting_json["ceremony_url"], expected_url, "{kind:?}");
            assert_eq!(awaiting_json["ceremony_expires_at_ms"], "10000", "{kind:?}");

            for state in non_actionable_states {
                let mut projection = awaiting.clone();
                projection
                    .reconcile_custody(
                        &CeremonyPublicStatus {
                            ceremony_id: Digest32::from_bytes([ordinal as u8 + 64; 32]),
                            ceremony_kind: kind,
                            operation_id: operation_id.clone(),
                            state,
                            expires_at_ms: DecimalU64::new(10_000),
                            // A compromised Broker must not make a non-actionable
                            // state owner-actionable by retaining a launch URL.
                            ceremony_url: Some(expected_url.clone()),
                            receipt_digest: matches!(
                                state,
                                CeremonyState::Completed | CeremonyState::Succeeded
                            )
                            .then(|| Digest32::from_bytes([ordinal as u8 + 96; 32])),
                        },
                        2_000,
                    )
                    .unwrap();
                assert_eq!(projection.ceremony_url(), None, "{kind:?} {state:?}");
                assert_eq!(projection.expires_at_ms(), None, "{kind:?} {state:?}");
                let persisted = serde_json::to_value(&projection).unwrap();
                assert!(persisted["ceremony_url"].is_null(), "{kind:?} {state:?}");
                assert!(
                    persisted["ceremony_expires_at_ms"].is_null(),
                    "{kind:?} {state:?}"
                );
            }
        }
    }

    #[test]
    fn policy_cli_exposes_prepare_and_receipt_only_commit() {
        let prepared = Cli::try_parse_from([
            "bloom",
            "wallet",
            "update-policy",
            "wallet",
            "--file",
            "proposed.json",
        ])
        .unwrap();
        assert!(matches!(
            prepared.cmd,
            Some(Cmd::Wallet(WalletCmd::UpdatePolicy {
                name,
                file,
                assurance_level,
            })) if name == "wallet"
                && file.as_os_str() == "proposed.json"
                && assurance_level == "user_verified"
        ));

        let committed =
            Cli::try_parse_from(["bloom", "wallet", "commit-policy", &"ab".repeat(32)]).unwrap();
        assert!(matches!(
            committed.cmd,
            Some(Cmd::Wallet(WalletCmd::CommitPolicy { .. }))
        ));
        assert!(
            Cli::try_parse_from(["bloom", "wallet", "update-policy", "wallet"]).is_err(),
            "prepare must require explicit proposed bytes"
        );
        assert!(
            Cli::try_parse_from(["bloom", "wallet", "sign-policy", "wallet"]).is_err(),
            "the legacy direct policy-signing path must stay removed"
        );
    }

    #[test]
    fn policy_commit_accepts_only_matching_completed_generic_custody_receipt() {
        let operation_id = bloom_broker_api::OperationId::from_bytes([71; 32]);
        let mut receipt = bloom_broker_api::CustodyResult {
            ceremony_kind: bloom_broker_api::CeremonyKind::PolicyUpdate,
            custody_operation_id: operation_id.clone(),
            public_status: bloom_broker_api::CeremonyState::Succeeded,
            wallet_id: Some(bloom_broker_api::Token::new("wallet").unwrap()),
            public_key_refs: Vec::new(),
            credential_summaries: Vec::new(),
            initial_policy: None,
            receipt_digest: bloom_broker_api::Digest32::from_bytes([72; 32]),
            encrypted_browser_result: None,
            signer_key_id: bloom_broker_api::Token::new("signer-ceremony-key").unwrap(),
            signer_signature: bloom_broker_api::Base64UrlBytes::from_bytes(&[73; 64]),
        };
        assert!(is_completed_policy_update_receipt(&receipt, &operation_id));

        receipt.public_status = bloom_broker_api::CeremonyState::Completed;
        assert!(!is_completed_policy_update_receipt(&receipt, &operation_id));
        receipt.public_status = bloom_broker_api::CeremonyState::Succeeded;
        receipt.ceremony_kind = bloom_broker_api::CeremonyKind::WalletDelete;
        assert!(!is_completed_policy_update_receipt(&receipt, &operation_id));
    }

    #[test]
    fn production_cli_has_no_in_process_daemon_fallback_call_site() {
        let source = include_str!("main.rs");
        let read_fallback = concat!("build_authenticated_", "read_daemon");
        let in_process_log = concat!("via_", "inproc");
        let fallback_log = concat!("ipc.no_daemon_", "fallback");
        let write_builder = concat!("build_write_", "daemon(home.clone())");
        assert!(
            !source.contains(read_fallback),
            "production CLI commands must never construct a read fallback daemon"
        );
        assert_eq!(
            source.matches(write_builder).count(),
            2,
            "only init and serve may construct the daemon"
        );
        assert!(!source.contains(fallback_log));
        assert!(!source.contains(in_process_log));
        let raw_process_args = concat!("std::env::", "args_os()");
        assert!(
            !source.contains(raw_process_args),
            "internal lifecycle protocols must be parsed below init or serve, not before Clap"
        );
    }

    #[test]
    fn permission_denied_endpoint_error_includes_daemon_recovery_instruction() {
        let error = endpoint_connection_error(
            "unix:/restricted/bloom.sock",
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        );
        let message = error.to_string();
        assert!(message.contains("unix:/restricted/bloom.sock"), "{message}");
        assert!(message.contains("bloom serve"), "{message}");
    }
}
