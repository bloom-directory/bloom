//! Keyless production Machine process.

#![forbid(unsafe_code)]

use std::{
    path::{Path, PathBuf},
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use bloom_broker_api::{
    Base64UrlBytes, CanonicalWalletPolicy, CeremonyKind, CeremonyState, CustodyResult, Digest32,
    Empty, MachineBrokerRequest, MachineBrokerResponse, OperationId, OperationRequest,
    PolicyCommitUpdateRequest, PolicyUpdateRequest, ProtocolError, ProtocolErrorCode, Token,
};
use bloom_machine_client::{
    CeremonyProjection, MachineBrokerClient, claimed_policy_authority_diff_digest,
};
use clap::{Parser, Subcommand};
use rand::RngCore as _;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const CEREMONY_OWNER_HEADER: &str = "x-bloom-ceremony-owner";
const CEREMONY_OWNER_VALUE: &str = "bloom-broker-v1";
const CEREMONY_DIAGNOSTIC_ADDR: &str = "127.0.0.1:18734";

const MAX_POLICY_DOCUMENT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "bloom-machine", version)]
struct Cli {
    #[arg(
        long,
        env = "BLOOM_BROKER_SOCKET",
        default_value = "/var/run/bloom/broker.sock"
    )]
    broker_socket: PathBuf,
    #[arg(
        long,
        env = "BLOOM_MACHINE_IDENTITY",
        default_value = "/var/run/bloom/machine-identity.json"
    )]
    identity: PathBuf,
    #[arg(
        long,
        env = "BLOOM_EDGE_MANIFEST",
        default_value = "/etc/bloom/edge-manifest.json"
    )]
    edge_manifest: PathBuf,
    /// Owner-private Machine projection state.
    #[arg(
        long,
        env = "BLOOM_MACHINE_STATE",
        default_value = "/var/lib/bloom-machine"
    )]
    state_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Query Broker readiness through the authenticated Machine edge.
    Readiness,
    /// Query the exact compiled Broker capability set.
    Capabilities,
    /// Dispatch one closed-schema Machine→Broker request from stdin.
    Request,
    /// Inspect, cancel, or retrieve a shared custody ceremony.
    #[command(subcommand)]
    Ceremony(CeremonyCommand),
    /// Inspect or cancel a Broker operation before downstream acceptance.
    #[command(subcommand)]
    Operation(OperationCommand),
    /// Prepare or commit a canonical wallet-policy update.
    #[command(subcommand)]
    Policy(PolicyCommand),
}

#[derive(Debug, Subcommand)]
enum CeremonyCommand {
    Status {
        operation_id: String,
    },
    Cancel {
        operation_id: String,
    },
    /// Print only public custody result fields. Encrypted Browser output is
    /// deliberately not emitted.
    Result {
        operation_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum OperationCommand {
    Status { operation_id: String },
    Cancel { operation_id: String },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Canonicalize proposed JSON and invoke policy.validate_update, which is
    /// the Broker-originated policy_update custody prepare.
    Update {
        wallet_id: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long, default_value = "user_verified")]
        assurance_level: String,
    },
    /// Retrieve the completed generic custody receipt, then invoke
    /// policy.commit_update. There is no direct commit form.
    Commit { operation_id: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let broker = MachineBrokerClient::connect_unix_from_files(
        cli.broker_socket,
        cli.identity,
        cli.edge_manifest,
    )
    .context("load authenticated Machine-to-Broker edge")?;

    let result = match cli.command {
        Command::Readiness => {
            dispatch_and_print(
                &broker,
                &cli.state_dir,
                MachineBrokerRequest::BrokerReadiness(Empty {}),
            )
            .await
        }
        Command::Capabilities => {
            dispatch_and_print(
                &broker,
                &cli.state_dir,
                MachineBrokerRequest::BrokerCapabilities(Empty {}),
            )
            .await
        }
        Command::Request => {
            let request = serde_json::from_reader(std::io::stdin().lock())
                .context("decode closed Machine-to-Broker request from stdin")?;
            dispatch_and_print(&broker, &cli.state_dir, request).await
        }
        Command::Ceremony(command) => handle_ceremony(&broker, &cli.state_dir, command).await,
        Command::Operation(command) => handle_operation(&broker, command).await,
        Command::Policy(command) => handle_policy(&broker, &cli.state_dir, command).await,
    };
    if let Err(error) = &result
        && error
            .chain()
            .filter_map(|cause| cause.downcast_ref::<ProtocolError>())
            .any(is_broker_connect_failure)
    {
        report_ceremony_listener_owner().await;
    }
    result
}

async fn handle_operation(broker: &MachineBrokerClient, command: OperationCommand) -> Result<()> {
    let (raw_operation_id, cancel) = match command {
        OperationCommand::Status { operation_id } => (operation_id, false),
        OperationCommand::Cancel { operation_id } => (operation_id, true),
    };
    let operation_id = parse_operation_id(raw_operation_id)?;
    let status = if cancel {
        broker
            .cancel_operation(operation_id.clone())
            .await
            .context("cancel Broker operation before downstream acceptance")?
    } else {
        broker
            .operation_status(operation_id.clone())
            .await
            .context("read Broker operation status")?
    };
    anyhow::ensure!(
        status.operation_id == operation_id,
        "Broker operation status identity mismatch"
    );
    serde_json::to_writer_pretty(std::io::stdout().lock(), &status)
        .context("encode Broker operation status")?;
    println!();
    Ok(())
}

fn is_broker_connect_failure(error: &ProtocolError) -> bool {
    error.code == ProtocolErrorCode::ServiceUnavailable
        && error.message.starts_with("connect Broker:")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CeremonyListenerOwner {
    BloomBroker,
    ForeignProcess,
    Unbound,
}

async fn report_ceremony_listener_owner() {
    eprintln!(
        "{}",
        ceremony_listener_diagnostic(probe_ceremony_listener_owner().await)
    );
}

fn ceremony_listener_diagnostic(owner: CeremonyListenerOwner) -> String {
    match owner {
        CeremonyListenerOwner::BloomBroker => format!(
            "Bloom Broker startup failed: a Bloom Broker appears to own the canonical ceremony listener at {CEREMONY_DIAGNOSTIC_ADDR}, normally because another login session acquired it first; this login fails closed"
        ),
        CeremonyListenerOwner::ForeignProcess => format!(
            "Bloom Broker startup failed: a foreign process occupies the canonical ceremony listener at {CEREMONY_DIAGNOSTIC_ADDR}; no fallback port will be used"
        ),
        CeremonyListenerOwner::Unbound => format!(
            "Bloom Broker is unavailable and no process currently owns the canonical ceremony listener at {CEREMONY_DIAGNOSTIC_ADDR}; the service manager may still be retrying activation"
        ),
    }
}

async fn probe_ceremony_listener_owner() -> CeremonyListenerOwner {
    probe_ceremony_listener_owner_at(CEREMONY_DIAGNOSTIC_ADDR).await
}

async fn probe_ceremony_listener_owner_at(address: &str) -> CeremonyListenerOwner {
    let Ok(Ok(mut stream)) = tokio::time::timeout(
        Duration::from_millis(500),
        tokio::net::TcpStream::connect(address),
    )
    .await
    else {
        return CeremonyListenerOwner::Unbound;
    };
    let request = b"GET / HTTP/1.1\r\nHost: localhost:18734\r\nConnection: close\r\n\r\n";
    if tokio::time::timeout(Duration::from_millis(500), stream.write_all(request))
        .await
        .is_err()
    {
        return CeremonyListenerOwner::ForeignProcess;
    }
    let mut response = Vec::with_capacity(2048);
    let read = tokio::time::timeout(
        Duration::from_millis(500),
        stream.take(8192).read_to_end(&mut response),
    )
    .await;
    if read.is_err() {
        return CeremonyListenerOwner::ForeignProcess;
    }
    classify_ceremony_listener_response(&response)
}

fn classify_ceremony_listener_response(response: &[u8]) -> CeremonyListenerOwner {
    let response = String::from_utf8_lossy(response).to_ascii_lowercase();
    let marker = format!("\r\n{}: {}", CEREMONY_OWNER_HEADER, CEREMONY_OWNER_VALUE);
    if response.contains(&marker) {
        CeremonyListenerOwner::BloomBroker
    } else {
        CeremonyListenerOwner::ForeignProcess
    }
}

async fn dispatch_and_print(
    broker: &MachineBrokerClient,
    state_dir: &Path,
    request: MachineBrokerRequest,
) -> Result<()> {
    preflight_raw_projection(state_dir, &request)?;
    let response = broker.request(request.clone()).await?;
    require_matching_method(&request, &response)?;
    reconcile_raw_projection(state_dir, &request, &response)?;
    serde_json::to_writer(std::io::stdout().lock(), &response).context("write Broker response")?;
    println!();
    Ok(())
}

async fn handle_ceremony(
    broker: &MachineBrokerClient,
    state_dir: &Path,
    command: CeremonyCommand,
) -> Result<()> {
    let (raw_operation_id, action) = match command {
        CeremonyCommand::Status { operation_id } => (operation_id, "status"),
        CeremonyCommand::Cancel { operation_id } => (operation_id, "cancel"),
        CeremonyCommand::Result { operation_id } => (operation_id, "result"),
    };
    let operation_id = parse_operation_id(raw_operation_id)?;
    if action == "result" {
        let result = broker
            .custody_result(OperationRequest {
                operation_id: operation_id.clone(),
            })
            .await
            .context("retrieve Broker custody result")?;
        anyhow::ensure!(
            result.custody_operation_id == operation_id,
            "Broker custody result operation identity mismatch"
        );
        reconcile_custody_result(state_dir, &result)?;
        print_public_custody_result(&result)?;
        return Ok(());
    }

    let status = if action == "cancel" {
        broker
            .cancel_ceremony(operation_id.clone())
            .await
            .context("cancel Broker ceremony")?
    } else {
        broker
            .ceremony_status(operation_id.clone())
            .await
            .context("read Broker ceremony status")?
    };
    anyhow::ensure!(
        status.operation_id == operation_id,
        "Broker ceremony status operation identity mismatch"
    );
    let now_ms = current_unix_ms();
    let mut projection = match load_projection(state_dir, &operation_id)? {
        Some(mut projection) => {
            projection
                .reconcile_custody(&status, now_ms)
                .context("reconcile durable Machine ceremony projection")?;
            projection
        }
        None => CeremonyProjection::from_custody_status(&status, now_ms)
            .context("rebuild Machine ceremony projection from Broker")?,
    };
    projection.expire_launch_secret(now_ms);
    let path = persist_projection(state_dir, &projection)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&projection).context("encode ceremony projection")?
    );
    println!("projection: {}", path.display());
    Ok(())
}

async fn handle_policy(
    broker: &MachineBrokerClient,
    state_dir: &Path,
    command: PolicyCommand,
) -> Result<()> {
    match command {
        PolicyCommand::Update {
            wallet_id,
            file,
            assurance_level,
        } => prepare_policy_update(broker, state_dir, wallet_id, &file, assurance_level).await,
        PolicyCommand::Commit { operation_id } => {
            commit_policy_update(broker, state_dir, operation_id).await
        }
    }
}

async fn prepare_policy_update(
    broker: &MachineBrokerClient,
    state_dir: &Path,
    raw_wallet_id: String,
    policy_file: &Path,
    raw_assurance_level: String,
) -> Result<()> {
    let wallet_id = Token::new(raw_wallet_id).context("wallet ID must be a protocol token")?;
    let assurance_level =
        Token::new(raw_assurance_level).context("assurance level must be a protocol token")?;
    let proposed_input = read_policy_file(policy_file)?;
    let proposed: CanonicalWalletPolicy = serde_json::from_slice(&proposed_input)
        .with_context(|| format!("parse proposed policy {}", policy_file.display()))?;
    anyhow::ensure!(
        proposed.wallet_id == wallet_id,
        "proposed policy wallet_id does not match requested wallet"
    );
    let proposed_bytes =
        serde_jcs::to_vec(&proposed).context("canonicalize proposed policy document")?;

    let baseline = broker
        .policy(wallet_id.clone())
        .await
        .context("read Signer-authenticated policy baseline from Broker")?;
    let baseline_bytes = baseline.canonical_policy.decode();
    anyhow::ensure!(
        Digest32::from_bytes(Sha256::digest(&baseline_bytes).into()) == baseline.policy_digest,
        "Broker policy baseline digest does not match its canonical bytes"
    );
    let baseline_policy: CanonicalWalletPolicy =
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

    let authority_diff_digest = claimed_policy_authority_diff_digest(&baseline_policy, &proposed)
        .context("digest claimed policy authority diff")?;
    let mut operation_bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut operation_bytes);
    let request = PolicyUpdateRequest {
        operation_id: OperationId::from_bytes(operation_bytes),
        wallet_id,
        baseline_version: baseline.version,
        baseline_digest: baseline.policy_digest,
        proposed_canonical_policy: Base64UrlBytes::from_bytes(&proposed_bytes),
        proposed_policy_digest: Digest32::from_bytes(Sha256::digest(&proposed_bytes).into()),
        authority_diff_digest,
        assurance_level,
    };
    let prepared = broker
        .validate_policy_update(request)
        .await
        .context("validate policy update and prepare Broker-originated ceremony")?;
    let projection = CeremonyProjection::from_policy_prepare(&prepared, current_unix_ms())
        .context("construct policy-update projection")?;
    let path = persist_projection(state_dir, &projection)?;
    println!("operation_id: {}", prepared.operation_id);
    println!("ceremony_kind: {:?}", prepared.ceremony_kind);
    println!(
        "review_manifest_digest: {}",
        prepared.review_manifest_digest
    );
    println!("ceremony_url: {}", prepared.ceremony_url);
    println!(
        "ceremony_expires_at_ms: {}",
        prepared.ceremony_expires_at_ms.get()
    );
    println!("projection: {}", path.display());
    Ok(())
}

async fn commit_policy_update(
    broker: &MachineBrokerClient,
    state_dir: &Path,
    raw_operation_id: String,
) -> Result<()> {
    let operation_id = parse_operation_id(raw_operation_id)?;
    let ceremony_receipt = broker
        .custody_result(OperationRequest {
            operation_id: operation_id.clone(),
        })
        .await
        .context("retrieve completed policy-update custody receipt")?;
    anyhow::ensure!(
        is_completed_policy_update_receipt(&ceremony_receipt, &operation_id),
        "policy commit requires the matching completed policy_update ceremony receipt"
    );
    let terminal_result = ceremony_receipt.clone();
    reconcile_custody_result(state_dir, &terminal_result)?;
    let receipt = broker
        .commit_policy_update(PolicyCommitUpdateRequest {
            operation_id: operation_id.clone(),
            ceremony_receipt,
        })
        .await
        .context("commit policy update through Broker and Signer compare-and-swap")?;
    anyhow::ensure!(
        receipt.operation_id == operation_id,
        "Broker policy commit receipt operation identity mismatch"
    );

    println!(
        "{}",
        serde_json::to_string_pretty(&receipt).context("encode policy commit receipt")?
    );
    Ok(())
}

fn read_policy_file(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let file = std::fs::File::open(path)
        .with_context(|| format!("open proposed policy {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect proposed policy {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= MAX_POLICY_DOCUMENT_BYTES,
        "proposed policy must be a regular file no larger than {MAX_POLICY_DOCUMENT_BYTES} bytes"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_POLICY_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read proposed policy {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_POLICY_DOCUMENT_BYTES,
        "proposed policy exceeds {MAX_POLICY_DOCUMENT_BYTES} bytes"
    );
    Ok(bytes)
}

fn is_completed_policy_update_receipt(receipt: &CustodyResult, operation_id: &OperationId) -> bool {
    receipt.custody_operation_id == *operation_id
        && receipt.ceremony_kind == CeremonyKind::PolicyUpdate
        && receipt.public_status == CeremonyState::Succeeded
}

fn print_public_custody_result(result: &CustodyResult) -> Result<()> {
    println!(
        "{}",
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
    );
    Ok(())
}

fn parse_operation_id(raw: String) -> Result<OperationId> {
    OperationId::new(raw).context("operation ID must be 64 lowercase hexadecimal characters")
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn projection_path(state_dir: &Path, projection_id: &str) -> PathBuf {
    state_dir
        .join("ceremonies")
        .join(format!("{projection_id}.json"))
}

fn persist_projection(state_dir: &Path, projection: &CeremonyProjection) -> Result<PathBuf> {
    use std::io::Write as _;

    let projection_id = projection
        .operation_id()
        .map(OperationId::as_str)
        .or_else(|| projection.approval_id().map(Digest32::as_str))
        .context("ceremony projection is missing identity")?;
    let path = projection_path(state_dir, projection_id);
    let parent = path.parent().context("ceremony projection parent")?;
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("protect {}", parent.display()))?;
    }
    let mut suffix = [0_u8; 8];
    rand::thread_rng().fill_bytes(&mut suffix);
    let temp_path = parent.join(format!(".{}.{}.tmp", projection_id, hex::encode(suffix)));
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

fn load_projection(
    state_dir: &Path,
    operation_id: &OperationId,
) -> Result<Option<CeremonyProjection>> {
    load_projection_by_id(state_dir, operation_id.as_str())
}

fn load_projection_by_id(
    state_dir: &Path,
    projection_id: &str,
) -> Result<Option<CeremonyProjection>> {
    let path = projection_path(state_dir, projection_id);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("parse {}", path.display()))
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn reconcile_custody_result(state_dir: &Path, result: &CustodyResult) -> Result<()> {
    let projection = match load_projection(state_dir, &result.custody_operation_id)? {
        Some(mut projection) => {
            projection
                .reconcile_custody_result(result)
                .context("reconcile terminal custody result")?;
            projection
        }
        None => CeremonyProjection::from_custody_result(result),
    };
    persist_projection(state_dir, &projection)?;
    Ok(())
}

fn reconcile_raw_projection(
    state_dir: &Path,
    request: &MachineBrokerRequest,
    response: &MachineBrokerResponse,
) -> Result<()> {
    let now_ms = current_unix_ms();
    match (request, response) {
        (
            MachineBrokerRequest::SealedApprovalPrepare(_)
            | MachineBrokerRequest::SealedApprovalRenew(_),
            MachineBrokerResponse::SealedApprovalPrepare(prepared)
            | MachineBrokerResponse::SealedApprovalRenew(prepared),
        ) => {
            let projection = CeremonyProjection::from_approval_prepare(prepared, now_ms)
                .context("construct approval projection")?;
            persist_projection(state_dir, &projection)?;
        }
        (
            MachineBrokerRequest::SealedApprovalStatus(_)
            | MachineBrokerRequest::SealedApprovalRevoke(_),
            MachineBrokerResponse::SealedApprovalStatus(status)
            | MachineBrokerResponse::SealedApprovalRevoke(status),
        ) => {
            if let Some(mut projection) =
                load_projection_by_id(state_dir, status.approval_id.as_str())?
            {
                projection
                    .reconcile_approval(status, now_ms)
                    .context("reconcile approval projection")?;
                projection.expire_launch_secret(now_ms);
                persist_projection(state_dir, &projection)?;
            }
        }
        (
            MachineBrokerRequest::PolicyValidateUpdate(_),
            MachineBrokerResponse::PolicyValidateUpdate(prepared),
        ) => {
            let projection = CeremonyProjection::from_policy_prepare(prepared, now_ms)
                .context("construct policy-update projection")?;
            persist_projection(state_dir, &projection)?;
        }
        (
            MachineBrokerRequest::WalletRegistrationPrepare(_),
            MachineBrokerResponse::WalletRegistrationPrepare(prepared),
        )
        | (
            MachineBrokerRequest::WalletUnlockPrepare(_),
            MachineBrokerResponse::WalletUnlockPrepare(prepared),
        )
        | (
            MachineBrokerRequest::WalletImportPrepare(_),
            MachineBrokerResponse::WalletImportPrepare(prepared),
        )
        | (
            MachineBrokerRequest::WalletExportPrepare(_),
            MachineBrokerResponse::WalletExportPrepare(prepared),
        )
        | (
            MachineBrokerRequest::WalletDeletePrepare(_),
            MachineBrokerResponse::WalletDeletePrepare(prepared),
        )
        | (
            MachineBrokerRequest::KeyDerivePrepare(_),
            MachineBrokerResponse::KeyDerivePrepare(prepared),
        )
        | (
            MachineBrokerRequest::KeyEnrollPrepare(_),
            MachineBrokerResponse::KeyEnrollPrepare(prepared),
        )
        | (
            MachineBrokerRequest::CredentialAddPrepare(_),
            MachineBrokerResponse::CredentialAddPrepare(prepared),
        )
        | (
            MachineBrokerRequest::CredentialReplacePrepare(_),
            MachineBrokerResponse::CredentialReplacePrepare(prepared),
        )
        | (
            MachineBrokerRequest::CredentialRemovePrepare(_),
            MachineBrokerResponse::CredentialRemovePrepare(prepared),
        )
        | (
            MachineBrokerRequest::RecoveryPrepare(_),
            MachineBrokerResponse::RecoveryPrepare(prepared),
        ) => {
            let projection = CeremonyProjection::from_custody_prepare(prepared, now_ms)
                .context("construct custody projection")?;
            persist_projection(state_dir, &projection)?;
        }
        (
            MachineBrokerRequest::CeremonyStatus(_) | MachineBrokerRequest::CeremonyCancel(_),
            MachineBrokerResponse::CeremonyStatus(status)
            | MachineBrokerResponse::CeremonyCancel(status),
        ) => {
            let mut projection = match load_projection(state_dir, &status.operation_id)? {
                Some(projection) => projection,
                None => CeremonyProjection::from_custody_status(status, now_ms)
                    .context("rebuild custody projection")?,
            };
            projection
                .reconcile_custody(status, now_ms)
                .context("reconcile custody projection")?;
            projection.expire_launch_secret(now_ms);
            persist_projection(state_dir, &projection)?;
        }
        (MachineBrokerRequest::CustodyResult(_), MachineBrokerResponse::CustodyResult(result)) => {
            reconcile_custody_result(state_dir, result)?
        }
        (
            MachineBrokerRequest::PolicyCommitUpdate(commit),
            MachineBrokerResponse::PolicyCommitUpdate(_),
        ) => reconcile_custody_result(state_dir, &commit.ceremony_receipt)?,
        _ => {}
    }
    Ok(())
}

fn preflight_raw_projection(state_dir: &Path, request: &MachineBrokerRequest) -> Result<()> {
    if let MachineBrokerRequest::PolicyCommitUpdate(commit) = request {
        anyhow::ensure!(
            is_completed_policy_update_receipt(&commit.ceremony_receipt, &commit.operation_id),
            "policy commit requires the matching completed policy_update ceremony receipt"
        );
        reconcile_custody_result(state_dir, &commit.ceremony_receipt)?;
    }
    Ok(())
}

fn require_matching_method(
    request: &MachineBrokerRequest,
    response: &MachineBrokerResponse,
) -> Result<(), ProtocolError> {
    let request_method = serde_json::to_value(request).ok().and_then(|value| {
        value
            .get("method")
            .and_then(|method| method.as_str())
            .map(str::to_owned)
    });
    let response_method = serde_json::to_value(response).ok().and_then(|value| {
        value
            .get("method")
            .and_then(|method| method.as_str())
            .map(str::to_owned)
    });
    if request_method != response_method {
        return Err(ProtocolError::new(
            ProtocolErrorCode::MalformedFrame,
            "Broker response method does not match the Machine request",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command as ProcessCommand;

    fn completed_receipt(operation_id: OperationId) -> CustodyResult {
        CustodyResult {
            ceremony_kind: CeremonyKind::PolicyUpdate,
            custody_operation_id: operation_id,
            public_status: CeremonyState::Succeeded,
            wallet_id: Some(Token::new("wallet").unwrap()),
            public_key_refs: Vec::new(),
            credential_summaries: Vec::new(),
            initial_policy: None,
            receipt_digest: Digest32::from_bytes([42; 32]),
            encrypted_browser_result: None,
            signer_key_id: Token::new("signer-ceremony-key").unwrap(),
            signer_signature: Base64UrlBytes::from_bytes(&[43; 64]),
        }
    }

    #[test]
    fn policy_surface_has_prepare_and_receipt_only_commit() {
        let prepared = Cli::try_parse_from([
            "bloom-machine",
            "policy",
            "update",
            "wallet",
            "--file",
            "proposed.json",
        ])
        .unwrap();
        assert!(matches!(
            prepared.command,
            Command::Policy(PolicyCommand::Update { .. })
        ));
        let committed =
            Cli::try_parse_from(["bloom-machine", "policy", "commit", &"ab".repeat(32)]).unwrap();
        assert!(matches!(
            committed.command,
            Command::Policy(PolicyCommand::Commit { .. })
        ));
        assert!(
            Cli::try_parse_from(["bloom-machine", "policy", "prepare"]).is_err(),
            "there is no additional policy prepare method"
        );
    }

    #[test]
    fn commit_guard_accepts_only_generic_completed_policy_receipt() {
        let operation_id = OperationId::from_bytes([41; 32]);
        let mut receipt = completed_receipt(operation_id.clone());
        assert!(is_completed_policy_update_receipt(&receipt, &operation_id));
        receipt.public_status = CeremonyState::Completed;
        assert!(!is_completed_policy_update_receipt(&receipt, &operation_id));
    }

    #[test]
    fn listener_diagnostic_distinguishes_bloom_from_a_foreign_process() {
        let bloom = b"HTTP/1.1 404 Not Found\r\nX-Bloom-Ceremony-Owner: bloom-broker-v1\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            classify_ceremony_listener_response(bloom),
            CeremonyListenerOwner::BloomBroker
        );
        assert_eq!(
            classify_ceremony_listener_response(b"HTTP/1.1 200 OK\r\nServer: unrelated\r\n\r\n"),
            CeremonyListenerOwner::ForeignProcess
        );
        assert_eq!(
            classify_ceremony_listener_response(
                b"HTTP/1.1 200 OK\r\nX-Bloom-Ceremony-Owner: bloom-broker-v2\r\n\r\n"
            ),
            CeremonyListenerOwner::ForeignProcess,
            "unknown marker versions fail closed as foreign"
        );
        let bloom_message = ceremony_listener_diagnostic(CeremonyListenerOwner::BloomBroker);
        assert!(bloom_message.contains("another login session acquired it first"));
        assert!(bloom_message.contains("fails closed"));
        let foreign_message = ceremony_listener_diagnostic(CeremonyListenerOwner::ForeignProcess);
        assert!(foreign_message.contains("foreign process occupies"));
        assert!(foreign_message.contains("no fallback port"));
        assert!(is_broker_connect_failure(&ProtocolError::new(
            ProtocolErrorCode::ServiceUnavailable,
            "connect Broker: connection refused"
        )));
        assert!(
            !is_broker_connect_failure(&ProtocolError::new(
                ProtocolErrorCode::ServiceUnavailable,
                "Signer is unavailable"
            )),
            "an application-level outage must not be misreported as listener ownership"
        );
    }

    #[tokio::test]
    async fn listener_diagnostic_is_bounded_without_claiming_the_production_port() {
        assert_eq!(CEREMONY_DIAGNOSTIC_ADDR, "127.0.0.1:18734");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("ephemeral listener must be available for the focused diagnostic test");
        let test_address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (mut bloom, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 128];
            let _ = bloom.read(&mut request).await.unwrap();
            bloom
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nX-Bloom-Ceremony-Owner: bloom-broker-v1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        assert_eq!(
            probe_ceremony_listener_owner_at(&test_address).await,
            CeremonyListenerOwner::BloomBroker
        );
        server.await.unwrap();

        assert_eq!(
            probe_ceremony_listener_owner_at(&test_address).await,
            CeremonyListenerOwner::Unbound,
            "a freed listener is not misreported as a foreign owner"
        );
    }

    #[test]
    fn projection_is_atomic_owner_only_and_drops_terminal_url() {
        let temp = tempfile::tempdir().unwrap();
        let operation_id = OperationId::from_bytes([44; 32]);
        let status = bloom_broker_api::CeremonyPublicStatus {
            ceremony_id: Digest32::from_bytes([45; 32]),
            ceremony_kind: CeremonyKind::PolicyUpdate,
            operation_id: operation_id.clone(),
            state: CeremonyState::AwaitingUser,
            expires_at_ms: bloom_broker_api::DecimalU64::new(u64::MAX),
            ceremony_url: Some("http://localhost:18734/ceremony/owner-secret".into()),
            receipt_digest: None,
        };
        let projection = CeremonyProjection::from_custody_status(&status, 1).unwrap();
        let path = persist_projection(temp.path(), &projection).unwrap();
        assert_eq!(
            load_projection(temp.path(), &operation_id)
                .unwrap()
                .unwrap(),
            projection
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let mut terminal = projection;
        terminal
            .reconcile_custody(
                &bloom_broker_api::CeremonyPublicStatus {
                    state: CeremonyState::Succeeded,
                    ceremony_url: None,
                    receipt_digest: Some(Digest32::from_bytes([46; 32])),
                    ..status
                },
                2,
            )
            .unwrap();
        assert!(terminal.ceremony_url().is_none());
    }

    #[test]
    fn raw_result_path_atomically_clears_stored_launch_url() {
        let temp = tempfile::tempdir().unwrap();
        let operation_id = OperationId::from_bytes([47; 32]);
        let awaiting = bloom_broker_api::CeremonyPublicStatus {
            ceremony_id: Digest32::from_bytes([48; 32]),
            ceremony_kind: CeremonyKind::PolicyUpdate,
            operation_id: operation_id.clone(),
            state: CeremonyState::AwaitingUser,
            expires_at_ms: bloom_broker_api::DecimalU64::new(u64::MAX),
            ceremony_url: Some("http://localhost:18734/ceremony/raw-owner-secret".into()),
            receipt_digest: None,
        };
        let projection = CeremonyProjection::from_custody_status(&awaiting, 1).unwrap();
        persist_projection(temp.path(), &projection).unwrap();
        let result = completed_receipt(operation_id.clone());

        reconcile_raw_projection(
            temp.path(),
            &MachineBrokerRequest::CustodyResult(OperationRequest {
                operation_id: operation_id.clone(),
            }),
            &MachineBrokerResponse::CustodyResult(result.clone()),
        )
        .unwrap();

        let terminal = load_projection(temp.path(), &operation_id)
            .unwrap()
            .unwrap();
        assert!(terminal.ceremony_url().is_none());
        assert_eq!(
            terminal.state(),
            Some(bloom_machine_client::CeremonyProjectionState::Custody(
                CeremonyState::Succeeded
            ))
        );
        assert_eq!(terminal.receipt_digest(), Some(&result.receipt_digest));
    }

    #[test]
    fn production_machine_dependency_graph_contains_no_key_or_signer_code() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap();
        let output = ProcessCommand::new(env!("CARGO"))
            .args([
                "tree",
                "-p",
                "bloom-machine",
                "--edges",
                "normal,build",
                "--prefix",
                "none",
            ])
            .current_dir(workspace)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cargo tree failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let graph = String::from_utf8(output.stdout).unwrap();
        for forbidden in [
            concat!("bloom-", "keystore "),
            "bloom-signer ",
            "bloom-signer-backend-",
            "bloom-broker ",
            "bloom-broker-debug-driver ",
            "webauthn-rs ",
        ] {
            assert!(
                !graph.contains(forbidden),
                "production Machine graph contains forbidden dependency {forbidden}:\n{graph}"
            );
        }
    }
}
