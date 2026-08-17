//! `wallets/<wallet>/...` — managed wallets and the outbox write surface.
//!
//! This handler wires public wallet projections, chain access, and the
//! transaction engine. Reads expose wallet metadata and per-chain
//! balance/nonce; writes go through the outbox stage-confirm flow.
//!
//! Paths handled:
//! - `wallets/`                                                     — list wallets
//! - `wallets/new`                                                  — write a wallet name to prepare registration
//! - `wallets/registrations/<petname>/status.json`                 — public registration projection
//! - `wallets/registrations/<petname>/result.json`                 — completed registration result
//! - `wallets/registrations/<petname>/cancel`                       — write `y`, `yes`, or `cancel` before acceptance
//! - `wallets/<wallet>/address`                                     — checksummed owner/signer address
//! - `wallets/<wallet>/address.qr.svg`                              — scannable QR image for the owner/signer address
//! - `wallets/<wallet>/address.qr.png`                              — scannable QR image for the owner/signer address
//! - `wallets/<wallet>/addresses.json`                              — owner/signer + role addresses
//! - `wallets/<wallet>/public_key`                                  — secp256k1 pubkey hex
//! - `wallets/<wallet>/kind`                                        — local/watch
//! - `wallets/<wallet>/policy.json`                                 — canonical triad policy
//! - `wallets/<wallet>/sealed-approvals/*`                          — Broker approval lifecycle
//! - `wallets/<wallet>/chains/<chain>/{balance,balance.raw,balance.json}` — native balance
//! - `wallets/<wallet>/chains/<chain>/nonce`
//! - `wallets/<wallet>/chains/<chain>/outbox/new.tx`                — write to stage
//! - `wallets/<wallet>/chains/<chain>/outbox/pending/<id>/<file>`   — read staged
//! - `wallets/<wallet>/chains/<chain>/outbox/pending/<id>/confirm`  — write to broadcast
//! - `wallets/<wallet>/chains/<chain>/outbox/sent/<id>/<file>`      — read sent
//! - `wallets/<wallet>/chains/<chain>/outbox/failed/<id>/<file>`    — read failed

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use bloom_broker_api::ProtocolErrorCode;
use bloom_evm::ChainRegistry;
use bloom_machine_client::WalletProjection;
use bloom_machine_client::{MachineBrokerClient, WalletProjectionReader};
use bloom_proto::{AddressBook, CapabilityViewEntry, HomeWritePermit, Policy, RawIntent};
use bloom_tx::{
    intent_parser,
    outbox::OutboxState,
    tx_engine::{TxEngine, TxEngineError},
};
use qrcode::QrCode;
use qrcode::render::svg;
use qrcode::types::Color as QrColor;

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

const APPROVAL_CHALLENGE_FILE: &str = "approval_challenge.json";
const WALLET_POLICY_SURFACE: &str = "wallet-policy";
/// Lifecycle states for a staged wallet-policy update, mirroring the
/// `/outbox/{pending,sent,failed}` stage/confirm structure. A policy update is
/// `pending` while it carries an unconsumed challenge, `confirmed` once the
/// approved policy is installed, or `failed` if the staged baseline changed
/// before the approved retry landed.
const POLICY_UPDATE_STATES: &[&str] = &["pending", "confirmed", "failed"];

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct TriadPolicyUpdateProjection {
    schema: String,
    wallet_id: bloom_broker_api::Token,
    operation_id: bloom_broker_api::OperationId,
    baseline_version: bloom_broker_api::DecimalU64,
    baseline_digest: bloom_broker_api::Digest32,
    proposed_policy_digest: bloom_broker_api::Digest32,
    authority_diff_digest: bloom_broker_api::Digest32,
    assurance_level: bloom_broker_api::Token,
    review_manifest_digest: Option<bloom_broker_api::Digest32>,
    ceremony_state: bloom_broker_api::CeremonyState,
    ceremony_url: Option<String>,
    ceremony_expires_at_ms: Option<bloom_broker_api::DecimalU64>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ApprovalCeremonyProjection {
    schema: String,
    wallet_id: bloom_broker_api::Token,
    operation_id: bloom_broker_api::OperationId,
    source_approval_id: Option<bloom_broker_api::Digest32>,
    response: bloom_broker_api::SealedApprovalPrepareResponse,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct WalletRegistrationProjection {
    schema: String,
    requested_name: String,
    operation_id: bloom_broker_api::OperationId,
    ceremony_kind: bloom_broker_api::CeremonyKind,
    ceremony_state: bloom_broker_api::CeremonyState,
    ceremony_url: Option<String>,
    ceremony_expires_at_ms: Option<bloom_broker_api::DecimalU64>,
    signer_contribution_digest: bloom_broker_api::Digest32,
}

impl TriadPolicyUpdateProjection {
    fn request(&self, proposed_canonical_policy: &[u8]) -> bloom_broker_api::PolicyUpdateRequest {
        bloom_broker_api::PolicyUpdateRequest {
            operation_id: self.operation_id.clone(),
            wallet_id: self.wallet_id.clone(),
            baseline_version: self.baseline_version.clone(),
            baseline_digest: self.baseline_digest.clone(),
            proposed_canonical_policy: bloom_broker_api::Base64UrlBytes::from_bytes(
                proposed_canonical_policy,
            ),
            proposed_policy_digest: self.proposed_policy_digest.clone(),
            authority_diff_digest: self.authority_diff_digest.clone(),
            assurance_level: self.assurance_level.clone(),
        }
    }

    fn adopt_prepare(
        &mut self,
        prepared: bloom_broker_api::PolicyUpdatePrepareResponse,
    ) -> Result<(), HandlerError> {
        if prepared.operation_id != self.operation_id
            || prepared.ceremony_kind != bloom_broker_api::CeremonyKind::PolicyUpdate
            || prepared.ceremony_url.trim().is_empty()
            || prepared.ceremony_expires_at_ms.get() <= now_ms_u64()
        {
            return Err(HandlerError::backend(
                "Broker policy prepare returned invalid identity, kind, URL, or expiry",
            ));
        }
        self.review_manifest_digest = Some(prepared.review_manifest_digest);
        self.ceremony_state = bloom_broker_api::CeremonyState::AwaitingUser;
        self.ceremony_url = Some(prepared.ceremony_url);
        self.ceremony_expires_at_ms = Some(prepared.ceremony_expires_at_ms);
        Ok(())
    }
}

#[derive(Clone)]
pub struct WalletsHandler {
    pub chains: ChainRegistry,
    pub tx_engine: TxEngine,
    pub address_book: Arc<AddressBook>,
    pub home_write_permit: Option<Arc<HomeWritePermit>>,
    pub mempool_indexes:
        Arc<std::collections::BTreeMap<String, Arc<bloom_mempool::PendingTxIndex>>>,
    /// Authenticated production authority edge. When absent, custody and
    /// policy mutations fail closed outside tests.
    pub broker: Option<MachineBrokerClient>,
    /// Key-free authenticated wallet view. Production public reads require it;
    /// the legacy keystore is never a fallback projection source.
    pub wallet_projections: Option<Arc<dyn WalletProjectionReader>>,
    /// Machine-owned workflow projections; never a Broker or Signer state root.
    policy_projection_root: std::path::PathBuf,
}

impl WalletsHandler {
    pub fn new(
        chains: ChainRegistry,
        tx_engine: TxEngine,
        address_book: AddressBook,
        wallet_projections: Arc<dyn WalletProjectionReader>,
        policy_projection_root: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            chains,
            tx_engine,
            address_book: Arc::new(address_book),
            home_write_permit: None,
            mempool_indexes: Arc::new(std::collections::BTreeMap::new()),
            broker: None,
            wallet_projections: Some(wallet_projections),
            policy_projection_root: policy_projection_root.into(),
        }
    }

    pub fn with_broker(mut self, broker: Option<MachineBrokerClient>) -> Self {
        self.broker = broker;
        self
    }

    pub fn with_home_write_permit(mut self, permit: Arc<HomeWritePermit>) -> Self {
        self.home_write_permit = Some(permit);
        self
    }

    pub fn with_home_write_permit_opt(mut self, permit: Option<Arc<HomeWritePermit>>) -> Self {
        self.home_write_permit = permit;
        self
    }

    pub fn with_mempool_indexes(
        mut self,
        indexes: std::collections::BTreeMap<String, Arc<bloom_mempool::PendingTxIndex>>,
    ) -> Self {
        self.mempool_indexes = Arc::new(indexes);
        self
    }

    async fn wallet_projection(&self, wallet: &str) -> Result<WalletProjection, HandlerError> {
        let wallet_id = bloom_broker_api::Token::new(wallet.to_owned())
            .map_err(|error| HandlerError::invalid(error.to_string()))?;
        self.wallet_projections
            .as_ref()
            .ok_or_else(|| {
                HandlerError::backend(
                    "SERVICE_UNAVAILABLE: Machine wallet projection reader is not configured",
                )
            })?
            .get_wallet(&wallet_id)
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))
    }

    async fn wallet_projection_list(&self) -> Result<Vec<WalletProjection>, HandlerError> {
        let Some(projections) = &self.wallet_projections else {
            return Ok(Vec::new());
        };
        match projections.list_wallets().await {
            Ok(wallets) => Ok(wallets),
            // Root directory enumeration is navigation, not an authority
            // decision. Prefer a previously authenticated cache when the live
            // edge is unavailable, and keep `new`/`registrations` reachable
            // even if no safe cached projection remains.
            Err(error) if error.code == ProtocolErrorCode::ServiceUnavailable => {
                match projections.cached_wallets() {
                    Ok(wallets) => Ok(wallets),
                    Err(cache_error)
                        if cache_error.code == ProtocolErrorCode::ServiceUnavailable =>
                    {
                        Ok(Vec::new())
                    }
                    Err(cache_error) => Err(HandlerError::backend(cache_error.to_string())),
                }
            }
            Err(error) => Err(HandlerError::backend(error.to_string())),
        }
    }

    async fn planning_wallet_inputs(
        &self,
        wallet: &str,
        chain: &str,
    ) -> Result<(alloy::primitives::Address, Policy), HandlerError> {
        let projection = self.wallet_projection(wallet).await?;
        let address = projection
            .primary_address()
            .map_err(err_be)?
            .parse()
            .map_err(|error| HandlerError::invalid(format!("wallet address: {error}")))?;
        let policy = crate::advisory_evm_policy(&projection, chain).map_err(err_be)?;
        Ok((address, policy))
    }

    fn projection_addresses_json(
        &self,
        projection: &WalletProjection,
    ) -> Result<Vec<u8>, HandlerError> {
        let owner = projection.primary_address().map_err(err_be)?;
        let body = serde_json::json!({
            "wallet": projection.wallet.wallet_id,
            "kind": projection.wallet.wallet_kind,
            "owner": owner,
            "signer": owner,
            "policy_status": "broker_verified",
            "policy_version": projection.wallet.policy_version,
            "policy_digest": projection.wallet.policy_digest,
            "wallet_revocation_epoch": projection.wallet.wallet_revocation_epoch,
            "unlocked": false,
            "freshness": projection.freshness,
            "observed_at_ms": projection.observed_at_ms,
            "roles": serde_json::Map::<String, serde_json::Value>::new(),
        });
        let mut out = serde_json::to_vec_pretty(&body).map_err(err_be)?;
        out.push(b'\n');
        Ok(out)
    }

    fn evm_capability_views_for(&self, _wallet: &str) -> Vec<CapabilityViewEntry> {
        Vec::new()
    }

    fn all_capability_views_for(&self, wallet: &str) -> Vec<CapabilityViewEntry> {
        let mut all = self.evm_capability_views_for(wallet);
        all.sort_by(|a, b| {
            a.created_ms
                .cmp(&b.created_ms)
                .then_with(|| a.id.cmp(&b.id))
        });
        all
    }

    fn capabilities_active_json(&self, wallet: &str) -> Result<Vec<u8>, HandlerError> {
        let entries = self.all_capability_views_for(wallet);
        let mut out = serde_json::to_vec_pretty(&entries).map_err(err_be)?;
        out.push(b'\n');
        Ok(out)
    }

    fn capabilities_active_md(&self, wallet: &str) -> Result<Vec<u8>, HandlerError> {
        let entries = self.all_capability_views_for(wallet);
        let mut md = String::new();
        md.push_str(&format!("# Capabilities for `{wallet}`\n\n"));
        if entries.is_empty() {
            md.push_str("No active capabilities.\n\n");
            md.push_str(&format!(
                "Manage reusable authority at `/wallets/{wallet}/sealed-approvals/`.\n"
            ));
        } else {
            for c in &entries {
                md.push_str(&format!(
                    "## {} ({})\n\n",
                    c.id,
                    serde_json::to_value(&c.venue)
                        .ok()
                        .and_then(|value| value.as_str().map(str::to_owned))
                        .unwrap_or_else(|| "unknown".to_owned()),
                ));
                md.push_str(&format!("- **Signing model:** {:?}\n", c.signing_model));
                md.push_str(&format!("- **Status:** {:?}\n", c.status));
                if let Some(secs) = c.expires_in_secs {
                    md.push_str(&format!("- **Expires in:** {secs}s\n"));
                }
                md.push_str(&format!("- **Next write:** `{}`\n", c.next_write_path));
                md.push_str(&format!("- **Stop:** `{}`\n", c.revoke_path));
                if !c.allowed.is_empty() {
                    md.push_str("- **Allowed:**\n");
                    for a in &c.allowed {
                        md.push_str(&format!("  - {a}\n"));
                    }
                }
                if !c.denied.is_empty() {
                    md.push_str("- **Denied:**\n");
                    for d in &c.denied {
                        md.push_str(&format!("  - {d}\n"));
                    }
                }
                md.push('\n');
            }
        }
        Ok(md.into_bytes())
    }

    fn write_permit(&self) -> Result<&HomeWritePermit, HandlerError> {
        self.home_write_permit.as_deref().ok_or_else(|| {
            HandlerError::backend(
                "wallet write surface is not attached to a home write permit; refusing mutation",
            )
        })
    }

    fn broker(&self) -> Result<&MachineBrokerClient, HandlerError> {
        self.broker.as_ref().ok_or_else(|| {
            HandlerError::backend(
                "Broker approval authority is unavailable; refusing Sealed Approval operation",
            )
        })
    }

    fn custody_broker(&self) -> Result<&MachineBrokerClient, HandlerError> {
        self.broker.as_ref().ok_or_else(|| {
            HandlerError::backend("custody requires the authenticated Machine-to-Broker edge")
        })
    }

    fn registration_root(&self) -> std::path::PathBuf {
        self.policy_projection_root.join("registrations")
    }

    fn registration_path(&self, requested_name: &str) -> std::path::PathBuf {
        self.registration_root()
            .join(format!("{requested_name}.json"))
    }

    fn registration_records(
        &self,
    ) -> Result<Vec<(std::path::PathBuf, WalletRegistrationProjection)>, HandlerError> {
        let root = self.registration_root();
        let mut records = Vec::new();
        let entries = match std::fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(records),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let projection: WalletRegistrationProjection = read_json(&path)?;
            let stem = path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| {
                    HandlerError::backend("registration projection filename is invalid")
                })?;
            if projection.schema != "bloom.machine-wallet-registration-projection.1"
                || projection.ceremony_kind != bloom_broker_api::CeremonyKind::WalletRegistration
                || Self::wallet_id(&projection.requested_name).is_err()
                || (stem != projection.requested_name && stem != projection.operation_id.as_str())
            {
                return Err(HandlerError::backend(
                    "Machine wallet registration projection identity is invalid",
                ));
            }
            if let Some(existing_index) = records.iter().position(
                |(_, existing): &(std::path::PathBuf, WalletRegistrationProjection)| {
                    existing.requested_name == projection.requested_name
                },
            ) {
                let canonical_path = self.registration_path(&projection.requested_name);
                let (existing_path, existing_projection) = &records[existing_index];
                if existing_projection != &projection
                    || existing_projection.operation_id != projection.operation_id
                    || (existing_path != &canonical_path && path != canonical_path)
                {
                    return Err(HandlerError::backend(
                        "multiple wallet registration projections claim the same petname",
                    ));
                }
                let legacy_path = if path == canonical_path {
                    let legacy = existing_path.clone();
                    records[existing_index] = (path, projection);
                    legacy
                } else {
                    path
                };
                if let Err(error) = std::fs::remove_file(&legacy_path) {
                    tracing::warn!(
                        path = %legacy_path.display(),
                        %error,
                        "wallet_registration.legacy_duplicate_cleanup_failed"
                    );
                }
                continue;
            }
            records.push((path, projection));
        }
        Ok(records)
    }

    fn registration_names(&self) -> Result<Vec<String>, HandlerError> {
        let mut names = self
            .registration_records()?
            .into_iter()
            .map(|(_, projection)| projection.requested_name)
            .collect::<Vec<_>>();
        names.sort();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(HandlerError::backend(
                "multiple wallet registration projections claim the same petname",
            ));
        }
        Ok(names)
    }

    fn registration_record(
        &self,
        requested_name: &str,
    ) -> Result<(std::path::PathBuf, WalletRegistrationProjection), HandlerError> {
        Self::wallet_id(requested_name)?;
        let mut matches = self
            .registration_records()?
            .into_iter()
            .filter(|(_, projection)| projection.requested_name == requested_name);
        let record = matches.next().ok_or_else(|| {
            HandlerError::not_found(format!("wallet registration {requested_name:?}"))
        })?;
        if matches.next().is_some() {
            return Err(HandlerError::backend(
                "multiple wallet registration projections claim the same petname",
            ));
        }
        Ok(record)
    }

    fn registration_result_ready(projection: &WalletRegistrationProjection) -> bool {
        projection.ceremony_state == bloom_broker_api::CeremonyState::Completed
    }

    fn registration_status_entry(
        projection: &WalletRegistrationProjection,
    ) -> Result<Entry, HandlerError> {
        let size = serde_json::to_vec_pretty(projection)
            .map_err(|error| HandlerError::backend(error.to_string()))?
            .len()
            .saturating_add(1);
        Ok(Entry::file("status.json").with_size(size as u64))
    }

    async fn prepare_wallet_registration(&self, data: &[u8]) -> Result<(), HandlerError> {
        use sha2::Digest as _;

        const PROJECTION_SCHEMA: &str = "bloom.machine-wallet-registration-projection.1";
        const MAX_REQUEST_BYTES: usize = 4096;
        if data.len() > MAX_REQUEST_BYTES {
            return Err(HandlerError::invalid("wallet name is too large"));
        }
        let requested_name = std::str::from_utf8(data)
            .map_err(|error| {
                HandlerError::invalid(format!("wallet name must be valid UTF-8: {error}"))
            })?
            .trim();
        if requested_name.is_empty()
            || requested_name.len() > 64
            || !requested_name.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        {
            return Err(HandlerError::invalid(
                "wallet name must be 1-64 ASCII alphanumeric, '-' or '_' characters",
            ));
        }
        let wallet_id = bloom_broker_api::Token::new(requested_name.to_owned())
            .map_err(|error| HandlerError::invalid(error.to_string()))?;
        let mut existing_records = self
            .registration_records()?
            .into_iter()
            .filter(|(_, existing)| existing.requested_name == requested_name);
        let existing = existing_records.next();
        if existing_records.next().is_some() {
            return Err(HandlerError::backend(
                "multiple wallet registration projections claim the same petname",
            ));
        }
        if let Some((_, projection)) = &existing
            && projection.ceremony_state == bloom_broker_api::CeremonyState::AwaitingUser
        {
            // A shell retry (or an NFS client replaying a committed write) must
            // not allocate a second Broker operation for the same live
            // registration. Refreshing also proves that the retained launch is
            // still actionable before reporting the retry as successful.
            let refreshed = self.registration_projection(requested_name).await?;
            if refreshed.ceremony_state == bloom_broker_api::CeremonyState::AwaitingUser {
                return Ok(());
            }
        }
        let registration_path = self.registration_path(requested_name);
        let legacy_registration_path = existing
            .map(|(path, _)| path)
            .filter(|path| path != &registration_path);

        let mut operation_bytes = [0_u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut operation_bytes);
        let operation_id = bloom_broker_api::OperationId::from_bytes(operation_bytes);
        let reviewed_terms = serde_jcs::to_vec(&serde_json::json!({
            "ceremony_kind": bloom_broker_api::CeremonyKind::WalletRegistration,
            "wallet_id": wallet_id,
        }))
        .map_err(|error| HandlerError::invalid(format!("canonicalize registration: {error}")))?;
        let prepared = self
            .custody_broker()?
            .prepare_custody(
                bloom_machine_client::CustodyPrepareMethod::WalletRegistration,
                bloom_broker_api::CustodyPrepareRequest {
                    ceremony_kind: bloom_broker_api::CeremonyKind::WalletRegistration,
                    custody_operation_id: operation_id.clone(),
                    wallet_id: Some(wallet_id),
                    key_ref: None,
                    exact_terms_digest: bloom_broker_api::Digest32::from_bytes(
                        sha2::Sha256::digest(reviewed_terms).into(),
                    ),
                    expected_input_class: bloom_broker_api::Token::new("passkey-prf")
                        .map_err(|error| HandlerError::invalid(error.to_string()))?,
                    browser_output_recipient_key: None,
                    petal_key_scope: None,
                    legacy_passkey_migration: None,
                },
            )
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        if prepared.custody_operation_id != operation_id
            || prepared.ceremony_kind != bloom_broker_api::CeremonyKind::WalletRegistration
            || prepared.ceremony_url.trim().is_empty()
            || prepared.ceremony_expires_at_ms.get() <= now_ms_u64()
        {
            return Err(HandlerError::backend(
                "Broker returned an invalid wallet registration prepare response",
            ));
        }
        let projection = WalletRegistrationProjection {
            schema: PROJECTION_SCHEMA.into(),
            requested_name: requested_name.to_owned(),
            operation_id,
            ceremony_kind: prepared.ceremony_kind,
            ceremony_state: bloom_broker_api::CeremonyState::AwaitingUser,
            ceremony_url: Some(prepared.ceremony_url),
            ceremony_expires_at_ms: Some(prepared.ceremony_expires_at_ms),
            signer_contribution_digest: prepared.signer_contribution_digest,
        };
        write_atomic_json(&registration_path, &projection)?;
        if let Some(legacy_path) = legacy_registration_path {
            std::fs::remove_file(legacy_path)?;
        }
        Ok(())
    }

    async fn registration_projection(
        &self,
        requested_name: &str,
    ) -> Result<WalletRegistrationProjection, HandlerError> {
        let (path, mut projection) = self.registration_record(requested_name)?;
        if matches!(
            projection.ceremony_state,
            bloom_broker_api::CeremonyState::Completed
                | bloom_broker_api::CeremonyState::Succeeded
                | bloom_broker_api::CeremonyState::Cancelled
                | bloom_broker_api::CeremonyState::Expired
                | bloom_broker_api::CeremonyState::Failed
        ) {
            return Ok(projection);
        }
        let local_launch_expired = projection
            .ceremony_expires_at_ms
            .as_ref()
            .is_some_and(|expires_at| expires_at.get() <= now_ms_u64());
        let status = match self
            .custody_broker()?
            .ceremony_status(projection.operation_id.clone())
            .await
        {
            Ok(status) => status,
            Err(error)
                if local_launch_expired && error.code == ProtocolErrorCode::ServiceUnavailable =>
            {
                // Never infer a terminal result from the launch deadline. The
                // owner may have completed at the boundary while Broker was
                // becoming unavailable. Remove only the stale bearer URL and
                // retain the operation for a later authoritative retry.
                projection.ceremony_url = None;
                projection.ceremony_expires_at_ms = None;
                write_atomic_json(&path, &projection)?;
                return Err(HandlerError::backend(error.to_string()));
            }
            Err(error) => return Err(HandlerError::backend(error.to_string())),
        };
        if status.operation_id != projection.operation_id
            || status.ceremony_kind != bloom_broker_api::CeremonyKind::WalletRegistration
        {
            return Err(HandlerError::backend(
                "Broker returned a mismatched wallet registration status",
            ));
        }
        projection.ceremony_state = status.state;
        if status.state == bloom_broker_api::CeremonyState::AwaitingUser {
            let ceremony_url = status
                .ceremony_url
                .filter(|url| !url.trim().is_empty())
                .ok_or_else(|| {
                    HandlerError::backend(
                        "Broker omitted the actionable wallet registration ceremony URL",
                    )
                })?;
            if status.expires_at_ms.get() <= now_ms_u64() {
                return Err(HandlerError::backend(
                    "Broker returned an expired wallet registration ceremony",
                ));
            }
            projection.ceremony_url = Some(ceremony_url);
            projection.ceremony_expires_at_ms = Some(status.expires_at_ms);
        } else {
            projection.ceremony_url = None;
            projection.ceremony_expires_at_ms = None;
        }
        write_atomic_json(&path, &projection)?;
        Ok(projection)
    }

    async fn cancel_wallet_registration(&self, requested_name: &str) -> Result<(), HandlerError> {
        let projection = self.registration_projection(requested_name).await?;
        let operation_id = projection.operation_id.clone();
        if projection.ceremony_state != bloom_broker_api::CeremonyState::AwaitingUser {
            return Err(HandlerError::invalid(
                "wallet registration is no longer cancellable",
            ));
        }
        let status = self
            .custody_broker()?
            .cancel_ceremony(operation_id.clone())
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        if status.operation_id != operation_id
            || status.ceremony_kind != bloom_broker_api::CeremonyKind::WalletRegistration
            || status.state != bloom_broker_api::CeremonyState::Cancelled
        {
            return Err(HandlerError::backend(
                "Broker did not confirm wallet registration cancellation",
            ));
        }
        let _ = self.registration_projection(requested_name).await?;
        Ok(())
    }

    async fn wallet_registration_result_json(
        &self,
        requested_name: &str,
    ) -> Result<Vec<u8>, HandlerError> {
        let projection = self.registration_projection(requested_name).await?;
        let operation_id = projection.operation_id;
        let result = self
            .custody_broker()?
            .custody_result(bloom_broker_api::OperationRequest {
                operation_id: operation_id.clone(),
            })
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        if result.custody_operation_id != operation_id
            || result.ceremony_kind != bloom_broker_api::CeremonyKind::WalletRegistration
        {
            return Err(HandlerError::backend(
                "Broker returned a mismatched wallet registration result",
            ));
        }
        let mut bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "ceremony_kind": result.ceremony_kind,
            "operation_id": result.custody_operation_id,
            "status": result.public_status,
            "wallet_id": result.wallet_id,
            "public_key_refs": result.public_key_refs,
            "credential_summaries": result.credential_summaries,
            "initial_policy": result.initial_policy,
            "receipt_digest": result.receipt_digest,
            "signer_key_id": result.signer_key_id,
            "signer_signature": result.signer_signature,
        }))
        .map_err(|error| HandlerError::backend(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    fn approval_id(value: &str) -> Result<bloom_broker_api::Digest32, HandlerError> {
        bloom_broker_api::Digest32::new(value.to_owned())
            .map_err(|error| HandlerError::invalid(error.to_string()))
    }

    fn wallet_id(value: &str) -> Result<bloom_broker_api::Token, HandlerError> {
        bloom_broker_api::Token::new(value.to_owned())
            .map_err(|error| HandlerError::invalid(error.to_string()))
    }

    fn approval_projection_path(
        &self,
        wallet: &str,
        source_approval_id: Option<&str>,
    ) -> std::path::PathBuf {
        let root = self
            .policy_projection_root
            .join(wallet)
            .join("sealed-approvals");
        match source_approval_id {
            Some(approval_id) => root.join(approval_id).join("renew.json"),
            None => root.join("new.json"),
        }
    }

    fn store_approval_ceremony_projection(
        &self,
        wallet: &str,
        operation_id: bloom_broker_api::OperationId,
        source_approval_id: Option<bloom_broker_api::Digest32>,
        response: bloom_broker_api::SealedApprovalPrepareResponse,
    ) -> Result<(), HandlerError> {
        let path = self
            .approval_projection_path(wallet, source_approval_id.as_ref().map(|id| id.as_str()));
        write_atomic_json(
            &path,
            &ApprovalCeremonyProjection {
                schema: "bloom.machine-approval-ceremony-projection.1".into(),
                wallet_id: Self::wallet_id(wallet)?,
                operation_id,
                source_approval_id,
                response,
            },
        )
    }

    async fn approval_ceremony_projection_json(
        &self,
        wallet: &str,
        source_approval_id: Option<&str>,
    ) -> Result<Option<Vec<u8>>, HandlerError> {
        let path = self.approval_projection_path(wallet, source_approval_id);
        if !path.is_file() {
            return Ok(None);
        }
        let projection: ApprovalCeremonyProjection = read_json(&path)?;
        let expected_source = source_approval_id.map(Self::approval_id).transpose()?;
        if projection.schema != "bloom.machine-approval-ceremony-projection.1"
            || projection.wallet_id != Self::wallet_id(wallet)?
            || projection.source_approval_id != expected_source
        {
            return Err(HandlerError::backend(
                "Machine Sealed Approval ceremony projection identity is invalid",
            ));
        }
        let ceremony = self
            .broker()?
            .ceremony_status(projection.operation_id.clone())
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        if ceremony.operation_id != projection.operation_id
            || ceremony.ceremony_kind != bloom_broker_api::CeremonyKind::SealedApproval
        {
            return Err(HandlerError::backend(
                "Broker returned a mismatched Sealed Approval ceremony projection",
            ));
        }
        if ceremony.state != bloom_broker_api::CeremonyState::AwaitingUser {
            if matches!(
                ceremony.state,
                bloom_broker_api::CeremonyState::Completed
                    | bloom_broker_api::CeremonyState::Succeeded
                    | bloom_broker_api::CeremonyState::Cancelled
                    | bloom_broker_api::CeremonyState::Expired
                    | bloom_broker_api::CeremonyState::Failed
            ) {
                match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            return Ok(None);
        }
        if ceremony.ceremony_url.as_deref() != Some(projection.response.ceremony_url.as_str())
            || ceremony.expires_at_ms != projection.response.ceremony_expires_at_ms
        {
            return Err(HandlerError::backend(
                "Broker ceremony status does not match the persisted Sealed Approval launch projection",
            ));
        }
        let status = self
            .approval_status_for_wallet(wallet, projection.response.approval_id.as_str())
            .await?;
        if !matches!(
            status.state,
            bloom_broker_api::ApprovalLifecycleState::Prepared
                | bloom_broker_api::ApprovalLifecycleState::AwaitingCeremony
        ) {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            return Ok(None);
        }
        let mut out = serde_json::to_vec_pretty(&projection.response).map_err(err_be)?;
        out.push(b'\n');
        Ok(Some(out))
    }

    async fn approval_status_for_wallet(
        &self,
        wallet: &str,
        approval_id: &str,
    ) -> Result<bloom_broker_api::ApprovalPublicStatus, HandlerError> {
        let wallet_id = Self::wallet_id(wallet)?;
        let status = self
            .broker()?
            .approval_status(Self::approval_id(approval_id)?)
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        if status.wallet_id != wallet_id {
            return Err(HandlerError::not_found(format!(
                "Sealed Approval {approval_id:?} for wallet {wallet:?}"
            )));
        }
        Ok(status)
    }

    async fn sealed_approvals_active_json(&self, wallet: &str) -> Result<Vec<u8>, HandlerError> {
        let statuses = self.approval_list_for_wallet(wallet).await?;
        let mut out = serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "bloom.sealed_approvals.active.v1",
            "wallet_id": wallet,
            "approvals": statuses,
        }))
        .map_err(err_be)?;
        out.push(b'\n');
        Ok(out)
    }

    async fn approval_list_for_wallet(
        &self,
        wallet: &str,
    ) -> Result<Vec<bloom_broker_api::ApprovalPublicStatus>, HandlerError> {
        let wallet_id = Self::wallet_id(wallet)?;
        let mut statuses = self
            .broker()?
            .list_approvals(wallet_id.clone())
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        if statuses.iter().any(|status| status.wallet_id != wallet_id) {
            return Err(HandlerError::backend(
                "Broker returned a cross-wallet Sealed Approval projection",
            ));
        }
        statuses.sort_by(|left, right| left.approval_id.cmp(&right.approval_id));
        if statuses
            .windows(2)
            .any(|pair| pair[0].approval_id == pair[1].approval_id)
        {
            return Err(HandlerError::backend(
                "Broker returned duplicate Sealed Approval projections",
            ));
        }
        Ok(statuses)
    }

    async fn sealed_approval_status_json(
        &self,
        wallet: &str,
        approval_id: &str,
    ) -> Result<Vec<u8>, HandlerError> {
        let status = self.approval_status_for_wallet(wallet, approval_id).await?;
        let mut out = serde_json::to_vec_pretty(&status).map_err(err_be)?;
        out.push(b'\n');
        Ok(out)
    }

    async fn sealed_approval_limits_json(
        &self,
        wallet: &str,
        approval_id: &str,
    ) -> Result<Vec<u8>, HandlerError> {
        self.approval_status_for_wallet(wallet, approval_id).await?;
        let state = self
            .broker()?
            .approval_limit_state(Self::approval_id(approval_id)?)
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        let mut out = serde_json::to_vec_pretty(&state).map_err(err_be)?;
        out.push(b'\n');
        Ok(out)
    }

    async fn prepare_sealed_approval(&self, wallet: &str, data: &[u8]) -> Result<(), HandlerError> {
        let request: bloom_broker_api::ApprovalPrepareRequest = serde_json::from_slice(data)
            .map_err(|error| HandlerError::invalid(error.to_string()))?;
        if request.terms.wallet_id != Self::wallet_id(wallet)? {
            return Err(HandlerError::invalid(
                "Sealed Approval terms wallet does not match mounted wallet path",
            ));
        }
        let expected_approval_id = request
            .terms
            .approval_id()
            .map_err(|error| HandlerError::invalid(error.to_string()))?;
        let approval_expires_at_ms = request.terms.expires_at_ms.clone();
        let operation_id = request.operation_id.clone();
        let response = self
            .broker()?
            .prepare_approval(request)
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        if response.approval_id != expected_approval_id
            || response.ceremony_expires_at_ms.get() > approval_expires_at_ms.get()
        {
            return Err(HandlerError::backend(
                "Broker Sealed Approval prepare response is not bound to the immutable request",
            ));
        }
        self.store_approval_ceremony_projection(wallet, operation_id, None, response)?;
        Ok(())
    }

    async fn renew_sealed_approval(
        &self,
        wallet: &str,
        approval_id: &str,
        data: &[u8],
    ) -> Result<(), HandlerError> {
        let request: bloom_broker_api::ApprovalRenewRequest = serde_json::from_slice(data)
            .map_err(|error| HandlerError::invalid(error.to_string()))?;
        let path_id = Self::approval_id(approval_id)?;
        if request.old_approval_id != path_id
            || request.replacement_terms.wallet_id != Self::wallet_id(wallet)?
        {
            return Err(HandlerError::invalid(
                "Sealed Approval renewal identity does not match mounted path",
            ));
        }
        let expected_approval_id = request
            .replacement_terms
            .approval_id()
            .map_err(|error| HandlerError::invalid(error.to_string()))?;
        let approval_expires_at_ms = request.replacement_terms.expires_at_ms.clone();
        let operation_id = request.operation_id.clone();
        let response = self
            .broker()?
            .renew_approval(request)
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        if response.approval_id != expected_approval_id
            || response.ceremony_expires_at_ms.get() > approval_expires_at_ms.get()
        {
            return Err(HandlerError::backend(
                "Broker Sealed Approval renew response is not bound to the immutable replacement terms",
            ));
        }
        self.store_approval_ceremony_projection(wallet, operation_id, Some(path_id), response)?;
        Ok(())
    }

    async fn revoke_sealed_approval(
        &self,
        wallet: &str,
        approval_id: &str,
        data: &[u8],
    ) -> Result<(), HandlerError> {
        let request: bloom_broker_api::RevokeRequest = serde_json::from_slice(data)
            .map_err(|error| HandlerError::invalid(error.to_string()))?;
        if request.wallet_id != Self::wallet_id(wallet)?
            || request.approval_id != Self::approval_id(approval_id)?
        {
            return Err(HandlerError::invalid(
                "Sealed Approval revocation identity does not match mounted path",
            ));
        }
        self.broker()?
            .revoke_approval(request)
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        Ok(())
    }

    async fn revoke_all_sealed_approvals(
        &self,
        wallet: &str,
        data: &[u8],
    ) -> Result<(), HandlerError> {
        let request: bloom_broker_api::WalletOperationRequest = serde_json::from_slice(data)
            .map_err(|error| HandlerError::invalid(error.to_string()))?;
        if request.wallet_id != Self::wallet_id(wallet)? {
            return Err(HandlerError::invalid(
                "Sealed Approval revoke_all wallet does not match mounted path",
            ));
        }
        self.broker()?
            .revoke_all_approvals(request)
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        Ok(())
    }

    async fn read_triad_wallet_policy(&self, wallet: &str) -> Result<Vec<u8>, HandlerError> {
        use sha2::Digest as _;

        let wallet_id = bloom_broker_api::Token::new(wallet.to_owned())
            .map_err(|error| HandlerError::invalid(error.to_string()))?;
        let snapshot = self.wallet_projection(wallet).await?.policy;
        let canonical = snapshot.canonical_policy.decode();
        if snapshot.wallet_id != wallet_id
            || bloom_broker_api::Digest32::from_bytes(sha2::Sha256::digest(&canonical).into())
                != snapshot.policy_digest
        {
            return Err(HandlerError::backend(
                "Broker policy projection has invalid wallet or digest binding",
            ));
        }
        let policy: bloom_broker_api::CanonicalWalletPolicy = serde_json::from_slice(&canonical)
            .map_err(|error| HandlerError::backend(format!("parse Broker policy: {error}")))?;
        if policy.wallet_id != wallet_id
            || serde_jcs::to_vec(&policy)
                .map_err(|error| HandlerError::backend(error.to_string()))?
                != canonical
        {
            return Err(HandlerError::backend(
                "Broker policy projection is not canonical",
            ));
        }
        Ok(canonical)
    }

    async fn reconcile_triad_policy_projection(
        &self,
        wallet: &str,
        state: &str,
        operation_id: &str,
    ) -> Result<String, HandlerError> {
        if state != "pending" {
            return Ok(state.to_owned());
        }
        let broker = self.broker.as_ref().ok_or_else(|| {
            HandlerError::backend(
                "SERVICE_UNAVAILABLE: policy projection requires the authenticated Broker edge",
            )
        })?;
        let projection_path = self
            .policy_update_action_dir(wallet, state, operation_id)
            .join(APPROVAL_CHALLENGE_FILE);
        let mut projection: TriadPolicyUpdateProjection = read_json(&projection_path)?;
        if projection.schema != "bloom.machine-policy-update-projection.1"
            || projection.wallet_id.as_str() != wallet
            || projection.operation_id.as_str() != operation_id
        {
            return Err(HandlerError::backend(
                "policy projection identity or schema is invalid",
            ));
        }
        let status = match broker
            .ceremony_status(projection.operation_id.clone())
            .await
        {
            Ok(status) => status,
            Err(error)
                if error.code == bloom_broker_api::ProtocolErrorCode::ApprovalNotFound
                    && projection.review_manifest_digest.is_none() =>
            {
                // The pre-prepare journal is authoritative, but a read cannot
                // dispatch the mutation because it does not retain proposed
                // policy bytes. It exposes no URL and the exact write retry
                // will resend policy.validate_update with this same ID.
                projection.ceremony_url = None;
                projection.ceremony_expires_at_ms = None;
                write_atomic_json(&projection_path, &projection)?;
                return Ok("pending".into());
            }
            Err(error) => return Err(HandlerError::backend(error.to_string())),
        };
        if status.operation_id != projection.operation_id
            || status.ceremony_kind != bloom_broker_api::CeremonyKind::PolicyUpdate
        {
            return Err(HandlerError::backend(
                "Broker policy ceremony status changed operation identity or kind",
            ));
        }
        projection.ceremony_state = status.state;
        if status.state == bloom_broker_api::CeremonyState::AwaitingUser {
            projection.ceremony_url = Some(status.ceremony_url.ok_or_else(|| {
                HandlerError::backend(
                    "awaiting Broker policy ceremony omitted its owner-visible URL",
                )
            })?);
            projection.ceremony_expires_at_ms = Some(status.expires_at_ms);
        } else {
            projection.ceremony_url = None;
            projection.ceremony_expires_at_ms = None;
        }
        write_atomic_json(&projection_path, &projection)?;
        match status.state {
            bloom_broker_api::CeremonyState::Cancelled
            | bloom_broker_api::CeremonyState::Expired
            | bloom_broker_api::CeremonyState::Failed => {
                self.policy_update_transition(wallet, operation_id, "pending", "failed")?;
                Ok("failed".into())
            }
            bloom_broker_api::CeremonyState::Completed => Err(HandlerError::backend(
                "policy_update ceremony reported the wallet-registration-only COMPLETED state",
            )),
            _ => Ok("pending".into()),
        }
    }

    async fn write_wallet_policy_update(
        &self,
        wallet: &str,
        _path: &str,
        data: &[u8],
    ) -> Result<(), HandlerError> {
        use sha2::Digest as _;

        const MAX_POLICY_BYTES: usize = 1024 * 1024;
        if data.len() > MAX_POLICY_BYTES {
            return Err(HandlerError::invalid(format!(
                "canonical policy exceeds {MAX_POLICY_BYTES} bytes"
            )));
        }
        let broker = self.broker.as_ref().ok_or_else(|| {
            HandlerError::backend(
                "SERVICE_UNAVAILABLE: policy update requires the authenticated Broker edge",
            )
        })?;
        let wallet_id = bloom_broker_api::Token::new(wallet.to_owned())
            .map_err(|error| HandlerError::invalid(error.to_string()))?;
        let proposed: bloom_broker_api::CanonicalWalletPolicy = serde_json::from_slice(data)
            .map_err(|error| {
                HandlerError::invalid(format!(
                    "triad policy writes require canonical policy JSON: {error}"
                ))
            })?;
        if proposed.wallet_id != wallet_id {
            return Err(HandlerError::invalid(
                "proposed policy wallet_id does not match the VFS wallet",
            ));
        }
        let proposed_bytes = serde_jcs::to_vec(&proposed)
            .map_err(|error| HandlerError::invalid(format!("canonicalize policy: {error}")))?;
        let proposed_policy_digest =
            bloom_broker_api::Digest32::from_bytes(sha2::Sha256::digest(&proposed_bytes).into());
        if let Some(operation_id) = self.policy_update_latest_pending_id(wallet) {
            let action_dir = self.policy_update_action_dir(wallet, "pending", &operation_id);
            let projection_path = action_dir.join(APPROVAL_CHALLENGE_FILE);
            let mut projection: TriadPolicyUpdateProjection = read_json(&projection_path)?;
            if projection.schema != "bloom.machine-policy-update-projection.1"
                || projection.wallet_id != wallet_id
                || projection.operation_id.as_str() != operation_id
                || projection.proposed_policy_digest != proposed_policy_digest
            {
                return Err(HandlerError::invalid(
                    "pending policy ceremony is bound to different canonical policy bytes",
                ));
            }
            let status = if projection.review_manifest_digest.is_none() {
                // The pre-prepare journal can survive a lost Broker response.
                // Repeat the exact idempotent prepare so Machine recovers the
                // review digest and URL that ceremony.status does not expose.
                let prepared = broker
                    .validate_policy_update(projection.request(&proposed_bytes))
                    .await
                    .map_err(|error| HandlerError::backend(error.to_string()))?;
                projection.adopt_prepare(prepared)?;
                write_atomic_json(&projection_path, &projection)?;
                return Err(HandlerError::PermissionDenied);
            } else {
                broker
                    .ceremony_status(projection.operation_id.clone())
                    .await
                    .map_err(|error| HandlerError::backend(error.to_string()))?
            };
            if status.operation_id != projection.operation_id
                || status.ceremony_kind != bloom_broker_api::CeremonyKind::PolicyUpdate
            {
                return Err(HandlerError::backend(
                    "Broker policy ceremony status changed operation identity or kind",
                ));
            }
            projection.ceremony_state = status.state;
            if status.state == bloom_broker_api::CeremonyState::AwaitingUser {
                projection.ceremony_url = Some(status.ceremony_url.ok_or_else(|| {
                    HandlerError::backend(
                        "awaiting Broker policy ceremony omitted its owner-visible URL",
                    )
                })?);
                projection.ceremony_expires_at_ms = Some(status.expires_at_ms);
            } else {
                projection.ceremony_url = None;
                projection.ceremony_expires_at_ms = None;
            }
            write_atomic_json(&projection_path, &projection)?;

            match status.state {
                bloom_broker_api::CeremonyState::Succeeded => {
                    let receipt = broker
                        .custody_result(bloom_broker_api::OperationRequest {
                            operation_id: projection.operation_id.clone(),
                        })
                        .await
                        .map_err(|error| HandlerError::backend(error.to_string()))?;
                    if receipt.custody_operation_id != projection.operation_id
                        || receipt.ceremony_kind != bloom_broker_api::CeremonyKind::PolicyUpdate
                        || receipt.public_status != bloom_broker_api::CeremonyState::Succeeded
                    {
                        return Err(HandlerError::backend(
                            "policy commit requires the matching completed policy_update receipt",
                        ));
                    }
                    let commit = broker
                        .commit_policy_update(bloom_broker_api::PolicyCommitUpdateRequest {
                            operation_id: projection.operation_id.clone(),
                            ceremony_receipt: receipt,
                        })
                        .await
                        .map_err(|error| HandlerError::backend(error.to_string()))?;
                    if commit.operation_id != projection.operation_id
                        || commit.wallet_id != wallet_id
                        || commit.previous_version != projection.baseline_version
                        || commit.committed.wallet_id != wallet_id
                        || commit.committed.version.get()
                            != projection.baseline_version.get().saturating_add(1)
                        || commit.committed.policy_digest != proposed_policy_digest
                        || commit.committed.canonical_policy.decode() != proposed_bytes
                        || commit.authority_diff_digest != projection.authority_diff_digest
                    {
                        return Err(HandlerError::backend(
                            "Broker policy commit receipt conflicts with the VFS projection",
                        ));
                    }
                    projection.ceremony_url = None;
                    projection.ceremony_expires_at_ms = None;
                    write_atomic_json(&projection_path, &projection)?;
                    self.policy_update_transition(
                        wallet,
                        projection.operation_id.as_str(),
                        "pending",
                        "confirmed",
                    )?;
                    return Ok(());
                }
                bloom_broker_api::CeremonyState::Cancelled
                | bloom_broker_api::CeremonyState::Expired
                | bloom_broker_api::CeremonyState::Failed => {
                    projection.ceremony_url = None;
                    projection.ceremony_expires_at_ms = None;
                    write_atomic_json(&projection_path, &projection)?;
                    self.policy_update_transition(
                        wallet,
                        projection.operation_id.as_str(),
                        "pending",
                        "failed",
                    )?;
                    return Err(HandlerError::invalid(format!(
                        "Broker policy ceremony is terminal: {:?}",
                        status.state
                    )));
                }
                _ => return Err(HandlerError::PermissionDenied),
            }
        }

        let baseline = broker
            .policy(wallet_id.clone())
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        let baseline_bytes = baseline.canonical_policy.decode();
        if bloom_broker_api::Digest32::from_bytes(sha2::Sha256::digest(&baseline_bytes).into())
            != baseline.policy_digest
        {
            return Err(HandlerError::backend(
                "Broker policy baseline digest does not match its canonical bytes",
            ));
        }
        let baseline_policy: bloom_broker_api::CanonicalWalletPolicy =
            serde_json::from_slice(&baseline_bytes)
                .map_err(|error| HandlerError::backend(format!("parse Broker policy: {error}")))?;
        if baseline_policy.wallet_id != wallet_id
            || serde_jcs::to_vec(&baseline_policy)
                .map_err(|error| HandlerError::backend(error.to_string()))?
                != baseline_bytes
        {
            return Err(HandlerError::backend(
                "Broker policy baseline is noncanonical or names another wallet",
            ));
        }
        let authority_diff_digest =
            bloom_machine_client::claimed_policy_authority_diff_digest(&baseline_policy, &proposed)
                .map_err(|error| HandlerError::invalid(error.to_string()))?;
        let mut operation_bytes = [0_u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut operation_bytes);
        let operation_id = bloom_broker_api::OperationId::from_bytes(operation_bytes);
        let mut projection = TriadPolicyUpdateProjection {
            schema: "bloom.machine-policy-update-projection.1".into(),
            wallet_id,
            operation_id: operation_id.clone(),
            baseline_version: baseline.version,
            baseline_digest: baseline.policy_digest,
            proposed_policy_digest,
            authority_diff_digest,
            assurance_level: bloom_broker_api::Token::new("user_verified")
                .map_err(|error| HandlerError::invalid(error.to_string()))?,
            review_manifest_digest: None,
            ceremony_state: bloom_broker_api::CeremonyState::Prepared,
            ceremony_url: None,
            ceremony_expires_at_ms: None,
        };
        let action_dir = self.policy_update_action_dir(wallet, "pending", operation_id.as_str());
        std::fs::create_dir_all(&action_dir)?;
        let projection_path = action_dir.join(APPROVAL_CHALLENGE_FILE);
        write_atomic_json(&projection_path, &projection)?;
        let prepared = broker
            .validate_policy_update(projection.request(&proposed_bytes))
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        projection.adopt_prepare(prepared)?;
        write_atomic_json(&projection_path, &projection)?;
        Err(HandlerError::PermissionDenied)
    }

    /// Approval — the canonical proposed policy lives in the sealed action
    /// subject, never in these side files. The root holds one subdirectory per
    /// lifecycle state (`pending`, `confirmed`, `failed`), matching the
    /// `/outbox/{pending,sent,failed}` stage/confirm structure.
    fn policy_updates_dir(&self, wallet: &str) -> std::path::PathBuf {
        self.policy_projection_root
            .join(wallet)
            .join("policy-updates")
    }

    fn policy_update_state_dir(&self, wallet: &str, state: &str) -> std::path::PathBuf {
        self.policy_updates_dir(wallet).join(state)
    }

    fn policy_update_action_dir(
        &self,
        wallet: &str,
        state: &str,
        action_id: &str,
    ) -> std::path::PathBuf {
        self.policy_update_state_dir(wallet, state).join(action_id)
    }

    /// Atomically move an action between lifecycle states (e.g. `pending` →
    /// `confirmed` once the approved policy is installed). Best-effort: a
    /// failure is logged but never overrides an already-decided install/error
    /// outcome. In production the Broker/Signer receipt is authoritative and
    /// this move changes only Machine's workflow projection.
    fn policy_update_transition(
        &self,
        wallet: &str,
        action_id: &str,
        from: &str,
        to: &str,
    ) -> std::io::Result<()> {
        let from_dir = self.policy_update_action_dir(wallet, from, action_id);
        let to_dir = self.policy_update_action_dir(wallet, to, action_id);
        if !from_dir.exists() {
            return Ok(());
        }
        if let Err(error) = std::fs::create_dir_all(self.policy_update_state_dir(wallet, to)) {
            tracing::warn!(
                wallet = wallet,
                action_id = action_id,
                from = from,
                to = to,
                error = %error,
                "policy_update.transition_directory_failed"
            );
            return Err(error);
        }
        std::fs::rename(&from_dir, &to_dir).map_err(|e| {
            tracing::warn!(
                wallet = wallet,
                action_id = action_id,
                from = from,
                to = to,
                error = %e,
                "policy_update.transition_failed"
            );
            e
        })
    }

    /// Sorted list of action ids currently in a given lifecycle state.
    fn policy_update_action_ids(&self, wallet: &str, state: &str) -> Vec<String> {
        let mut ids = Vec::new();
        let dir = self.policy_update_state_dir(wallet, state);
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for ent in rd.flatten() {
                if ent.file_type().map(|t| t.is_dir()).unwrap_or(false)
                    && let Some(name) = ent.file_name().to_str()
                {
                    ids.push(name.to_string());
                }
            }
        }
        ids.sort();
        ids
    }

    /// The most recently staged pending action id, keyed off the challenge
    /// file's mtime so later artefact writes (e.g. an approval landing) do not
    /// reshuffle the ordering. Mirrors `OutboxHandler::latest_pending_action_id`.
    fn policy_update_latest_pending_id(&self, wallet: &str) -> Option<String> {
        let pending = self.policy_update_state_dir(wallet, "pending");
        let rd = std::fs::read_dir(&pending).ok()?;
        let mut entries: Vec<_> = rd
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let challenge = e.path().join(APPROVAL_CHALLENGE_FILE);
                std::fs::metadata(&challenge)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mtime| (mtime, e.file_name()))
            })
            .collect();
        // Newest mtime first; lexicographic action id ascending as a stable
        // tie-breaker (same convention as the outbox latest ordering).
        entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        entries
            .first()
            .map(|(_, name)| name.to_string_lossy().into_owned())
    }

    fn policy_update_latest_target(&self, wallet: &str) -> Option<String> {
        self.policy_update_latest_pending_id(wallet)
            .map(|id| format!("pending/{id}"))
    }

    /// Raw approval challenge JSON for a staged policy update, surfaced through
    /// the mount so an agent can discover the ceremony (including `ceremony_url`)
    /// without reading `BLOOM_HOME`. Contains only bounded challenge metadata —
    /// no signatures, grants, or key material.
    fn read_policy_update_challenge(
        &self,
        wallet: &str,
        state: &str,
        action_id: &str,
    ) -> Result<Vec<u8>, HandlerError> {
        validate_policy_action_id(action_id)?;
        let path = self
            .policy_update_action_dir(wallet, state, action_id)
            .join(APPROVAL_CHALLENGE_FILE);
        if !path.exists() {
            return Err(HandlerError::not_found(format!(
                "policy-updates/{state}/{action_id}/{APPROVAL_CHALLENGE_FILE}"
            )));
        }
        Ok(std::fs::read(&path)?)
    }

    /// Human/agent-facing status view for a policy update. The lifecycle folder
    /// (`pending`/`confirmed`/`failed`) and Broker-authenticated projection are
    /// authoritative. Within `pending`, the Broker ceremony state distinguishes
    /// a completed ceremony ready for commit from one still awaiting custody.
    /// Exposes `ceremony_url` and the exact retry path; never exposes the completed
    /// ceremony receipt or Broker validation receipt.
    fn policy_update_status_json(
        &self,
        wallet: &str,
        state: &str,
        action_id: &str,
    ) -> Result<Vec<u8>, HandlerError> {
        validate_policy_action_id(action_id)?;
        let action_dir = self.policy_update_action_dir(wallet, state, action_id);
        if !action_dir.is_dir() {
            return Err(HandlerError::not_found(format!(
                "policy-updates/{state}/{action_id}"
            )));
        }
        let challenge_path = action_dir.join(APPROVAL_CHALLENGE_FILE);
        let triad_projection: Option<TriadPolicyUpdateProjection> = if challenge_path.exists() {
            let projection: TriadPolicyUpdateProjection =
                read_json(&challenge_path).map_err(|_| {
                    HandlerError::backend(
                        "legacy or malformed Machine policy-update projection is not authoritative",
                    )
                })?;
            if projection.schema != "bloom.machine-policy-update-projection.1" {
                return Err(HandlerError::backend(
                    "legacy or malformed Machine policy-update projection is not authoritative",
                ));
            }
            Some(projection)
        } else {
            None
        };
        let (status, next_step) = match state {
            "confirmed" => (
                "confirmed",
                "policy installed by Signer compare-and-swap; this projection is audit history",
            ),
            "failed" => (
                "failed",
                "Broker ceremony failed or the staged baseline changed; restage the policy update",
            ),
            _ if triad_projection.as_ref().is_some_and(|projection| {
                projection.ceremony_state == bloom_broker_api::CeremonyState::Succeeded
            }) =>
            {
                (
                    "ready_to_commit",
                    "re-write the exact same canonical policy JSON to submit the completed custody receipt",
                )
            }
            _ if triad_projection.as_ref().is_some_and(|projection| {
                projection.review_manifest_digest.is_none() && projection.ceremony_url.is_none()
            }) =>
            {
                (
                    "prepare_pending",
                    "re-write the exact same canonical policy JSON to reconcile policy.validate_update with the same operation ID",
                )
            }
            _ if triad_projection.is_some() => (
                "awaiting_custody",
                "complete the Broker policy_update ceremony, then re-write the exact same canonical policy JSON to commit",
            ),
            _ => {
                return Err(HandlerError::backend(
                    "policy-update projection has no Broker ceremony state",
                ));
            }
        };
        let ceremony_url = triad_projection
            .as_ref()
            .and_then(|projection| projection.ceremony_url.clone());
        let expiry_ms = triad_projection.as_ref().and_then(|projection| {
            projection
                .ceremony_expires_at_ms
                .as_ref()
                .map(bloom_broker_api::DecimalU64::get)
        });
        let body = serde_json::json!({
            "schema": "bloom.wallet_policy_update_view.v1",
            "wallet": wallet,
            "action_id": action_id,
            "surface": WALLET_POLICY_SURFACE,
            "state": state,
            "status": status,
            "write_path": policy_update_vfs_write_path(wallet),
            "installation_target": policy_update_vfs_write_path(wallet),
            "challenge_path": format!("/wallets/{wallet}/policy-updates/{state}/{action_id}/{APPROVAL_CHALLENGE_FILE}"),
            "assurance": null,
            "ceremony_kind": triad_projection.as_ref().map(|_| "policy_update"),
            "ceremony_state": triad_projection.as_ref().map(|p| p.ceremony_state),
            "review_manifest_digest": triad_projection.as_ref().map(|p| p.review_manifest_digest.clone()),
            "ceremony_url": ceremony_url,
            "expiry_ms": expiry_ms,
            "next_step": next_step,
        });
        let mut out = serde_json::to_vec_pretty(&body).map_err(err_be)?;
        out.push(b'\n');
        Ok(out)
    }

    fn wallet_dir_entries() -> Vec<Entry> {
        vec![
            Entry::file("address"),
            Entry::file("address.qr.png"),
            Entry::file("address.qr.svg"),
            Entry::file("addresses.json"),
            Entry::file("public_key"),
            Entry::file("kind"),
            Entry::file("projection.json"),
            Entry::writable_file("policy.json"),
            Entry::dir("chains"),
            Entry::dir("sealed-approvals"),
            Entry::dir("policy-updates"),
            Entry::dir("capabilities"),
        ]
    }

    fn outbox_dir_entries() -> Vec<Entry> {
        vec![
            Entry::writable_file("new.tx"),
            Entry::dir("pending"),
            Entry::dir("sent"),
            Entry::dir("failed"),
        ]
    }
}

fn err_be(e: impl std::fmt::Display) -> HandlerError {
    HandlerError::backend(e.to_string())
}

/// Reject a policy-update action id that could escape its state directory
/// (path traversal, the `latest` sentinel, or NUL). Real ids are
/// `policy-update-<blake3-hex>`, so this is defense-in-depth.
fn validate_policy_action_id(id: &str) -> Result<(), HandlerError> {
    if id.is_empty()
        || id == "latest"
        || id.contains('/')
        || id.contains('\\')
        || id.contains('\0')
        || id.contains("..")
    {
        return Err(HandlerError::invalid(format!("invalid action id: {id}")));
    }
    Ok(())
}

fn tx_open_err(e: TxEngineError) -> HandlerError {
    match e {
        TxEngineError::ApprovalRequired(_) => HandlerError::PermissionDenied,
        TxEngineError::PolicyDenied | TxEngineError::BroadcastDisabled(_) => {
            HandlerError::OperationNotPermitted
        }
        TxEngineError::EnsoQuoteStale { .. }
        | TxEngineError::DependencyNotSatisfied { .. }
        | TxEngineError::SimulationReverted { .. }
        | TxEngineError::NonceGap { .. } => HandlerError::invalid(e.to_string()),
        other => err_be(other),
    }
}

fn render_address_qr_svg(address: &str) -> Result<Vec<u8>, HandlerError> {
    let code = QrCode::new(address.as_bytes())
        .map_err(|e| HandlerError::backend(format!("qr svg encode: {e}")))?;
    Ok(code
        .render::<svg::Color>()
        .min_dimensions(256, 256)
        .quiet_zone(true)
        .build()
        .into_bytes())
}

fn render_address_qr_png(address: &str) -> Result<Vec<u8>, HandlerError> {
    let code = QrCode::new(address.as_bytes())
        .map_err(|e| HandlerError::backend(format!("qr png encode: {e}")))?;
    let module_width = code.width();
    let quiet_modules = 4usize;
    let total_modules = module_width + quiet_modules * 2;
    let scale = 256usize.div_ceil(total_modules).max(1);
    let pixels = total_modules * scale;
    let row_len = 1 + pixels;
    let mut raw = Vec::with_capacity(row_len * pixels);
    for y in 0..pixels {
        raw.push(0); // PNG filter type 0.
        let module_y = y / scale;
        for x in 0..pixels {
            let module_x = x / scale;
            let dark = module_x >= quiet_modules
                && module_x < quiet_modules + module_width
                && module_y >= quiet_modules
                && module_y < quiet_modules + module_width
                && code[(module_x - quiet_modules, module_y - quiet_modules)] == QrColor::Dark;
            raw.push(if dark { 0 } else { 255 });
        }
    }

    let mut png = Vec::new();
    png.extend_from_slice(b"\x89PNG\r\n\x1a\n");

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&(pixels as u32).to_be_bytes());
    ihdr.extend_from_slice(&(pixels as u32).to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(0); // grayscale
    ihdr.push(0); // deflate
    ihdr.push(0); // adaptive filtering
    ihdr.push(0); // no interlace
    push_png_chunk(&mut png, b"IHDR", &ihdr);

    let compressed = zlib_store(&raw);
    push_png_chunk(&mut png, b"IDAT", &compressed);
    push_png_chunk(&mut png, b"IEND", &[]);
    Ok(png)
}

fn push_png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(kind.len() + data.len());
    crc_input.extend_from_slice(kind);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
}

fn zlib_store(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 65_535 * 5 + 8);
    out.extend_from_slice(&[0x78, 0x01]);
    for (i, chunk) in data.chunks(65_535).enumerate() {
        let final_block = i == data.len().saturating_sub(1) / 65_535;
        out.push(if final_block { 0x01 } else { 0x00 });
        let len = chunk.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in data {
        a = (a + u32::from(byte)) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn now_ms_u64() -> u64 {
    now_ms().min(u128::from(u64::MAX)) as u64
}

fn policy_update_vfs_write_path(wallet: &str) -> String {
    format!("/wallets/{wallet}/policy.json")
}

fn write_atomic_file(path: &Path, bytes: &[u8]) -> Result<(), HandlerError> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| HandlerError::backend("atomic write target has no file name"))?;
    let mut nonce = [0_u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let tmp = path.with_file_name(format!(".{file_name}.tmp-{}", hex::encode(nonce)));
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn write_atomic_json(path: &Path, value: &impl serde::Serialize) -> Result<(), HandlerError> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| HandlerError::backend(error.to_string()))?;
    write_atomic_file(path, &bytes)
}

fn read_json<T: for<'de> serde::Deserialize<'de>>(
    path: impl AsRef<Path>,
) -> Result<T, HandlerError> {
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|e| HandlerError::backend(e.to_string()))
}

/// Parse a state segment (`pending` / `sent` / `failed`) into an
/// [`OutboxState`], rejecting anything else as NotFound.
fn parse_state_seg(s: &str) -> Result<OutboxState, HandlerError> {
    OutboxState::parse(s).ok_or_else(|| HandlerError::not_found(format!("outbox state '{}'", s)))
}

fn open_regular_outbox_artifact(dir: &Path, fname: &str) -> Result<std::fs::File, HandlerError> {
    let path = dir.join(fname);
    let descriptor = rustix::fs::open(
        &path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| {
        if matches!(error, rustix::io::Errno::NOENT | rustix::io::Errno::LOOP) {
            HandlerError::not_found(fname)
        } else {
            HandlerError::Io(std::io::Error::from_raw_os_error(error.raw_os_error()))
        }
    })?;
    let file = std::fs::File::from(descriptor);
    if !file.metadata()?.file_type().is_file() {
        return Err(HandlerError::not_found(fname));
    }
    Ok(file)
}

fn first_confirm_line(confirm_text: &str) -> &str {
    confirm_text.lines().next().unwrap_or(confirm_text).trim()
}

#[async_trait]
impl Handler for WalletsHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let r = self.lookup_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(
                path = %path.to_string_path(),
                error = %e,
                "wallets.lookup_err"
            );
        }
        r
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let r = self.read_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(
                path = %path.to_string_path(),
                error = %e,
                "wallets.read_err"
            );
        }
        r
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let r = self.write_inner(path, data).await;
        if let Err(e) = &r {
            tracing::debug!(
                path = %path.to_string_path(),
                bytes = data.len(),
                error = %e,
                "wallets.write_err"
            );
        }
        r
    }

    fn is_async_write_command(&self, path: &VfsPath) -> bool {
        let segs = path.segments();
        matches!(segs, [_, leaf] if leaf == "policy.json")
    }

    async fn prepare_write_open(&self, path: &VfsPath) -> Result<(), HandlerError> {
        let segs = path.segments();
        let r = match segs {
            [wallet, chains, chain, outbox, pending, id, fname]
                if chains == "chains"
                    && outbox == "outbox"
                    && pending == "pending"
                    && fname == "confirm.override" =>
            {
                let (_, policy) = self.planning_wallet_inputs(wallet, chain).await?;
                let client = self
                    .chains
                    .get(chain)
                    .ok_or_else(|| HandlerError::not_found(format!("chain '{}'", chain)))?;
                self.tx_engine
                    .prepare_confirm_write_open(
                        self.write_permit()?,
                        wallet,
                        chain,
                        id,
                        &client,
                        &policy,
                        true,
                    )
                    .await
                    .map_err(tx_open_err)
            }
            _ => Ok(()),
        };
        if let Err(e) = &r {
            tracing::debug!(
                path = %path.to_string_path(),
                error = %e,
                "wallets.prepare_write_open_err"
            );
        }
        r
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let r = self.list_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(
                path = %path.to_string_path(),
                error = %e,
                "wallets.list_err"
            );
        }
        r
    }

    fn cache_ttl(&self, path: &VfsPath) -> Option<std::time::Duration> {
        let segs = path.segments();
        match segs {
            [_, s, _, leaf]
                if s == "chains"
                    && matches!(
                        leaf.as_str(),
                        "balance" | "balance.raw" | "balance.json" | "nonce"
                    ) =>
            {
                Some(super::balances::LIVE_BALANCE_TTL)
            }
            _ => None,
        }
    }

    /// Defense-in-depth gate against the mount layer rendering at
    /// GETATTR. Sign / outbox-control paths are write-only sinks (mode
    /// 0o644) so the mount-side mode-bit check already skips them, but
    /// we declare them side-effecting here too so any future caller
    /// that bypasses the mode check still cannot trigger a sign or
    /// broadcast just by stat'ing.
    fn is_read_side_effecting(&self, path: &VfsPath) -> bool {
        let segs = path.segments();
        // wallets/<w>/chains/<c>/outbox/pending/<id>/{confirm,confirm.override,replace,cancel}
        if segs.len() == 7
            && segs[1] == "chains"
            && segs[3] == "outbox"
            && segs[4] == "pending"
            && matches!(
                segs[6].as_str(),
                "confirm" | "confirm.override" | "replace" | "cancel"
            )
        {
            return true;
        }
        false
    }
}

impl WalletsHandler {
    async fn lookup_inner(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segs = path.segments();
        if segs.is_empty() {
            return Ok(Entry::dir(""));
        }
        if segs.len() == 1 && segs[0] == "new" {
            return Ok(Entry::writable_file("new"));
        }
        if segs[0] == "registrations" {
            return match segs {
                [_] => Ok(Entry::dir("registrations")),
                [_, requested_name] => {
                    let _ = self.registration_record(requested_name)?;
                    Ok(Entry::dir(requested_name))
                }
                [_, requested_name, leaf] if leaf == "status.json" => {
                    let (_, projection) = self.registration_record(requested_name)?;
                    Self::registration_status_entry(&projection)
                }
                [_, requested_name, leaf] if leaf == "result.json" => {
                    let projection = self.registration_projection(requested_name).await?;
                    if Self::registration_result_ready(&projection) {
                        Ok(Entry::file(leaf))
                    } else {
                        Err(HandlerError::not_found(path.to_string_path()))
                    }
                }
                [_, requested_name, leaf] if leaf == "cancel" => {
                    let _ = self.registration_record(requested_name)?;
                    Ok(Entry::writable_file("cancel"))
                }
                _ => Err(HandlerError::not_found(path.to_string_path())),
            };
        }
        let wallet = &segs[0];
        let _projection = self.wallet_projection(wallet).await?;
        if segs.len() == 1 {
            return Ok(Entry::dir(wallet));
        }
        match segs[1].as_str() {
            "address" | "address.qr.png" | "address.qr.svg" | "addresses.json" | "public_key"
            | "kind" | "projection.json" => Ok(Entry::file(&segs[1])),
            "policy.json" => Ok(Entry::writable_file("policy.json")),
            "chains" => match segs.len() {
                2 => Ok(Entry::dir("chains")),
                3 => {
                    let _ = self
                        .chains
                        .get(&segs[2])
                        .ok_or_else(|| HandlerError::not_found(format!("chain '{}'", segs[2])))?;
                    Ok(Entry::dir(&segs[2]))
                }
                _ => self.lookup_chain(wallet, &segs[2], &segs[3..]).await,
            },
            "sealed-approvals" => match segs.len() {
                2 => Ok(Entry::dir("sealed-approvals")),
                3 if segs[2] == "new.json" => Ok(Entry::writable_file("new.json")),
                3 if segs[2] == "active.json" => Ok(Entry::file("active.json")),
                3 if segs[2] == "revoke_all" => Ok(Entry::writable_file("revoke_all")),
                3 => {
                    self.approval_status_for_wallet(wallet, &segs[2]).await?;
                    Ok(Entry::dir(&segs[2]))
                }
                4 if segs[3] == "status.json" => {
                    self.approval_status_for_wallet(wallet, &segs[2]).await?;
                    Ok(Entry::file("status.json"))
                }
                4 if segs[3] == "limits.json" => {
                    self.approval_status_for_wallet(wallet, &segs[2]).await?;
                    Ok(Entry::file("limits.json"))
                }
                4 if matches!(segs[3].as_str(), "renew" | "revoke") => {
                    self.approval_status_for_wallet(wallet, &segs[2]).await?;
                    Ok(Entry::writable_file(&segs[3]))
                }
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "policy-updates" => match segs.len() {
                2 => Ok(Entry::dir("policy-updates")),
                3 if POLICY_UPDATE_STATES.contains(&segs[2].as_str()) => Ok(Entry::dir(&segs[2])),
                3 if segs[2] == "latest" => {
                    let target = self
                        .policy_update_latest_target(wallet)
                        .ok_or_else(|| HandlerError::not_found("policy-updates/latest"))?;
                    Ok(Entry::symlink("latest", &target))
                }
                4 if segs[2] == "latest"
                    && matches!(segs[3].as_str(), "status.json" | APPROVAL_CHALLENGE_FILE) =>
                {
                    let action_id = self
                        .policy_update_latest_pending_id(wallet)
                        .ok_or_else(|| HandlerError::not_found("policy-updates/latest"))?;
                    let dir = self.policy_update_action_dir(wallet, "pending", &action_id);
                    // status.json is derived from the action dir, not persisted;
                    // the challenge is a real file.
                    let present = if segs[3] == "status.json" {
                        dir.is_dir()
                    } else {
                        dir.join(&segs[3]).is_file()
                    };
                    if present {
                        Ok(Entry::file(&segs[3]))
                    } else {
                        Err(HandlerError::not_found(path.to_string_path()))
                    }
                }
                4 if POLICY_UPDATE_STATES.contains(&segs[2].as_str()) => {
                    validate_policy_action_id(&segs[3])?;
                    let dir = self.policy_update_action_dir(wallet, &segs[2], &segs[3]);
                    if dir.is_dir() {
                        Ok(Entry::dir(&segs[3]))
                    } else {
                        Err(HandlerError::not_found(path.to_string_path()))
                    }
                }
                5 if POLICY_UPDATE_STATES.contains(&segs[2].as_str())
                    && segs[4] == "status.json" =>
                {
                    validate_policy_action_id(&segs[3])?;
                    let dir = self.policy_update_action_dir(wallet, &segs[2], &segs[3]);
                    if dir.is_dir() {
                        Ok(Entry::file("status.json"))
                    } else {
                        Err(HandlerError::not_found(path.to_string_path()))
                    }
                }
                5 if POLICY_UPDATE_STATES.contains(&segs[2].as_str())
                    && segs[4] == APPROVAL_CHALLENGE_FILE =>
                {
                    validate_policy_action_id(&segs[3])?;
                    let fpath = self
                        .policy_update_action_dir(wallet, &segs[2], &segs[3])
                        .join(APPROVAL_CHALLENGE_FILE);
                    if fpath.is_file() {
                        Ok(Entry::file(APPROVAL_CHALLENGE_FILE))
                    } else {
                        Err(HandlerError::not_found(path.to_string_path()))
                    }
                }
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "capabilities" => match segs.len() {
                2 => Ok(Entry::dir("capabilities")),
                3 if segs[2] == "active.json" => Ok(Entry::file("active.json")),
                3 if segs[2] == "active.md" => Ok(Entry::file("active.md")),
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn read_inner(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = path.segments();
        if segs.is_empty() {
            return Err(HandlerError::NotAFile(path.to_string_path()));
        }
        if segs.len() == 1 && segs[0] == "new" {
            return Ok(b"Write a wallet name matching [A-Za-z0-9_-]{1,64}.\n".to_vec());
        }
        if segs[0] == "registrations" {
            return match segs {
                [_, requested_name, leaf] if leaf == "status.json" => {
                    let projection = self.registration_projection(requested_name).await?;
                    let mut bytes = serde_json::to_vec_pretty(&projection)
                        .map_err(|error| HandlerError::backend(error.to_string()))?;
                    bytes.push(b'\n');
                    Ok(bytes)
                }
                [_, requested_name, leaf] if leaf == "result.json" => {
                    let projection = self.registration_projection(requested_name).await?;
                    if !Self::registration_result_ready(&projection) {
                        return Err(HandlerError::not_found(path.to_string_path()));
                    }
                    self.wallet_registration_result_json(requested_name).await
                }
                _ => Err(HandlerError::NotAFile(path.to_string_path())),
            };
        }
        let wallet = &segs[0];
        match segs.get(1).map(|s| s.as_str()).unwrap_or("") {
            "address" => {
                let projection = self.wallet_projection(wallet).await?;
                Ok(format!("{}\n", projection.primary_address().map_err(err_be)?).into_bytes())
            }
            "address.qr.svg" => {
                let projection = self.wallet_projection(wallet).await?;
                render_address_qr_svg(projection.primary_address().map_err(err_be)?)
            }
            "address.qr.png" => {
                let projection = self.wallet_projection(wallet).await?;
                render_address_qr_png(projection.primary_address().map_err(err_be)?)
            }
            "addresses.json" => {
                let projection = self.wallet_projection(wallet).await?;
                self.projection_addresses_json(&projection)
            }
            "public_key" => {
                let projection = self.wallet_projection(wallet).await?;
                Ok(format!(
                    "0x{}\n",
                    hex::encode(
                        projection
                            .primary_key()
                            .map_err(err_be)?
                            .canonical_public_key
                            .decode()
                    )
                )
                .into_bytes())
            }
            "kind" => {
                let projection = self.wallet_projection(wallet).await?;
                Ok(format!("{}\n", projection.wallet.wallet_kind.as_str()).into_bytes())
            }
            "projection.json" => {
                let projection = self.wallet_projection(wallet).await?;
                let mut out = serde_json::to_vec_pretty(&projection).map_err(err_be)?;
                out.push(b'\n');
                Ok(out)
            }
            "policy.json" => self.read_triad_wallet_policy(wallet).await,
            "chains" if segs.len() >= 4 => self.read_chain(wallet, &segs[2], &segs[3..]).await,
            "sealed-approvals" if segs.len() == 3 && segs[2] == "new.json" => {
                match self
                    .approval_ceremony_projection_json(wallet, None)
                    .await?
                {
                    Some(projection) => Ok(projection),
                    None => Ok(b"{\"schema\":\"bloom.approval_prepare_request.v1\",\"write\":\"complete ApprovalPrepareRequest JSON\"}\n".to_vec()),
                }
            }
            "sealed-approvals" if segs.len() == 3 && segs[2] == "active.json" => {
                self.sealed_approvals_active_json(wallet).await
            }
            "sealed-approvals" if segs.len() == 4 && segs[3] == "status.json" => {
                self.sealed_approval_status_json(wallet, &segs[2]).await
            }
            "sealed-approvals" if segs.len() == 4 && segs[3] == "limits.json" => {
                self.sealed_approval_limits_json(wallet, &segs[2]).await
            }
            "sealed-approvals" if segs.len() == 4 && segs[3] == "renew" => self
                .approval_ceremony_projection_json(wallet, Some(&segs[2]))
                .await?
                .ok_or_else(|| HandlerError::not_found(path.to_string_path())),
            "policy-updates" if segs.len() == 4 && segs[2] == "latest" => {
                let action_id = self
                    .policy_update_latest_pending_id(wallet)
                    .ok_or_else(|| HandlerError::not_found("policy-updates/latest"))?;
                let state = self
                    .reconcile_triad_policy_projection(wallet, "pending", &action_id)
                    .await?;
                match segs[3].as_str() {
                    "approval_challenge.json" => {
                        self.read_policy_update_challenge(wallet, &state, &action_id)
                    }
                    "status.json" => self.policy_update_status_json(wallet, &state, &action_id),
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                }
            }
            "policy-updates"
                if segs.len() == 5
                    && POLICY_UPDATE_STATES.contains(&segs[2].as_str())
                    && segs[4] == "approval_challenge.json" =>
            {
                validate_policy_action_id(&segs[3])?;
                let state = self
                    .reconcile_triad_policy_projection(wallet, &segs[2], &segs[3])
                    .await?;
                self.read_policy_update_challenge(wallet, &state, &segs[3])
            }
            "policy-updates"
                if segs.len() == 5
                    && POLICY_UPDATE_STATES.contains(&segs[2].as_str())
                    && segs[4] == "status.json" =>
            {
                validate_policy_action_id(&segs[3])?;
                let state = self
                    .reconcile_triad_policy_projection(wallet, &segs[2], &segs[3])
                    .await?;
                self.policy_update_status_json(wallet, &state, &segs[3])
            }
            "capabilities" if segs.len() == 3 && segs[2] == "active.json" => {
                self.capabilities_active_json(wallet)
            }
            "capabilities" if segs.len() == 3 && segs[2] == "active.md" => {
                self.capabilities_active_md(wallet)
            }
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn write_inner(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let segs = path.segments();
        if segs.is_empty() {
            return Err(HandlerError::PermissionDenied);
        }
        if segs.len() == 1 && segs[0] == "new" {
            self.write_permit()?;
            return self.prepare_wallet_registration(data).await;
        }
        if segs[0] == "registrations" {
            if let [_, requested_name, leaf] = segs
                && leaf == "cancel"
            {
                self.write_permit()?;
                let confirmation = std::str::from_utf8(data)
                    .map_err(|_| {
                        HandlerError::invalid(
                            "registration cancellation requires UTF-8 confirmation",
                        )
                    })?
                    .trim();
                if !confirmation.eq_ignore_ascii_case("y")
                    && !confirmation.eq_ignore_ascii_case("yes")
                    && !confirmation.eq_ignore_ascii_case("cancel")
                {
                    return Err(HandlerError::invalid(
                        "registration cancellation accepts only `y`, `yes`, or `cancel`",
                    ));
                }
                return self.cancel_wallet_registration(requested_name).await;
            }
            return Err(HandlerError::PermissionDenied);
        }
        let wallet = &segs[0];
        if segs.len() >= 4 && segs[1] == "chains" && segs[3] == "outbox" {
            return self.write_outbox(wallet, &segs[2], &segs[4..], data).await;
        }
        if segs.len() == 2 && segs[1] == "policy.json" {
            self.write_permit()?;
            return self
                .write_wallet_policy_update(wallet, &path.to_string_path(), data)
                .await;
        }
        if segs.len() == 3 && segs[1] == "sealed-approvals" && segs[2] == "new.json" {
            self.write_permit()?;
            return self.prepare_sealed_approval(wallet, data).await;
        }
        if segs.len() == 4 && segs[1] == "sealed-approvals" && segs[3] == "renew" {
            self.write_permit()?;
            return self.renew_sealed_approval(wallet, &segs[2], data).await;
        }
        if segs.len() == 4 && segs[1] == "sealed-approvals" && segs[3] == "revoke" {
            self.write_permit()?;
            return self.revoke_sealed_approval(wallet, &segs[2], data).await;
        }
        if segs.len() == 3 && segs[1] == "sealed-approvals" && segs[2] == "revoke_all" {
            self.write_permit()?;
            return self.revoke_all_sealed_approvals(wallet, data).await;
        }
        Err(HandlerError::PermissionDenied)
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segs = path.segments();
        if segs.is_empty() {
            let mut out: Vec<Entry> = self
                .wallet_projection_list()
                .await?
                .into_iter()
                .map(|projection| Entry::dir(projection.wallet.wallet_id.as_str()))
                .collect();
            out.push(Entry::writable_file("new"));
            out.push(Entry::dir("registrations"));
            return Ok(out);
        }
        if segs[0] == "registrations" {
            return match segs {
                [_] => Ok(self
                    .registration_names()?
                    .into_iter()
                    .map(|name| Entry::dir(&name))
                    .collect()),
                [_, requested_name] => {
                    // Directory enumeration and GETATTR must remain local:
                    // shells issue them implicitly for `cd` and `ls`, and a
                    // stale or unavailable Broker is not a filesystem error.
                    let (_, projection) = self.registration_record(requested_name)?;
                    let mut entries = vec![
                        Self::registration_status_entry(&projection)?,
                        Entry::writable_file("cancel"),
                    ];
                    if Self::registration_result_ready(&projection) {
                        entries.push(Entry::file("result.json"));
                    }
                    Ok(entries)
                }
                _ => Err(HandlerError::NotADir(path.to_string_path())),
            };
        }
        let wallet = &segs[0];
        let _projection = self.wallet_projection(wallet).await?;
        match segs.len() {
            1 => Ok(Self::wallet_dir_entries()),
            2 if segs[1] == "chains" => Ok(self
                .chains
                .list_names()
                .into_iter()
                .map(|n| Entry::dir(&n))
                .collect()),
            2 if segs[1] == "sealed-approvals" => {
                let mut entries = vec![
                    Entry::writable_file("new.json"),
                    Entry::file("active.json"),
                    Entry::writable_file("revoke_all"),
                ];
                entries.extend(
                    self.approval_list_for_wallet(wallet)
                        .await?
                        .into_iter()
                        .map(|status| Entry::dir(status.approval_id.as_str())),
                );
                Ok(entries)
            }
            3 if segs[1] == "sealed-approvals" => {
                self.approval_status_for_wallet(wallet, &segs[2]).await?;
                Ok(vec![
                    Entry::file("status.json"),
                    Entry::file("limits.json"),
                    Entry::writable_file("renew"),
                    Entry::writable_file("revoke"),
                ])
            }
            2 if segs[1] == "policy-updates" => {
                let mut entries: Vec<Entry> =
                    POLICY_UPDATE_STATES.iter().map(|s| Entry::dir(s)).collect();
                if let Some(target) = self.policy_update_latest_target(wallet) {
                    entries.push(Entry::symlink("latest", &target));
                }
                Ok(entries)
            }
            3 if segs[1] == "policy-updates"
                && POLICY_UPDATE_STATES.contains(&segs[2].as_str()) =>
            {
                Ok(self
                    .policy_update_action_ids(wallet, &segs[2])
                    .iter()
                    .map(|id| Entry::dir(id))
                    .collect())
            }
            4 if segs[1] == "policy-updates"
                && POLICY_UPDATE_STATES.contains(&segs[2].as_str()) =>
            {
                validate_policy_action_id(&segs[3])?;
                let dir = self.policy_update_action_dir(wallet, &segs[2], &segs[3]);
                if !dir.is_dir() {
                    return Err(HandlerError::not_found(path.to_string_path()));
                }
                let mut out = Vec::new();
                if dir.join(APPROVAL_CHALLENGE_FILE).exists() {
                    out.push(Entry::file("approval_challenge.json"));
                }
                out.push(Entry::file("status.json"));
                Ok(out)
            }
            n if n >= 3 && segs[1] == "chains" => {
                self.list_chain(wallet, &segs[2], &segs[3..]).await
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }
}

impl WalletsHandler {
    async fn lookup_chain(
        &self,
        _wallet: &str,
        chain: &str,
        rest: &[String],
    ) -> Result<Entry, HandlerError> {
        let _client = self
            .chains
            .get(chain)
            .ok_or_else(|| HandlerError::not_found(format!("chain '{}'", chain)))?;
        match rest {
            [] => Ok(Entry::dir(chain)),
            [s] if s == "balance" || s == "balance.raw" || s == "balance.json" || s == "nonce" => {
                Ok(Entry::file(s))
            }
            [s] if s == "pending_external.jsonl" || s == "nonce_conflicts.json" => {
                Ok(Entry::file(s))
            }
            [s] if s == "outbox" => Ok(Entry::dir("outbox")),
            [s, ..] if s == "outbox" => self.lookup_outbox(_wallet, chain, &rest[1..]).await,
            _ => Err(HandlerError::not_found(rest.join("/"))),
        }
    }

    async fn lookup_outbox(
        &self,
        wallet: &str,
        chain: &str,
        rest: &[String],
    ) -> Result<Entry, HandlerError> {
        match rest {
            [] => Ok(Entry::dir("outbox")),
            [s] if s == "new.tx" => Ok(Entry::writable_file("new.tx")),
            [s] if s == "pending" || s == "sent" || s == "failed" => Ok(Entry::dir(s)),
            [state, id] => {
                let st = parse_state_seg(state)?;
                // Confirm the entry actually lives in the requested state
                // (fix #8): a stale path like `outbox/sent/<pending-id>`
                // should NotFound, not silently succeed.
                let entry = self
                    .tx_engine
                    .outbox
                    .read_in_state(wallet, chain, id, st)
                    .map_err(err_be)?;
                Ok(Entry::dir(id).with_modified_ms(entry.staged.created_ms))
            }
            [state, id, fname] => {
                let st = parse_state_seg(state)?;
                let entry = self
                    .tx_engine
                    .outbox
                    .read_in_state(wallet, chain, id, st)
                    .map_err(err_be)?;
                // Pending entries advertise the writable controls
                // (`confirm`, `replace`, `cancel`) even when those files
                // don't yet exist on disk — they are virtual write sinks.
                if st == OutboxState::Pending
                    && matches!(
                        fname.as_str(),
                        "confirm" | "confirm.override" | "replace" | "cancel"
                    )
                {
                    Ok(Entry::writable_file(fname).with_modified_ms(entry.staged.created_ms))
                } else {
                    open_regular_outbox_artifact(&entry.dir, fname)?;
                    Ok(Entry::file(fname).with_modified_ms(entry.staged.created_ms))
                }
            }
            _ => Err(HandlerError::not_found(rest.join("/"))),
        }
    }

    /// Collect the set of tx hashes (lowercased `0x...` hex) that bloom
    /// itself has staged or sent for `(wallet, chain)`. Used to filter
    /// the mempool-index snapshot so we don't double-count our own txs
    /// as "external pending" / "nonce conflict".
    fn bloom_staged_hashes(&self, wallet: &str, chain: &str) -> std::collections::HashSet<String> {
        let mut out = std::collections::HashSet::new();
        for st in [OutboxState::Pending, OutboxState::Sent] {
            let ids = match self.tx_engine.outbox.list(wallet, chain, st) {
                Ok(v) => v,
                Err(_) => continue,
            };
            for id in ids {
                let Ok(entry) = self.tx_engine.outbox.read_in_state(wallet, chain, &id, st) else {
                    continue;
                };
                if let Some(h) = entry.staged.tx_hash.as_deref() {
                    out.insert(h.to_lowercase());
                }
            }
        }
        out
    }

    /// Read bloom's outbox view of nonces for `(wallet, chain)` in the
    /// given state. Returns `(sorted_unique_nonces, nonce -> hashes)`
    /// where the hash list contains only entries that already have a
    /// `tx_hash` (pending entries may not).
    fn bloom_outbox_nonces(
        &self,
        wallet: &str,
        chain: &str,
        state: OutboxState,
    ) -> (Vec<u64>, std::collections::BTreeMap<u64, Vec<String>>) {
        let mut by_nonce: std::collections::BTreeMap<u64, Vec<String>> =
            std::collections::BTreeMap::new();
        let mut nonces: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        let ids = match self.tx_engine.outbox.list(wallet, chain, state) {
            Ok(v) => v,
            Err(_) => return (Vec::new(), by_nonce),
        };
        for id in ids {
            let Ok(entry) = self
                .tx_engine
                .outbox
                .read_in_state(wallet, chain, &id, state)
            else {
                continue;
            };
            nonces.insert(entry.staged.nonce);
            if let Some(h) = entry.staged.tx_hash.as_deref() {
                by_nonce
                    .entry(entry.staged.nonce)
                    .or_default()
                    .push(h.to_lowercase());
            }
        }
        (nonces.into_iter().collect(), by_nonce)
    }

    async fn read_chain(
        &self,
        wallet: &str,
        chain: &str,
        rest: &[String],
    ) -> Result<Vec<u8>, HandlerError> {
        // Read-only chain leaves (balance/nonce): never gated on policy sig.
        let address: alloy::primitives::Address = self
            .wallet_projection(wallet)
            .await?
            .primary_address()
            .map_err(err_be)?
            .parse()
            .map_err(|error| {
                HandlerError::backend(format!("invalid projected address: {error}"))
            })?;
        let client = self
            .chains
            .get(chain)
            .ok_or_else(|| HandlerError::not_found(format!("chain '{}'", chain)))?;
        match rest {
            [s] if s == "balance" => {
                let bal = client.balance(address).await.map_err(err_be)?;
                let spec = client.spec();
                Ok(super::balances::display_line(
                    bal,
                    spec.native_decimals,
                    &spec.native_symbol,
                ))
            }
            [s] if s == "balance.raw" => {
                let bal = client.balance(address).await.map_err(err_be)?;
                Ok(super::balances::raw_line(bal))
            }
            [s] if s == "balance.json" => {
                let bal = client.balance(address).await.map_err(err_be)?;
                let spec = client.spec();
                Ok(super::balances::balance_json(
                    chain,
                    "native",
                    None,
                    &spec.native_symbol,
                    spec.native_decimals,
                    bal,
                ))
            }
            [s] if s == "nonce" => {
                let n = client.nonce(address).await.map_err(err_be)?;
                Ok(format!("{}\n", n).into_bytes())
            }
            [s, state, id, fname] if s == "outbox" => {
                let st = parse_state_seg(state)?;
                // Honour the path's state segment (fix #8): only read from
                // the requested state, NotFound otherwise.
                let entry = self
                    .tx_engine
                    .outbox
                    .read_in_state(wallet, chain, id, st)
                    .map_err(err_be)?;
                let mut file = open_regular_outbox_artifact(&entry.dir, fname)?;
                let mut bytes = Vec::new();
                std::io::Read::read_to_end(&mut file, &mut bytes)?;
                Ok(bytes)
            }
            [s] if s == "pending_external.jsonl" => {
                // Cross-reference against the outbox so we don't surface
                // bloom's own txs as "external pending". A tx is external
                // iff its hash is NOT in the union of pending+sent outbox
                // entries for this wallet+chain (pending entries may have
                // no hash yet — those are dropped from the exclusion set).
                let idx = match self.mempool_indexes.get(chain) {
                    Some(i) => i,
                    None => return Ok(Vec::new()),
                };
                let own_hashes = self.bloom_staged_hashes(wallet, chain);
                let mut out = Vec::new();
                for tx in idx.snapshot().into_iter().filter(|t| t.from == address) {
                    let hex = format!("{:?}", tx.hash).to_lowercase();
                    if own_hashes.contains(&hex) {
                        continue;
                    }
                    serde_json::to_writer(&mut out, &tx).map_err(err_be)?;
                    out.push(b'\n');
                }
                Ok(out)
            }
            [s] if s == "nonce_conflicts.json" => {
                // A real conflict is a (nonce, hash) the mempool index
                // observed for this wallet that doesn't match any of
                // bloom's own outbox entries at that nonce. Report the
                // raw observed_nonces set for backward compat, and add
                // the outbox-side view + the computed conflict list.
                let (observed, mempool_by_nonce) = match self.mempool_indexes.get(chain) {
                    Some(i) => {
                        let snap = i.snapshot();
                        let observed = i.observed_nonces(address);
                        // (nonce -> hash) for this address in the mempool.
                        // Multiple entries at the same nonce are possible
                        // (replacements). We surface them all as candidate
                        // conflicts and let the dedupe against our own
                        // hashes filter them out below.
                        let mut by_nonce: std::collections::BTreeMap<u64, Vec<String>> =
                            std::collections::BTreeMap::new();
                        for tx in snap.into_iter().filter(|t| t.from == address) {
                            let hex = format!("{:?}", tx.hash).to_lowercase();
                            by_nonce.entry(tx.nonce).or_default().push(hex);
                        }
                        (observed, by_nonce)
                    }
                    None => (Vec::new(), std::collections::BTreeMap::new()),
                };
                let (pending_nonces, pending_by_nonce) =
                    self.bloom_outbox_nonces(wallet, chain, OutboxState::Pending);
                let (sent_nonces, sent_by_nonce) =
                    self.bloom_outbox_nonces(wallet, chain, OutboxState::Sent);
                // Union of nonces we ourselves staged or sent: any nonce
                // the mempool also sees here is a candidate for conflict.
                let mut conflicts: Vec<serde_json::Value> = Vec::new();
                let mut outbox_by_nonce: std::collections::BTreeMap<u64, Vec<String>> =
                    std::collections::BTreeMap::new();
                for (n, hs) in pending_by_nonce.iter().chain(sent_by_nonce.iter()) {
                    outbox_by_nonce
                        .entry(*n)
                        .or_default()
                        .extend(hs.iter().cloned());
                }
                for (nonce, mempool_hashes) in mempool_by_nonce.iter() {
                    let Some(outbox_hashes) = outbox_by_nonce.get(nonce) else {
                        continue;
                    };
                    for mh in mempool_hashes {
                        // Only flag when the mempool's hash isn't one of
                        // our own — i.e. someone else (or a re-broadcast
                        // we don't recognise) is occupying our nonce.
                        if outbox_hashes.iter().any(|oh| oh == mh) {
                            continue;
                        }
                        // Pick any outbox hash at this nonce for the
                        // report; callers can cross-reference if they
                        // want more detail.
                        let outbox_hash = outbox_hashes.first().cloned();
                        conflicts.push(serde_json::json!({
                            "nonce": nonce,
                            "mempool_hash": mh,
                            "outbox_hash": outbox_hash,
                        }));
                    }
                }
                let body = serde_json::json!({
                    "address": bloom_proto::checksum_address(&address),
                    "observed_nonces": observed,
                    "outbox_pending_nonces": pending_nonces,
                    "outbox_sent_nonces": sent_nonces,
                    "conflicts": conflicts,
                });
                serde_json::to_vec_pretty(&body).map_err(err_be)
            }
            _ => Err(HandlerError::NotAFile(rest.join("/"))),
        }
    }

    async fn list_chain(
        &self,
        wallet: &str,
        chain: &str,
        rest: &[String],
    ) -> Result<Vec<Entry>, HandlerError> {
        let _projection = self.wallet_projection(wallet).await?;
        let _client = self
            .chains
            .get(chain)
            .ok_or_else(|| HandlerError::not_found(format!("chain '{}'", chain)))?;
        match rest {
            [] => Ok(vec![
                Entry::file("balance"),
                Entry::file("balance.raw"),
                Entry::file("balance.json"),
                Entry::file("nonce"),
                Entry::file("pending_external.jsonl"),
                Entry::file("nonce_conflicts.json"),
                Entry::dir("outbox"),
            ]),
            [s] if s == "outbox" => Ok(Self::outbox_dir_entries()),
            [s, state] if s == "outbox" => {
                let st = match state.as_str() {
                    "pending" => OutboxState::Pending,
                    "sent" => OutboxState::Sent,
                    "failed" => OutboxState::Failed,
                    _ => return Err(HandlerError::not_found(state.clone())),
                };
                let ids = self
                    .tx_engine
                    .outbox
                    .list(wallet, chain, st)
                    .map_err(err_be)?;
                let entries = ids
                    .into_iter()
                    .map(|id| {
                        match self.tx_engine.outbox.read_in_state(wallet, chain, &id, st) {
                            Ok(entry) => {
                                Entry::dir(&id).with_modified_ms(entry.staged.created_ms)
                            }
                            Err(e) => {
                                tracing::warn!(id = %id, error = %e, "wallets.outbox.metadata_fallback");
                                Entry::dir(&id)
                            }
                        }
                    })
                    .collect();
                Ok(entries)
            }
            [s, state, id] if s == "outbox" => {
                let st = parse_state_seg(state)?;
                // The state segment is authoritative (fix #8): if the id
                // isn't in this state we report NotFound rather than
                // shadowing whatever lives at the other states.
                let entry = self
                    .tx_engine
                    .outbox
                    .read_in_state(wallet, chain, id, st)
                    .map_err(err_be)?;
                let mut out = Vec::new();
                if let Ok(rd) = std::fs::read_dir(&entry.dir) {
                    for r in rd.flatten() {
                        if let Some(n) = r.file_name().to_str()
                            && r.file_type().map(|t| t.is_file()).unwrap_or(false)
                        {
                            // Pending entries' control files are writable;
                            // everything else is read-only metadata.
                            if entry.state == OutboxState::Pending
                                && matches!(
                                    n,
                                    "confirm" | "confirm.override" | "replace" | "cancel"
                                )
                            {
                                out.push(
                                    Entry::writable_file(n)
                                        .with_modified_ms(entry.staged.created_ms),
                                );
                            } else {
                                out.push(Entry::file(n).with_modified_ms(entry.staged.created_ms));
                            }
                        }
                    }
                }
                // Always advertise the pending control files even before
                // they've been written, so agents can `echo y > confirm`
                // (and similarly for replace / cancel — fix #10).
                if entry.state == OutboxState::Pending {
                    for ctrl in ["confirm", "confirm.override", "replace", "cancel"] {
                        if !out.iter().any(|e| e.name == ctrl) {
                            out.push(
                                Entry::writable_file(ctrl)
                                    .with_modified_ms(entry.staged.created_ms),
                            );
                        }
                    }
                }
                Ok(out)
            }
            _ => Err(HandlerError::NotADir(rest.join("/"))),
        }
    }

    async fn write_outbox(
        &self,
        wallet: &str,
        chain: &str,
        rest: &[String],
        data: &[u8],
    ) -> Result<(), HandlerError> {
        let (wallet_address, policy) = self.planning_wallet_inputs(wallet, chain).await?;
        let client = self
            .chains
            .get(chain)
            .ok_or_else(|| HandlerError::not_found(format!("chain '{}'", chain)))?;
        match rest {
            // outbox/new.tx — stage
            [s] if s == "new.tx" => {
                let body = std::str::from_utf8(data)
                    .map_err(|_| HandlerError::invalid("non-utf8 intent"))?;
                let intent: RawIntent = intent_parser::parse(body).map_err(err_be)?;
                let staged = self
                    .tx_engine
                    .stage(
                        self.write_permit()?,
                        wallet,
                        wallet_address,
                        intent,
                        &client,
                        &policy,
                        Some(&self.address_book),
                    )
                    .await
                    .map_err(err_be)?;
                tracing::info!(wallet, chain, id = %staged.id, "outbox.staged");
                Ok(())
            }
            // outbox/pending/<id>/confirm — broadcast
            [state, id, fname]
                if state == "pending" && (fname == "confirm" || fname == "confirm.override") =>
            {
                // Fix #9: confirm must have non-empty content. Quietly
                // accepting an empty body (the old behaviour) made every
                // empty `> confirm` a footgun that broadcast a tx.
                let confirm_text = std::str::from_utf8(data)
                    .map_err(|_| HandlerError::invalid("non-utf8 confirm content"))?
                    .trim();
                if confirm_text.is_empty() {
                    return Err(HandlerError::invalid(
                        "confirm requires non-empty content (e.g. 'y' or override token)",
                    ));
                }
                if confirm_text.eq_ignore_ascii_case("cancel") {
                    self.write_permit()?;
                    self.tx_engine
                        .outbox
                        .cancel(wallet, chain, id)
                        .map_err(err_be)?;
                    return Ok(());
                }
                let confirm_text = if fname == "confirm.override" {
                    policy.override_sentinel()
                } else {
                    first_confirm_line(confirm_text)
                };
                let _staged = self
                    .tx_engine
                    .confirm(
                        self.write_permit()?,
                        wallet,
                        chain,
                        id,
                        &client,
                        &policy,
                        confirm_text,
                    )
                    .await
                    .map_err(|e| match e {
                        TxEngineError::EnsoQuoteStale { .. } => {
                            HandlerError::invalid(e.to_string())
                        }
                        TxEngineError::ApprovalRequired(_) => HandlerError::PermissionDenied,
                        other => err_be(other),
                    })?;
                Ok(())
            }
            // outbox/pending/<id>/cancel — fire a self-send replacement.
            // Same content rules as confirm (fix #9 / #10).
            [state, id, fname] if state == "pending" && fname == "cancel" => {
                let cancel_text = std::str::from_utf8(data)
                    .map_err(|_| HandlerError::invalid("non-utf8 cancel content"))?
                    .trim();
                if cancel_text.is_empty() {
                    return Err(HandlerError::invalid(
                        "cancel requires non-empty content (e.g. 'y' or override token)",
                    ));
                }
                let _ = self
                    .tx_engine
                    .cancel(
                        self.write_permit()?,
                        wallet,
                        chain,
                        id,
                        &client,
                        10,
                        &policy,
                    )
                    .await
                    .map_err(err_be)?;
                Ok(())
            }
            // outbox/pending/<id>/replace — restage with bumped fees from
            // the same intent body the user provides (fix #10). Body is a
            // RawIntent (TOML/JSON/shell). The original is left in place so
            // diff against the bumped tx is visible; the engine writes
            // `replacement_intent.json` alongside.
            [state, id, fname] if state == "pending" && fname == "replace" => {
                let body = std::str::from_utf8(data)
                    .map_err(|_| HandlerError::invalid("non-utf8 replace intent"))?;
                if body.trim().is_empty() {
                    return Err(HandlerError::invalid(
                        "replace requires a non-empty intent body",
                    ));
                }
                let intent: RawIntent = intent_parser::parse(body).map_err(err_be)?;
                // Bump at >= 10% (mempool floor) and substitute the
                // calldata derived from the new intent — same nonce,
                // possibly different to / value / data. Use the
                // address book the handler holds so name lookups in
                // the body resolve identically to a fresh stage.
                let _ = self
                    .tx_engine
                    .replace_with_intent(
                        self.write_permit()?,
                        wallet,
                        chain,
                        id,
                        &client,
                        10,
                        Some(intent),
                        Some(self.address_book.as_ref()),
                        &policy,
                    )
                    .await
                    .map_err(err_be)?;
                Ok(())
            }
            _ => Err(HandlerError::PermissionDenied),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;
    use bloom_broker_api::{
        ActivationMode, ApprovalLifecycleState, ApprovalLimitState, ApprovalLimits,
        ApprovalPrepareRequest, ApprovalPrepareState, ApprovalPublicStatus, ApprovalRenewRequest,
        ApprovalSelector, ApprovalSubject, Base64UrlBytes, CanonicalWalletPolicy, CeremonyKind,
        CeremonyPublicStatus, CeremonyState, CredentialPublic, CryptoSuite, CustodyPrepareResponse,
        CustodyPrepareState, CustodyResult, DecimalU64, Digest32, KeyPublic, KeyRef, KeySpec,
        MachineBrokerRequest, MachineBrokerResponse, MachineBrokerService, OperationId,
        ProtocolError, ProtocolErrorCode, RequestNonce, RevocationState, RevokeRequest,
        SealedApprovalPrepareResponse, SealedApprovalTerms, ServiceFuture, SignedPolicySnapshot,
        Token, WalletOperationRequest, WalletPublic,
    };
    use bloom_machine_client::{ProjectionFreshness, ProjectionVerification};
    use bloom_proto::AddressBook;
    use bloom_tx::outbox::Outbox;
    use bloom_tx::tx_engine::TxEngine;
    use sha2::Digest as _;
    use std::sync::Mutex;

    #[test]
    fn wallet_directory_excludes_retired_policy_toml_surface() {
        let entries = WalletsHandler::wallet_dir_entries();
        assert!(entries.iter().any(|entry| entry.name == "policy.json"));
        assert!(!entries.iter().any(|entry| entry.name == "policy.toml"));
    }

    struct Fixture {
        _tmp: tempfile::TempDir,
        handler: WalletsHandler,
        wallet_name: String,
        wallet_addr: Address,
    }

    struct ApprovalBroker {
        requests: Mutex<Vec<MachineBrokerRequest>>,
        statuses: Mutex<Vec<ApprovalPublicStatus>>,
        ceremony_state: Mutex<CeremonyState>,
        ceremony_projection_mismatch: Mutex<bool>,
        prepare_id_mismatch: Mutex<bool>,
        prepare_response: SealedApprovalPrepareResponse,
        renew_response: SealedApprovalPrepareResponse,
    }

    struct RegistrationBroker {
        requests: Mutex<Vec<MachineBrokerRequest>>,
        state: Mutex<CeremonyState>,
        omit_ceremony_url: Mutex<bool>,
        status_error: Mutex<Option<ProtocolErrorCode>>,
    }

    impl MachineBrokerService for RegistrationBroker {
        fn dispatch<'a>(
            &'a self,
            request: MachineBrokerRequest,
        ) -> ServiceFuture<'a, MachineBrokerResponse> {
            Box::pin(async move {
                self.requests.lock().unwrap().push(request.clone());
                match request {
                    MachineBrokerRequest::WalletRegistrationPrepare(request) => Ok(
                        MachineBrokerResponse::WalletRegistrationPrepare(CustodyPrepareResponse {
                            ceremony_kind: CeremonyKind::WalletRegistration,
                            custody_operation_id: request.custody_operation_id,
                            state: CustodyPrepareState::AwaitingUser,
                            ceremony_url: "http://localhost:18734/ceremony/registration-secret"
                                .into(),
                            ceremony_expires_at_ms: DecimalU64::new(u64::MAX),
                            signer_contribution_digest: digest(61),
                        }),
                    ),
                    MachineBrokerRequest::CeremonyStatus(request) => {
                        if let Some(code) = *self.status_error.lock().unwrap() {
                            return Err(ProtocolError::new(
                                code,
                                "registration status unavailable",
                            ));
                        }
                        let state = *self.state.lock().unwrap();
                        let omit_ceremony_url = *self.omit_ceremony_url.lock().unwrap();
                        Ok(MachineBrokerResponse::CeremonyStatus(
                            CeremonyPublicStatus {
                                ceremony_id: digest(62),
                                ceremony_kind: CeremonyKind::WalletRegistration,
                                operation_id: OperationId::new(request.id.as_str().to_owned())?,
                                state,
                                expires_at_ms: DecimalU64::new(u64::MAX),
                                ceremony_url: (state == CeremonyState::AwaitingUser
                                    && !omit_ceremony_url)
                                    .then(|| {
                                        "http://localhost:18734/ceremony/registration-secret".into()
                                    }),
                                receipt_digest: None,
                            },
                        ))
                    }
                    MachineBrokerRequest::CeremonyCancel(request) => {
                        *self.state.lock().unwrap() = CeremonyState::Cancelled;
                        Ok(MachineBrokerResponse::CeremonyCancel(
                            CeremonyPublicStatus {
                                ceremony_id: digest(62),
                                ceremony_kind: CeremonyKind::WalletRegistration,
                                operation_id: OperationId::new(request.id.as_str().to_owned())?,
                                state: CeremonyState::Cancelled,
                                expires_at_ms: DecimalU64::new(u64::MAX),
                                ceremony_url: None,
                                receipt_digest: None,
                            },
                        ))
                    }
                    MachineBrokerRequest::CustodyResult(request) => {
                        Ok(MachineBrokerResponse::CustodyResult(CustodyResult {
                            ceremony_kind: CeremonyKind::WalletRegistration,
                            custody_operation_id: request.operation_id,
                            public_status: *self.state.lock().unwrap(),
                            wallet_id: Some(token("main")),
                            public_key_refs: Vec::new(),
                            credential_summaries: Vec::new(),
                            initial_policy: None,
                            receipt_digest: digest(63),
                            encrypted_browser_result: None,
                            signer_key_id: token("signer-key"),
                            signer_signature: Base64UrlBytes::from_bytes(&[64; 64]),
                        }))
                    }
                    _ => Err(ProtocolError::new(
                        ProtocolErrorCode::UnknownMethod,
                        "unexpected registration request",
                    )),
                }
            })
        }
    }

    #[derive(Clone)]
    struct StaticProjection(WalletProjection);

    struct UnavailableProjection;

    struct IntegrityFailureProjection(Arc<dyn WalletProjectionReader>);

    #[async_trait]
    impl WalletProjectionReader for IntegrityFailureProjection {
        async fn list_wallets(
            &self,
        ) -> Result<Vec<WalletProjection>, bloom_broker_api::ProtocolError> {
            Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "wallet projection identity is invalid",
            ))
        }

        async fn get_wallet(
            &self,
            wallet_id: &Token,
        ) -> Result<WalletProjection, bloom_broker_api::ProtocolError> {
            self.0.get_wallet(wallet_id).await
        }

        fn cached_wallets(&self) -> Result<Vec<WalletProjection>, bloom_broker_api::ProtocolError> {
            self.0.cached_wallets()
        }
    }

    #[async_trait]
    impl WalletProjectionReader for UnavailableProjection {
        async fn list_wallets(
            &self,
        ) -> Result<Vec<WalletProjection>, bloom_broker_api::ProtocolError> {
            Err(ProtocolError::new(
                ProtocolErrorCode::ServiceUnavailable,
                "wallet projection edge unavailable",
            ))
        }

        async fn get_wallet(
            &self,
            _wallet_id: &Token,
        ) -> Result<WalletProjection, bloom_broker_api::ProtocolError> {
            Err(ProtocolError::new(
                ProtocolErrorCode::ServiceUnavailable,
                "wallet projection edge unavailable",
            ))
        }

        fn cached_wallets(&self) -> Result<Vec<WalletProjection>, bloom_broker_api::ProtocolError> {
            Err(ProtocolError::new(
                ProtocolErrorCode::ServiceUnavailable,
                "wallet projection cache unavailable",
            ))
        }
    }

    #[async_trait]
    impl WalletProjectionReader for StaticProjection {
        async fn list_wallets(
            &self,
        ) -> Result<Vec<WalletProjection>, bloom_broker_api::ProtocolError> {
            Ok(vec![self.0.clone()])
        }

        async fn get_wallet(
            &self,
            wallet_id: &Token,
        ) -> Result<WalletProjection, bloom_broker_api::ProtocolError> {
            if self.0.wallet.wallet_id == *wallet_id {
                Ok(self.0.clone())
            } else {
                Err(ProtocolError::new(
                    ProtocolErrorCode::BackendInvalidRequest,
                    "unknown wallet projection",
                ))
            }
        }

        fn cached_wallets(&self) -> Result<Vec<WalletProjection>, bloom_broker_api::ProtocolError> {
            Ok(vec![self.0.clone()])
        }
    }

    fn static_projection(address: Address) -> Arc<dyn WalletProjectionReader> {
        let wallet_id = token("alice");
        let key_ref = KeyRef {
            backend: token("local"),
            backend_instance: token("primary"),
            locator: "alice/root".into(),
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: digest(70),
            derivation: None,
        };
        let canonical = serde_jcs::to_vec(&CanonicalWalletPolicy {
            wallet_id: wallet_id.clone(),
            maximum_approval_lifetime_ms: 300_000,
            allowed_petal_packages: Vec::new(),
            allowed_destinations: Vec::new(),
            required_verifiers: Vec::new(),
        })
        .unwrap();
        let policy_digest = Digest32::from_bytes(sha2::Sha256::digest(&canonical).into());
        Arc::new(StaticProjection(WalletProjection {
            wallet: WalletPublic {
                wallet_id: wallet_id.clone(),
                wallet_kind: token("local"),
                root_key_ref: key_ref.clone(),
                key_refs: vec![key_ref.clone()],
                policy_version: DecimalU64::new(1),
                policy_digest: policy_digest.clone(),
                wallet_revocation_epoch: DecimalU64::new(0),
            },
            keys: vec![KeyPublic {
                key_ref,
                role: bloom_broker_api::KeyRole::WalletRoot,
                canonical_public_key: Base64UrlBytes::from_bytes(&[3; 33]),
                addresses: vec![format!("{address:#x}")],
                supported_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
            }],
            credentials: Vec::<CredentialPublic>::new(),
            policy: SignedPolicySnapshot {
                wallet_id,
                version: DecimalU64::new(1),
                canonical_policy: Base64UrlBytes::from_bytes(&canonical),
                policy_digest,
                policy_signing_key_id: token("policy-key"),
                policy_verifying_key: Base64UrlBytes::from_bytes(&[4; 32]),
                signer_signature: Base64UrlBytes::from_bytes(&[5; 64]),
            },
            source_protocol: "bloom.machine-broker.v1".into(),
            response_digest: digest(71),
            observed_at_ms: 1,
            freshness: ProjectionFreshness::Fresh,
            verification: ProjectionVerification::AuthenticatedBroker,
        }))
    }

    impl MachineBrokerService for ApprovalBroker {
        fn dispatch<'a>(
            &'a self,
            request: MachineBrokerRequest,
        ) -> ServiceFuture<'a, MachineBrokerResponse> {
            Box::pin(async move {
                self.requests.lock().unwrap().push(request.clone());
                match request {
                    MachineBrokerRequest::SealedApprovalPrepare(_) => {
                        let mut response = self.prepare_response.clone();
                        if *self.prepare_id_mismatch.lock().unwrap() {
                            response.approval_id = digest(99);
                        }
                        Ok(MachineBrokerResponse::SealedApprovalPrepare(response))
                    }
                    MachineBrokerRequest::SealedApprovalRenew(_) => Ok(
                        MachineBrokerResponse::SealedApprovalRenew(self.renew_response.clone()),
                    ),
                    MachineBrokerRequest::SealedApprovalList(request) => {
                        Ok(MachineBrokerResponse::SealedApprovalList(
                            self.statuses
                                .lock()
                                .unwrap()
                                .iter()
                                .filter(|status| status.wallet_id == request.wallet_id)
                                .cloned()
                                .collect(),
                        ))
                    }
                    MachineBrokerRequest::SealedApprovalStatus(request) => self
                        .statuses
                        .lock()
                        .unwrap()
                        .iter()
                        .find(|status| status.approval_id == request.id)
                        .cloned()
                        .map(MachineBrokerResponse::SealedApprovalStatus)
                        .ok_or_else(|| {
                            ProtocolError::new(
                                ProtocolErrorCode::ApprovalNotFound,
                                "approval not found",
                            )
                        }),
                    MachineBrokerRequest::CeremonyStatus(request) => {
                        let renewal =
                            request.id.as_str() == OperationId::from_bytes([40; 32]).as_str();
                        let mismatch = *self.ceremony_projection_mismatch.lock().unwrap();
                        let state = *self.ceremony_state.lock().unwrap();
                        let expected_url = if renewal {
                            "http://localhost:18734/ceremony/renew-exact"
                        } else {
                            "http://localhost:18734/ceremony/prepare-exact"
                        };
                        let ceremony_url = (state == CeremonyState::AwaitingUser).then(|| {
                            if mismatch {
                                "http://localhost:18734/ceremony/mismatch".into()
                            } else {
                                expected_url.into()
                            }
                        });
                        Ok(MachineBrokerResponse::CeremonyStatus(
                            CeremonyPublicStatus {
                                ceremony_id: digest(98),
                                ceremony_kind: CeremonyKind::SealedApproval,
                                operation_id: OperationId::new(request.id.as_str().to_owned())?,
                                state,
                                expires_at_ms: DecimalU64::new(60_000),
                                ceremony_url,
                                receipt_digest: None,
                            },
                        ))
                    }
                    MachineBrokerRequest::SealedApprovalLimitState(request) => Ok(
                        MachineBrokerResponse::SealedApprovalLimitState(ApprovalLimitState {
                            approval_id: request.id,
                            committed_operations: DecimalU64::new(1),
                            reserved_operations: DecimalU64::new(2),
                            quarantined_operations: DecimalU64::new(3),
                            committed_signatures: DecimalU64::new(4),
                            reserved_signatures: DecimalU64::new(5),
                            quarantined_signatures: DecimalU64::new(6),
                        }),
                    ),
                    MachineBrokerRequest::SealedApprovalRevoke(request) => Ok(
                        MachineBrokerResponse::SealedApprovalRevoke(ApprovalPublicStatus {
                            approval_id: request.approval_id,
                            wallet_id: request.wallet_id,
                            state: ApprovalLifecycleState::Revoked,
                            effective_claim_assurance: None,
                            ceremony_url: None,
                            ceremony_expires_at_ms: None,
                        }),
                    ),
                    MachineBrokerRequest::SealedApprovalRevokeAll(request) => Ok(
                        MachineBrokerResponse::SealedApprovalRevokeAll(RevocationState {
                            wallet_id: request.wallet_id,
                            wallet_revocation_epoch: DecimalU64::new(2),
                            wallet_tombstone: None,
                            approval_tombstone_digest: digest(33),
                            approval_tombstone_count: DecimalU64::new(1),
                            observed_at_ms: DecimalU64::new(4),
                            issuer_service_id: token("bloom-broker"),
                            key_id: token("broker-key"),
                            signature: Base64UrlBytes::from_bytes(&[1, 2, 3]),
                        }),
                    ),
                    _ => Err(ProtocolError::new(
                        ProtocolErrorCode::UnknownMethod,
                        "unexpected request",
                    )),
                }
            })
        }
    }

    fn make_handler() -> Fixture {
        make_handler_with_chain(false)
    }

    fn token(value: &str) -> Token {
        Token::new(value).unwrap()
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn approval_status(
        approval_id: Digest32,
        wallet: &str,
        state: ApprovalLifecycleState,
    ) -> ApprovalPublicStatus {
        ApprovalPublicStatus {
            approval_id,
            wallet_id: token(wallet),
            state,
            effective_claim_assurance: None,
            ceremony_url: None,
            ceremony_expires_at_ms: None,
        }
    }

    fn approval_terms(wallet: &str, renewal_of: Option<Digest32>) -> SealedApprovalTerms {
        SealedApprovalTerms {
            subject: ApprovalSubject::Cli {
                client_id: token("bloom-cli"),
                command_class: token("vfs.test"),
            },
            wallet_id: token(wallet),
            key_ref: KeyRef {
                backend: token("local"),
                backend_instance: token("primary"),
                locator: "wallet/root".into(),
                key_spec: KeySpec::Secp256k1,
                public_key_fingerprint: digest(20),
                derivation: None,
            },
            allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
            selector: ApprovalSelector::Exact {
                ordered_payload_digests: vec![digest(21)],
                ordered_hashes: vec![digest(22)],
            },
            limits: ApprovalLimits {
                max_operations: DecimalU64::new(1),
                max_signatures: DecimalU64::new(1),
                operation_rate_limits: vec![],
                signature_rate_limits: vec![],
                value_limits: vec![],
            },
            activation_mode: ActivationMode::BootBound,
            wallet_revocation_epoch: DecimalU64::new(1),
            policy_version: DecimalU64::new(1),
            policy_digest: digest(23),
            provenance_digest: digest(24),
            request_nonce: RequestNonce::from_bytes([25; 16]),
            issued_at_ms: DecimalU64::new(1_000),
            not_before_ms: DecimalU64::new(1_000),
            expires_at_ms: DecimalU64::new(61_000),
            renewal_of,
        }
    }

    fn prepare_approval_id() -> Digest32 {
        approval_terms("alice", None).approval_id().unwrap()
    }

    fn renew_approval_id() -> Digest32 {
        approval_terms("alice", Some(digest(1)))
            .approval_id()
            .unwrap()
    }

    fn approval_broker(statuses: Vec<ApprovalPublicStatus>) -> Arc<ApprovalBroker> {
        let prepare_id = prepare_approval_id();
        let renew_id = renew_approval_id();
        Arc::new(ApprovalBroker {
            requests: Mutex::new(Vec::new()),
            statuses: Mutex::new(statuses),
            ceremony_state: Mutex::new(CeremonyState::AwaitingUser),
            ceremony_projection_mismatch: Mutex::new(false),
            prepare_id_mismatch: Mutex::new(false),
            prepare_response: SealedApprovalPrepareResponse {
                approval_id: prepare_id,
                state: ApprovalPrepareState::AwaitingCeremony,
                ceremony_url: "http://localhost:18734/ceremony/prepare-exact".into(),
                ceremony_expires_at_ms: DecimalU64::new(60_000),
                review_manifest_digest: digest(11),
            },
            renew_response: SealedApprovalPrepareResponse {
                approval_id: renew_id,
                state: ApprovalPrepareState::AwaitingCeremony,
                ceremony_url: "http://localhost:18734/ceremony/renew-exact".into(),
                ceremony_expires_at_ms: DecimalU64::new(60_000),
                review_manifest_digest: digest(13),
            },
        })
    }

    /// Build a wallet fixture; when `with_chain` is true a stub `anvil`
    /// chain is registered (RPC URL is unreachable, so any test that
    /// triggers an actual broadcast will surface as an RPC error rather
    /// than silently succeeding). Outbox-state tests don't need the chain
    /// to be reachable.
    fn make_handler_with_chain(with_chain: bool) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let outbox_root = tmp.path().join("outbox");
        let wallet_addr = Address::repeat_byte(0x11);
        let chains = ChainRegistry::new();
        if with_chain {
            let spec = bloom_proto::ChainSpec {
                name: "anvil".into(),
                chain_id: 31337,
                rpc_urls: vec!["http://127.0.0.1:1".into()],
                rpc_endpoints: Vec::new(),
                allow_broadcast: true,
                etherscan_api_url: None,
                display_name: None,
                native_symbol: "ETH".into(),
                native_decimals: 18,
                legacy_tx: false,
                op_stack: false,
            };
            chains.add(bloom_evm::ChainClient::new(spec).unwrap());
        }
        let outbox = Outbox::new(&outbox_root).unwrap();
        let tx_engine = TxEngine::new(outbox, 60_000);
        let address_book = AddressBook::default();
        let home = bloom_proto::HomeDir::at(tmp.path().join("home"));
        let permit = Arc::new(HomeWritePermit::acquire(&home).unwrap());
        let handler = WalletsHandler::new(
            chains,
            tx_engine,
            address_book,
            static_projection(wallet_addr),
            tmp.path().join("machine-policy-projections"),
        )
        .with_home_write_permit(permit);
        Fixture {
            _tmp: tmp,
            handler,
            wallet_name: "alice".to_string(),
            wallet_addr,
        }
    }

    #[tokio::test]
    async fn balance_cache_ttl_covers_wallet_native_balance_leaves() {
        let f = make_handler_with_chain(true);
        for leaf in ["balance", "balance.raw", "balance.json", "nonce"] {
            let p = VfsPath::parse(&format!("/alice/chains/anvil/{leaf}")).unwrap();
            assert_eq!(
                f.handler.cache_ttl(&p),
                Some(super::super::balances::LIVE_BALANCE_TTL),
                "leaf {leaf}"
            );
        }
        let outbox = VfsPath::parse("/alice/chains/anvil/outbox").unwrap();
        assert_eq!(f.handler.cache_ttl(&outbox), None);
    }

    /// Write a synthetic staged tx directly into the outbox so the tests
    /// that drive confirm/replace/cancel don't have to spin up a chain.
    fn seed_pending(f: &Fixture, id: &str) {
        let staged = bloom_proto::StagedTx {
            id: id.into(),
            wallet: f.wallet_name.clone(),
            chain: "anvil".into(),
            chain_id: 31337,
            from: bloom_proto::checksum_address(&f.wallet_addr),
            to: "0x0000000000000000000000000000000000000002".into(),
            value_wei: "0".into(),
            data_hex: "0x".into(),
            gas_limit: 21000,
            max_fee_per_gas: Some("100".into()),
            max_priority_fee_per_gas: Some("10".into()),
            gas_price: None,
            nonce: 0,
            policy_checks: vec![],
            created_ms: 0,
            // Far in the future so expiry never trips during tests.
            expires_ms: u128::MAX,
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
        f.handler
            .tx_engine
            .outbox
            .write_pending(&staged, "p")
            .unwrap();
    }

    #[tokio::test]
    async fn legacy_wallet_sign_surface_is_absent() {
        let f = make_handler();
        let directory = VfsPath::parse(&format!("/{}/sign", f.wallet_name)).unwrap();
        assert!(matches!(
            f.handler.lookup(&directory).await,
            Err(HandlerError::NotFound(_))
        ));
        let path = VfsPath::parse(&format!("/{}/sign/hash", f.wallet_name)).unwrap();
        assert!(matches!(
            f.handler.write(&path, b"not a signing oracle").await,
            Err(HandlerError::PermissionDenied)
        ));
        assert!(!f._tmp.path().join("keystore").exists());
    }

    #[tokio::test]
    async fn direct_machine_wallet_creation_is_removed_for_every_legacy_body() {
        let f = make_handler();
        let path = VfsPath::parse("/new").unwrap();
        let error = f.handler.write(&path, b"alice").await.unwrap_err();
        assert!(matches!(&error, HandlerError::Backend(_)));
        assert!(
            error
                .to_string()
                .contains("custody requires the authenticated Machine-to-Broker edge"),
            "unexpected missing-Broker error: {error}"
        );
        for body in [
            &b"name = \"bob\"\nkind = \"local\"\npassphrase = \"secret\"\n"[..],
            b"name = \"observer\"\nkind = \"watch\"\naddress = \"0x0000000000000000000000000000000000000001\"\n",
            b"name = \"imported\"\nkind = \"import\"\nprivate_key = \"secret\"\n",
        ] {
            let error = f.handler.write(&path, body).await.unwrap_err();
            assert!(
                matches!(error, HandlerError::Invalid(_) | HandlerError::Unsupported(_)),
                "unexpected direct wallet creation result: {error:?}"
            );
        }
        assert!(!f._tmp.path().join("keystore").exists());
    }

    #[tokio::test]
    async fn list_root_includes_new() {
        let f = make_handler();
        let p = VfsPath::parse("/").unwrap();
        let entries = f.handler.list(&p).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"alice"));
        assert!(names.contains(&"new"));
        assert!(names.contains(&"registrations"));
    }

    #[tokio::test]
    async fn wallet_root_controls_remain_accessible_when_projection_reader_is_unavailable() {
        let mut f = make_handler();
        f.handler.wallet_projections = Some(Arc::new(UnavailableProjection));
        let entries = f.handler.list(&VfsPath::parse("/").unwrap()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, ["new", "registrations"]);
    }

    #[tokio::test]
    async fn wallet_root_does_not_mask_projection_integrity_failures_with_cached_wallets() {
        let mut f = make_handler();
        let cached = f.handler.wallet_projections.take().unwrap();
        f.handler.wallet_projections = Some(Arc::new(IntegrityFailureProjection(cached)));
        let error = f
            .handler
            .list(&VfsPath::parse("/").unwrap())
            .await
            .unwrap_err();
        assert!(matches!(error, HandlerError::Backend(_)));
        assert!(
            error
                .to_string()
                .contains("wallet projection identity is invalid")
        );
    }

    #[tokio::test]
    async fn mounted_registration_accepts_a_trimmed_plain_name() {
        let mut fixture = make_handler();
        let broker = Arc::new(RegistrationBroker {
            requests: Mutex::new(Vec::new()),
            state: Mutex::new(CeremonyState::AwaitingUser),
            omit_ceremony_url: Mutex::new(false),
            status_error: Mutex::new(None),
        });
        fixture.handler = fixture
            .handler
            .with_broker(Some(MachineBrokerClient::new(broker.clone())));

        let new = VfsPath::parse("/new").unwrap();
        fixture.handler.write(&new, b" \nmain\t\n").await.unwrap();

        assert_eq!(
            fixture.handler.read(&new).await.unwrap(),
            b"Write a wallet name matching [A-Za-z0-9_-]{1,64}.\n"
        );

        let petnamed_projection_path = fixture.handler.registration_path("main");
        assert!(petnamed_projection_path.is_file());
        let persisted: WalletRegistrationProjection = read_json(&petnamed_projection_path).unwrap();
        let legacy_operation_path = fixture
            .handler
            .registration_path(persisted.operation_id.as_str());
        std::fs::rename(&petnamed_projection_path, &legacy_operation_path).unwrap();

        let registrations = fixture
            .handler
            .list(&VfsPath::parse("/registrations").unwrap())
            .await
            .unwrap();
        assert_eq!(registrations.len(), 1);
        assert_eq!(registrations[0].name, "main");
        assert!(
            fixture
                .handler
                .lookup(
                    &VfsPath::parse(&format!(
                        "/registrations/{}/status.json",
                        persisted.operation_id
                    ))
                    .unwrap()
                )
                .await
                .is_err()
        );
        let status_path = VfsPath::parse("/registrations/main/status.json").unwrap();
        let status: serde_json::Value =
            serde_json::from_slice(&fixture.handler.read(&status_path).await.unwrap()).unwrap();
        assert_eq!(status["requested_name"], "main");
        assert_eq!(
            status["ceremony_url"],
            "http://localhost:18734/ceremony/registration-secret"
        );
        let registration_wallet_id =
            broker
                .requests
                .lock()
                .unwrap()
                .iter()
                .find_map(|request| match request {
                    MachineBrokerRequest::WalletRegistrationPrepare(request) => {
                        request.wallet_id.clone()
                    }
                    _ => None,
                });
        assert_eq!(registration_wallet_id.as_ref(), Some(&token("main")));

        let metadata_request_count = broker.requests.lock().unwrap().len();
        fixture
            .handler
            .lookup(&VfsPath::parse("/registrations/main").unwrap())
            .await
            .unwrap();
        fixture
            .handler
            .lookup(&VfsPath::parse("/registrations/main/status.json").unwrap())
            .await
            .unwrap();
        fixture
            .handler
            .lookup(&VfsPath::parse("/registrations/main/cancel").unwrap())
            .await
            .unwrap();
        let pending_entries = fixture
            .handler
            .list(&VfsPath::parse("/registrations/main").unwrap())
            .await
            .unwrap();
        assert_eq!(
            pending_entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["status.json", "cancel"]
        );
        assert_eq!(
            broker.requests.lock().unwrap().len(),
            metadata_request_count,
            "registration directory metadata must not contact the Broker"
        );
        assert!(matches!(
            fixture
                .handler
                .lookup(&VfsPath::parse("/registrations/main/result.json").unwrap())
                .await,
            Err(HandlerError::NotFound(_))
        ));
        assert!(matches!(
            fixture
                .handler
                .read(&VfsPath::parse("/registrations/main/result.json").unwrap())
                .await,
            Err(HandlerError::NotFound(_))
        ));

        let prepare_count = broker
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| matches!(request, MachineBrokerRequest::WalletRegistrationPrepare(_)))
            .count();
        fixture.handler.write(&new, b"main\n").await.unwrap();
        assert_eq!(
            broker
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|request| {
                    matches!(request, MachineBrokerRequest::WalletRegistrationPrepare(_))
                })
                .count(),
            prepare_count,
            "retrying a live registration must reuse its Broker operation"
        );

        *broker.omit_ceremony_url.lock().unwrap() = true;
        assert!(matches!(
            fixture.handler.read(&status_path).await,
            Err(HandlerError::Backend(_))
        ));
        *broker.omit_ceremony_url.lock().unwrap() = false;

        assert!(matches!(
            fixture
                .handler
                .write(&VfsPath::parse("/registrations/main/cancel").unwrap(), b"",)
                .await,
            Err(HandlerError::Invalid(_))
        ));
        assert!(matches!(
            fixture
                .handler
                .write(
                    &VfsPath::parse("/registrations/main/cancel").unwrap(),
                    b"maybe\n",
                )
                .await,
            Err(HandlerError::Invalid(_))
        ));

        fixture
            .handler
            .write(
                &VfsPath::parse("/registrations/main/cancel").unwrap(),
                b"y\n",
            )
            .await
            .unwrap();
        let terminal: serde_json::Value =
            serde_json::from_slice(&fixture.handler.read(&status_path).await.unwrap()).unwrap();
        assert_eq!(terminal["ceremony_state"], "CANCELLED");
        assert!(terminal["ceremony_url"].is_null());
        assert!(matches!(
            fixture
                .handler
                .read(&VfsPath::parse("/registrations/main/result.json").unwrap())
                .await,
            Err(HandlerError::NotFound(_))
        ));

        let (projection_path, mut completion_projection) =
            fixture.handler.registration_record("main").unwrap();
        completion_projection.ceremony_state = CeremonyState::AwaitingUser;
        completion_projection.ceremony_url =
            Some("http://localhost:18734/ceremony/registration-secret".into());
        completion_projection.ceremony_expires_at_ms = Some(DecimalU64::new(1));
        write_atomic_json(&projection_path, &completion_projection).unwrap();
        *broker.state.lock().unwrap() = CeremonyState::Completed;
        let _: serde_json::Value =
            serde_json::from_slice(&fixture.handler.read(&status_path).await.unwrap()).unwrap();
        let completed_entries = fixture
            .handler
            .list(&VfsPath::parse("/registrations/main").unwrap())
            .await
            .unwrap();
        assert!(
            completed_entries
                .iter()
                .any(|entry| entry.name == "result.json")
        );
        let result = fixture
            .handler
            .read(&VfsPath::parse("/registrations/main/result.json").unwrap())
            .await
            .unwrap();
        assert!(
            !String::from_utf8(result)
                .unwrap()
                .contains("encrypted_browser_result")
        );
        assert!(
            broker
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|request| matches!(
                    request,
                    MachineBrokerRequest::WalletRegistrationPrepare(_)
                ))
        );

        let (projection_path, mut expired_projection) =
            fixture.handler.registration_record("main").unwrap();
        expired_projection.ceremony_state = CeremonyState::AwaitingUser;
        expired_projection.ceremony_url = Some("http://localhost:18734/ceremony/expired".into());
        expired_projection.ceremony_expires_at_ms = Some(DecimalU64::new(1));
        write_atomic_json(&projection_path, &expired_projection).unwrap();
        *broker.state.lock().unwrap() = CeremonyState::Expired;
        let requests_before_expiry_reconciliation = broker.requests.lock().unwrap().len();

        let expired: serde_json::Value =
            serde_json::from_slice(&fixture.handler.read(&status_path).await.unwrap()).unwrap();
        assert_eq!(expired["ceremony_state"], "EXPIRED");
        assert!(expired["ceremony_url"].is_null());
        assert_eq!(
            broker.requests.lock().unwrap().len(),
            requests_before_expiry_reconciliation + 1,
            "local expiry must reconcile with Broker before becoming terminal"
        );
        let expired_again: serde_json::Value =
            serde_json::from_slice(&fixture.handler.read(&status_path).await.unwrap()).unwrap();
        assert_eq!(expired_again["ceremony_state"], "EXPIRED");
        assert_eq!(
            broker.requests.lock().unwrap().len(),
            requests_before_expiry_reconciliation + 1,
            "persisted terminal status must not be refreshed from the Broker"
        );
    }

    #[tokio::test]
    async fn mounted_registration_rejects_invalid_names_without_calling_broker() {
        let mut fixture = make_handler();
        let broker = Arc::new(RegistrationBroker {
            requests: Mutex::new(Vec::new()),
            state: Mutex::new(CeremonyState::AwaitingUser),
            omit_ceremony_url: Mutex::new(false),
            status_error: Mutex::new(None),
        });
        fixture.handler = fixture
            .handler
            .with_broker(Some(MachineBrokerClient::new(broker.clone())));
        let new = VfsPath::parse("/new").unwrap();

        for body in [
            &b" \n\t"[..],
            b"main/sub",
            br#"{"schema":"bloom.wallet-registration-request.1","requested_name":"main"}"#,
            &[0xff],
            &[b'a'; 65],
        ] {
            assert!(
                matches!(
                    fixture.handler.write(&new, body).await,
                    Err(HandlerError::Invalid(_))
                ),
                "unexpected registration result for {body:?}"
            );
            assert!(
                broker.requests.lock().unwrap().is_empty(),
                "invalid registration reached Broker for {body:?}"
            );
        }
    }

    #[tokio::test]
    async fn identical_canonical_and_legacy_registration_records_recover_after_crash() {
        let mut fixture = make_handler();
        let broker = Arc::new(RegistrationBroker {
            requests: Mutex::new(Vec::new()),
            state: Mutex::new(CeremonyState::AwaitingUser),
            omit_ceremony_url: Mutex::new(false),
            status_error: Mutex::new(None),
        });
        fixture.handler = fixture
            .handler
            .with_broker(Some(MachineBrokerClient::new(broker.clone())));
        fixture
            .handler
            .write(&VfsPath::parse("/new").unwrap(), b"main")
            .await
            .unwrap();

        let canonical = fixture.handler.registration_path("main");
        let projection: WalletRegistrationProjection = read_json(&canonical).unwrap();
        let legacy = fixture
            .handler
            .registration_path(projection.operation_id.as_str());
        std::fs::copy(&canonical, &legacy).unwrap();

        let entries = fixture
            .handler
            .list(&VfsPath::parse("/registrations").unwrap())
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "main");
        assert!(canonical.is_file());
        assert!(!legacy.exists());
        assert_eq!(
            broker
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|request| matches!(
                    request,
                    MachineBrokerRequest::WalletRegistrationPrepare(_)
                ))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn expired_registration_clears_stale_url_but_stays_retryable_when_broker_is_unavailable()
    {
        let mut fixture = make_handler();
        let broker = Arc::new(RegistrationBroker {
            requests: Mutex::new(Vec::new()),
            state: Mutex::new(CeremonyState::AwaitingUser),
            omit_ceremony_url: Mutex::new(false),
            status_error: Mutex::new(None),
        });
        fixture.handler = fixture
            .handler
            .with_broker(Some(MachineBrokerClient::new(broker.clone())));
        fixture
            .handler
            .write(&VfsPath::parse("/new").unwrap(), b"main")
            .await
            .unwrap();
        let (path, mut projection) = fixture.handler.registration_record("main").unwrap();
        projection.ceremony_expires_at_ms = Some(DecimalU64::new(1));
        write_atomic_json(&path, &projection).unwrap();
        *broker.status_error.lock().unwrap() = Some(ProtocolErrorCode::ServiceUnavailable);

        let error = fixture
            .handler
            .read(&VfsPath::parse("/registrations/main/status.json").unwrap())
            .await
            .unwrap_err();
        assert!(matches!(error, HandlerError::Backend(_)));
        let retained: WalletRegistrationProjection = read_json(&path).unwrap();
        assert_eq!(retained.ceremony_state, CeremonyState::AwaitingUser);
        assert!(retained.ceremony_url.is_none());
        assert!(retained.ceremony_expires_at_ms.is_none());
    }

    #[tokio::test]
    async fn mounted_registration_accepts_a_64_character_name() {
        let mut fixture = make_handler();
        let broker = Arc::new(RegistrationBroker {
            requests: Mutex::new(Vec::new()),
            state: Mutex::new(CeremonyState::AwaitingUser),
            omit_ceremony_url: Mutex::new(false),
            status_error: Mutex::new(None),
        });
        fixture.handler = fixture
            .handler
            .with_broker(Some(MachineBrokerClient::new(broker.clone())));
        let name = "a".repeat(64);

        fixture
            .handler
            .write(&VfsPath::parse("/new").unwrap(), name.as_bytes())
            .await
            .unwrap();

        let requests = broker.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let MachineBrokerRequest::WalletRegistrationPrepare(request) = &requests[0] else {
            panic!("expected wallet registration prepare request")
        };
        assert_eq!(request.wallet_id.as_ref(), Some(&token(&name)));
    }

    #[tokio::test]
    async fn sealed_approval_vfs_is_broker_backed_sorted_and_wallet_scoped() {
        let mut f = make_handler();
        let first = digest(1);
        let second = digest(2);
        let broker = approval_broker(vec![
            approval_status(
                second.clone(),
                "alice",
                ApprovalLifecycleState::AwaitingCeremony,
            ),
            approval_status(first.clone(), "alice", ApprovalLifecycleState::Active),
            approval_status(digest(3), "bob", ApprovalLifecycleState::Active),
        ]);
        f.handler = f
            .handler
            .with_broker(Some(MachineBrokerClient::new(broker.clone())));

        let wallet_entries = f
            .handler
            .list(&VfsPath::parse("/alice").unwrap())
            .await
            .unwrap();
        assert!(
            wallet_entries
                .iter()
                .any(|entry| entry.name == "sealed-approvals")
        );
        assert!(
            !wallet_entries
                .iter()
                .any(|entry| entry.name == concat!("policy-", "session"))
        );
        assert!(matches!(
            f.handler
                .lookup(&VfsPath::parse(concat!("/alice/policy-", "session")).unwrap())
                .await,
            Err(HandlerError::NotFound(_))
        ));

        let entries = f
            .handler
            .list(&VfsPath::parse("/alice/sealed-approvals").unwrap())
            .await
            .unwrap();
        let names: Vec<_> = entries.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(&names[..3], &["new.json", "active.json", "revoke_all"]);
        assert_eq!(&names[3..], &[first.as_str(), second.as_str()]);

        let active = f
            .handler
            .read(&VfsPath::parse("/alice/sealed-approvals/active.json").unwrap())
            .await
            .unwrap();
        let active: serde_json::Value = serde_json::from_slice(&active).unwrap();
        assert_eq!(active["approvals"][0]["approval_id"], first.as_str());
        assert_eq!(active["approvals"][1]["approval_id"], second.as_str());

        let status_path = VfsPath::parse(&format!(
            "/alice/sealed-approvals/{}/status.json",
            first.as_str()
        ))
        .unwrap();
        let returned: ApprovalPublicStatus =
            serde_json::from_slice(&f.handler.read(&status_path).await.unwrap()).unwrap();
        assert_eq!(returned.approval_id, first);

        let limits_path = VfsPath::parse(&format!(
            "/alice/sealed-approvals/{}/limits.json",
            second.as_str()
        ))
        .unwrap();
        let limits: ApprovalLimitState =
            serde_json::from_slice(&f.handler.read(&limits_path).await.unwrap()).unwrap();
        assert_eq!(limits.reserved_signatures, DecimalU64::new(5));

        let cross_wallet = VfsPath::parse(&format!(
            "/alice/sealed-approvals/{}/status.json",
            digest(3).as_str()
        ))
        .unwrap();
        assert!(matches!(
            f.handler.read(&cross_wallet).await,
            Err(HandlerError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn sealed_approval_vfs_fails_closed_without_broker() {
        let f = make_handler();
        let error = f
            .handler
            .read(&VfsPath::parse("/alice/sealed-approvals/active.json").unwrap())
            .await
            .unwrap_err();
        assert!(matches!(error, HandlerError::Backend(message) if message.contains("Broker")));
    }

    #[tokio::test]
    async fn approval_prepare_projection_preserves_exact_ceremony_and_reconciles_terminal_state() {
        let mut f = make_handler();
        let broker = approval_broker(vec![approval_status(
            prepare_approval_id(),
            "alice",
            ApprovalLifecycleState::AwaitingCeremony,
        )]);
        f.handler = f
            .handler
            .with_broker(Some(MachineBrokerClient::new(broker.clone())));
        let request = ApprovalPrepareRequest {
            operation_id: OperationId::from_bytes([30; 32]),
            terms: approval_terms("alice", None),
            canonical_plan_facts_digest: digest(31),
        };
        let path = VfsPath::parse("/alice/sealed-approvals/new.json").unwrap();
        f.handler
            .write(&path, &serde_json::to_vec(&request).unwrap())
            .await
            .unwrap();

        let projected: SealedApprovalPrepareResponse =
            serde_json::from_slice(&f.handler.read(&path).await.unwrap()).unwrap();
        assert_eq!(projected, broker.prepare_response);

        let restarted = f.handler.clone();
        let after_restart: SealedApprovalPrepareResponse =
            serde_json::from_slice(&restarted.read(&path).await.unwrap()).unwrap();
        assert_eq!(after_restart, broker.prepare_response);

        broker.statuses.lock().unwrap()[0].state = ApprovalLifecycleState::Active;
        *broker.ceremony_state.lock().unwrap() = CeremonyState::Succeeded;
        let terminal = restarted.read(&path).await.unwrap();
        let terminal = String::from_utf8(terminal).unwrap();
        assert!(!terminal.contains("ceremony_url"));
        assert!(!restarted.approval_projection_path("alice", None).exists());
    }

    #[tokio::test]
    async fn approval_prepare_projection_hides_every_failed_terminal_launch_token() {
        for terminal_state in [
            CeremonyState::Cancelled,
            CeremonyState::Expired,
            CeremonyState::Failed,
        ] {
            let mut f = make_handler();
            let broker = approval_broker(vec![approval_status(
                prepare_approval_id(),
                "alice",
                ApprovalLifecycleState::AwaitingCeremony,
            )]);
            f.handler = f
                .handler
                .with_broker(Some(MachineBrokerClient::new(broker.clone())));
            let request = ApprovalPrepareRequest {
                operation_id: OperationId::from_bytes([30; 32]),
                terms: approval_terms("alice", None),
                canonical_plan_facts_digest: digest(31),
            };
            let path = VfsPath::parse("/alice/sealed-approvals/new.json").unwrap();
            f.handler
                .write(&path, &serde_json::to_vec(&request).unwrap())
                .await
                .unwrap();
            *broker.ceremony_state.lock().unwrap() = terminal_state;

            let terminal = String::from_utf8(f.handler.read(&path).await.unwrap()).unwrap();
            assert!(!terminal.contains("ceremony_url"));
            assert!(!f.handler.approval_projection_path("alice", None).exists());
        }
    }

    #[tokio::test]
    async fn approval_prepare_projection_fails_closed_on_ceremony_url_or_expiry_mismatch() {
        let mut f = make_handler();
        let broker = approval_broker(vec![approval_status(
            prepare_approval_id(),
            "alice",
            ApprovalLifecycleState::AwaitingCeremony,
        )]);
        f.handler = f
            .handler
            .with_broker(Some(MachineBrokerClient::new(broker.clone())));
        let request = ApprovalPrepareRequest {
            operation_id: OperationId::from_bytes([30; 32]),
            terms: approval_terms("alice", None),
            canonical_plan_facts_digest: digest(31),
        };
        let path = VfsPath::parse("/alice/sealed-approvals/new.json").unwrap();
        f.handler
            .write(&path, &serde_json::to_vec(&request).unwrap())
            .await
            .unwrap();
        *broker.ceremony_projection_mismatch.lock().unwrap() = true;

        let error = f.handler.read(&path).await.unwrap_err();
        assert!(matches!(
            error,
            HandlerError::Backend(message) if message.contains("does not match")
        ));
        assert!(f.handler.approval_projection_path("alice", None).exists());
    }

    #[tokio::test]
    async fn approval_prepare_rejects_mismatched_broker_approval_id_before_projection() {
        let mut f = make_handler();
        let broker = approval_broker(vec![]);
        *broker.prepare_id_mismatch.lock().unwrap() = true;
        f.handler = f
            .handler
            .with_broker(Some(MachineBrokerClient::new(broker)));
        let request = ApprovalPrepareRequest {
            operation_id: OperationId::from_bytes([30; 32]),
            terms: approval_terms("alice", None),
            canonical_plan_facts_digest: digest(31),
        };
        let path = VfsPath::parse("/alice/sealed-approvals/new.json").unwrap();

        let error = f
            .handler
            .write(&path, &serde_json::to_vec(&request).unwrap())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            HandlerError::Backend(message)
                if message.contains("different sealed_approval.prepare terms")
        ));
        assert!(!f.handler.approval_projection_path("alice", None).exists());
    }

    #[tokio::test]
    async fn approval_renew_projection_is_owner_readable_and_mutations_keep_exact_identity() {
        let mut f = make_handler();
        let old_id = digest(1);
        let broker = approval_broker(vec![
            approval_status(old_id.clone(), "alice", ApprovalLifecycleState::Active),
            approval_status(
                renew_approval_id(),
                "alice",
                ApprovalLifecycleState::AwaitingCeremony,
            ),
        ]);
        f.handler = f
            .handler
            .with_broker(Some(MachineBrokerClient::new(broker.clone())));
        let renewal = ApprovalRenewRequest {
            operation_id: OperationId::from_bytes([40; 32]),
            old_approval_id: old_id.clone(),
            replacement_terms: approval_terms("alice", Some(old_id.clone())),
        };
        let renew_path = VfsPath::parse(&format!(
            "/alice/sealed-approvals/{}/renew",
            old_id.as_str()
        ))
        .unwrap();
        f.handler
            .write(&renew_path, &serde_json::to_vec(&renewal).unwrap())
            .await
            .unwrap();
        let projected: SealedApprovalPrepareResponse =
            serde_json::from_slice(&f.handler.read(&renew_path).await.unwrap()).unwrap();
        assert_eq!(projected, broker.renew_response);

        let mismatched = RevokeRequest {
            operation_id: OperationId::from_bytes([41; 32]),
            approval_id: old_id,
            wallet_id: token("bob"),
            reason: "wrong wallet".into(),
        };
        let revoke_path =
            VfsPath::parse(&renew_path.to_string_path().replace("renew", "revoke")).unwrap();
        let before = broker.requests.lock().unwrap().len();
        assert!(matches!(
            f.handler
                .write(&revoke_path, &serde_json::to_vec(&mismatched).unwrap())
                .await,
            Err(HandlerError::Invalid(_))
        ));
        assert_eq!(broker.requests.lock().unwrap().len(), before);

        let revoke_all = WalletOperationRequest {
            operation_id: OperationId::from_bytes([42; 32]),
            wallet_id: token("alice"),
        };
        f.handler
            .write(
                &VfsPath::parse("/alice/sealed-approvals/revoke_all").unwrap(),
                &serde_json::to_vec(&revoke_all).unwrap(),
            )
            .await
            .unwrap();
        assert!(broker.requests.lock().unwrap().iter().any(|request| {
            request == &MachineBrokerRequest::SealedApprovalRevokeAll(revoke_all.clone())
        }));
    }

    #[tokio::test]
    async fn addresses_json_reports_owner_and_signer() {
        let f = make_handler();
        let p = VfsPath::parse(&format!("/{}/addresses.json", f.wallet_name)).unwrap();
        let body = f.handler.read(&p).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let owner = bloom_proto::checksum_address(&f.wallet_addr);
        assert_eq!(v["wallet"], "alice");
        assert_eq!(v["owner"], owner);
        assert_eq!(v["signer"], owner, "owner and signer are the same EOA");
        assert_eq!(v["policy_status"], "broker_verified");
        assert_eq!(v["unlocked"], false);
        assert!(v["roles"].as_object().unwrap().is_empty());
        // addresses.json is also a listed dir entry.
        let dir = VfsPath::parse(&format!("/{}", f.wallet_name)).unwrap();
        let names: Vec<String> = f
            .handler
            .list(&dir)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.iter().any(|n| n == "addresses.json"));
    }

    #[tokio::test]
    async fn wallet_dir_surfaces_address_qr_images() {
        let f = make_handler();
        let dir = VfsPath::parse(&format!("/{}", f.wallet_name)).unwrap();
        let entries = f.handler.list(&dir).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"address.qr.png"));
        assert!(names.contains(&"address.qr.svg"));

        for leaf in ["address.qr.png", "address.qr.svg"] {
            let path = VfsPath::parse(&format!("/{}/{leaf}", f.wallet_name)).unwrap();
            let entry = f.handler.lookup(&path).await.unwrap();
            assert_eq!(entry.name, leaf);
            assert!(matches!(entry.kind, crate::handler::EntryKind::File));
        }
    }

    #[tokio::test]
    async fn address_qr_svg_is_scannable_svg_document() {
        let f = make_handler();
        let path = VfsPath::parse(&format!("/{}/address.qr.svg", f.wallet_name)).unwrap();
        let body = f.handler.read(&path).await.unwrap();
        let svg = String::from_utf8(body).unwrap();
        assert!(svg.contains("<svg"), "{svg}");
        assert!(svg.contains("</svg>"), "{svg}");
        assert!(
            svg.contains("width=\"") && svg.contains("height=\""),
            "{svg}"
        );
    }

    #[tokio::test]
    async fn address_qr_png_is_png_document() {
        let f = make_handler();
        let path = VfsPath::parse(&format!("/{}/address.qr.png", f.wallet_name)).unwrap();
        let body = f.handler.read(&path).await.unwrap();
        assert!(body.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert!(
            body.windows(4).any(|w| w == b"IHDR") && body.windows(4).any(|w| w == b"IDAT"),
            "PNG chunks missing"
        );
        assert!(body.len() > 1024, "PNG too small to contain a QR image");
    }

    #[tokio::test]
    async fn legacy_sign_directory_is_not_listed() {
        let f = make_handler();
        let p = VfsPath::parse(&format!("/{}/sign", f.wallet_name)).unwrap();
        assert!(matches!(
            f.handler.list(&p).await,
            Err(HandlerError::NotADir(_))
        ));
    }

    /// Fix #8: reading `outbox/sent/<pending-id>/intent.json` must
    /// NotFound, even though the id exists in `pending`. Before the fix
    /// the read silently followed the id wherever it lived.
    #[tokio::test]
    async fn outbox_read_honours_state_segment() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-test");
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/sent/0001-test/intent.json",
            f.wallet_name
        ))
        .unwrap();
        let r = f.handler.read(&p).await;
        assert!(r.is_err(), "expected NotFound but got {r:?}");
    }

    /// Fix #8: listing `outbox/sent/<pending-id>/` must NotFound when
    /// the entry isn't actually in `sent`.
    #[tokio::test]
    async fn outbox_list_honours_state_segment() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-test");
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/sent/0001-test",
            f.wallet_name
        ))
        .unwrap();
        let r = f.handler.list(&p).await;
        assert!(r.is_err(), "expected NotFound, got {r:?}");
    }

    #[tokio::test]
    async fn outbox_listing_advertises_new_tx_as_writable() {
        let f = make_handler_with_chain(true);
        let p = VfsPath::parse(&format!("/{}/chains/anvil/outbox", f.wallet_name)).unwrap();

        let entries = f.handler.list(&p).await.unwrap();
        let new_tx = entries.iter().find(|entry| entry.name == "new.tx").unwrap();

        assert_eq!(new_tx.mode, 0o644);
    }

    #[tokio::test]
    async fn outbox_lookup_rejects_absent_artifacts_but_preserves_virtual_sinks() {
        let f = make_handler_with_chain(true);
        for (state_name, state, id) in [
            ("pending", OutboxState::Pending, "0001-pending"),
            ("sent", OutboxState::Sent, "0002-sent"),
            ("failed", OutboxState::Failed, "0003-failed"),
        ] {
            seed_pending(&f, id);
            let entry = f
                .handler
                .tx_engine
                .outbox
                .read_in_state(&f.wallet_name, "anvil", id, OutboxState::Pending)
                .unwrap();
            std::fs::write(entry.dir.join("runtime-result-42.json"), state_name).unwrap();
            if state != OutboxState::Pending {
                f.handler
                    .tx_engine
                    .outbox
                    .transition(&entry, state)
                    .unwrap();
            }

            let real_suffix = format!("{state_name}/{id}/runtime-result-42.json");
            let real = VfsPath::parse(&format!(
                "/{}/chains/anvil/outbox/{real_suffix}",
                f.wallet_name
            ))
            .unwrap();
            let metadata = f.handler.lookup(&real).await.unwrap();
            assert_eq!(metadata.kind, crate::handler::EntryKind::File);
            assert_eq!(metadata.mode, 0o444);
            assert_eq!(f.handler.read(&real).await.unwrap(), state_name.as_bytes());

            let absent = VfsPath::parse(&format!(
                "/{}/chains/anvil/outbox/{state_name}/{id}/does-not-exist.json",
                f.wallet_name
            ))
            .unwrap();
            assert!(matches!(
                f.handler.lookup(&absent).await,
                Err(HandlerError::NotFound(_))
            ));
            assert!(matches!(
                f.handler.read(&absent).await,
                Err(HandlerError::NotFound(_))
            ));
        }

        let new_tx =
            VfsPath::parse(&format!("/{}/chains/anvil/outbox/new.tx", f.wallet_name)).unwrap();
        let metadata = f.handler.lookup(&new_tx).await.unwrap();
        assert_eq!(metadata.kind, crate::handler::EntryKind::File);
        assert_eq!(metadata.mode, 0o644);

        for control in ["confirm", "confirm.override", "replace", "cancel"] {
            let path = VfsPath::parse(&format!(
                "/{}/chains/anvil/outbox/pending/0001-pending/{control}",
                f.wallet_name
            ))
            .unwrap();
            let metadata = f.handler.lookup(&path).await.unwrap();
            assert_eq!(metadata.kind, crate::handler::EntryKind::File);
            assert_eq!(metadata.mode, 0o644);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn outbox_lookup_and_read_reject_non_regular_artifacts() {
        use std::os::unix::fs::symlink;

        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-test");
        let entry = f
            .handler
            .tx_engine
            .outbox
            .read_in_state(&f.wallet_name, "anvil", "0001-test", OutboxState::Pending)
            .unwrap();
        std::fs::create_dir(entry.dir.join("artifact-dir")).unwrap();
        let outside = f._tmp.path().join("outside-secret.json");
        std::fs::write(&outside, b"secret").unwrap();
        symlink(&outside, entry.dir.join("artifact-link.json")).unwrap();

        for artifact in ["artifact-dir", "artifact-link.json"] {
            let path = VfsPath::parse(&format!(
                "/{}/chains/anvil/outbox/pending/0001-test/{artifact}",
                f.wallet_name
            ))
            .unwrap();
            assert!(matches!(
                f.handler.lookup(&path).await,
                Err(HandlerError::NotFound(_))
            ));
            assert!(matches!(
                f.handler.read(&path).await,
                Err(HandlerError::NotFound(_))
            ));
        }

        let directory = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/pending/0001-test",
            f.wallet_name
        ))
        .unwrap();
        let entries = f.handler.list(&directory).await.unwrap();
        assert!(!entries.iter().any(|entry| entry.name == "artifact-dir"));
        assert!(
            !entries
                .iter()
                .any(|entry| entry.name == "artifact-link.json")
        );

        let intent = entries
            .iter()
            .find(|entry| entry.name == "intent.json")
            .unwrap();
        assert_eq!(intent.kind, crate::handler::EntryKind::File);
        assert_eq!(intent.mode, 0o444);
        for control in ["confirm", "confirm.override", "replace", "cancel"] {
            let metadata = entries.iter().find(|entry| entry.name == control).unwrap();
            assert_eq!(metadata.kind, crate::handler::EntryKind::File);
            assert_eq!(metadata.mode, 0o644);
        }
    }

    #[cfg(unix)]
    #[test]
    fn opened_outbox_artifact_is_pinned_across_path_replacement() {
        use std::io::Read as _;
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let artifact = directory.path().join("result.json");
        let displaced = directory.path().join("result.original.json");
        let outside = directory.path().join("outside-secret.json");
        std::fs::write(&artifact, b"original").unwrap();
        std::fs::write(&outside, b"secret").unwrap();

        let mut opened = open_regular_outbox_artifact(directory.path(), "result.json").unwrap();
        std::fs::rename(&artifact, &displaced).unwrap();
        symlink(&outside, &artifact).unwrap();

        let mut bytes = Vec::new();
        opened.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
        assert!(matches!(
            open_regular_outbox_artifact(directory.path(), "result.json"),
            Err(HandlerError::NotFound(_))
        ));
    }

    /// Fix #9: writing an empty body to `pending/<id>/confirm` must
    /// surface as Invalid rather than broadcasting.
    #[tokio::test]
    async fn confirm_empty_body_rejected() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-test");
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/pending/0001-test/confirm",
            f.wallet_name
        ))
        .unwrap();
        let r = f.handler.write(&p, b"").await;
        assert!(matches!(r, Err(HandlerError::Invalid(_))), "got: {r:?}");
        // Whitespace-only is also rejected.
        let r = f.handler.write(&p, b"   \n\t").await;
        assert!(matches!(r, Err(HandlerError::Invalid(_))), "got: {r:?}");
    }

    #[tokio::test]
    async fn confirm_cancel_discards_pending_locally() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-test");
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/pending/0001-test/confirm",
            f.wallet_name
        ))
        .unwrap();
        f.handler.write(&p, b"cancel").await.unwrap();

        let entry = f
            .handler
            .tx_engine
            .outbox
            .read(&f.wallet_name, "anvil", "0001-test")
            .unwrap();
        assert_eq!(entry.state, OutboxState::Failed);
        assert!(!entry.dir.join("broadcast_attempted.json").exists());
        assert!(!entry.dir.join("raw_tx").exists());
    }

    #[tokio::test]
    async fn normal_confirm_open_preserves_body_control_semantics() {
        let f = make_handler_with_chain(true);
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/pending/not-yet-staged/confirm",
            f.wallet_name
        ))
        .unwrap();

        // OPEN cannot know whether the later body is `cancel`, a legacy
        // override sentinel, or an ordinary confirmation. It must therefore
        // allow the write through to write_inner, which owns those semantics.
        f.handler.prepare_write_open(&p).await.unwrap();
    }

    #[test]
    fn confirm_text_uses_first_line_only() {
        assert_eq!(first_confirm_line("y\nreview_hash=abc123\n"), "y");
        assert_eq!(first_confirm_line("override"), "override");
    }

    /// Fix #2 + #10: writing `outbox/sent/<id>/confirm` is not a valid
    /// route and must not rebroadcast. (Also covers the path-routing
    /// half of fix #2 — the engine layer is covered in tx_engine tests.)
    #[tokio::test]
    async fn confirm_path_only_valid_for_pending() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-test");
        // Move id to sent so it's no longer pending.
        let entry = f
            .handler
            .tx_engine
            .outbox
            .read(&f.wallet_name, "anvil", "0001-test")
            .unwrap();
        f.handler
            .tx_engine
            .outbox
            .transition(&entry, OutboxState::Sent)
            .unwrap();
        // Path that points at sent — must be permission denied (no route).
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/sent/0001-test/confirm",
            f.wallet_name
        ))
        .unwrap();
        let r = f.handler.write(&p, b"y").await;
        assert!(
            matches!(r, Err(HandlerError::PermissionDenied)),
            "got: {r:?}"
        );
        // Path under pending/<id> still resolves but the engine rejects
        // because the id isn't actually pending.
        let p2 = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/pending/0001-test/confirm",
            f.wallet_name
        ))
        .unwrap();
        let r2 = f.handler.write(&p2, b"y").await;
        assert!(r2.is_err(), "expected error from engine, got {r2:?}");
    }

    /// Fix #10: cancel route exists, demands a non-empty body, and
    /// rejects non-pending ids.
    #[tokio::test]
    async fn cancel_route_demands_body() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-test");
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/pending/0001-test/cancel",
            f.wallet_name
        ))
        .unwrap();
        let r = f.handler.write(&p, b"").await;
        assert!(matches!(r, Err(HandlerError::Invalid(_))), "got: {r:?}");
    }

    /// Fix #10: replace route exists and demands a non-empty body.
    #[tokio::test]
    async fn replace_route_demands_body() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-test");
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/pending/0001-test/replace",
            f.wallet_name
        ))
        .unwrap();
        let r = f.handler.write(&p, b"").await;
        assert!(matches!(r, Err(HandlerError::Invalid(_))), "got: {r:?}");
    }

    /// Fix #10: list of `pending/<id>/` advertises the writable control
    /// files (confirm, replace, cancel) even before they've been written.
    #[tokio::test]
    async fn list_pending_advertises_control_files() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-test");
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/pending/0001-test",
            f.wallet_name
        ))
        .unwrap();
        let entries = f.handler.list(&p).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"confirm"), "names={names:?}");
        assert!(names.contains(&"replace"), "names={names:?}");
        assert!(names.contains(&"cancel"), "names={names:?}");
    }

    #[tokio::test]
    async fn list_pending_returns_seeded_ids() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-21699");
        let p = VfsPath::parse(&format!("/{}/chains/anvil/outbox/pending", f.wallet_name)).unwrap();
        let entries = f.handler.list(&p).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"0001-21699"), "names={names:?}");
    }

    #[tokio::test]
    async fn pending_external_includes_index_txs_for_wallet_address() {
        let f = make_handler_with_chain(true);
        use alloy::primitives::{B256, Bytes, U256};
        use bloom_mempool::{PendingTx, PendingTxIndex, TxFees};

        let idx = PendingTxIndex::new(8);
        let mut other = [0u8; 20];
        other[0] = 9;
        let other_addr = Address::from(other);

        let mut h1 = [0u8; 32];
        h1[0] = 1;
        idx.insert(PendingTx {
            hash: B256::from(h1),
            from: f.wallet_addr,
            to: None,
            nonce: 0,
            value: U256::ZERO,
            gas_limit: 21_000,
            fees: TxFees::Legacy { gas_price: 1 },
            input: Bytes::new(),
            observed_at: std::time::SystemTime::now(),
        });
        let mut h2 = [0u8; 32];
        h2[0] = 2;
        idx.insert(PendingTx {
            hash: B256::from(h2),
            from: other_addr,
            to: None,
            nonce: 0,
            value: U256::ZERO,
            gas_limit: 21_000,
            fees: TxFees::Legacy { gas_price: 1 },
            input: Bytes::new(),
            observed_at: std::time::SystemTime::now(),
        });

        let mut map = std::collections::BTreeMap::new();
        map.insert("anvil".to_string(), idx);
        let handler = f.handler.clone().with_mempool_indexes(map);

        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/pending_external.jsonl",
            f.wallet_name
        ))
        .unwrap();
        let body = handler.read(&p).await.unwrap();
        let lines: Vec<&[u8]> = body
            .split(|c| *c == b'\n')
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(lines.len(), 1, "only the wallet's own tx should appear");
    }

    #[tokio::test]
    async fn nonce_conflicts_reports_observed_nonces_for_wallet_address() {
        let f = make_handler_with_chain(true);
        use alloy::primitives::{B256, Bytes, U256};
        use bloom_mempool::{PendingTx, PendingTxIndex, TxFees};

        let idx = PendingTxIndex::new(8);
        for (hash_b, nonce) in [(1u8, 3u64), (2u8, 5u64)] {
            let mut h = [0u8; 32];
            h[0] = hash_b;
            idx.insert(PendingTx {
                hash: B256::from(h),
                from: f.wallet_addr,
                to: None,
                nonce,
                value: U256::ZERO,
                gas_limit: 21_000,
                fees: TxFees::Legacy { gas_price: 1 },
                input: Bytes::new(),
                observed_at: std::time::SystemTime::now(),
            });
        }
        let mut map = std::collections::BTreeMap::new();
        map.insert("anvil".to_string(), idx);
        let handler = f.handler.clone().with_mempool_indexes(map);

        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/nonce_conflicts.json",
            f.wallet_name
        ))
        .unwrap();
        let body = handler.read(&p).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["observed_nonces"], serde_json::json!([3, 5]));
        // checksum address is non-empty hex
        assert!(v["address"].as_str().unwrap().starts_with("0x"));
    }

    #[tokio::test]
    async fn local_wallet_passkey_properties() {
        let f = make_handler();

        // kind reads "local"
        let bytes = f
            .handler
            .read(&VfsPath::parse("/alice/kind").unwrap())
            .await
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&bytes).trim(), "local");

        // unlock-passkey resolves to NotFound
        let r = f
            .handler
            .lookup(&VfsPath::parse("/alice/unlock-passkey").unwrap())
            .await;
        assert!(matches!(r, Err(HandlerError::NotFound(_))), "got {r:?}");

        // Direct Machine unlock writes are fail-closed for every wallet kind.
        let r = f
            .handler
            .write(&VfsPath::parse("/alice/unlock-passkey").unwrap(), b"unlock")
            .await;
        assert!(
            matches!(r, Err(HandlerError::PermissionDenied)),
            "got {r:?}"
        );

        // listing does NOT contain unlock-passkey
        let entries = f
            .handler
            .list(&VfsPath::parse("/alice").unwrap())
            .await
            .unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(!names.contains(&"unlock-passkey"), "names={names:?}");
    }

    /// The staged challenge is discoverable and readable through the mount:
    /// `policy-updates/` lists the action, its `approval_challenge.json` carries
    /// a `ceremony_url`, `status.json` renders the retry guidance, and none of it
    /// leaks the signed approval or any secret material.

    #[tokio::test]
    async fn pending_external_returns_empty_when_no_index_for_chain() {
        let f = make_handler_with_chain(true);
        // Don't install any mempool index.
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/pending_external.jsonl",
            f.wallet_name
        ))
        .unwrap();
        let body = f.handler.read(&p).await.unwrap();
        assert!(body.is_empty());
    }
}
