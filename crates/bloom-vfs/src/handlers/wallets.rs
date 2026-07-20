//! `wallets/<wallet>/...` — managed wallets and the outbox write surface.
//!
//! This handler wires keystore + chain + tx engine together. Reads expose
//! wallet metadata and per-chain balance/nonce; writes go through the
//! outbox stage-confirm flow.
//!
//! Paths handled:
//! - `wallets/`                                                     — list wallets
//! - `wallets/new`                                                  — write to create wallet (plain name or TOML spec)
//! - `wallets/<wallet>/address`                                     — checksummed owner/signer address
//! - `wallets/<wallet>/address.qr.svg`                              — scannable QR image for the owner/signer address
//! - `wallets/<wallet>/address.qr.png`                              — scannable QR image for the owner/signer address
//! - `wallets/<wallet>/addresses.json`                              — owner/signer + role addresses
//! - `wallets/<wallet>/public_key`                                  — secp256k1 pubkey hex
//! - `wallets/<wallet>/kind`                                        — local/watch
//! - `wallets/<wallet>/policy.toml`                                 — read+write policy
//! - `wallets/<wallet>/chains/<chain>/{balance,balance.raw,balance.json}` — native balance
//! - `wallets/<wallet>/chains/<chain>/nonce`
//! - `wallets/<wallet>/chains/<chain>/outbox/new.tx`                — write to stage
//! - `wallets/<wallet>/chains/<chain>/outbox/pending/<id>/<file>`   — read staged
//! - `wallets/<wallet>/chains/<chain>/outbox/pending/<id>/confirm`  — write to broadcast
//! - `wallets/<wallet>/chains/<chain>/outbox/sent/<id>/<file>`      — read sent
//! - `wallets/<wallet>/chains/<chain>/outbox/failed/<id>/<file>`    — read failed

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64_STANDARD, URL_SAFE_NO_PAD};
use bloom_auth_api::{
    ApprovalChallenge, AssuranceLevel, CanonicalEnvelope, CanonicalIntentHeader, DaemonGrantTerms,
    EVM_ERC20_TRANSFER_METHOD, EVM_OWNER_SESSION_MINT_ACTION_KIND,
    EVM_OWNER_SESSION_USE_ACTION_KIND, EVM_OWNER_SIGNING_SESSION_KIND, EVM_TX_SIGN_INTENT,
    EvmFeePolicy, EvmOwnerSigningSessionCounters, EvmOwnerSigningSessionScope,
    EvmOwnerSigningSessionUse, ExecutorKind, PetalPolicySnapshot, SIGNING_ATTESTATION_SCHEMA_V1,
    SealedAction, SignHashRequest, SignedApproval, SigningAttestation, petal_identity,
};
use bloom_evm::ChainRegistry;
use bloom_keystore::Keystore;
use bloom_proto::{
    AddressBook, CapabilityStatus, CapabilityViewEntry, HomeWritePermit, Policy, PolicyEditClass,
    RawIntent, SigningModel, Venue, classify_policy_edit,
};
use bloom_tx::{
    intent_parser,
    outbox::OutboxState,
    tx_engine::{TxEngine, TxEngineError},
};
use qrcode::QrCode;
use qrcode::render::svg;
use qrcode::types::Color as QrColor;

use crate::auth::AuthServices;
use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

const APPROVAL_FILE: &str = "approval.json";
const APPROVAL_CHALLENGE_FILE: &str = "approval_challenge.json";
const APPROVAL_TTL_MS: u64 = 5 * 60 * 1000;
const WALLET_POLICY_SURFACE: &str = "wallet-policy";
const WALLET_POLICY_ACTION_KIND: &str = "policy_update";
const WALLET_POLICY_SUBJECT_SCHEMA: &str = "bloom.wallet_policy_update_subject.v1";
const WALLET_POLICY_SIGN_INTENT: &str = "wallet_policy.sign";

#[derive(Clone)]
pub struct WalletsHandler {
    pub keystore: Keystore,
    pub chains: ChainRegistry,
    pub tx_engine: TxEngine,
    pub address_book: Arc<AddressBook>,
    pub home_write_permit: Option<Arc<HomeWritePermit>>,
    pub mempool_indexes:
        Arc<std::collections::BTreeMap<String, Arc<bloom_mempool::PendingTxIndex>>>,
    /// Optional Hyperliquid handler for capability roll-up aggregation.
    pub hyperliquid_handler: Option<Arc<crate::handlers::hyperliquid::HyperliquidHandler>>,
    /// Optional Layer-B auth services. Migrated signer paths must use this
    /// instead of marker files; absent means legacy behavior remains explicit.
    pub auth_services: AuthServices,
}

impl WalletsHandler {
    pub fn new(
        keystore: Keystore,
        chains: ChainRegistry,
        tx_engine: TxEngine,
        address_book: AddressBook,
    ) -> Self {
        Self {
            keystore,
            chains,
            tx_engine,
            address_book: Arc::new(address_book),
            home_write_permit: None,
            mempool_indexes: Arc::new(std::collections::BTreeMap::new()),
            hyperliquid_handler: None,
            auth_services: AuthServices::default(),
        }
    }

    pub fn with_auth_services(mut self, auth_services: AuthServices) -> Self {
        self.auth_services = auth_services;
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

    pub fn with_hyperliquid_handler(
        mut self,
        hl: Option<Arc<crate::handlers::hyperliquid::HyperliquidHandler>>,
    ) -> Self {
        self.hyperliquid_handler = hl;
        self
    }

    pub fn with_mempool_indexes(
        mut self,
        indexes: std::collections::BTreeMap<String, Arc<bloom_mempool::PendingTxIndex>>,
    ) -> Self {
        self.mempool_indexes = Arc::new(indexes);
        self
    }

    /// Role-labeled address view for a wallet. The keystore `address` is both
    /// the `owner` and the `signer` (the owner key signs). Venue-specific
    /// role addresses are exposed by their installed Petals.
    fn addresses_json(
        &self,
        wallet: &str,
        info: &bloom_keystore::WalletInfo,
    ) -> Result<Vec<u8>, HandlerError> {
        use bloom_keystore::{PolicyStatus, WalletKind};

        let kind = match info.kind {
            WalletKind::Local => "local",
            WalletKind::Watch => "watch",
            WalletKind::PasskeyGated => "passkey",
        };
        let policy_status = match self.keystore.policy_status(wallet).map_err(err_be)? {
            PolicyStatus::Signed => "signed",
            PolicyStatus::Unsigned => "unsigned",
            PolicyStatus::Stale => "stale",
            PolicyStatus::NotApplicable => "not_applicable",
        };
        let unlocked = self.keystore.is_unlocked(wallet);
        let owner = bloom_proto::checksum_address(&info.address);

        let roles = serde_json::Map::new();

        let body = serde_json::json!({
            "wallet": wallet,
            "kind": kind,
            "owner": owner,
            "signer": owner,
            "policy_status": policy_status,
            "unlocked": unlocked,
            "roles": serde_json::Value::Object(roles),
        });
        let mut out = serde_json::to_vec_pretty(&body).map_err(err_be)?;
        out.push(b'\n');
        Ok(out)
    }

    fn evm_capability_views_for(&self, wallet: &str) -> Vec<CapabilityViewEntry> {
        let now_ms = bloom_proto::capability::now_ms_u128();
        let sessions = self.tx_engine.session_store().active(now_ms);
        let mut out = Vec::new();
        for s in sessions {
            if s.wallet != wallet {
                continue;
            }
            let status = if s.expires_ms <= now_ms {
                CapabilityStatus::Expired
            } else {
                CapabilityStatus::Active
            };
            let chains_display: Vec<String> = s.chains.iter().map(|id| id.to_string()).collect();
            let limits = serde_json::json!({
                "max_usd": s.max_micro_usd as f64 / 1_000_000.0,
                "spent_usd": s.spent_micro_usd as f64 / 1_000_000.0,
                "chains": &chains_display,
                "allowed_pending_ids": s.allowed_pending_ids,
            });
            let pending_ids: Vec<&str> = s
                .allowed_pending_ids
                .iter()
                .map(|s| s.as_str())
                .take(10)
                .collect();
            let mut allowed = vec![format!(
                "confirm {} pending tx ids",
                s.allowed_pending_ids.len()
            )];
            if !chains_display.is_empty() {
                allowed.push(format!("on chains: {}", chains_display.join(", ")));
            }
            allowed.push(format!(
                "max total spend: ${:.2}",
                s.max_micro_usd as f64 / 1_000_000.0
            ));
            if s.spent_micro_usd > 0 {
                allowed.push(format!(
                    "spent: ${:.2}",
                    s.spent_micro_usd as f64 / 1_000_000.0
                ));
            }
            let denied = vec!["tx ids not listed above require a fresh review".to_string()];
            out.push(CapabilityViewEntry {
                id: s.id.clone(),
                wallet: wallet.to_string(),
                venue: Venue::EvmOutbox,
                signing_model: SigningModel::AuthorizesOwnerSigning,
                created_ms: 0, // EVM sessions don't track creation time
                expires_ms: Some(s.expires_ms),
                expires_in_secs: if s.expires_ms > now_ms {
                    Some(((s.expires_ms - now_ms) / 1000) as u64)
                } else {
                    None
                },
                status,
                limits,
                next_write_path: if let Some(first) = pending_ids.first() {
                    // Pending keys are chain-qualified: `"{chain_id}:{outbox_id}"`.
                    // Resolve the chain segment from the id rather than assuming a
                    // single chain, so multi-chain sessions render a confirm path
                    // that actually resolves.
                    let (chain, outbox_id) = match first.split_once(':') {
                        Some((chain_id, id)) => {
                            let chain = chain_id
                                .parse::<u64>()
                                .ok()
                                .and_then(|cid| self.chains.name_for_chain_id(cid))
                                .unwrap_or_else(|| chain_id.to_string());
                            (chain, id)
                        }
                        None => ("ethereum".to_string(), *first),
                    };
                    format!("/wallets/{wallet}/chains/{chain}/outbox/pending/{outbox_id}/confirm")
                } else {
                    format!("/wallets/{wallet}/policy-session/active.json")
                },
                revoke_path: format!("/wallets/{wallet}/policy-session/{}/revoke", s.id),
                audit_ref: "/status/audit/head".to_string(),
                review_ref: format!("/wallets/{wallet}/policy-session/active.json"),
                allowed,
                denied,
            });
        }
        out
    }

    fn all_capability_views_for(&self, wallet: &str) -> Vec<CapabilityViewEntry> {
        let mut all = self.evm_capability_views_for(wallet);
        if let Some(ref hl) = self.hyperliquid_handler {
            let hl_views = hl.capability_views_for(wallet);
            all.extend(hl_views);
        }
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
            md.push_str("Create a Hyperliquid session at `/hyperliquid/<net>/agent_sessions/{wallet}/new.json`");
            md.push_str(" or an EVM policy session at `/wallets/{wallet}/policy-session/new`.\n");
        } else {
            for c in &entries {
                md.push_str(&format!(
                    "## {} ({})\n\n",
                    c.id,
                    match c.venue {
                        Venue::Hyperliquid => "Hyperliquid",
                        Venue::EvmOutbox => "EVM outbox",
                        Venue::Defi => "DeFi",
                    }
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

    fn policy_session_dir_entries() -> Vec<Entry> {
        vec![Entry::writable_file("new"), Entry::file("active.json")]
    }

    /// List this wallet's live policy sessions.
    async fn policy_session_active_json(&self, wallet: &str) -> Result<Vec<u8>, HandlerError> {
        let mut sessions: Vec<serde_json::Value> = self
            .tx_engine
            .session_store()
            .active(now_ms())
            .into_iter()
            .filter(|s| s.wallet == wallet)
            .map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "chains": s.chains.iter().copied().collect::<Vec<u64>>(),
                    "expires_ms": s.expires_ms,
                    "max_micro_usd": s.max_micro_usd,
                    "spent_micro_usd": s.spent_micro_usd,
                    "allowed_pending_ids": s.allowed_pending_ids.iter().cloned().collect::<Vec<String>>(),
                })
            })
            .collect();
        if let Some(store) = self.auth_services.store()
            && let Ok(standing) = store
                .active_standing_sessions(
                    wallet,
                    Some(EVM_OWNER_SIGNING_SESSION_KIND),
                    now_ms_u64(),
                )
                .await
        {
            sessions.extend(standing.into_iter().map(|s| {
                serde_json::json!({
                    "id": s.session_id,
                    "wallet": s.wallet,
                    "petal_id": s.petal_id,
                    "session_kind": s.session_kind,
                    "scope": s.scope,
                    "counters": s.counters,
                    "frozen_policy_version": s.frozen_policy_version,
                    "frozen_petal_policy_digest": s.frozen_petal_policy_digest,
                    "issued_ms": s.issued_ms,
                    "expires_ms": s.expires_ms,
                    "revoked_ms": s.revoked_ms,
                    "orphan": s.orphan,
                    "created_ms": s.created_ms,
                })
            }));
        }
        let mut out = serde_json::to_vec_pretty(&serde_json::json!({ "sessions": sessions }))
            .map_err(err_be)?;
        out.push(b'\n');
        Ok(out)
    }

    /// Mint a bounded policy session from a descriptor written to
    /// `policy-session/new`. The descriptor is the security envelope: the
    /// chains, total USD cap, TTL, and the exact pending-tx ids it authorizes.
    async fn mint_policy_session(&self, wallet: &str, data: &[u8]) -> Result<(), HandlerError> {
        if looks_like_evm_owner_session_descriptor(data) {
            return self.mint_evm_owner_session(wallet, data).await;
        }
        // Each authorized tx is a (chain_id, outbox id) pair — outbox ids are
        // unique only within a chain, so the allowlist must be chain-qualified.
        #[derive(serde::Deserialize)]
        struct PendingId {
            chain_id: u64,
            id: String,
        }
        #[derive(serde::Deserialize)]
        struct Descriptor {
            /// Total spend cap in USD (dollars).
            max_usd: f64,
            ttl_secs: u64,
            #[serde(default)]
            pending_ids: Vec<PendingId>,
        }
        let d: Descriptor = serde_json::from_slice(data)
            .map_err(|e| HandlerError::invalid(format!("policy-session descriptor: {e}")))?;
        if d.pending_ids.is_empty() || d.ttl_secs == 0 || d.max_usd <= 0.0 {
            return Err(HandlerError::invalid(
                "policy-session requires non-empty pending_ids ({chain_id,id} pairs), \
                 ttl_secs > 0, and max_usd > 0",
            ));
        }
        let path = format!("/wallets/{wallet}/policy-session/new");
        self.require_sealed_policy_session_approval(wallet, &path, data)
            .await?;
        // Chains are derived from the authorized pairs; the allowlist holds
        // chain-qualified keys so a same-id tx on another chain can't slip in.
        let chains = d.pending_ids.iter().map(|p| p.chain_id).collect();
        let allowed_pending_ids = d
            .pending_ids
            .iter()
            .map(|p| bloom_tx::session::pending_key(p.chain_id, &p.id))
            .collect();
        let now = now_ms();
        let id = format!("{wallet}-{now:x}");
        let session = bloom_tx::session::ActiveSession {
            id: id.clone(),
            wallet: wallet.to_string(),
            chains,
            expires_ms: now + (d.ttl_secs as u128) * 1000,
            max_micro_usd: (d.max_usd * 1_000_000.0) as i128,
            spent_micro_usd: 0,
            allowed_pending_ids,
        };
        self.tx_engine.session_store().mint(session);
        tracing::info!(wallet, session = %id, "wallet.policy_session.minted");
        Ok(())
    }

    async fn mint_evm_owner_session(&self, wallet: &str, data: &[u8]) -> Result<(), HandlerError> {
        let d: EvmOwnerSessionMintDescriptor = serde_json::from_slice(data)
            .map_err(|e| HandlerError::invalid(format!("evm owner-session descriptor: {e}")))?;
        if d.ttl_secs == 0
            || d.max_signature_count == 0
            || d.daily_cap_base_units.trim().is_empty()
            || d.token_contract.trim().is_empty()
            || d.recipient.trim().is_empty()
            || d.reason.trim().is_empty()
        {
            return Err(HandlerError::invalid(
                "evm owner-session requires token_contract, recipient, reason, \
                 daily_cap_base_units, ttl_secs > 0, and max_signature_count > 0",
            ));
        }
        if d.method != EVM_ERC20_TRANSFER_METHOD || d.native_transfers_allowed {
            return Err(HandlerError::invalid(
                "evm owner-session MVP supports only ERC-20 transfer and no native transfer",
            ));
        }
        let now = now_ms_u64();
        let scope = EvmOwnerSigningSessionScope {
            wallet: wallet.to_string(),
            chain_id: d.chain_id,
            token_contract: d.token_contract,
            recipient: d.recipient,
            method: d.method,
            daily_cap_base_units: d.daily_cap_base_units,
            ttl_ms: d.ttl_secs.saturating_mul(1000),
            fee_policy: d.fee_policy,
            max_signature_count: d.max_signature_count,
            autonomy_classification: d
                .autonomy_classification
                .unwrap_or_else(|| "bounded_owner_signing".into()),
            policy_snapshot_digest: d
                .policy_snapshot_digest
                .unwrap_or_else(|| "pending-sealed-policy-digest".into()),
            petal_id: petal_identity::PETAL_ID_EVM_WALLET.into(),
            petal_digest: petal_identity::PLACEHOLDER_DIGEST_EVM_WALLET.into(),
            petal_version: petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
            reason: d.reason,
            native_transfers_allowed: false,
        };
        let path = format!("/wallets/{wallet}/policy-session/new");
        self.require_sealed_evm_owner_session_approval(wallet, &path, data, &scope, now)
            .await?;
        let id = evm_owner_session_action_id(wallet, data);
        let counters = EvmOwnerSigningSessionCounters {
            daily_window_start_ms: now,
            spent_base_units: "0".into(),
            reserved_base_units: "0".into(),
            signature_count: 0,
            pending_reservations: BTreeMap::new(),
        };
        let expires_ms = now.saturating_add(scope.ttl_ms);
        let action = evm_owner_session_sealed_action(wallet, &path, data, &scope, now)?;
        let stored = self
            .auth_services
            .require_writer()?
            .create_standing_session(
                &id,
                wallet,
                petal_identity::PETAL_ID_EVM_WALLET,
                EVM_OWNER_SIGNING_SESSION_KIND,
                serde_json::to_value(&scope).map_err(err_be)?,
                serde_json::to_value(&counters).map_err(err_be)?,
                action.policy_version,
                &action.petal_policy_digest,
                now,
                expires_ms,
                now,
            )
            .await
            .map_err(|e| HandlerError::backend(format!("create evm owner-session: {e}")))?;
        tracing::info!(wallet, session = %stored.session_id, "wallet.evm_owner_session.minted");
        Ok(())
    }

    async fn use_evm_owner_session(
        &self,
        wallet: &str,
        session_id: &str,
        data: &[u8],
    ) -> Result<(), HandlerError> {
        let mut value: serde_json::Value = serde_json::from_slice(data)
            .map_err(|e| HandlerError::invalid(format!("evm owner-session use: {e}")))?;
        if let Some(obj) = value.as_object_mut() {
            obj.entry("wallet".to_string())
                .or_insert_with(|| serde_json::Value::String(wallet.to_string()));
        }
        let request: EvmOwnerSigningSessionUse =
            serde_json::from_value(value).map_err(|e| HandlerError::invalid(e.to_string()))?;
        let now = now_ms_u64();
        let reservation_id = format!("evmuse-{session_id}-{now:x}");
        let writer = self.auth_services.require_writer()?;
        let reserved = writer
            .reserve_evm_owner_session_use(session_id, &reservation_id, request.clone(), true, now)
            .await
            .map_err(|e| HandlerError::invalid(format!("evm owner-session denied: {e}")))?;
        let chain_name = match request.chain.as_deref().filter(|s| !s.trim().is_empty()) {
            Some(name) => name.to_string(),
            None => self
                .chains
                .name_for_chain_id(request.chain_id)
                .ok_or_else(|| HandlerError::not_found(format!("chain id {}", request.chain_id)))?,
        };
        let chain = self
            .chains
            .get(&chain_name)
            .ok_or_else(|| HandlerError::not_found(format!("chain '{chain_name}'")))?;
        let info = self.keystore.info(wallet).map_err(err_be)?;
        let execution = self
            .tx_engine
            .execute_evm_owner_session_use(
                wallet,
                session_id,
                &reservation_id,
                &request,
                &reserved,
                &chain_name,
                &chain,
                info.address,
                &Policy::permissive(),
            )
            .await;
        let execution = match execution {
            Ok(execution) => execution,
            Err(err) => {
                let _ = writer
                    .release_evm_owner_session_use(session_id, &reservation_id, now_ms_u64())
                    .await;
                return Err(HandlerError::invalid(format!(
                    "evm owner-session execution failed: {err}"
                )));
            }
        };
        writer
            .commit_evm_owner_session_use(session_id, &reservation_id, now)
            .await
            .map_err(|e| HandlerError::backend(format!("commit evm owner-session use: {e}")))?;
        tracing::info!(
            wallet,
            session = %session_id,
            tx_hash = %format!("{:#x}", execution.tx_hash),
            nonce = execution.nonce,
            signing_hash = %format!("{:#x}", execution.signing_hash),
            "wallet.evm_owner_session.use.broadcast"
        );
        Ok(())
    }

    async fn require_sealed_policy_session_approval(
        &self,
        wallet: &str,
        path: &str,
        data: &[u8],
    ) -> Result<(), HandlerError> {
        let action_id = policy_session_action_id(wallet, data);
        let envelope = policy_session_canonical_envelope(wallet, path, &action_id, data)?;
        self.auth_services
            .require_writer()?
            .stage_entry(envelope, AssuranceLevel::Hardened, now_ms_u64())
            .await
            .map_err(|e| HandlerError::backend(format!("stage policy-session auth entry: {e}")))?;
        let approval_path = self
            .keystore
            .root()
            .join(wallet)
            .join("policy-session")
            .join(&action_id)
            .join(APPROVAL_FILE);
        if approval_path.exists() {
            let approval: SignedApproval = read_json(&approval_path)?;
            self.auth_services
                .require_approval_verifier()?
                .verify_and_consume(approval, now_ms_u64())
                .await
                .map_err(|e| HandlerError::invalid(format!("Sealed Approval rejected: {e}")))?;
            return Ok(());
        }
        let challenge = self.issue_policy_session_challenge(&action_id).await?;
        let challenge_path = approval_path.with_file_name(APPROVAL_CHALLENGE_FILE);
        if let Some(parent) = challenge_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_json(challenge_path, &challenge)?;
        Err(HandlerError::PermissionDenied)
    }

    async fn write_wallet_policy_update(
        &self,
        wallet: &str,
        path: &str,
        data: &[u8],
    ) -> Result<(), HandlerError> {
        let proposed_policy_toml = std::str::from_utf8(data)
            .map_err(|e| HandlerError::invalid(format!("policy must be UTF-8: {e}")))?;
        let proposed_policy: Policy = toml::from_str(proposed_policy_toml)
            .map_err(|e| HandlerError::invalid(format!("invalid policy TOML: {e}")))?;
        let (old_policy_toml, kind) = self.keystore.raw_policy(wallet).map_err(err_be)?;
        if kind != bloom_keystore::WalletKind::PasskeyGated {
            self.keystore.write_policy(wallet, data).map_err(err_be)?;
            return Ok(());
        }
        if old_policy_toml.as_bytes() == data {
            return Ok(());
        }
        #[cfg(feature = "unsafe-debug-signer")]
        if std::env::var("BLOOM_UNSAFE_DEBUG_SIGNER_WALLET").as_deref() == Ok(wallet)
            && self.keystore.is_unlocked(wallet)
        {
            tracing::warn!(wallet, "wallet.unsafe_debug_policy_approval_bypass");
            self.keystore.write_policy(wallet, data).map_err(err_be)?;
            return Ok(());
        }
        let old_policy: Policy = toml::from_str(&old_policy_toml)
            .map_err(|e| HandlerError::backend(format!("existing policy TOML is invalid: {e}")))?;
        let now = now_ms_u64();
        let action = wallet_policy_sealed_action(
            wallet,
            path,
            old_policy_toml.as_bytes(),
            data,
            &old_policy,
            &proposed_policy,
            now,
        )?;
        let action_id = action.action_id().to_string();
        let petal_id = action.petal_id().to_string();
        let petal_digest = action.petal_digest().to_string();
        self.auth_services
            .require_writer()?
            .stage_action(action, now)
            .await
            .map_err(|e| HandlerError::backend(format!("stage wallet-policy action: {e}")))?;
        if self
            .auth_services
            .require_grant_store()?
            .get_active(wallet, &action_id, &petal_id, &petal_digest, now)
            .await
            .map_err(|e| HandlerError::backend(format!("lookup wallet-policy grant: {e}")))?
            .is_none()
        {
            let approval_path = self
                .keystore
                .root()
                .join(wallet)
                .join("policy-updates")
                .join(&action_id)
                .join(APPROVAL_FILE);
            if approval_path.exists() {
                let approval: SignedApproval = read_json(&approval_path)?;
                self.auth_services
                    .require_approval_verifier()?
                    .verify_and_mint_grant(
                        approval,
                        self.auth_services.require_grant_store()?.as_ref(),
                        now_ms_u64(),
                    )
                    .await
                    .map_err(|e| HandlerError::invalid(format!("Sealed Approval rejected: {e}")))?;
            } else {
                let challenge = self.issue_wallet_policy_challenge(&action_id).await?;
                let challenge_path = approval_path.with_file_name(APPROVAL_CHALLENGE_FILE);
                if let Some(parent) = challenge_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                write_json(challenge_path, &challenge)?;
                return Err(HandlerError::PermissionDenied);
            }
        }
        self.execute_wallet_policy_update(wallet, &action_id, &old_policy_toml, data)
            .await
    }

    async fn issue_wallet_policy_challenge(
        &self,
        action_id: &str,
    ) -> Result<ApprovalChallenge, HandlerError> {
        let now = now_ms_u64();
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let nonce = URL_SAFE_NO_PAD.encode(nonce);
        self.auth_services
            .require_writer()?
            .issue_challenge(
                WALLET_POLICY_SURFACE,
                action_id,
                &nonce,
                now + APPROVAL_TTL_MS,
                now,
            )
            .await
            // Project the stable local ceremony URL so the mounted flow can open
            // the approval page without touching BLOOM_HOME. Same convention as
            // the paid-http/outbox confirm challenges; the token derives from the
            // (single-use) server_nonce and is not part of the signed preimage.
            .map(|challenge| challenge.with_local_ceremony_url())
            .map_err(|e| HandlerError::backend(format!("issue wallet-policy challenge: {e}")))
    }

    async fn execute_wallet_policy_update(
        &self,
        wallet: &str,
        action_id: &str,
        old_policy_toml: &str,
        proposed_policy: &[u8],
    ) -> Result<(), HandlerError> {
        let current = std::fs::read(self.keystore.root().join(wallet).join("policy.toml"))?;
        if current != old_policy_toml.as_bytes() {
            return Err(HandlerError::invalid(
                "wallet policy changed after approval; restage the policy update",
            ));
        }
        let proposed_policy_toml = std::str::from_utf8(proposed_policy)
            .map_err(|e| HandlerError::invalid(format!("policy must be UTF-8: {e}")))?;
        let policy_hash = blake3::hash(format!("{wallet}:{proposed_policy_toml}").as_bytes());
        let policy_hash_hex = hex::encode(policy_hash.as_bytes());
        let hash_hex = format!("0x{policy_hash_hex}");
        let mut facts = BTreeMap::new();
        facts.insert("wallet".into(), serde_json::json!(wallet));
        facts.insert("action_id".into(), serde_json::json!(action_id));
        facts.insert("policy_hash_hex".into(), serde_json::json!(hash_hex));
        facts.insert(
            "proposed_policy_blake3".into(),
            serde_json::json!(wallet_policy_hash_hex(proposed_policy)),
        );
        facts.insert(
            "installation_target".into(),
            serde_json::json!(format!("/wallets/{wallet}/policy.toml")),
        );
        let sealed_sig = self
            .auth_services
            .require_petal_host()?
            .sign_hash(
                SignHashRequest {
                    wallet: wallet.to_string(),
                    action_id: action_id.to_string(),
                    intent: WALLET_POLICY_SIGN_INTENT.into(),
                    hash_hex,
                },
                &SigningAttestation {
                    schema: SIGNING_ATTESTATION_SCHEMA_V1.into(),
                    petal_id: petal_identity::PETAL_ID_WALLET_POLICY.into(),
                    petal_digest: petal_identity::PLACEHOLDER_DIGEST_WALLET_POLICY.into(),
                    intent: WALLET_POLICY_SIGN_INTENT.into(),
                    facts,
                },
                now_ms_u64(),
            )
            .await
            .map_err(|e| HandlerError::invalid(format!("wallet-policy signing denied: {e}")))?;
        let sig_raw = B64_STANDARD
            .decode(sealed_sig.signature_b64.as_bytes())
            .map_err(|e| HandlerError::backend(format!("decode wallet-policy signature: {e}")))?;
        let sig = alloy::primitives::Signature::from_raw(&sig_raw)
            .map_err(|e| HandlerError::backend(format!("wallet-policy signature: {e}")))?;
        let sig_json = serde_json::json!({
            "blake3_hex": policy_hash_hex,
            "sig_hex": sig.to_string(),
        });
        let wallet_dir = self.keystore.root().join(wallet);
        write_atomic_file(
            &wallet_dir.join("policy.toml.sig"),
            sig_json.to_string().as_bytes(),
        )?;
        write_atomic_file(&wallet_dir.join("policy.toml"), proposed_policy)?;
        Ok(())
    }

    /// On-disk root for staged wallet-policy update artifacts (challenges and,
    /// once approved, the signed approval). These are *views* of a pending
    /// Sealed Approval — the canonical proposed policy lives in the sealed
    /// action subject, never in these side files.
    fn policy_updates_dir(&self, wallet: &str) -> std::path::PathBuf {
        self.keystore.root().join(wallet).join("policy-updates")
    }

    /// Sorted list of staged policy-update action ids that have on-disk
    /// artifacts, for the `policy-updates/` VFS listing.
    fn policy_update_action_ids(&self, wallet: &str) -> Vec<String> {
        let mut ids = Vec::new();
        if let Ok(rd) = std::fs::read_dir(self.policy_updates_dir(wallet)) {
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

    /// Raw approval challenge JSON for a staged policy update, surfaced through
    /// the mount so an agent can discover the ceremony (including `ceremony_url`)
    /// without reading `BLOOM_HOME`. Contains only bounded challenge metadata —
    /// no signatures, grants, or key material.
    fn read_policy_update_challenge(
        &self,
        wallet: &str,
        action_id: &str,
    ) -> Result<Vec<u8>, HandlerError> {
        let path = self
            .policy_updates_dir(wallet)
            .join(action_id)
            .join(APPROVAL_CHALLENGE_FILE);
        if !path.exists() {
            return Err(HandlerError::not_found(format!(
                "policy-updates/{action_id}/{APPROVAL_CHALLENGE_FILE}"
            )));
        }
        Ok(std::fs::read(&path)?)
    }

    /// Human/agent-facing status view for a staged policy update. Derives its
    /// `status` from which artifacts exist on disk (a challenge alone means the
    /// ceremony is still pending; an approval means the one-shot grant can be
    /// minted by re-writing the same proposed policy). Exposes `ceremony_url`
    /// and the exact retry path; never exposes the signed approval itself.
    fn policy_update_status_json(
        &self,
        wallet: &str,
        action_id: &str,
    ) -> Result<Vec<u8>, HandlerError> {
        let action_dir = self.policy_updates_dir(wallet).join(action_id);
        if !action_dir.is_dir() {
            return Err(HandlerError::not_found(format!(
                "policy-updates/{action_id}"
            )));
        }
        let challenge_path = action_dir.join(APPROVAL_CHALLENGE_FILE);
        let challenge: Option<ApprovalChallenge> = if challenge_path.exists() {
            Some(read_json(&challenge_path)?)
        } else {
            None
        };
        let approved = action_dir.join(APPROVAL_FILE).exists();
        let status = if approved { "approved" } else { "challenged" };
        let next_step = if approved {
            "re-write the same proposed policy to /wallets/<wallet>/policy.toml to install"
        } else {
            "open ceremony_url, approve, then re-write the same proposed policy.toml"
        };
        let body = serde_json::json!({
            "schema": "bloom.wallet_policy_update_view.v1",
            "wallet": wallet,
            "action_id": action_id,
            "surface": WALLET_POLICY_SURFACE,
            "status": status,
            "write_path": format!("/wallets/{wallet}/policy.toml"),
            "installation_target": format!("/wallets/{wallet}/policy.toml"),
            "challenge_path": format!("/wallets/{wallet}/policy-updates/{action_id}/{APPROVAL_CHALLENGE_FILE}"),
            "assurance": challenge.as_ref().map(|c| c.assurance),
            "ceremony_url": challenge.as_ref().and_then(|c| c.ceremony_url.clone()),
            "expiry_ms": challenge.as_ref().map(|c| c.expiry_ms),
            "next_step": next_step,
        });
        let mut out = serde_json::to_vec_pretty(&body).map_err(err_be)?;
        out.push(b'\n');
        Ok(out)
    }

    async fn require_sealed_evm_owner_session_approval(
        &self,
        wallet: &str,
        path: &str,
        data: &[u8],
        scope: &EvmOwnerSigningSessionScope,
        now: u64,
    ) -> Result<(), HandlerError> {
        let action_id = evm_owner_session_action_id(wallet, data);
        let action = evm_owner_session_sealed_action(wallet, path, data, scope, now)?;
        let petal_id = action.petal_id().to_string();
        let petal_digest = action.petal_digest().to_string();
        self.auth_services
            .require_writer()?
            .stage_action(action, now)
            .await
            .map_err(|e| {
                HandlerError::backend(format!("stage evm owner-session auth entry: {e}"))
            })?;
        if self
            .auth_services
            .require_grant_store()?
            .get_active(wallet, &action_id, &petal_id, &petal_digest, now)
            .await
            .map_err(|e| HandlerError::backend(format!("lookup owner-session grant: {e}")))?
            .is_some()
        {
            return Ok(());
        }
        let approval_path = self
            .keystore
            .root()
            .join(wallet)
            .join("policy-session")
            .join(&action_id)
            .join(APPROVAL_FILE);
        if approval_path.exists() {
            let approval: SignedApproval = read_json(&approval_path)?;
            self.auth_services
                .require_approval_verifier()?
                .verify_and_mint_grant(
                    approval,
                    self.auth_services.require_grant_store()?.as_ref(),
                    now_ms_u64(),
                )
                .await
                .map_err(|e| HandlerError::invalid(format!("Sealed Approval rejected: {e}")))?;
            return Ok(());
        }
        let challenge = self.issue_policy_session_challenge(&action_id).await?;
        let challenge_path = approval_path.with_file_name(APPROVAL_CHALLENGE_FILE);
        if let Some(parent) = challenge_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_json(challenge_path, &challenge)?;
        Err(HandlerError::PermissionDenied)
    }

    async fn issue_policy_session_challenge(
        &self,
        action_id: &str,
    ) -> Result<ApprovalChallenge, HandlerError> {
        let now = now_ms_u64();
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let nonce = URL_SAFE_NO_PAD.encode(nonce);
        self.auth_services
            .require_writer()?
            .issue_challenge(
                "policy-session",
                action_id,
                &nonce,
                now.saturating_add(APPROVAL_TTL_MS),
                now,
            )
            .await
            .map_err(|e| HandlerError::backend(format!("issue policy-session challenge: {e}")))
    }

    fn wallet_dir_entries(kind: bloom_keystore::WalletKind) -> Vec<Entry> {
        let mut entries = vec![
            Entry::file("address"),
            Entry::file("address.qr.png"),
            Entry::file("address.qr.svg"),
            Entry::file("addresses.json"),
            Entry::file("public_key"),
            Entry::file("kind"),
            Entry::file("policy.toml"),
            Entry::dir("chains"),
            Entry::dir("sign"),
            Entry::dir("policy-session"),
            Entry::dir("policy-updates"),
            Entry::dir("capabilities"),
        ];
        if kind == bloom_keystore::WalletKind::PasskeyGated {
            entries.push(Entry::writable_file("unlock-passkey"));
        }
        entries
    }

    fn sign_dir_entries() -> Vec<Entry> {
        vec![
            Entry::writable_file("message"),
            Entry::writable_file("hash"),
            Entry::writable_file("typed_data"),
        ]
    }

    fn outbox_dir_entries() -> Vec<Entry> {
        vec![
            Entry::file("new.tx"),
            Entry::dir("pending"),
            Entry::dir("sent"),
            Entry::dir("failed"),
        ]
    }
}

fn err_be(e: impl std::fmt::Display) -> HandlerError {
    HandlerError::backend(e.to_string())
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

fn write_json(path: impl AsRef<Path>, v: &impl serde::Serialize) -> Result<(), HandlerError> {
    std::fs::write(
        path,
        serde_json::to_vec_pretty(v).map_err(|e| HandlerError::backend(e.to_string()))?,
    )?;
    Ok(())
}

fn write_atomic_file(path: &Path, bytes: &[u8]) -> Result<(), HandlerError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| HandlerError::backend("atomic write target has no file name"))?;
    let tmp = path.with_file_name(format!(".{file_name}.tmp-{}", now_ms_u64()));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn read_json<T: for<'de> serde::Deserialize<'de>>(
    path: impl AsRef<Path>,
) -> Result<T, HandlerError> {
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|e| HandlerError::backend(e.to_string()))
}

fn policy_session_action_id(wallet: &str, data: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.policy_session.entry.v1");
    hasher.update(wallet.as_bytes());
    hasher.update(&[0]);
    hasher.update(data);
    format!("ps-{}", hasher.finalize().to_hex())
}

#[derive(serde::Deserialize)]
struct EvmOwnerSessionMintDescriptor {
    chain_id: u64,
    token_contract: String,
    recipient: String,
    #[serde(default = "default_evm_owner_session_method")]
    method: String,
    daily_cap_base_units: String,
    ttl_secs: u64,
    #[serde(default)]
    fee_policy: EvmFeePolicy,
    max_signature_count: u32,
    #[serde(default)]
    autonomy_classification: Option<String>,
    #[serde(default)]
    policy_snapshot_digest: Option<String>,
    reason: String,
    #[serde(default)]
    native_transfers_allowed: bool,
}

fn default_evm_owner_session_method() -> String {
    EVM_ERC20_TRANSFER_METHOD.to_string()
}

fn looks_like_evm_owner_session_descriptor(data: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(data)
        .ok()
        .map(|v| {
            v.get("token_contract").is_some()
                || v.get("recipient").is_some()
                || v.get("daily_cap_base_units").is_some()
        })
        .unwrap_or(false)
}

fn evm_owner_session_action_id(wallet: &str, data: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.evm_owner_session.entry.v1");
    hasher.update(wallet.as_bytes());
    hasher.update(&[0]);
    hasher.update(data);
    format!("evm-ownersess-{}", hasher.finalize().to_hex())
}

fn wallet_policy_hash_hex(policy: &[u8]) -> String {
    blake3::hash(policy).to_hex().to_string()
}

fn wallet_policy_action_id(wallet: &str, old_policy: &[u8], proposed_policy: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.wallet_policy.update.v1");
    hasher.update(wallet.as_bytes());
    hasher.update(&[0]);
    hasher.update(wallet_policy_hash_hex(old_policy).as_bytes());
    hasher.update(&[0]);
    hasher.update(wallet_policy_hash_hex(proposed_policy).as_bytes());
    format!("policy-update-{}", hasher.finalize().to_hex())
}

fn wallet_policy_diff_summary(
    before: &Policy,
    after: &Policy,
    old_policy: &[u8],
    proposed_policy: &[u8],
) -> Result<serde_json::Value, HandlerError> {
    let class = classify_policy_edit(before, after);
    let (classification, reasons) = match class {
        PolicyEditClass::NotExpanding => ("not_expanding", Vec::new()),
        PolicyEditClass::AuthorityExpanding { reasons } => ("authority_expanding", reasons),
    };
    Ok(serde_json::json!({
        "schema": "bloom.wallet_policy_diff.v1",
        "classification": classification,
        "reasons": reasons,
        "old_policy_blake3": wallet_policy_hash_hex(old_policy),
        "proposed_policy_blake3": wallet_policy_hash_hex(proposed_policy),
        "old_line_count": String::from_utf8_lossy(old_policy).lines().count(),
        "proposed_line_count": String::from_utf8_lossy(proposed_policy).lines().count(),
    }))
}

fn wallet_policy_assurance(before: &Policy, after: &Policy) -> AssuranceLevel {
    if classify_policy_edit(before, after).is_authority_expanding() {
        AssuranceLevel::Hardened
    } else {
        AssuranceLevel::Standard
    }
}

fn wallet_policy_canonical_envelope(
    wallet: &str,
    path: &str,
    action_id: &str,
    old_policy: &[u8],
    proposed_policy: &[u8],
    before: &Policy,
    after: &Policy,
) -> Result<CanonicalEnvelope, HandlerError> {
    let diff = wallet_policy_diff_summary(before, after, old_policy, proposed_policy)?;
    let subject = serde_json::to_vec(&serde_json::json!({
        "schema": WALLET_POLICY_SUBJECT_SCHEMA,
        "wallet": wallet,
        "path": path,
        "action_kind": WALLET_POLICY_ACTION_KIND,
        "installation_target": format!("/wallets/{wallet}/policy.toml"),
        "policy_version": 0,
        "old_policy_blake3": wallet_policy_hash_hex(old_policy),
        "proposed_policy_blake3": wallet_policy_hash_hex(proposed_policy),
        "proposed_policy_toml_b64": B64_STANDARD.encode(proposed_policy),
        "normalized_diff": diff,
    }))
    .map_err(|e| HandlerError::backend(e.to_string()))?;
    Ok(CanonicalEnvelope::new(
        CanonicalIntentHeader {
            schema: bloom_auth_api::CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
            wallet: wallet.to_string(),
            surface: WALLET_POLICY_SURFACE.into(),
            action_id: action_id.to_string(),
            petal_id: petal_identity::PETAL_ID_WALLET_POLICY.into(),
            petal_digest: petal_identity::PLACEHOLDER_DIGEST_WALLET_POLICY.into(),
            petal_version: petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
            executor_kind: ExecutorKind::FirstParty,
            network: "wallet-policy".into(),
            account: wallet.into(),
            action_kind: WALLET_POLICY_ACTION_KIND.into(),
            value_movement: false,
            authority_change: true,
            expires_ms: 0,
        },
        "wallet_policy_update",
        WALLET_POLICY_SUBJECT_SCHEMA,
        subject,
    ))
}

fn wallet_policy_sealed_action(
    wallet: &str,
    path: &str,
    old_policy: &[u8],
    proposed_policy: &[u8],
    before: &Policy,
    after: &Policy,
    now_ms: u64,
) -> Result<SealedAction, HandlerError> {
    let action_id = wallet_policy_action_id(wallet, old_policy, proposed_policy);
    let assurance = wallet_policy_assurance(before, after);
    let envelope = wallet_policy_canonical_envelope(
        wallet,
        path,
        &action_id,
        old_policy,
        proposed_policy,
        before,
        after,
    )?;
    let diff = wallet_policy_diff_summary(before, after, old_policy, proposed_policy)?;
    let mut extra = BTreeMap::new();
    extra.insert(
        "action_kind".to_string(),
        serde_json::json!(WALLET_POLICY_ACTION_KIND),
    );
    extra.insert(
        "old_policy_blake3".to_string(),
        serde_json::json!(wallet_policy_hash_hex(old_policy)),
    );
    extra.insert(
        "proposed_policy_blake3".to_string(),
        serde_json::json!(wallet_policy_hash_hex(proposed_policy)),
    );
    extra.insert("classification".to_string(), diff["classification"].clone());
    let terms = DaemonGrantTerms {
        max_ttl_secs: APPROVAL_TTL_MS / 1_000,
        max_signatures: 1,
        allowed_sign_intents: vec![WALLET_POLICY_SIGN_INTENT.into()],
        assurance,
        extra,
    };
    let mut config = BTreeMap::new();
    config.insert(
        "installation_target".to_string(),
        serde_json::json!(format!("/wallets/{wallet}/policy.toml")),
    );
    config.insert(
        "old_policy_blake3".to_string(),
        serde_json::json!(wallet_policy_hash_hex(old_policy)),
    );
    config.insert(
        "proposed_policy_blake3".to_string(),
        serde_json::json!(wallet_policy_hash_hex(proposed_policy)),
    );
    config.insert("normalized_diff".to_string(), diff.clone());
    let snapshot = PetalPolicySnapshot {
        policy_version: 0,
        wallet: wallet.to_string(),
        petal_id: petal_identity::PETAL_ID_WALLET_POLICY.into(),
        petal_digest: petal_identity::PLACEHOLDER_DIGEST_WALLET_POLICY.into(),
        caps: BTreeMap::new(),
        hard_rules: Vec::new(),
        step_up_rules: Vec::new(),
        config,
        budget_state: BTreeMap::new(),
        session_scope: None,
    };
    SealedAction::new(
        envelope,
        format!(
            "Update wallet policy for {wallet} ({})",
            diff["classification"].as_str().unwrap_or("unknown")
        ),
        Vec::new(),
        terms,
        snapshot,
        now_ms,
    )
    .map_err(err_be)
}

fn evm_owner_session_sealed_action(
    wallet: &str,
    path: &str,
    data: &[u8],
    scope: &EvmOwnerSigningSessionScope,
    now_ms: u64,
) -> Result<SealedAction, HandlerError> {
    let action_id = evm_owner_session_action_id(wallet, data);
    let envelope = evm_owner_session_canonical_envelope(wallet, path, &action_id, data, scope)?;
    let mut extra = BTreeMap::new();
    extra.insert(
        "action_kind".to_string(),
        serde_json::json!(EVM_OWNER_SESSION_MINT_ACTION_KIND),
    );
    extra.insert(
        "session_kind".to_string(),
        serde_json::json!(EVM_OWNER_SIGNING_SESSION_KIND),
    );
    extra.insert("signer_cache_required".to_string(), serde_json::json!(true));
    let terms = DaemonGrantTerms {
        max_ttl_secs: scope.ttl_ms / 1000,
        max_signatures: scope.max_signature_count,
        allowed_sign_intents: vec![EVM_TX_SIGN_INTENT.to_string()],
        assurance: AssuranceLevel::Hardened,
        extra,
    };
    let scope_value = serde_json::to_value(scope).map_err(err_be)?;
    let scope_map = scope_value
        .as_object()
        .ok_or_else(|| HandlerError::backend("evm owner-session scope is not an object"))?
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut caps = BTreeMap::new();
    caps.insert(
        "daily_cap_base_units".to_string(),
        serde_json::json!(scope.daily_cap_base_units),
    );
    caps.insert(
        "max_signature_count".to_string(),
        serde_json::json!(scope.max_signature_count),
    );
    let mut config = BTreeMap::new();
    config.insert("chain_id".to_string(), serde_json::json!(scope.chain_id));
    config.insert(
        "token_contract".to_string(),
        serde_json::json!(scope.token_contract),
    );
    config.insert("recipient".to_string(), serde_json::json!(scope.recipient));
    config.insert("method".to_string(), serde_json::json!(scope.method));
    let snapshot = PetalPolicySnapshot {
        policy_version: 0,
        wallet: wallet.to_string(),
        petal_id: petal_identity::PETAL_ID_EVM_WALLET.into(),
        petal_digest: petal_identity::PLACEHOLDER_DIGEST_EVM_WALLET.into(),
        caps,
        hard_rules: Vec::new(),
        step_up_rules: Vec::new(),
        config,
        budget_state: BTreeMap::new(),
        session_scope: Some(scope_map),
    };
    SealedAction::new(
        envelope,
        format!(
            "Mint bounded EVM owner-signing session for {wallet}: {}",
            scope.reason
        ),
        Vec::new(),
        terms,
        snapshot,
        now_ms,
    )
    .map_err(err_be)
}

fn evm_owner_session_canonical_envelope(
    wallet: &str,
    path: &str,
    action_id: &str,
    data: &[u8],
    scope: &EvmOwnerSigningSessionScope,
) -> Result<CanonicalEnvelope, HandlerError> {
    let descriptor: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| HandlerError::invalid(format!("evm owner-session descriptor: {e}")))?;
    let subject = serde_json::to_vec(&serde_json::json!({
        "schema": "bloom.evm_owner_session_subject.v1",
        "wallet": wallet,
        "path": path,
        "action_kind": EVM_OWNER_SESSION_MINT_ACTION_KIND,
        "use_action_kind": EVM_OWNER_SESSION_USE_ACTION_KIND,
        "session_kind": EVM_OWNER_SIGNING_SESSION_KIND,
        "scope": scope,
        "descriptor": descriptor,
        "descriptor_blake3": blake3::hash(data).to_hex().to_string(),
    }))
    .map_err(|e| HandlerError::backend(e.to_string()))?;
    Ok(CanonicalEnvelope::new(
        CanonicalIntentHeader {
            schema: bloom_auth_api::CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
            wallet: wallet.to_string(),
            surface: "policy-session".into(),
            action_id: action_id.to_string(),
            petal_id: petal_identity::PETAL_ID_EVM_WALLET.into(),
            petal_digest: petal_identity::PLACEHOLDER_DIGEST_EVM_WALLET.into(),
            petal_version: petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
            executor_kind: ExecutorKind::FirstParty,
            network: scope.chain_id.to_string(),
            account: "owner".into(),
            action_kind: EVM_OWNER_SESSION_MINT_ACTION_KIND.into(),
            value_movement: false,
            authority_change: true,
            expires_ms: 0,
        },
        "policy_session",
        "bloom.evm_owner_session_subject.v1",
        subject,
    ))
}

fn policy_session_canonical_envelope(
    wallet: &str,
    path: &str,
    action_id: &str,
    data: &[u8],
) -> Result<CanonicalEnvelope, HandlerError> {
    let descriptor: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| HandlerError::invalid(format!("policy-session descriptor: {e}")))?;
    let subject = serde_json::to_vec(&serde_json::json!({
        "schema": "bloom.policy_session_subject.v1",
        "wallet": wallet,
        "path": path,
        "descriptor": descriptor,
        "descriptor_blake3": blake3::hash(data).to_hex().to_string(),
    }))
    .map_err(|e| HandlerError::backend(e.to_string()))?;
    Ok(CanonicalEnvelope::new(
        CanonicalIntentHeader {
            schema: bloom_auth_api::CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
            wallet: wallet.to_string(),
            surface: "policy-session".into(),
            action_id: action_id.to_string(),
            petal_id: petal_identity::PETAL_ID_WALLET_POLICY.into(),
            petal_digest: petal_identity::PLACEHOLDER_DIGEST_WALLET_POLICY.into(),
            petal_version: petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
            executor_kind: ExecutorKind::FirstParty,
            network: "multi-chain".into(),
            account: "default".into(),
            action_kind: "policy_session_mint".into(),
            value_movement: false,
            authority_change: true,
            // Staged on every write attempt for the same descriptor bytes, so
            // this must stay deterministic (a clock-derived expiry would make
            // re-sealing collide with the already-sealed entry).
            // TODO(ws-K): commit a real expiry when the wallet-policy petal
            // computes venue terms.
            expires_ms: 0,
        },
        "policy_session",
        "bloom.policy_session_subject.v1",
        subject,
    ))
}

/// Parse a state segment (`pending` / `sent` / `failed`) into an
/// [`OutboxState`], rejecting anything else as NotFound.
fn parse_state_seg(s: &str) -> Result<OutboxState, HandlerError> {
    OutboxState::parse(s).ok_or_else(|| HandlerError::not_found(format!("outbox state '{}'", s)))
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

    async fn prepare_write_open(&self, path: &VfsPath) -> Result<(), HandlerError> {
        let segs = path.segments();
        let r = match segs {
            [wallet, chains, chain, outbox, pending, id, fname]
                if chains == "chains"
                    && outbox == "outbox"
                    && pending == "pending"
                    && fname == "confirm.override" =>
            {
                let info = self.keystore.info(wallet).map_err(err_be)?;
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
                        &info.policy,
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
        // wallets/<w>/sign/<kind>
        if segs.len() == 3
            && segs[1] == "sign"
            && matches!(segs[2].as_str(), "message" | "hash" | "typed_data")
        {
            return true;
        }
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
        let wallet = &segs[0];
        let info = self.keystore.info_unverified(wallet).map_err(err_be)?;
        if segs.len() == 1 {
            return Ok(Entry::dir(wallet));
        }
        match segs[1].as_str() {
            "address" | "address.qr.png" | "address.qr.svg" | "addresses.json" | "public_key"
            | "kind" => Ok(Entry::file(&segs[1])),
            "policy.toml" => Ok(Entry::writable_file("policy.toml")),
            "unlock-passkey" if info.kind == bloom_keystore::WalletKind::PasskeyGated => {
                Ok(Entry::writable_file("unlock-passkey"))
            }
            "sign" => match segs.len() {
                2 => Ok(Entry::dir("sign")),
                3 if matches!(segs[2].as_str(), "message" | "hash" | "typed_data") => {
                    Ok(Entry::writable_file(&segs[2]))
                }
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
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
            "policy-session" => match segs.len() {
                2 => Ok(Entry::dir("policy-session")),
                3 if segs[2] == "new" => Ok(Entry::writable_file("new")),
                3 if segs[2] == "active.json" => Ok(Entry::file("active.json")),
                4 if segs[3] == "revoke" => Ok(Entry::writable_file("revoke")),
                4 if segs[3] == "use" => Ok(Entry::writable_file("use")),
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "policy-updates" => match segs.len() {
                2 => Ok(Entry::dir("policy-updates")),
                3 if self.policy_updates_dir(wallet).join(&segs[2]).is_dir() => {
                    Ok(Entry::dir(&segs[2]))
                }
                4 if segs[3] == "status.json" => {
                    let action_dir = self.policy_updates_dir(wallet).join(&segs[2]);
                    if action_dir.is_dir() {
                        Ok(Entry::file("status.json"))
                    } else {
                        Err(HandlerError::not_found(path.to_string_path()))
                    }
                }
                4 if segs[3] == APPROVAL_CHALLENGE_FILE => {
                    let challenge_path = self
                        .policy_updates_dir(wallet)
                        .join(&segs[2])
                        .join(APPROVAL_CHALLENGE_FILE);
                    if challenge_path.is_file() {
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
            return Ok(b"# write a wallet name (plain text) or a TOML spec to create a wallet\n# defaults to a passkey (WebAuthn) wallet; passkey is the safe default.\n# examples:\n#   echo alice > /wallets/new                          # passkey ceremony\n#   printf 'name = \"alice\"\\nkind = \"watch\"\\naddress = \"0xabc\"\\n' > /wallets/new\n# kind: passkey (default) | local | import (with private_key) | watch (with address)\n# local/import require allow_passphrase_wallet = true and a passphrase field.\n".to_vec());
        }
        let wallet = &segs[0];
        let info = self.keystore.info_unverified(wallet).map_err(err_be)?;
        match segs.get(1).map(|s| s.as_str()).unwrap_or("") {
            "address" => {
                Ok(format!("{}\n", bloom_proto::checksum_address(&info.address)).into_bytes())
            }
            "address.qr.svg" => {
                let address = bloom_proto::checksum_address(&info.address);
                render_address_qr_svg(&address)
            }
            "address.qr.png" => {
                let address = bloom_proto::checksum_address(&info.address);
                render_address_qr_png(&address)
            }
            "addresses.json" => self.addresses_json(wallet, &info),
            "public_key" => Ok(format!("0x{}\n", info.pubkey_hex).into_bytes()),
            "kind" => {
                let s = match info.kind {
                    bloom_keystore::WalletKind::Local => "local",
                    bloom_keystore::WalletKind::Watch => "watch",
                    bloom_keystore::WalletKind::PasskeyGated => "passkey",
                };
                Ok(format!("{}\n", s).into_bytes())
            }
            "policy.toml" => {
                let body = toml::to_string_pretty(&info.policy).map_err(err_be)?;
                Ok(body.into_bytes())
            }
            "chains" if segs.len() >= 4 => self.read_chain(wallet, &segs[2], &segs[3..]).await,
            "policy-session" if segs.len() == 3 && segs[2] == "active.json" => {
                self.policy_session_active_json(wallet).await
            }
            "policy-updates" if segs.len() == 4 && segs[3] == "approval_challenge.json" => {
                self.read_policy_update_challenge(wallet, &segs[2])
            }
            "policy-updates" if segs.len() == 4 && segs[3] == "status.json" => {
                self.policy_update_status_json(wallet, &segs[2])
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
            return self.write_new_wallet(data).await;
        }
        let wallet = &segs[0];
        let info = self.keystore.info(wallet).map_err(err_be)?;
        if segs.len() >= 4 && segs[1] == "chains" && segs[3] == "outbox" {
            return self.write_outbox(wallet, &segs[2], &segs[4..], data).await;
        }
        // WS-11a: arbitrary-bytes wallet signing oracle closed. Signing
        // caller-supplied message/hash/typed_data (e.g. a draining ERC-20
        // permit's EIP-712 TypedData) straight from the cached signer is an
        // unbounded surface with no action binding, grant, or staged Sealed
        // Approval. Value/authority signing must be staged as an action and
        // signed via PetalHost::sign_hash. Applies to every wallet kind and
        // every write lane (plain IPC write and the write_unlocked ceremony
        // lane both land here).
        if segs.len() == 3 && segs[1] == "sign" {
            return Err(HandlerError::Unsupported(
                "arbitrary wallet signing via /<wallet>/sign/{message,hash,typed_data} \
                 is removed; stage a sealed approval action and sign via \
                 PetalHost::sign_hash"
                    .into(),
            ));
        }
        if segs.len() == 2 && segs[1] == "policy.toml" {
            self.write_permit()?;
            return self
                .write_wallet_policy_update(wallet, &path.to_string_path(), data)
                .await;
        }
        // PasskeyGated wallet: browser WebAuthn authentication ceremony.
        if segs.len() == 2 && segs[1] == "unlock-passkey" {
            if info.kind != bloom_keystore::WalletKind::PasskeyGated {
                return Err(HandlerError::invalid(
                    "unlock-passkey only applies to passkey wallets",
                ));
            }
            if self.keystore.is_unlocked(wallet) {
                return Ok(()); // already unlocked — ceremony not needed
            }
            self.keystore.unlock_passkey(wallet).await.map_err(err_be)?;
            return Ok(());
        }
        // Mint a bounded policy session (one ceremony authorizes many in-bounds
        // confirms). The IPC/CLI ceremony lane renders the envelope before this
        // write lands for passkey wallets.
        if segs.len() == 3 && segs[1] == "policy-session" && segs[2] == "new" {
            self.write_permit()?;
            return self.mint_policy_session(wallet, data).await;
        }
        if segs.len() == 4 && segs[1] == "policy-session" && segs[3] == "revoke" {
            self.write_permit()?;
            // Wallet-scoped: a session may only be revoked through its owning
            // wallet's path, so one wallet can't revoke another's session by id.
            return if self.tx_engine.session_store().revoke_for(wallet, &segs[2]) {
                Ok(())
            } else if let Some(store) = self.auth_services.store()
                && let Ok(Some(session)) = store.standing_session(&segs[2]).await
                && session.wallet == *wallet
            {
                self.auth_services
                    .require_writer()?
                    .revoke_standing_session(&segs[2], now_ms_u64())
                    .await
                    .map_err(|e| HandlerError::backend(format!("revoke standing session: {e}")))?;
                Ok(())
            } else {
                Err(HandlerError::not_found(format!(
                    "policy session '{}'",
                    segs[2]
                )))
            };
        }
        if segs.len() == 4 && segs[1] == "policy-session" && segs[3] == "use" {
            self.write_permit()?;
            return self.use_evm_owner_session(wallet, &segs[2], data).await;
        }
        Err(HandlerError::PermissionDenied)
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segs = path.segments();
        if segs.is_empty() {
            let infos = self.keystore.list().map_err(err_be)?;
            let mut out: Vec<Entry> = infos.into_iter().map(|i| Entry::dir(&i.name)).collect();
            out.push(Entry::writable_file("new"));
            return Ok(out);
        }
        let wallet = &segs[0];
        let info = self.keystore.info_unverified(wallet).map_err(err_be)?;
        match segs.len() {
            1 => Ok(Self::wallet_dir_entries(info.kind)),
            2 if segs[1] == "chains" => Ok(self
                .chains
                .list_names()
                .into_iter()
                .map(|n| Entry::dir(&n))
                .collect()),
            2 if segs[1] == "sign" => Ok(Self::sign_dir_entries()),
            2 if segs[1] == "policy-session" => Ok(Self::policy_session_dir_entries()),
            2 if segs[1] == "policy-updates" => Ok(self
                .policy_update_action_ids(wallet)
                .iter()
                .map(|id| Entry::dir(id))
                .collect()),
            3 if segs[1] == "policy-updates" => {
                let dir = self.policy_updates_dir(wallet).join(&segs[2]);
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
        let info = self.keystore.info_unverified(wallet).map_err(err_be)?;
        let client = self
            .chains
            .get(chain)
            .ok_or_else(|| HandlerError::not_found(format!("chain '{}'", chain)))?;
        match rest {
            [s] if s == "balance" => {
                let bal = client.balance(info.address).await.map_err(err_be)?;
                let spec = client.spec();
                Ok(super::balances::display_line(
                    bal,
                    spec.native_decimals,
                    &spec.native_symbol,
                ))
            }
            [s] if s == "balance.raw" => {
                let bal = client.balance(info.address).await.map_err(err_be)?;
                Ok(super::balances::raw_line(bal))
            }
            [s] if s == "balance.json" => {
                let bal = client.balance(info.address).await.map_err(err_be)?;
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
                let n = client.nonce(info.address).await.map_err(err_be)?;
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
                let path = entry.dir.join(fname.as_str());
                let bytes = std::fs::read(&path).map_err(HandlerError::Io)?;
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
                for tx in idx
                    .snapshot()
                    .into_iter()
                    .filter(|t| t.from == info.address)
                {
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
                        let observed = i.observed_nonces(info.address);
                        // (nonce -> hash) for this address in the mempool.
                        // Multiple entries at the same nonce are possible
                        // (replacements). We surface them all as candidate
                        // conflicts and let the dedupe against our own
                        // hashes filter them out below.
                        let mut by_nonce: std::collections::BTreeMap<u64, Vec<String>> =
                            std::collections::BTreeMap::new();
                        for tx in snap.into_iter().filter(|t| t.from == info.address) {
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
                    "address": bloom_proto::checksum_address(&info.address),
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
        let _info = self.keystore.info_unverified(wallet).map_err(err_be)?;
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
                        if let Some(n) = r.file_name().to_str() {
                            if r.file_type().map(|t| t.is_file()).unwrap_or(false) {
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
                                    out.push(
                                        Entry::file(n).with_modified_ms(entry.staged.created_ms),
                                    );
                                }
                            } else {
                                out.push(Entry::dir(n).with_modified_ms(entry.staged.created_ms));
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
        let info = self.keystore.info(wallet).map_err(err_be)?;
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
                        info.address,
                        intent,
                        &client,
                        &info.policy,
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
                    info.policy.override_sentinel()
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
                        &info.policy,
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
                        &info.policy,
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
                        &info.policy,
                    )
                    .await
                    .map_err(err_be)?;
                Ok(())
            }
            _ => Err(HandlerError::PermissionDenied),
        }
    }

    async fn write_new_wallet(&self, data: &[u8]) -> Result<(), HandlerError> {
        let body = std::str::from_utf8(data)
            .map_err(|_| HandlerError::invalid("wallets/new body must be utf-8"))?
            .trim();
        if body.is_empty() {
            return Err(HandlerError::invalid("wallets/new body is empty"));
        }

        let spec = parse_new_wallet_spec(body)?;

        // Passphrase wallets (local/import) require an explicit acknowledgment.
        // Without this gate an agent could write `kind = "local"` + a
        // machine-chosen passphrase to /wallets/new and silently mint a
        // fund-holding wallet — passkey is the default for a reason.
        let passphrase_kind = matches!(spec.kind.as_str(), "local" | "import");
        if passphrase_kind {
            if !spec.allow_passphrase_wallet {
                return Err(HandlerError::invalid(
                    "creating a passphrase (kind=local/import) wallet via the VFS requires \
                     allow_passphrase_wallet = true in the spec; passkey is the default — omit \
                     kind (or use kind = \"passkey\") for a WebAuthn ceremony",
                ));
            }
            if spec.passphrase.as_deref().unwrap_or("").is_empty() {
                return Err(HandlerError::invalid(
                    "passphrase required in the TOML spec for kind=local/import",
                ));
            }
        }

        let info = match spec.kind.as_str() {
            "local" => {
                let pass = spec.passphrase.as_deref().unwrap_or("");
                let info = self
                    .keystore
                    .create_local(&spec.name, pass)
                    .map_err(err_be)?;
                write_passphrase_recovery(self.keystore.root(), &spec.name, pass)?;
                info
            }
            "import" => {
                let pass = spec.passphrase.as_deref().unwrap_or("");
                let key = spec
                    .private_key
                    .as_deref()
                    .ok_or_else(|| HandlerError::invalid("import requires private_key"))?;
                let info = self
                    .keystore
                    .import_hex(&spec.name, key, pass)
                    .map_err(err_be)?;
                write_passphrase_recovery(self.keystore.root(), &spec.name, pass)?;
                info
            }
            "watch" => {
                let addr_str = spec
                    .address
                    .as_deref()
                    .ok_or_else(|| HandlerError::invalid("watch requires address"))?;
                let addr: alloy::primitives::Address = addr_str
                    .parse()
                    .map_err(|e| HandlerError::invalid(format!("address: {e}")))?;
                self.keystore.add_watch(&spec.name, addr).map_err(err_be)?
            }
            // PasskeyGated: opens a browser WebAuthn registration ceremony.
            "passkey" => self
                .keystore
                .create_passkey(&spec.name)
                .await
                .map_err(err_be)?,
            // PasskeyGated from an existing hex private key.
            "passkey-import" => {
                let key = spec
                    .private_key
                    .as_deref()
                    .ok_or_else(|| HandlerError::invalid("passkey-import requires private_key"))?;
                self.keystore
                    .import_passkey(&spec.name, key)
                    .await
                    .map_err(err_be)?
            }
            other => {
                return Err(HandlerError::invalid(format!(
                    "unknown wallet kind '{other}'; expected local|import|watch|passkey|passkey-import"
                )));
            }
        };
        tracing::info!(wallet=%info.name, address=%info.address, kind=?info.kind, "wallet.created");
        Ok(())
    }
}

#[derive(Default)]
struct NewWalletSpec {
    name: String,
    kind: String,
    passphrase: Option<String>,
    /// Explicit acknowledgment required to create a passphrase (local/import)
    /// wallet via the VFS. Prevents silent agent creation of passphrase wallets
    /// — passkey is the default.
    allow_passphrase_wallet: bool,
    address: Option<String>,
    private_key: Option<String>,
}

/// Write `<keystore_root>/<name>/RECOVERY.txt` (mode 0600) containing the
/// passphrase. Surfaces the agent/caller-chosen secret so a passphrase wallet
/// created via the VFS can never be fully silent.
fn write_passphrase_recovery(
    keystore_root: &Path,
    name: &str,
    passphrase: &str,
) -> Result<(), HandlerError> {
    let path = keystore_root.join(name).join("RECOVERY.txt");
    let body = format!(
        "Bloom passphrase-wallet recovery\n\
         wallet: {name}\n\
         \n\
         passphrase: {passphrase}\n\
         \n\
         This wallet was created with a passphrase via the VFS. Store this file\n\
         securely or migrate to a passkey wallet and remove this file.\n"
    );
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| HandlerError::backend(format!("create {}: {e}", tmp.display())))?;
        file.write_all(body.as_bytes())
            .map_err(|e| HandlerError::backend(format!("write {}: {e}", tmp.display())))?;
        file.sync_all()
            .map_err(|e| HandlerError::backend(format!("sync {}: {e}", tmp.display())))?;
        std::fs::rename(&tmp, &path)
            .map_err(|e| HandlerError::backend(format!("rename {}: {e}", path.display())))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, body.as_bytes())
            .map_err(|e| HandlerError::backend(format!("write {}: {e}", path.display())))?;
    }
    tracing::warn!(
        wallet = name,
        path = %path.display(),
        "wallet.passphrase_recovery_written"
    );
    Ok(())
}

fn parse_new_wallet_spec(body: &str) -> Result<NewWalletSpec, HandlerError> {
    let trimmed = body.trim();
    if !trimmed.contains('=') && !trimmed.contains('\n') {
        return Ok(NewWalletSpec {
            name: trimmed.to_string(),
            kind: "passkey".into(),
            ..Default::default()
        });
    }
    let table: toml::Table = trimmed
        .parse()
        .map_err(|e| HandlerError::invalid(format!("toml: {e}")))?;
    let name = table
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| HandlerError::invalid("name required"))?
        .to_string();
    let kind = table
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("passkey")
        .to_string();
    Ok(NewWalletSpec {
        name,
        kind,
        passphrase: table
            .get("passphrase")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        allow_passphrase_wallet: table
            .get("allow_passphrase_wallet")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        address: table
            .get("address")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        private_key: table
            .get("private_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, B256};
    use alloy::signers::SignerSync;
    use bloom_auth_api::{
        APPROVAL_CHALLENGE_SCHEMA_V1, APPROVAL_SCHEMA_V1, ApprovalVerifier, AuthApiError,
        AuthEntryRecord, AuthEntryState, AuthStoreView, AuthStoreWriter, DaemonGrantTerms,
        GrantStore, NonceState, PetalHost, SealedAction, SealedApprovalGrant, SealedPetalContext,
        SealedSignature, SignerTransport, StandingSessionRecord, WebAuthnAssertionRecord,
    };
    use bloom_proto::AddressBook;
    use bloom_tx::outbox::Outbox;
    use bloom_tx::tx_engine::TxEngine;
    use std::sync::Mutex;

    struct Fixture {
        _tmp: tempfile::TempDir,
        handler: WalletsHandler,
        wallet_name: String,
        wallet_addr: Address,
    }

    struct ChallengeOnlyWriter;

    struct AcceptingVerifier;

    struct SigningPetalHost {
        signer: Arc<alloy::signers::local::PrivateKeySigner>,
    }

    struct UnusedGrantStore;

    #[async_trait]
    impl GrantStore for UnusedGrantStore {
        async fn mint(
            &self,
            _sealed: &SealedAction,
            _approval_expiry_ms: u64,
            _now_ms: u64,
        ) -> Result<SealedApprovalGrant, AuthApiError> {
            Err(AuthApiError::Store(
                "test grant store should not mint directly".into(),
            ))
        }

        async fn consume_signature(
            &self,
            _grant_id: &str,
            _intent: &str,
            _now_ms: u64,
        ) -> Result<SealedApprovalGrant, AuthApiError> {
            Err(AuthApiError::Store(
                "test grant store should not consume".into(),
            ))
        }

        async fn revoke(&self, _grant_id: &str, _now_ms: u64) -> Result<(), AuthApiError> {
            Ok(())
        }

        async fn revoke_all_for_wallet(
            &self,
            _wallet: &str,
            _now_ms: u64,
        ) -> Result<usize, AuthApiError> {
            Ok(0)
        }

        async fn get_active(
            &self,
            _wallet: &str,
            _action_id: &str,
            _petal_id: &str,
            _petal_digest: &str,
            _now_ms: u64,
        ) -> Result<Option<SealedApprovalGrant>, AuthApiError> {
            Ok(None)
        }
    }

    #[async_trait]
    impl ApprovalVerifier for AcceptingVerifier {
        async fn verify_and_consume(
            &self,
            approval: SignedApproval,
            _now_ms: u64,
        ) -> Result<(), AuthApiError> {
            if approval.surface != "policy-session" && approval.surface != WALLET_POLICY_SURFACE {
                return Err(AuthApiError::Denied("wrong surface".into()));
            }
            Ok(())
        }

        async fn verify_and_mint_grant(
            &self,
            approval: SignedApproval,
            _grant_store: &dyn GrantStore,
            now_ms: u64,
        ) -> Result<SealedApprovalGrant, AuthApiError> {
            self.verify_and_consume(approval.clone(), now_ms).await?;
            let mut daemon_terms = DaemonGrantTerms::minimal(AssuranceLevel::Hardened);
            daemon_terms.allowed_sign_intents =
                vec![EVM_TX_SIGN_INTENT.into(), WALLET_POLICY_SIGN_INTENT.into()];
            daemon_terms.max_signatures = 5;
            Ok(SealedApprovalGrant {
                grant_id: format!("test-grant-{}", approval.action_id),
                wallet: approval.wallet,
                action_id: approval.action_id,
                intent_hash: approval.intent_hash,
                petal_id: approval.petal_id,
                petal_digest: approval.petal_digest,
                petal_version: petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
                daemon_terms,
                petal_policy_digest: approval.petal_policy_digest,
                policy_version: approval.policy_version,
                issued_ms: now_ms,
                expiry_ms: approval.expiry_ms,
                max_signatures: 5,
                consumed_signature_count: 0,
                revoked: false,
            })
        }
    }

    #[async_trait]
    impl PetalHost for SigningPetalHost {
        async fn seal_context(&self, _petal_id: &str) -> Result<SealedPetalContext, AuthApiError> {
            Err(AuthApiError::Store("test seal_context unused".into()))
        }

        async fn sealed_policy_snapshot(
            &self,
            _wallet: &str,
            _petal_id: &str,
        ) -> Result<PetalPolicySnapshot, AuthApiError> {
            Err(AuthApiError::Store(
                "test sealed_policy_snapshot unused".into(),
            ))
        }

        async fn sign_hash(
            &self,
            request: SignHashRequest,
            attestation: &SigningAttestation,
            now_ms: u64,
        ) -> Result<SealedSignature, AuthApiError> {
            if request.intent != WALLET_POLICY_SIGN_INTENT
                || attestation.intent != WALLET_POLICY_SIGN_INTENT
                || attestation.petal_id != petal_identity::PETAL_ID_WALLET_POLICY
            {
                return Err(AuthApiError::Denied("unexpected wallet-policy sign".into()));
            }
            let hash = hex::decode(request.hash_hex.trim_start_matches("0x"))
                .map_err(|e| AuthApiError::Denied(format!("hash hex: {e}")))?;
            let hash = B256::from_slice(&hash);
            let sig = self
                .signer
                .sign_hash_sync(&hash)
                .map_err(|e| AuthApiError::Denied(format!("test sign: {e}")))?;
            Ok(SealedSignature {
                intent_hash: "test-wallet-policy-intent".into(),
                signature_b64: B64_STANDARD.encode(sig.as_bytes()),
                signed_at_ms: now_ms,
            })
        }

        async fn audit(&self, _event: bloom_auth_api::AuditEvent) -> Result<(), AuthApiError> {
            Ok(())
        }
    }

    struct RejectingVerifier;

    #[async_trait]
    impl ApprovalVerifier for RejectingVerifier {
        async fn verify_and_consume(
            &self,
            _approval: SignedApproval,
            _now_ms: u64,
        ) -> Result<(), AuthApiError> {
            Err(AuthApiError::Denied("test verifier rejects".into()))
        }
    }

    #[async_trait]
    impl AuthStoreWriter for ChallengeOnlyWriter {
        async fn stage_entry(
            &self,
            envelope: CanonicalEnvelope,
            assurance: AssuranceLevel,
            now_ms: u64,
        ) -> Result<AuthEntryRecord, AuthApiError> {
            let intent_hash = envelope.intent_hash()?;
            Ok(AuthEntryRecord {
                surface: envelope.header.surface.clone(),
                action_id: envelope.header.action_id.clone(),
                state: AuthEntryState::Staged,
                intent_hash,
                assurance,
                nonce: None,
                nonce_state: NonceState::Unused,
                reservation_id: None,
                updated_ms: now_ms,
            })
        }

        async fn stage_action(
            &self,
            action: SealedAction,
            now_ms: u64,
        ) -> Result<AuthEntryRecord, AuthApiError> {
            self.stage_entry(action.envelope, action.daemon_terms.assurance, now_ms)
                .await
        }

        async fn issue_challenge(
            &self,
            surface: &str,
            action_id: &str,
            server_nonce: &str,
            expiry_ms: u64,
            _now_ms: u64,
        ) -> Result<ApprovalChallenge, AuthApiError> {
            Ok(ApprovalChallenge {
                schema: APPROVAL_CHALLENGE_SCHEMA_V1.to_string(),
                action_id: action_id.to_string(),
                wallet: "alice".to_string(),
                surface: surface.to_string(),
                petal_id: petal_identity::PETAL_ID_WALLET_POLICY.to_string(),
                petal_digest: petal_identity::PLACEHOLDER_DIGEST_WALLET_POLICY.to_string(),
                intent_hash: "policy-session-intent".to_string(),
                server_nonce: server_nonce.to_string(),
                assurance: AssuranceLevel::Hardened,
                daemon_terms_digest: "1".repeat(64),
                petal_policy_digest: "2".repeat(64),
                policy_version: 0,
                expiry_ms,
                ceremony_url: None,
            })
        }

        async fn issue_review_session(
            &self,
            review_session_id: &str,
            surface: &str,
            action_id: &str,
            expires_ms: u64,
            now_ms: u64,
        ) -> Result<bloom_auth_api::ReviewSessionRecord, AuthApiError> {
            Ok(bloom_auth_api::ReviewSessionRecord {
                review_session_id: review_session_id.to_string(),
                surface: surface.to_string(),
                action_id: action_id.to_string(),
                intent_hash: "policy-session-intent".to_string(),
                assurance: AssuranceLevel::Hardened,
                expires_ms,
                consumed_ms: None,
                created_ms: now_ms,
            })
        }
    }

    #[derive(Default)]
    struct EvmSessionAuth {
        sessions: Mutex<BTreeMap<String, StandingSessionRecord>>,
    }

    #[async_trait]
    impl AuthStoreView for EvmSessionAuth {
        async fn sealed_intent(
            &self,
            intent_hash: &str,
        ) -> Result<bloom_auth_api::SealedIntentRecord, AuthApiError> {
            Err(AuthApiError::NotFound(format!(
                "sealed intent {intent_hash}"
            )))
        }

        async fn standing_session(
            &self,
            session_id: &str,
        ) -> Result<Option<StandingSessionRecord>, AuthApiError> {
            Ok(self.sessions.lock().unwrap().get(session_id).cloned())
        }

        async fn active_standing_sessions(
            &self,
            wallet: &str,
            session_kind: Option<&str>,
            now_ms: u64,
        ) -> Result<Vec<StandingSessionRecord>, AuthApiError> {
            Ok(self
                .sessions
                .lock()
                .unwrap()
                .values()
                .filter(|s| {
                    s.wallet == wallet
                        && s.expires_ms > now_ms
                        && s.revoked_ms.is_none()
                        && !s.orphan
                        && session_kind.is_none_or(|kind| s.session_kind == kind)
                })
                .cloned()
                .collect())
        }
    }

    #[async_trait]
    impl AuthStoreWriter for EvmSessionAuth {
        async fn stage_entry(
            &self,
            envelope: CanonicalEnvelope,
            assurance: AssuranceLevel,
            now_ms: u64,
        ) -> Result<AuthEntryRecord, AuthApiError> {
            let intent_hash = envelope.intent_hash()?;
            Ok(AuthEntryRecord {
                surface: envelope.header.surface.clone(),
                action_id: envelope.header.action_id.clone(),
                state: AuthEntryState::Staged,
                intent_hash,
                assurance,
                nonce: None,
                nonce_state: NonceState::Unused,
                reservation_id: None,
                updated_ms: now_ms,
            })
        }

        async fn stage_action(
            &self,
            action: SealedAction,
            now_ms: u64,
        ) -> Result<AuthEntryRecord, AuthApiError> {
            self.stage_entry(action.envelope, action.daemon_terms.assurance, now_ms)
                .await
        }

        async fn issue_challenge(
            &self,
            surface: &str,
            action_id: &str,
            server_nonce: &str,
            expiry_ms: u64,
            _now_ms: u64,
        ) -> Result<ApprovalChallenge, AuthApiError> {
            Ok(ApprovalChallenge {
                schema: APPROVAL_CHALLENGE_SCHEMA_V1.to_string(),
                action_id: action_id.to_string(),
                wallet: "alice".to_string(),
                surface: surface.to_string(),
                petal_id: petal_identity::PETAL_ID_EVM_WALLET.to_string(),
                petal_digest: petal_identity::PLACEHOLDER_DIGEST_EVM_WALLET.to_string(),
                intent_hash: "evm-owner-session-intent".to_string(),
                server_nonce: server_nonce.to_string(),
                assurance: AssuranceLevel::Hardened,
                daemon_terms_digest: "1".repeat(64),
                petal_policy_digest: "2".repeat(64),
                policy_version: 0,
                expiry_ms,
                ceremony_url: None,
            })
        }

        async fn issue_review_session(
            &self,
            review_session_id: &str,
            surface: &str,
            action_id: &str,
            expires_ms: u64,
            now_ms: u64,
        ) -> Result<bloom_auth_api::ReviewSessionRecord, AuthApiError> {
            Ok(bloom_auth_api::ReviewSessionRecord {
                review_session_id: review_session_id.to_string(),
                surface: surface.to_string(),
                action_id: action_id.to_string(),
                intent_hash: "evm-owner-session-intent".to_string(),
                assurance: AssuranceLevel::Hardened,
                expires_ms,
                consumed_ms: None,
                created_ms: now_ms,
            })
        }

        async fn create_standing_session(
            &self,
            session_id: &str,
            wallet: &str,
            petal_id: &str,
            session_kind: &str,
            scope: serde_json::Value,
            counters: serde_json::Value,
            frozen_policy_version: u64,
            frozen_petal_policy_digest: &str,
            issued_ms: u64,
            expires_ms: u64,
            now_ms: u64,
        ) -> Result<StandingSessionRecord, AuthApiError> {
            let record = StandingSessionRecord {
                session_id: session_id.to_string(),
                wallet: wallet.to_string(),
                petal_id: petal_id.to_string(),
                session_kind: session_kind.to_string(),
                scope,
                counters,
                frozen_policy_version,
                frozen_petal_policy_digest: frozen_petal_policy_digest.to_string(),
                issued_ms,
                expires_ms,
                revoked_ms: None,
                orphan: false,
                created_ms: now_ms,
            };
            self.sessions
                .lock()
                .unwrap()
                .insert(session_id.to_string(), record.clone());
            Ok(record)
        }

        async fn revoke_standing_session(
            &self,
            session_id: &str,
            now_ms: u64,
        ) -> Result<(), AuthApiError> {
            if let Some(session) = self.sessions.lock().unwrap().get_mut(session_id) {
                session.revoked_ms = Some(now_ms);
            }
            Ok(())
        }

        async fn reserve_evm_owner_session_use(
            &self,
            session_id: &str,
            reservation_id: &str,
            request: EvmOwnerSigningSessionUse,
            signer_material_available: bool,
            _now_ms: u64,
        ) -> Result<StandingSessionRecord, AuthApiError> {
            if !signer_material_available {
                return Err(AuthApiError::Denied(
                    "session_missing_signer_material".into(),
                ));
            }
            let mut guard = self.sessions.lock().unwrap();
            let session = guard
                .get_mut(session_id)
                .ok_or_else(|| AuthApiError::Denied("session_not_found".into()))?;
            let scope: EvmOwnerSigningSessionScope =
                serde_json::from_value(session.scope.clone()).map_err(AuthApiError::Json)?;
            if scope.wallet != request.wallet
                || scope.chain_id != request.chain_id
                || scope.token_contract != request.token_contract
                || scope.recipient != request.recipient
                || scope.method != request.method
                || request.value_wei != "0"
            {
                return Err(AuthApiError::Denied("session_scope_mismatch".into()));
            }
            let mut counters: EvmOwnerSigningSessionCounters =
                serde_json::from_value(session.counters.clone()).map_err(AuthApiError::Json)?;
            let amount: u128 = request
                .amount_base_units
                .parse()
                .map_err(|_| AuthApiError::Denied("session_wrong_amount".into()))?;
            let reserved: u128 = counters.reserved_base_units.parse().unwrap_or(0);
            counters.reserved_base_units = reserved.saturating_add(amount).to_string();
            counters
                .pending_reservations
                .insert(reservation_id.to_string(), amount.to_string());
            session.counters = serde_json::to_value(counters).map_err(AuthApiError::Json)?;
            Ok(session.clone())
        }

        async fn commit_evm_owner_session_use(
            &self,
            session_id: &str,
            reservation_id: &str,
            _now_ms: u64,
        ) -> Result<StandingSessionRecord, AuthApiError> {
            let mut guard = self.sessions.lock().unwrap();
            let session = guard
                .get_mut(session_id)
                .ok_or_else(|| AuthApiError::Denied("session_not_found".into()))?;
            let mut counters: EvmOwnerSigningSessionCounters =
                serde_json::from_value(session.counters.clone()).map_err(AuthApiError::Json)?;
            let amount = counters
                .pending_reservations
                .remove(reservation_id)
                .ok_or_else(|| AuthApiError::Denied("session_reservation_not_found".into()))?;
            let amount: u128 = amount.parse().unwrap();
            let reserved: u128 = counters.reserved_base_units.parse().unwrap_or(0);
            let spent: u128 = counters.spent_base_units.parse().unwrap_or(0);
            counters.reserved_base_units = reserved.saturating_sub(amount).to_string();
            counters.spent_base_units = spent.saturating_add(amount).to_string();
            counters.signature_count += 1;
            session.counters = serde_json::to_value(counters).map_err(AuthApiError::Json)?;
            Ok(session.clone())
        }

        async fn release_evm_owner_session_use(
            &self,
            session_id: &str,
            reservation_id: &str,
            _now_ms: u64,
        ) -> Result<StandingSessionRecord, AuthApiError> {
            let mut guard = self.sessions.lock().unwrap();
            let session = guard
                .get_mut(session_id)
                .ok_or_else(|| AuthApiError::Denied("session_not_found".into()))?;
            let mut counters: EvmOwnerSigningSessionCounters =
                serde_json::from_value(session.counters.clone()).map_err(AuthApiError::Json)?;
            let amount = counters
                .pending_reservations
                .remove(reservation_id)
                .ok_or_else(|| AuthApiError::Denied("session_reservation_not_found".into()))?;
            let amount: u128 = amount.parse().unwrap();
            let reserved: u128 = counters.reserved_base_units.parse().unwrap_or(0);
            counters.reserved_base_units = reserved.saturating_sub(amount).to_string();
            session.counters = serde_json::to_value(counters).map_err(AuthApiError::Json)?;
            Ok(session.clone())
        }
    }

    fn make_handler() -> Fixture {
        make_handler_with_chain(false)
    }

    /// Simulate the IPC ceremony lane writing the one-time mint approval marker
    /// for `body`, so a direct handler `write` to `policy-session/new` is allowed.
    fn approve_mint(f: &Fixture, wallet: &str, body: &[u8]) {
        let path = format!("/wallets/{wallet}/policy-session/new");
        let intent = bloom_proto::policy_session_mint_intent(wallet, &path, body);
        let home = f.handler.keystore.root().parent().unwrap().to_path_buf();
        crate::policy_session_review::persist_review_approved(&home, wallet, &intent.intent_hash())
            .unwrap();
    }

    /// Build a wallet fixture; when `with_chain` is true a stub `anvil`
    /// chain is registered (RPC URL is unreachable, so any test that
    /// triggers an actual broadcast will surface as an RPC error rather
    /// than silently succeeding). Outbox-state tests don't need the chain
    /// to be reachable.
    fn make_handler_with_chain(with_chain: bool) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let ks_root = tmp.path().join("keystore");
        let outbox_root = tmp.path().join("outbox");
        let keystore = bloom_keystore::Keystore::new(&ks_root).unwrap();
        let info = keystore.create_local("alice", "passphrase").unwrap();
        keystore.unlock("alice", "passphrase").unwrap();
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
        let handler = WalletsHandler::new(keystore, chains, tx_engine, address_book)
            .with_home_write_permit(permit);
        Fixture {
            _tmp: tmp,
            handler,
            wallet_name: "alice".to_string(),
            wallet_addr: info.address,
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
            tx_hash: None,
            token: None,
            nft: None,
            usd_value: None,
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
    async fn local_wallet_sign_message_is_denied() {
        let f = make_handler();
        let p = VfsPath::parse(&format!("/{}/sign/message", f.wallet_name)).unwrap();
        let r = f.handler.write(&p, b"hello world").await;
        assert_denied_oracle(r);
        assert_no_sig_file(&f, "message");
    }

    #[tokio::test]
    async fn local_wallet_sign_hash_is_denied() {
        let f = make_handler();
        // A valid 32-byte digest: the write must still be refused, since the
        // oracle is closed regardless of input shape.
        let digest_hex = "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";
        let p = VfsPath::parse(&format!("/{}/sign/hash", f.wallet_name)).unwrap();
        let r = f.handler.write(&p, digest_hex.as_bytes()).await;
        assert_denied_oracle(r);
        assert_no_sig_file(&f, "hash");
    }

    #[tokio::test]
    async fn local_wallet_sign_typed_data_is_denied() {
        let f = make_handler();
        let addr_hex = bloom_proto::checksum_address(&f.wallet_addr);
        // A draining ERC-20 permit looks exactly like this shape; the oracle
        // must refuse to sign it straight from the cached signer.
        let json = serde_json::json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"}
                ],
                "Mail": [
                    {"name": "from", "type": "address"},
                    {"name": "to", "type": "address"},
                    {"name": "contents", "type": "string"}
                ]
            },
            "primaryType": "Mail",
            "domain": {"name": "Test", "version": "1", "chainId": 1},
            "message": {"from": addr_hex, "to": addr_hex, "contents": "hi"}
        });
        let body = serde_json::to_vec(&json).unwrap();
        let p = VfsPath::parse(&format!("/{}/sign/typed_data", f.wallet_name)).unwrap();
        let r = f.handler.write(&p, &body).await;
        assert_denied_oracle(r);
        assert_no_sig_file(&f, "typed_data");
    }

    #[tokio::test]
    async fn passkey_wallet_sign_paths_are_denied() {
        let f = make_handler();
        seed_passkey_wallet(&f, "pk-wallet");
        for (kind, body) in [
            ("message", &b"hello world"[..]),
            ("hash", b"0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"),
            ("typed_data", br#"{"types":{"EIP712Domain":[]},"primaryType":"EIP712Domain","domain":{},"message":{}}"#),
        ] {
            let p = VfsPath::parse(&format!("/pk-wallet/sign/{kind}")).unwrap();
            let r = f.handler.write(&p, body).await;
            assert_denied_oracle(r);
            let sig_path = f
                ._tmp
                .path()
                .join("keystore")
                .join("pk-wallet")
                .join("sign")
                .join(format!("{kind}.sig"));
            assert!(!sig_path.exists(), "{kind}.sig should not be written");
        }
    }

    fn assert_denied_oracle(r: Result<(), HandlerError>) {
        match r {
            Err(HandlerError::Unsupported(msg)) => {
                assert!(
                    msg.contains("arbitrary wallet signing")
                        && msg.contains("PetalHost::sign_hash"),
                    "migration message, got: {msg}"
                );
            }
            ref other => panic!("expected Unsupported oracle-closed error, got: {other:?}"),
        }
    }

    fn assert_no_sig_file(f: &Fixture, kind: &str) {
        let sig_path = f
            ._tmp
            .path()
            .join("keystore")
            .join(&f.wallet_name)
            .join("sign")
            .join(format!("{kind}.sig"));
        assert!(!sig_path.exists(), "{kind}.sig should not be written");
    }

    #[tokio::test]
    async fn write_new_wallet_toml_creates_local_wallet() {
        let f = make_handler();
        let p = VfsPath::parse("/new").unwrap();
        f.handler
            .write(
                &p,
                b"name = \"bob\"\nkind = \"local\"\npassphrase = \"p\"\nallow_passphrase_wallet = true\n",
            )
            .await
            .unwrap();
        let info = f.handler.keystore.info("bob").unwrap();
        assert!(matches!(info.kind, bloom_keystore::WalletKind::Local));
        // Passphrase wallets must surface a recovery file so they can never be
        // created fully silently.
        let recovery = f.handler.keystore.root().join("bob").join("RECOVERY.txt");
        assert!(
            recovery.exists(),
            "expected RECOVERY.txt at {}",
            recovery.display()
        );
        let body = std::fs::read_to_string(&recovery).unwrap();
        assert!(body.contains("passphrase: p"));
    }

    /// A `kind = "local"` spec WITHOUT `allow_passphrase_wallet = true` must be
    /// rejected — this is the gate that prevents an agent from silently writing
    /// a passphrase wallet via the VFS.
    #[tokio::test]
    async fn write_new_wallet_local_rejected_without_allow_flag() {
        let f = make_handler();
        let p = VfsPath::parse("/new").unwrap();
        let r = f
            .handler
            .write(
                &p,
                b"name = \"sneaky\"\nkind = \"local\"\npassphrase = \"p\"\n",
            )
            .await;
        assert!(
            matches!(r, Err(HandlerError::Invalid(_))),
            "expected Invalid error without allow_passphrase_wallet, got: {r:?}"
        );
        // And nothing was created.
        assert!(f.handler.keystore.info("sneaky").is_err());
    }

    /// A plain name spec now defaults to passkey (the safe default), so it
    /// can never silently produce a passphrase (`local`) wallet.
    #[test]
    fn parse_new_wallet_spec_plain_name_defaults_to_passkey() {
        let spec = parse_new_wallet_spec("alice").unwrap();
        assert_eq!(spec.name, "alice");
        assert_eq!(spec.kind, "passkey");
    }

    #[test]
    fn parse_new_wallet_spec_toml_without_kind_defaults_to_passkey() {
        let spec = parse_new_wallet_spec("name = \"bob\"\n").unwrap();
        assert_eq!(spec.kind, "passkey");
    }

    #[tokio::test]
    async fn write_new_wallet_toml_creates_watch_wallet() {
        let f = make_handler();
        let p = VfsPath::parse("/new").unwrap();
        let body =
            b"name = \"observer\"\nkind = \"watch\"\naddress = \"0x0000000000000000000000000000000000000001\"\n";
        f.handler.write(&p, body).await.unwrap();
        let info = f.handler.keystore.info("observer").unwrap();
        assert!(matches!(info.kind, bloom_keystore::WalletKind::Watch));
    }

    #[tokio::test]
    async fn write_new_wallet_toml_imports_private_key() {
        let f = make_handler();
        let p = VfsPath::parse("/new").unwrap();
        // Anvil's first signer; use just for deterministic round-trip check.
        let key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let body = format!(
            "name = \"imported\"\nkind = \"import\"\nprivate_key = \"{}\"\npassphrase = \"x\"\nallow_passphrase_wallet = true\n",
            key
        );
        f.handler.write(&p, body.as_bytes()).await.unwrap();
        let info = f.handler.keystore.info("imported").unwrap();
        assert_eq!(
            format!("{:?}", info.address).to_lowercase(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }

    #[tokio::test]
    async fn list_root_includes_new() {
        let f = make_handler();
        let p = VfsPath::parse("/").unwrap();
        let entries = f.handler.list(&p).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"alice"));
        assert!(names.contains(&"new"));
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
        // Local wallet: no signed policy required, no role addresses known.
        assert_eq!(v["policy_status"], "not_applicable");
        // Local wallet is unlocked at creation time; passkey wallets start
        // locked and require an unlock ceremony.
        assert_eq!(v["unlocked"], true);
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
    async fn policy_session_mint_list_revoke() {
        let mut f = make_handler();
        f.handler = f.handler.with_auth_services(AuthServices::new(
            Some(Arc::new(AcceptingVerifier)),
            None,
            Some(Arc::new(ChallengeOnlyWriter)),
        ));
        let new_p = VfsPath::parse("/alice/policy-session/new").unwrap();
        let body = br#"{"max_usd":10,"ttl_secs":600,"pending_ids":[{"chain_id":42161,"id":"0001-a"},{"chain_id":8453,"id":"0001-b"}]}"#;
        // Mint requires a sealed approval; a write without one is refused.
        assert!(f.handler.write(&new_p, body).await.is_err());
        let action_id = policy_session_action_id("alice", body);
        let approval_dir = f
            .handler
            .keystore
            .root()
            .join("alice")
            .join("policy-session")
            .join(&action_id);
        std::fs::create_dir_all(&approval_dir).unwrap();
        write_json(
            approval_dir.join(APPROVAL_FILE),
            &SignedApproval {
                schema: APPROVAL_SCHEMA_V1.into(),
                wallet: "alice".into(),
                surface: "policy-session".into(),
                action_id: action_id.clone(),
                intent_hash: "policy-session-intent".into(),
                petal_id: petal_identity::PETAL_ID_WALLET_POLICY.into(),
                petal_digest: petal_identity::PLACEHOLDER_DIGEST_WALLET_POLICY.into(),
                assurance: AssuranceLevel::Hardened,
                server_nonce: "nonce-1".into(),
                daemon_terms_digest: "1".repeat(64),
                petal_policy_digest: "2".repeat(64),
                policy_version: 0,
                expiry_ms: now_ms_u64() + 60_000,
                signer_transport: SignerTransport::BrowserWebauthn,
                credential_id: "cred-1".into(),
                review_session_id: None,
                webauthn_assertion: WebAuthnAssertionRecord {
                    credential_id: "cred-1".into(),
                    authenticator_data_b64: "AA".into(),
                    client_data_json_b64: "e30".into(),
                    signature_b64: "AA".into(),
                    user_handle_b64: None,
                },
            },
        )
        .unwrap();
        f.handler.write(&new_p, body).await.unwrap();

        let active_p = VfsPath::parse("/alice/policy-session/active.json").unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&f.handler.read(&active_p).await.unwrap()).unwrap();
        let sessions = v["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["max_micro_usd"], 10_000_000);
        let id = sessions[0]["id"].as_str().unwrap().to_string();

        // The minted session actually authorizes a covered confirm.
        assert!(
            f.handler
                .tx_engine
                .session_store()
                .authorize_and_debit("alice", 42161, "0001-a", Some(1_000_000), true, now_ms())
                .is_some()
        );

        // Revoke clears it.
        let revoke_p = VfsPath::parse(&format!("/alice/policy-session/{id}/revoke")).unwrap();
        f.handler.write(&revoke_p, b"y").await.unwrap();
        let second_response: serde_json::Value =
            serde_json::from_slice(&f.handler.read(&active_p).await.unwrap()).unwrap();
        assert!(second_response["sessions"].as_array().unwrap().is_empty());

        // A degenerate descriptor (no chains/ids) is rejected.
        let bad = br#"{"chains":[],"max_usd":10,"ttl_secs":600,"pending_ids":[]}"#;
        assert!(f.handler.write(&new_p, bad).await.is_err());
    }

    #[tokio::test]
    async fn wired_auth_policy_session_mint_ignores_legacy_marker_and_issues_challenge() {
        let mut f = make_handler();
        f.handler = f.handler.with_auth_services(AuthServices::new(
            None,
            None,
            Some(Arc::new(ChallengeOnlyWriter)),
        ));
        let new_p = VfsPath::parse("/alice/policy-session/new").unwrap();
        let body =
            br#"{"max_usd":10,"ttl_secs":600,"pending_ids":[{"chain_id":42161,"id":"0001-a"}]}"#;
        approve_mint(&f, "alice", body);

        let err = f.handler.write(&new_p, body).await.unwrap_err();
        assert!(matches!(err, HandlerError::PermissionDenied), "{err}");
        assert!(
            !f.handler
                .tx_engine
                .session_store()
                .active(now_ms())
                .iter()
                .any(|session| session.wallet == "alice")
        );

        let action_id = policy_session_action_id("alice", body);
        let challenge_path = f
            .handler
            .keystore
            .root()
            .join("alice")
            .join("policy-session")
            .join(&action_id)
            .join(APPROVAL_CHALLENGE_FILE);
        let challenge: ApprovalChallenge = read_json(challenge_path).unwrap();
        assert_eq!(challenge.surface, "policy-session");
        assert_eq!(challenge.action_id, action_id);
        assert_eq!(challenge.intent_hash, "policy-session-intent");
        assert_eq!(challenge.assurance, AssuranceLevel::Hardened);
    }

    #[tokio::test]
    async fn wired_auth_policy_session_mint_accepts_approval_without_legacy_marker() {
        let mut f = make_handler();
        f.handler = f.handler.with_auth_services(AuthServices::new(
            Some(Arc::new(AcceptingVerifier)),
            None,
            Some(Arc::new(ChallengeOnlyWriter)),
        ));
        let new_p = VfsPath::parse("/alice/policy-session/new").unwrap();
        let body =
            br#"{"max_usd":10,"ttl_secs":600,"pending_ids":[{"chain_id":42161,"id":"0001-a"}]}"#;
        let action_id = policy_session_action_id("alice", body);
        let approval_dir = f
            .handler
            .keystore
            .root()
            .join("alice")
            .join("policy-session")
            .join(&action_id);
        std::fs::create_dir_all(&approval_dir).unwrap();
        write_json(
            approval_dir.join(APPROVAL_FILE),
            &SignedApproval {
                schema: APPROVAL_SCHEMA_V1.into(),
                wallet: "alice".into(),
                surface: "policy-session".into(),
                action_id: action_id.clone(),
                intent_hash: "policy-session-intent".into(),
                petal_id: petal_identity::PETAL_ID_WALLET_POLICY.into(),
                petal_digest: petal_identity::PLACEHOLDER_DIGEST_WALLET_POLICY.into(),
                assurance: AssuranceLevel::Hardened,
                server_nonce: "nonce-1".into(),
                daemon_terms_digest: "1".repeat(64),
                petal_policy_digest: "2".repeat(64),
                policy_version: 0,
                expiry_ms: now_ms_u64() + 60_000,
                signer_transport: SignerTransport::BrowserWebauthn,
                credential_id: "cred-1".into(),
                review_session_id: None,
                webauthn_assertion: WebAuthnAssertionRecord {
                    credential_id: "cred-1".into(),
                    authenticator_data_b64: "AA".into(),
                    client_data_json_b64: "e30".into(),
                    signature_b64: "AA".into(),
                    user_handle_b64: None,
                },
            },
        )
        .unwrap();

        f.handler.write(&new_p, body).await.unwrap();
        let sessions = f.handler.tx_engine.session_store().active(now_ms());
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].wallet, "alice");
        assert_eq!(sessions[0].max_micro_usd, 10_000_000);
    }

    #[tokio::test]
    async fn evm_owner_session_mint_active_and_use_surface() {
        let mut f = make_handler_with_chain(true);
        let auth = Arc::new(EvmSessionAuth::default());
        f.handler = f.handler.with_auth_services(
            AuthServices::new(
                Some(Arc::new(AcceptingVerifier)),
                Some(auth.clone()),
                Some(auth),
            )
            .with_grant_store(Arc::new(UnusedGrantStore)),
        );
        let new_p = VfsPath::parse("/alice/policy-session/new").unwrap();
        let body = br#"{
            "chain_id": 31337,
            "token_contract": "0x0000000000000000000000000000000000000003",
            "recipient": "0x0000000000000000000000000000000000000002",
            "daily_cap_base_units": "100000000",
            "ttl_secs": 600,
            "fee_policy": {
                "max_fee_per_gas_wei": "200",
                "max_priority_fee_per_gas_wei": "20",
                "max_total_fee_wei": "1000000"
            },
            "max_signature_count": 5,
            "reason": "test bounded payments"
        }"#;

        let err = f.handler.write(&new_p, body).await.unwrap_err();
        assert!(matches!(err, HandlerError::PermissionDenied), "{err}");
        let action_id = evm_owner_session_action_id("alice", body);
        let approval_dir = f
            .handler
            .keystore
            .root()
            .join("alice")
            .join("policy-session")
            .join(&action_id);
        std::fs::create_dir_all(&approval_dir).unwrap();
        write_json(
            approval_dir.join(APPROVAL_FILE),
            &SignedApproval {
                schema: APPROVAL_SCHEMA_V1.into(),
                wallet: "alice".into(),
                surface: "policy-session".into(),
                action_id,
                intent_hash: "evm-owner-session-intent".into(),
                petal_id: petal_identity::PETAL_ID_EVM_WALLET.into(),
                petal_digest: petal_identity::PLACEHOLDER_DIGEST_EVM_WALLET.into(),
                assurance: AssuranceLevel::Hardened,
                server_nonce: "nonce-1".into(),
                daemon_terms_digest: "1".repeat(64),
                petal_policy_digest: "2".repeat(64),
                policy_version: 0,
                expiry_ms: now_ms_u64() + 60_000,
                signer_transport: SignerTransport::BrowserWebauthn,
                credential_id: "cred-1".into(),
                review_session_id: None,
                webauthn_assertion: WebAuthnAssertionRecord {
                    credential_id: "cred-1".into(),
                    authenticator_data_b64: "AA".into(),
                    client_data_json_b64: "e30".into(),
                    signature_b64: "AA".into(),
                    user_handle_b64: None,
                },
            },
        )
        .unwrap();

        f.handler.write(&new_p, body).await.unwrap();
        let active_p = VfsPath::parse("/alice/policy-session/active.json").unwrap();
        let active: serde_json::Value =
            serde_json::from_slice(&f.handler.read(&active_p).await.unwrap()).unwrap();
        let session = active["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["session_kind"] == EVM_OWNER_SIGNING_SESSION_KIND)
            .expect("standing EVM owner session");
        let session_id = session["id"].as_str().unwrap();

        let recipient = "0000000000000000000000000000000000000002";
        let calldata = format!("0xa9059cbb{recipient:0>64}{:064x}", 1_000_000u128);
        let use_body = serde_json::json!({
            "chain_id": 31337,
            "token_contract": "0x0000000000000000000000000000000000000003",
            "recipient": "0x0000000000000000000000000000000000000002",
            "method": EVM_ERC20_TRANSFER_METHOD,
            "calldata_hex": calldata,
            "amount_base_units": "1000000",
            "value_wei": "0",
            "chain": "anvil",
            "nonce": 0,
            "gas_limit": 65000,
            "max_fee_per_gas_wei": "200",
            "max_priority_fee_per_gas_wei": "20",
            "max_total_fee_wei": "1000000"
        });
        let use_p = VfsPath::parse(&format!("/alice/policy-session/{session_id}/use")).unwrap();
        let err = f
            .handler
            .write(&use_p, serde_json::to_string(&use_body).unwrap().as_bytes())
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("Sealed Approval Petal host is not wired"),
            "{err}"
        );

        let active_after: serde_json::Value =
            serde_json::from_slice(&f.handler.read(&active_p).await.unwrap()).unwrap();
        let session_after = active_after["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == session_id)
            .unwrap();
        assert_eq!(session_after["counters"]["spent_base_units"], "0");
        assert_eq!(session_after["counters"]["reserved_base_units"], "0");
        assert_eq!(session_after["counters"]["signature_count"], 0);
    }

    #[tokio::test]
    async fn policy_session_mint_fails_closed_when_verifier_rejects() {
        let mut f = make_handler();
        f.handler = f.handler.with_auth_services(AuthServices::new(
            Some(Arc::new(RejectingVerifier)),
            None,
            Some(Arc::new(ChallengeOnlyWriter)),
        ));
        let new_p = VfsPath::parse("/alice/policy-session/new").unwrap();
        let body =
            br#"{"max_usd":10,"ttl_secs":600,"pending_ids":[{"chain_id":42161,"id":"0001-a"}]}"#;
        let action_id = policy_session_action_id("alice", body);
        let approval_dir = f
            .handler
            .keystore
            .root()
            .join("alice")
            .join("policy-session")
            .join(&action_id);
        std::fs::create_dir_all(&approval_dir).unwrap();
        write_json(
            approval_dir.join(APPROVAL_FILE),
            &SignedApproval {
                schema: APPROVAL_SCHEMA_V1.into(),
                wallet: "alice".into(),
                surface: "policy-session".into(),
                action_id: action_id.clone(),
                intent_hash: "policy-session-intent".into(),
                petal_id: petal_identity::PETAL_ID_WALLET_POLICY.into(),
                petal_digest: petal_identity::PLACEHOLDER_DIGEST_WALLET_POLICY.into(),
                assurance: AssuranceLevel::Hardened,
                server_nonce: "nonce-1".into(),
                daemon_terms_digest: "1".repeat(64),
                petal_policy_digest: "2".repeat(64),
                policy_version: 0,
                expiry_ms: now_ms_u64() + 60_000,
                signer_transport: SignerTransport::BrowserWebauthn,
                credential_id: "cred-1".into(),
                review_session_id: None,
                webauthn_assertion: WebAuthnAssertionRecord {
                    credential_id: "cred-1".into(),
                    authenticator_data_b64: "AA".into(),
                    client_data_json_b64: "e30".into(),
                    signature_b64: "AA".into(),
                    user_handle_b64: None,
                },
            },
        )
        .unwrap();

        // Verifier rejects → write must error and NO session is minted.
        let err = f.handler.write(&new_p, body).await.unwrap_err();
        assert!(
            err.to_string().contains("Sealed Approval rejected"),
            "{err}"
        );
        let sessions = f.handler.tx_engine.session_store().active(now_ms());
        assert!(
            sessions.iter().all(|s| s.wallet != "alice"),
            "no session should be minted when the verifier rejects"
        );
    }

    #[tokio::test]
    async fn capability_confirm_path_uses_real_chain_segment() {
        let mut f = make_handler();
        f.handler = f.handler.with_auth_services(AuthServices::new(
            Some(Arc::new(AcceptingVerifier)),
            None,
            Some(Arc::new(ChallengeOnlyWriter)),
        ));
        // Register arbitrum so chain-id 42161 resolves to its path segment.
        let spec = bloom_proto::ChainSpec {
            name: "arbitrum".into(),
            chain_id: 42161,
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
        f.handler
            .chains
            .add(bloom_evm::ChainClient::new(spec).unwrap());

        let new_p = VfsPath::parse("/alice/policy-session/new").unwrap();
        let body =
            br#"{"max_usd":10,"ttl_secs":600,"pending_ids":[{"chain_id":42161,"id":"0001-a"}]}"#;
        let action_id = policy_session_action_id("alice", body);
        let approval_dir = f
            .handler
            .keystore
            .root()
            .join("alice")
            .join("policy-session")
            .join(&action_id);
        std::fs::create_dir_all(&approval_dir).unwrap();
        write_json(
            approval_dir.join(APPROVAL_FILE),
            &SignedApproval {
                schema: APPROVAL_SCHEMA_V1.into(),
                wallet: "alice".into(),
                surface: "policy-session".into(),
                action_id: action_id.clone(),
                intent_hash: "policy-session-intent".into(),
                petal_id: petal_identity::PETAL_ID_WALLET_POLICY.into(),
                petal_digest: petal_identity::PLACEHOLDER_DIGEST_WALLET_POLICY.into(),
                assurance: AssuranceLevel::Hardened,
                server_nonce: "nonce-1".into(),
                daemon_terms_digest: "1".repeat(64),
                petal_policy_digest: "2".repeat(64),
                policy_version: 0,
                expiry_ms: now_ms_u64() + 60_000,
                signer_transport: SignerTransport::BrowserWebauthn,
                credential_id: "cred-1".into(),
                review_session_id: None,
                webauthn_assertion: WebAuthnAssertionRecord {
                    credential_id: "cred-1".into(),
                    authenticator_data_b64: "AA".into(),
                    client_data_json_b64: "e30".into(),
                    signature_b64: "AA".into(),
                    user_handle_b64: None,
                },
            },
        )
        .unwrap();
        f.handler.write(&new_p, body).await.unwrap();

        let views = f.handler.evm_capability_views_for("alice");
        assert_eq!(views.len(), 1);
        assert!(
            views[0].next_write_path.contains("/chains/arbitrum/"),
            "expected arbitrum segment, got {}",
            views[0].next_write_path
        );
        assert!(views[0].next_write_path.contains("0001-a"));
        assert!(!views[0].next_write_path.contains("ethereum"));
    }

    #[tokio::test]
    async fn list_sign_dir_returns_three_writable_files() {
        let f = make_handler();
        let p = VfsPath::parse(&format!("/{}/sign", f.wallet_name)).unwrap();
        let entries = f.handler.list(&p).await.unwrap();
        assert_eq!(entries.len(), 3);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"message"));
        assert!(names.contains(&"hash"));
        assert!(names.contains(&"typed_data"));
        for e in &entries {
            assert!(matches!(e.kind, crate::handler::EntryKind::File));
        }
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

    /// Helper: construct a passkey wallet on disk (no browser ceremony needed).
    /// Returns the wallet's address.
    fn seed_passkey_wallet(f: &Fixture, name: &str) -> Address {
        let info = f.handler.keystore.create_local(name, "passphrase").unwrap();
        f.handler.keystore.unlock(name, "passphrase").unwrap();
        let wallet_dir = f._tmp.path().join("keystore").join(name);
        std::fs::write(wallet_dir.join("kind"), b"passkey").unwrap();
        f.handler.keystore.sign_policy(name).unwrap();
        info.address
    }

    fn convert_wallet_to_passkey(f: &Fixture, name: &str) {
        let wallet_dir = f._tmp.path().join("keystore").join(name);
        std::fs::write(wallet_dir.join("kind"), b"passkey").unwrap();
        f.handler.keystore.sign_policy(name).unwrap();
    }

    fn wallet_policy_auth_services(f: &Fixture) -> AuthServices {
        AuthServices::new(
            Some(Arc::new(AcceptingVerifier)),
            None,
            Some(Arc::new(ChallengeOnlyWriter)),
        )
        .with_grant_store(Arc::new(UnusedGrantStore))
        .with_petal_host(Arc::new(SigningPetalHost {
            signer: f
                .handler
                .keystore
                .signer(&f.wallet_name)
                .expect("fixture local signer before passkey conversion"),
        }))
    }

    fn signed_wallet_policy_approval(challenge: &ApprovalChallenge) -> SignedApproval {
        SignedApproval {
            schema: APPROVAL_SCHEMA_V1.into(),
            wallet: challenge.wallet.clone(),
            surface: challenge.surface.clone(),
            action_id: challenge.action_id.clone(),
            intent_hash: challenge.intent_hash.clone(),
            petal_id: challenge.petal_id.clone(),
            petal_digest: challenge.petal_digest.clone(),
            assurance: challenge.assurance,
            server_nonce: challenge.server_nonce.clone(),
            daemon_terms_digest: challenge.daemon_terms_digest.clone(),
            petal_policy_digest: challenge.petal_policy_digest.clone(),
            policy_version: challenge.policy_version,
            expiry_ms: challenge.expiry_ms,
            signer_transport: SignerTransport::BrowserWebauthn,
            credential_id: "cred-1".into(),
            review_session_id: None,
            webauthn_assertion: WebAuthnAssertionRecord {
                credential_id: "cred-1".into(),
                authenticator_data_b64: "AA".into(),
                client_data_json_b64: "e30".into(),
                signature_b64: "AA".into(),
                user_handle_b64: None,
            },
        }
    }

    /// Passkey wallet: dir lists `unlock-passkey`, lookup gives writable file,
    /// and `kind` reads "passkey".
    #[tokio::test]
    async fn passkey_wallet_vfs_properties() {
        let f = make_handler();
        let _addr = seed_passkey_wallet(&f, "pk");

        // listing includes unlock-passkey
        let entries = f
            .handler
            .list(&VfsPath::parse("/pk").unwrap())
            .await
            .unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"unlock-passkey"), "names={names:?}");

        // unlock-passkey is a writable file
        let entry = f
            .handler
            .lookup(&VfsPath::parse("/pk/unlock-passkey").unwrap())
            .await
            .unwrap();
        assert!(matches!(entry.kind, crate::handler::EntryKind::File));
        assert_eq!(entry.mode, 0o644);

        // kind reads "passkey"
        let bytes = f
            .handler
            .read(&VfsPath::parse("/pk/kind").unwrap())
            .await
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&bytes).trim(), "passkey");
    }

    #[tokio::test]
    async fn unlock_passkey_write_is_noop_when_passkey_signer_is_cached() {
        let f = make_handler();
        seed_passkey_wallet(&f, "pk");
        assert!(f.handler.keystore.is_unlocked("pk"));

        f.handler
            .write(&VfsPath::parse("/pk/unlock-passkey").unwrap(), b"")
            .await
            .unwrap();

        assert!(f.handler.keystore.is_unlocked("pk"));
    }

    #[tokio::test]
    async fn wallet_policy_noop_write_does_not_stage_update() {
        let mut f = make_handler();
        let services = wallet_policy_auth_services(&f);
        convert_wallet_to_passkey(&f, "alice");
        f.handler = f.handler.with_auth_services(services);
        let (policy, _) = f.handler.keystore.raw_policy("alice").unwrap();
        let p = VfsPath::parse("/alice/policy.toml").unwrap();
        f.handler.write(&p, policy.as_bytes()).await.unwrap();
        assert!(
            !f.handler
                .keystore
                .root()
                .join("alice")
                .join("policy-updates")
                .exists(),
            "no-op policy write should not stage an approval challenge"
        );
    }

    #[tokio::test]
    async fn wallet_policy_expanding_edit_requires_hardened_sealed_approval_and_installs_signature()
    {
        let mut f = make_handler();
        let services = wallet_policy_auth_services(&f);
        convert_wallet_to_passkey(&f, "alice");
        f.handler = f.handler.with_auth_services(services);
        let (old_policy, _) = f.handler.keystore.raw_policy("alice").unwrap();
        let mut proposed: Policy = toml::from_str(&old_policy).unwrap();
        proposed.approval.agent_autonomy = Some(bloom_proto::AgentAutonomyMode::UnderPolicy);
        proposed.limits.max_tx_usd = Some("10".into());
        proposed.limits.max_day_usd = Some("100".into());
        let proposed = toml::to_string_pretty(&proposed).unwrap();
        let action_id =
            wallet_policy_action_id("alice", old_policy.as_bytes(), proposed.as_bytes());
        let p = VfsPath::parse("/alice/policy.toml").unwrap();

        let err = f.handler.write(&p, proposed.as_bytes()).await.unwrap_err();
        assert!(matches!(err, HandlerError::PermissionDenied), "{err}");
        let dir = f
            .handler
            .keystore
            .root()
            .join("alice")
            .join("policy-updates")
            .join(&action_id);
        let challenge: ApprovalChallenge = read_json(dir.join(APPROVAL_CHALLENGE_FILE)).unwrap();
        assert_eq!(challenge.surface, WALLET_POLICY_SURFACE);
        assert_eq!(challenge.assurance, AssuranceLevel::Hardened);
        let on_disk =
            std::fs::read_to_string(f.handler.keystore.root().join("alice/policy.toml")).unwrap();
        assert_eq!(on_disk, old_policy);

        write_json(
            dir.join(APPROVAL_FILE),
            &signed_wallet_policy_approval(&challenge),
        )
        .unwrap();
        f.handler.write(&p, proposed.as_bytes()).await.unwrap();
        let on_disk =
            std::fs::read_to_string(f.handler.keystore.root().join("alice/policy.toml")).unwrap();
        assert_eq!(on_disk, proposed);
        f.handler.keystore.info("alice").unwrap();
    }

    #[tokio::test]
    async fn wallet_policy_tampered_retry_bytes_do_not_reuse_approval() {
        let mut f = make_handler();
        let services = wallet_policy_auth_services(&f);
        convert_wallet_to_passkey(&f, "alice");
        f.handler = f.handler.with_auth_services(services);
        let (old_policy, _) = f.handler.keystore.raw_policy("alice").unwrap();
        let mut proposed: Policy = toml::from_str(&old_policy).unwrap();
        proposed.denylists.recipients.insert("0x1111".into());
        let proposed = toml::to_string_pretty(&proposed).unwrap();
        let mut tampered: Policy = toml::from_str(&old_policy).unwrap();
        tampered.approval.agent_autonomy = Some(bloom_proto::AgentAutonomyMode::UnderPolicy);
        tampered.limits.max_tx_usd = Some("1000".into());
        tampered.limits.max_day_usd = Some("1000".into());
        let tampered = toml::to_string_pretty(&tampered).unwrap();
        let action_id =
            wallet_policy_action_id("alice", old_policy.as_bytes(), proposed.as_bytes());
        let p = VfsPath::parse("/alice/policy.toml").unwrap();

        assert!(matches!(
            f.handler.write(&p, proposed.as_bytes()).await.unwrap_err(),
            HandlerError::PermissionDenied
        ));
        let dir = f
            .handler
            .keystore
            .root()
            .join("alice")
            .join("policy-updates")
            .join(&action_id);
        let challenge: ApprovalChallenge = read_json(dir.join(APPROVAL_CHALLENGE_FILE)).unwrap();
        write_json(
            dir.join(APPROVAL_FILE),
            &signed_wallet_policy_approval(&challenge),
        )
        .unwrap();

        assert!(matches!(
            f.handler.write(&p, tampered.as_bytes()).await.unwrap_err(),
            HandlerError::PermissionDenied
        ));
        let on_disk =
            std::fs::read_to_string(f.handler.keystore.root().join("alice/policy.toml")).unwrap();
        assert_eq!(on_disk, old_policy);

        f.handler.write(&p, proposed.as_bytes()).await.unwrap();
        let on_disk =
            std::fs::read_to_string(f.handler.keystore.root().join("alice/policy.toml")).unwrap();
        assert_eq!(on_disk, proposed);
    }

    #[tokio::test]
    async fn wallet_policy_tightening_edit_uses_standard_assurance() {
        let mut f = make_handler();
        let mut initial = Policy::default();
        initial.approval.agent_autonomy = Some(bloom_proto::AgentAutonomyMode::UnderPolicy);
        initial.limits.max_tx_usd = Some("10".into());
        initial.limits.max_day_usd = Some("100".into());
        f.handler
            .keystore
            .write_policy(
                "alice",
                toml::to_string_pretty(&initial).unwrap().as_bytes(),
            )
            .unwrap();
        let services = wallet_policy_auth_services(&f);
        convert_wallet_to_passkey(&f, "alice");
        f.handler = f.handler.with_auth_services(services);
        let (old_policy, _) = f.handler.keystore.raw_policy("alice").unwrap();
        let mut proposed: Policy = toml::from_str(&old_policy).unwrap();
        proposed.approval.assurance = AssuranceLevel::Hardened;
        proposed.limits.max_tx_usd = Some("5".into());
        proposed.denylists.recipients.insert("0x2222".into());
        let proposed = toml::to_string_pretty(&proposed).unwrap();
        let old_parsed: Policy = toml::from_str(&old_policy).unwrap();
        let proposed_parsed: Policy = toml::from_str(&proposed).unwrap();
        let action = wallet_policy_sealed_action(
            "alice",
            "/alice/policy.toml",
            old_policy.as_bytes(),
            proposed.as_bytes(),
            &old_parsed,
            &proposed_parsed,
            now_ms_u64(),
        )
        .unwrap();
        assert_eq!(action.daemon_terms.assurance, AssuranceLevel::Standard);
        let p = VfsPath::parse("/alice/policy.toml").unwrap();

        assert!(matches!(
            f.handler.write(&p, proposed.as_bytes()).await.unwrap_err(),
            HandlerError::PermissionDenied
        ));
    }

    /// Local wallet: `kind` reads "local", `unlock-passkey` is not exposed
    /// (lookup → NotFound, write → Invalid, list → absent).
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

        // writing to unlock-passkey is Invalid
        let r = f
            .handler
            .write(&VfsPath::parse("/alice/unlock-passkey").unwrap(), b"unlock")
            .await;
        assert!(matches!(r, Err(HandlerError::Invalid(_))), "got {r:?}");

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
    async fn wallet_policy_challenge_is_visible_and_secret_free_via_vfs() {
        let mut f = make_handler();
        let services = wallet_policy_auth_services(&f);
        convert_wallet_to_passkey(&f, "alice");
        f.handler = f.handler.with_auth_services(services);
        let (old_policy, _) = f.handler.keystore.raw_policy("alice").unwrap();
        let mut proposed: Policy = toml::from_str(&old_policy).unwrap();
        proposed.approval.agent_autonomy = Some(bloom_proto::AgentAutonomyMode::UnderPolicy);
        proposed.limits.max_tx_usd = Some("10".into());
        proposed.limits.max_day_usd = Some("100".into());
        let proposed = toml::to_string_pretty(&proposed).unwrap();
        let action_id =
            wallet_policy_action_id("alice", old_policy.as_bytes(), proposed.as_bytes());
        let p = VfsPath::parse("/alice/policy.toml").unwrap();
        assert!(matches!(
            f.handler.write(&p, proposed.as_bytes()).await.unwrap_err(),
            HandlerError::PermissionDenied
        ));

        // policy-updates/ lists the staged action.
        let listed = f
            .handler
            .list(&VfsPath::parse("/alice/policy-updates").unwrap())
            .await
            .unwrap();
        assert!(
            listed.iter().any(|e| e.name == action_id),
            "policy-updates listing missing action id: {listed:?}"
        );

        // The action dir advertises its readable artifacts.
        let artifacts = f
            .handler
            .list(&VfsPath::parse(&format!("/alice/policy-updates/{action_id}")).unwrap())
            .await
            .unwrap();
        let names: Vec<&str> = artifacts.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"approval_challenge.json"), "{names:?}");
        assert!(names.contains(&"status.json"), "{names:?}");

        for leaf in ["status.json", APPROVAL_CHALLENGE_FILE] {
            let entry = f
                .handler
                .lookup(
                    &VfsPath::parse(&format!("/alice/policy-updates/{action_id}/{leaf}")).unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(entry.name, leaf);
        }

        // The raw challenge parses and carries a ceremony_url.
        let challenge_bytes = f
            .handler
            .read(
                &VfsPath::parse(&format!(
                    "/alice/policy-updates/{action_id}/approval_challenge.json"
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        let challenge: ApprovalChallenge = serde_json::from_slice(&challenge_bytes).unwrap();
        assert_eq!(challenge.surface, WALLET_POLICY_SURFACE);
        assert!(
            challenge.ceremony_url.is_some(),
            "challenge should project a ceremony_url"
        );

        // status.json renders the retry guidance and the same ceremony_url.
        let status_bytes = f
            .handler
            .read(
                &VfsPath::parse(&format!("/alice/policy-updates/{action_id}/status.json")).unwrap(),
            )
            .await
            .unwrap();
        let status: serde_json::Value = serde_json::from_slice(&status_bytes).unwrap();
        assert_eq!(status["status"], "challenged");
        assert_eq!(status["write_path"], "/wallets/alice/policy.toml");
        assert!(status["ceremony_url"].is_string());

        // Approve, then confirm the signed approval is NOT reachable through the
        // mount — only bounded challenge/status views are.
        write_json(
            f.handler
                .keystore
                .root()
                .join("alice")
                .join("policy-updates")
                .join(&action_id)
                .join(APPROVAL_FILE),
            &signed_wallet_policy_approval(&challenge),
        )
        .unwrap();
        let approval_read = f
            .handler
            .read(
                &VfsPath::parse(&format!(
                    "/alice/policy-updates/{action_id}/{APPROVAL_FILE}"
                ))
                .unwrap(),
            )
            .await;
        assert!(
            approval_read.is_err(),
            "signed approval.json must not be readable via VFS"
        );
        // The challenge bytes carry no key/PRF/grant material.
        let challenge_str = String::from_utf8_lossy(&challenge_bytes);
        for needle in ["private_key", "prf", "webauthn_assertion", "signature_b64"] {
            assert!(
                !challenge_str.contains(needle),
                "challenge leaked `{needle}`: {challenge_str}"
            );
        }
    }

    #[tokio::test]
    async fn wallet_policy_update_lookup_rejects_missing_action_artifacts() {
        let f = make_handler();

        for leaf in ["status.json", APPROVAL_CHALLENGE_FILE] {
            let path = VfsPath::parse(&format!("/alice/policy-updates/missing/{leaf}")).unwrap();
            let result = f.handler.lookup(&path).await;
            assert!(
                matches!(result, Err(HandlerError::NotFound(_))),
                "lookup should reject missing action artifact {leaf}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn wallet_policy_update_lookup_requires_challenge_file() {
        let f = make_handler();
        let action_id = "policy-no-challenge";
        std::fs::create_dir_all(
            f.handler
                .keystore
                .root()
                .join("alice")
                .join("policy-updates")
                .join(action_id),
        )
        .unwrap();

        let status = f
            .handler
            .lookup(
                &VfsPath::parse(&format!("/alice/policy-updates/{action_id}/status.json")).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(status.name, "status.json");

        let challenge = f
            .handler
            .lookup(
                &VfsPath::parse(&format!(
                    "/alice/policy-updates/{action_id}/{APPROVAL_CHALLENGE_FILE}"
                ))
                .unwrap(),
            )
            .await;
        assert!(
            matches!(challenge, Err(HandlerError::NotFound(_))),
            "lookup should reject missing challenge file: {challenge:?}"
        );
    }

    /// A validly-signed on-disk policy that changes after the update is staged
    /// invalidates the prior approval: the approved retry re-derives a fresh
    /// action id (bound to the new baseline), finds no matching grant/approval,
    /// and fails closed asking for a restage — the proposed policy is not
    /// installed.
    #[tokio::test]
    async fn wallet_policy_on_disk_change_after_staging_requires_restage() {
        let mut f = make_handler();
        let services = wallet_policy_auth_services(&f);
        convert_wallet_to_passkey(&f, "alice");
        f.handler = f.handler.with_auth_services(services);
        let (old_policy, _) = f.handler.keystore.raw_policy("alice").unwrap();
        let mut proposed: Policy = toml::from_str(&old_policy).unwrap();
        proposed.denylists.recipients.insert("0x1234".into());
        let proposed = toml::to_string_pretty(&proposed).unwrap();
        let action_id =
            wallet_policy_action_id("alice", old_policy.as_bytes(), proposed.as_bytes());
        let p = VfsPath::parse("/alice/policy.toml").unwrap();

        assert!(matches!(
            f.handler.write(&p, proposed.as_bytes()).await.unwrap_err(),
            HandlerError::PermissionDenied
        ));
        let dir = f
            .handler
            .keystore
            .root()
            .join("alice")
            .join("policy-updates")
            .join(&action_id);
        let challenge: ApprovalChallenge = read_json(dir.join(APPROVAL_CHALLENGE_FILE)).unwrap();
        write_json(
            dir.join(APPROVAL_FILE),
            &signed_wallet_policy_approval(&challenge),
        )
        .unwrap();

        // Out-of-band but still validly-signed change to the current policy.
        let mut baseline_shift: Policy = toml::from_str(&old_policy).unwrap();
        baseline_shift.denylists.recipients.insert("0x9999".into());
        let baseline_shift = toml::to_string_pretty(&baseline_shift).unwrap();
        f.handler
            .keystore
            .write_policy("alice", baseline_shift.as_bytes())
            .unwrap();

        // Approved retry now re-baselines and must restage rather than install.
        assert!(matches!(
            f.handler.write(&p, proposed.as_bytes()).await.unwrap_err(),
            HandlerError::PermissionDenied
        ));
        let on_disk =
            std::fs::read_to_string(f.handler.keystore.root().join("alice/policy.toml")).unwrap();
        assert_eq!(
            on_disk, baseline_shift,
            "proposed policy must not be installed"
        );
    }

    /// A passkey wallet whose `policy.toml.sig` is already stale (out-of-band
    /// edit outside the VFS/sandbox) fails closed on the first VFS write: the
    /// signed-policy check in `info` rejects it and no repair/challenge is
    /// attempted.
    #[tokio::test]
    async fn wallet_policy_stale_signature_fails_closed_without_repair() {
        let mut f = make_handler();
        let services = wallet_policy_auth_services(&f);
        convert_wallet_to_passkey(&f, "alice");
        f.handler = f.handler.with_auth_services(services);
        let (old_policy, _) = f.handler.keystore.raw_policy("alice").unwrap();

        // Break the signed-policy invariant out of band (as a hand edit to
        // BLOOM_HOME would): mutate policy.toml but leave the old signature.
        let mut tampered: Policy = toml::from_str(&old_policy).unwrap();
        tampered.denylists.recipients.insert("0xdead".into());
        let tampered = toml::to_string_pretty(&tampered).unwrap();
        std::fs::write(
            f.handler.keystore.root().join("alice/policy.toml"),
            tampered.as_bytes(),
        )
        .unwrap();

        let mut proposed: Policy = toml::from_str(&old_policy).unwrap();
        proposed.limits.max_tx_usd = Some("5".into());
        let proposed = toml::to_string_pretty(&proposed).unwrap();
        let p = VfsPath::parse("/alice/policy.toml").unwrap();
        let err = f.handler.write(&p, proposed.as_bytes()).await.unwrap_err();
        assert!(
            !matches!(err, HandlerError::PermissionDenied),
            "stale policy must fail closed with the signed-policy error, not a challenge: {err}"
        );
        assert!(
            !f.handler
                .keystore
                .root()
                .join("alice")
                .join("policy-updates")
                .exists(),
            "stale-signature write must not stage or repair a policy update"
        );
    }

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
