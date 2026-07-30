//! Daemon library — wires the engines (keystore, chain, tx, vfs) into a
//! single runtime that can serve VFS calls. The actual NFS mount lives
//! in `bloom-mount` and is feature-gated; this library always exposes the
//! VFS via [`Daemon`] for in-process consumers like the CLI.

#![forbid(unsafe_code)]

pub mod ceremony_server;
pub mod ipc;
pub mod registration;
pub mod sealed_ceremony;
pub mod sign_hash;

mod ens_resolver;
mod price_oracle;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, U256};
use alloy::rpc::types::eth::TransactionRequest;
#[cfg(feature = "unsafe-debug-signer")]
use alloy::signers::SignerSync;
#[cfg(feature = "unsafe-debug-signer")]
use alloy::signers::local::PrivateKeySigner;
use base64::Engine as _;
use bloom_auth::{AuthStore, StoreApprovalVerifier};
use bloom_auth_api::{
    AssuranceLevel, CANONICAL_INTENT_HEADER_SCHEMA_V1, CanonicalEnvelope, CanonicalIntentHeader,
    DaemonGrantTerms, ExecutorKind, PETAL_PETAL_ID_PREFIX,
    PETAL_SIGNING_ATTESTATION_FACTS_SCHEMA_V1, PetalPolicySnapshot, PetalSigningAttestationFacts,
    PolicyCheckClass, PolicyCheckResult, SealedAction, SealedSignBatchEntry, SignHashRequest,
    signing_attestation_facts_digest,
};
use bloom_evm::{ChainClient, ChainRegistry};

use bloom_ens::EnsClient;
use bloom_etherscan::EtherscanClient;
use bloom_hyperliquid::{HyperliquidClient, HyperliquidNetwork};
use bloom_keystore::{Keystore, KeystoreApprovalSignatureVerifier};
use bloom_paid_http::PaidHttpChainRpcResolver;
use bloom_petals::abi::{
    ApprovalRequired, ChainRequest, ChainResponse, EvmOutboxInspection, EvmOutboxOutcome,
    EvmTransactionRequest, PetalRouteContext,
};
use bloom_petals::{
    HostError, HostVfsEntry, HttpRequest, HttpResponse, LateVfsHost, NameRegistry, NetPolicy,
    PetalHost, PetalRouter, PetalRunner, PetalStore, PetalVm, SignBatchOutcome, SignBatchRequest,
    SignOutcome, SignRequest,
};
use bloom_prices::PricesClient;
use bloom_proto::audit::AuditRecord;
use bloom_proto::{
    AddressBook, AuditLog, ChainSpec, Config, GasStrategy, HomeDir, HomeWritePermit, RawIntent,
    RawIntentBody,
};
use bloom_revert::{
    AbiSource, BuiltinDecoder, DecoderChain, EtherscanAbiDecoder, EtherscanAbiSource,
    OpenchainDecoder, boxed,
};
use bloom_tx::DynPriceOracle;
use bloom_tx::outbox::{CentralActionIdentity, CentralOutboxProjection, Outbox, OutboxState};
use bloom_tx::tx_engine::{Eip1559FeeOverrides, TxEngine};
use bloom_vfs::handlers::outbox::StagedPetalIdentity;
use bloom_vfs::handlers::status::{MempoolBackendStatus, PrivateRpcBackendStatus};
use bloom_vfs::handlers::{
    AddressBookHandler, CentralOutbox, ChainsHandler, DocsHandler, EnsHandler, HyperliquidHandler,
    OutboxHandler, PricesHandler, RequestsHandler, SimulateHandler, StatusHandler, ToolsHandler,
    WalletsHandler, WatchHandler,
};
use bloom_vfs::{AuthServices, PathCache, Vfs};
use bloom_watch::{WatchExecutor, WatchRegistry};
use futures::StreamExt;
use rand::RngCore;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use std::sync::Mutex;

const PETAL_HTTP_MAX_REDIRECTS: usize = 5;
const PETAL_ACTION_TTL_MS: u64 = 120_000;
const MAX_ACTIVE_PETAL_ACTION_IDENTITIES: usize = 4_096;
const PETAL_SIGNING_SUBJECT_KIND: &str = "petal_sign_hash";
const PETAL_SIGNING_SUBJECT_SCHEMA_V1: &str = "bloom.petal.sign_hash_subject.v1";
const PETAL_SIGNING_ACTION_DOMAIN: &[u8] = b"bloom.petal.sign_hash.action.v1";
const PETAL_SIGNING_BATCH_ACTION_DOMAIN: &[u8] = b"bloom.petal.sign_hash_batch.action.v1";
const MAX_PETAL_SIGN_BATCH: usize = 16;

#[derive(Clone)]
struct PetalActionIdentity {
    action_id: String,
    expires_ms: u64,
}

#[derive(Default)]
struct PetalActionIdentityCache {
    entries: std::collections::HashMap<[u8; 32], PetalActionIdentity>,
}

impl PetalActionIdentityCache {
    /// Keep one request identity for the challenge's complete live interval.
    /// Expiry remains part of the action id, so the same scoped request gets a
    /// fresh identity in its next lifecycle and cannot revive an old grant.
    /// The fixed capacity fails closed rather than evicting a live approval.
    fn resolve(
        &mut self,
        domain: &[u8],
        action_id_prefix: &str,
        fingerprint: &[u8],
        now_ms: u64,
    ) -> Result<PetalActionIdentity, HostError> {
        self.entries
            .retain(|_, identity| identity.expires_ms > now_ms);

        let mut request_hasher = blake3::Hasher::new();
        request_hasher.update(domain);
        request_hasher.update(fingerprint);
        let request_key = *request_hasher.finalize().as_bytes();
        if let Some(identity) = self.entries.get(&request_key) {
            return Ok(identity.clone());
        }
        if self.entries.len() >= MAX_ACTIVE_PETAL_ACTION_IDENTITIES {
            return Err(HostError::Backend(
                "too many active petal signing approval identities".into(),
            ));
        }

        let expires_ms = now_ms
            .checked_add(PETAL_ACTION_TTL_MS)
            .ok_or_else(|| HostError::Backend("petal action expiry overflow".into()))?;
        let mut action_hasher = blake3::Hasher::new();
        action_hasher.update(domain);
        action_hasher.update(fingerprint);
        action_hasher.update(&expires_ms.to_be_bytes());
        let identity = PetalActionIdentity {
            action_id: format!("{action_id_prefix}{}", action_hasher.finalize().to_hex()),
            expires_ms,
        };
        self.entries.insert(request_key, identity.clone());
        Ok(identity)
    }
}

/// Concrete adapter that bridges [`CentralOutbox`] (filesystem) and
/// [`AuthStore`] (action_id_map) to satisfy [`CentralOutboxProjection`]
/// for the EVM tx-engine outbox.
struct EvmOutboxProjection {
    central: CentralOutbox,
    auth: Mutex<AuthStore>,
}

impl EvmOutboxProjection {
    fn new(central: CentralOutbox, auth: AuthStore) -> Self {
        Self {
            central,
            auth: Mutex::new(auth),
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
        let mut auth = self.auth.lock().map_err(|e| e.to_string())?;
        auth.allocate_action_id(surface, venue_local_id, wallet, staged_at_ms)
            .map_err(|e| e.to_string())
    }

    fn stage_action(
        &self,
        action_id: &str,
        intent_json: &[u8],
        plan_md: &str,
        policy_check_json: &[u8],
        identity: CentralActionIdentity<'_>,
    ) -> Result<(), String> {
        let intent_hash = bloom_auth_api::intent_hash_of(intent_json);
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
    #[error("keystore: {0}")]
    Keystore(String),
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
    auth_services: AuthServices,
    tx_outbox: Option<PetalTxOutbox>,
    tx_stage_lock: tokio::sync::Mutex<()>,
    sign_batch_lock: tokio::sync::Mutex<()>,
    petal_action_identities: Mutex<PetalActionIdentityCache>,
    #[cfg(feature = "unsafe-debug-signer")]
    unsafe_debug_signer: Option<(String, Arc<PrivateKeySigner>)>,
}

#[derive(Clone)]
struct PetalTxOutbox {
    tx_engine: TxEngine,
    chains: ChainRegistry,
    keystore: Keystore,
    address_book: Arc<AddressBook>,
    write_permit: Option<Arc<HomeWritePermit>>,
}

impl DaemonPetalHost {
    fn new(vfs: Arc<LateVfsHost>, audit: Arc<AuditLog>, auth_services: AuthServices) -> Self {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .build()
            .expect("daemon petal http client must build");
        Self {
            vfs,
            http,
            audit,
            auth_services,
            tx_outbox: None,
            tx_stage_lock: tokio::sync::Mutex::new(()),
            sign_batch_lock: tokio::sync::Mutex::new(()),
            petal_action_identities: Mutex::new(PetalActionIdentityCache::default()),
            #[cfg(feature = "unsafe-debug-signer")]
            unsafe_debug_signer: None,
        }
    }

    fn with_tx_outbox(mut self, tx_outbox: PetalTxOutbox) -> Self {
        self.tx_outbox = Some(tx_outbox);
        self
    }

    #[cfg(feature = "unsafe-debug-signer")]
    fn with_unsafe_debug_signer(mut self, wallet: String, signer: Arc<PrivateKeySigner>) -> Self {
        self.unsafe_debug_signer = Some((wallet, signer));
        self
    }

    #[cfg(feature = "unsafe-debug-signer")]
    fn unsafe_debug_signer(&self, wallet: &str) -> Option<&Arc<PrivateKeySigner>> {
        self.unsafe_debug_signer
            .as_ref()
            .filter(|(configured, _)| configured == wallet)
            .map(|(_, signer)| signer)
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
            petal_id: format!("{PETAL_PETAL_ID_PREFIX}{}", context.petal_root),
            petal_digest: context.package_hash.clone(),
            petal_version: "v1-package".into(),
        })
    }

    fn validate_petal_signing_scope(
        req: &SignRequest,
        context: &PetalRouteContext,
    ) -> Result<std::collections::BTreeMap<String, String>, HostError> {
        if req.wallet.trim().is_empty() || req.purpose.trim().is_empty() {
            return Err(HostError::Invalid(
                "sign-hash wallet and intent must be non-empty".into(),
            ));
        }
        if context.petal_root.trim().is_empty()
            || context.route_id.trim().is_empty()
            || !bloom_petals::store::is_valid_hex_hash(&context.package_hash)
        {
            return Err(HostError::Invalid(
                "trusted Petal route context is incomplete or has an invalid package hash".into(),
            ));
        }
        if !matches!(context.op.as_str(), "lookup" | "list" | "read" | "write") {
            return Err(HostError::Invalid(
                "trusted Petal route context has an invalid operation".into(),
            ));
        }
        let mut params = std::collections::BTreeMap::new();
        for (key, value) in &context.params {
            if params.insert(key.clone(), value.clone()).is_some() {
                return Err(HostError::Invalid(
                    "trusted Petal route context has duplicate parameter names".into(),
                ));
            }
        }
        Ok(params)
    }

    fn petal_action(
        &self,
        req: &SignRequest,
        context: &PetalRouteContext,
        now_ms: u64,
    ) -> Result<(SealedAction, bloom_auth_api::SigningAttestation), HostError> {
        self.petal_action_with_identity(req, context, now_ms, None)
    }

    fn petal_action_with_identity(
        &self,
        req: &SignRequest,
        context: &PetalRouteContext,
        now_ms: u64,
        identity: Option<&PetalActionIdentity>,
    ) -> Result<(SealedAction, bloom_auth_api::SigningAttestation), HostError> {
        let params = Self::validate_petal_signing_scope(req, context)?;

        let hash_hex = format!("0x{}", hex::encode(req.hash32));
        let fingerprint = serde_json::to_vec(&serde_json::json!({
            "wallet": req.wallet,
            "hash_hex": hash_hex,
            "intent": req.purpose,
            "petal_root": context.petal_root,
            "package_hash": context.package_hash,
            "route_id": context.route_id,
            "op": context.op,
            "path": context.path,
            "params": params,
            "actor": context.actor,
        }))
        .map_err(|e| HostError::Backend(format!("encode petal action fingerprint: {e}")))?;
        let identity = match identity {
            Some(identity) => identity.clone(),
            None => self
                .petal_action_identities
                .lock()
                .map_err(|e| HostError::Backend(format!("lock petal action identities: {e}")))?
                .resolve(
                    PETAL_SIGNING_ACTION_DOMAIN,
                    "appsign-",
                    &fingerprint,
                    now_ms,
                )?,
        };
        let action_id = identity.action_id;
        let expires_ms = identity.expires_ms;
        let petal_id = format!("{PETAL_PETAL_ID_PREFIX}{}", context.petal_root);
        let header = CanonicalIntentHeader {
            schema: CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
            wallet: req.wallet.clone(),
            surface: "petals".into(),
            action_id: action_id.clone(),
            petal_id: petal_id.clone(),
            petal_digest: context.package_hash.clone(),
            petal_version: "v1-package".into(),
            executor_kind: ExecutorKind::Wasm,
            network: "local".into(),
            account: req.wallet.clone(),
            action_kind: "petal.sign_hash".into(),
            value_movement: true,
            authority_change: true,
            expires_ms,
        };
        let mut terms = DaemonGrantTerms::minimal(AssuranceLevel::Standard);
        terms.max_ttl_secs = PETAL_ACTION_TTL_MS / 1_000;
        terms.max_signatures = 1;
        terms.allowed_sign_intents = vec![req.purpose.clone()];
        terms.extra.insert(
            "required.signing_hash".into(),
            serde_json::Value::String(hash_hex.clone()),
        );

        let mut snapshot = PetalPolicySnapshot::minimal(&header);
        snapshot.config.insert(
            "petal_root".into(),
            serde_json::Value::String(context.petal_root.clone()),
        );
        snapshot.config.insert(
            "package_hash".into(),
            serde_json::Value::String(context.package_hash.clone()),
        );
        snapshot.config.insert(
            "route_id".into(),
            serde_json::Value::String(context.route_id.clone()),
        );
        let policy_snapshot_digest = snapshot
            .petal_policy_digest()
            .map_err(|e| HostError::Backend(format!("digest petal policy snapshot: {e}")))?;
        let facts = PetalSigningAttestationFacts {
            facts_schema: PETAL_SIGNING_ATTESTATION_FACTS_SCHEMA_V1.into(),
            action_id,
            wallet: req.wallet.clone(),
            surface: "petals".into(),
            petal_id,
            petal_digest: context.package_hash.clone(),
            petal_version: "v1-package".into(),
            petal_root: context.petal_root.clone(),
            package_hash: context.package_hash.clone(),
            route_id: context.route_id.clone(),
            op: context.op.clone(),
            path: context.path.clone(),
            params,
            actor: context.actor.clone(),
            intent: req.purpose.clone(),
            signing_hash: hash_hex,
            policy_snapshot_digest,
        };
        let facts_map = facts
            .to_facts_map()
            .map_err(|e| HostError::Backend(format!("encode petal signing facts: {e}")))?;
        let facts_digest = signing_attestation_facts_digest(&facts_map)
            .map_err(|e| HostError::Backend(format!("digest petal signing facts: {e}")))?;
        terms.extra.insert(
            "required.attestation_facts_digest".into(),
            serde_json::Value::String(facts_digest),
        );
        let attestation = facts
            .signing_attestation()
            .map_err(|e| HostError::Backend(format!("build petal signing attestation: {e}")))?;
        let subject = serde_json::to_vec(&facts)
            .map_err(|e| HostError::Backend(format!("encode petal signing subject: {e}")))?;
        let envelope = CanonicalEnvelope::new(
            header,
            PETAL_SIGNING_SUBJECT_KIND,
            PETAL_SIGNING_SUBJECT_SCHEMA_V1,
            subject,
        );
        let plan = format!(
            "# Approve Petal signature\n\nPetal: `{}`\nPackage: `{}`\nRoute: `{}` {} `{}`\nWallet: `{}`\nIntent: `{}`\nHash: `{}`\n",
            context.petal_root,
            context.package_hash,
            context.route_id,
            context.op,
            context.path,
            req.wallet,
            req.purpose,
            attestation
                .facts
                .get("signing_hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
        );
        let action = SealedAction::new(
            envelope,
            plan,
            vec![PolicyCheckResult {
                rule_id: "petal.route_provenance".into(),
                rule_class: PolicyCheckClass::Informational,
                outcome: "pass".into(),
                message: "signature request is bound to the resolved Petal package and route"
                    .into(),
                step_up_ceiling: None,
            }],
            terms,
            snapshot,
            now_ms,
        )
        .map_err(|e| HostError::Backend(format!("seal petal signing action: {e}")))?;
        Ok((action, attestation))
    }

    fn petal_batch_action(
        &self,
        requests: &[SignRequest],
        now_ms: u64,
    ) -> Result<(SealedAction, Vec<bloom_auth_api::SigningAttestation>), HostError> {
        if requests.is_empty() || requests.len() > MAX_PETAL_SIGN_BATCH {
            return Err(HostError::Invalid(format!(
                "petal signing batch requires 1..={MAX_PETAL_SIGN_BATCH} requests"
            )));
        }
        let first_context = requests[0].context.as_ref().ok_or_else(|| {
            HostError::Denied("signing batch requires trusted Petal route context".into())
        })?;
        let first_wallet = requests[0].wallet.as_str();
        let mut seen = std::collections::BTreeSet::new();
        for request in requests {
            if request.wallet != first_wallet || request.context.as_ref() != Some(first_context) {
                return Err(HostError::Invalid(
                    "signing batch entries must share one wallet and trusted route context".into(),
                ));
            }
            let tuple = (
                request.wallet.clone(),
                request.hash32,
                request.purpose.clone(),
            );
            if !seen.insert(tuple) {
                return Err(HostError::Invalid(
                    "signing batch contains a duplicate wallet/hash/intent entry".into(),
                ));
            }
            Self::validate_petal_signing_scope(request, first_context)?;
        }

        let params = Self::validate_petal_signing_scope(&requests[0], first_context)?;
        let request_fingerprint: Vec<_> = requests
            .iter()
            .map(|request| {
                serde_json::json!({
                    "wallet": request.wallet,
                    "hash_hex": format!("0x{}", hex::encode(request.hash32)),
                    "intent": request.purpose,
                })
            })
            .collect();
        let fingerprint = serde_json::to_vec(&serde_json::json!({
            "requests": request_fingerprint,
            "petal_root": first_context.petal_root,
            "package_hash": first_context.package_hash,
            "route_id": first_context.route_id,
            "op": first_context.op,
            "path": first_context.path,
            "params": params,
            "actor": first_context.actor,
        }))
        .map_err(|e| HostError::Backend(format!("encode petal batch fingerprint: {e}")))?;
        let identity = self
            .petal_action_identities
            .lock()
            .map_err(|e| HostError::Backend(format!("lock petal action identities: {e}")))?
            .resolve(
                PETAL_SIGNING_BATCH_ACTION_DOMAIN,
                "appsign-batch-",
                &fingerprint,
                now_ms,
            )?;
        let action_id = identity.action_id.clone();
        let expires_ms = identity.expires_ms;

        let mut individual = Vec::with_capacity(requests.len());
        for request in requests {
            individual.push(self.petal_action_with_identity(
                request,
                first_context,
                now_ms,
                Some(&identity),
            )?);
        }

        let mut attestations = Vec::with_capacity(individual.len());
        let mut entries = Vec::with_capacity(individual.len());
        for ((_, attestation), request) in individual.into_iter().zip(requests) {
            let mut facts = PetalSigningAttestationFacts::from_attestation(&attestation)
                .map_err(|e| HostError::Backend(format!("decode petal attestation: {e}")))?;
            facts.action_id = action_id.clone();
            let attestation = facts
                .signing_attestation()
                .map_err(|e| HostError::Backend(format!("build batch attestation: {e}")))?;
            entries.push(SealedSignBatchEntry {
                wallet: request.wallet.clone(),
                intent: request.purpose.clone(),
                hash_hex: format!("0x{}", hex::encode(request.hash32)),
                attestation_facts_digest: signing_attestation_facts_digest(&attestation.facts)
                    .map_err(|e| HostError::Backend(format!("digest batch attestation: {e}")))?,
            });
            attestations.push(attestation);
        }

        let petal_id = format!("{PETAL_PETAL_ID_PREFIX}{}", first_context.petal_root);
        let header = CanonicalIntentHeader {
            schema: CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
            wallet: first_wallet.into(),
            surface: "petals".into(),
            action_id: action_id.clone(),
            petal_id,
            petal_digest: first_context.package_hash.clone(),
            petal_version: "v1-package".into(),
            executor_kind: ExecutorKind::Wasm,
            network: "local".into(),
            account: first_wallet.into(),
            action_kind: "petal.sign_hash_batch".into(),
            value_movement: true,
            authority_change: true,
            expires_ms,
        };
        let mut terms = DaemonGrantTerms::minimal(AssuranceLevel::Hardened);
        terms.max_ttl_secs = PETAL_ACTION_TTL_MS / 1_000;
        terms.max_signatures = u32::try_from(entries.len())
            .map_err(|_| HostError::Invalid("signing batch is too large".into()))?;
        terms.allowed_sign_intents = requests
            .iter()
            .map(|request| request.purpose.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        terms.extra.insert(
            "required.signing_requests".into(),
            serde_json::to_value(&entries)
                .map_err(|e| HostError::Backend(format!("encode sealed signing batch: {e}")))?,
        );
        let mut snapshot = PetalPolicySnapshot::minimal(&header);
        snapshot.config.insert(
            "petal_root".into(),
            serde_json::Value::String(first_context.petal_root.clone()),
        );
        snapshot.config.insert(
            "package_hash".into(),
            serde_json::Value::String(first_context.package_hash.clone()),
        );
        snapshot.config.insert(
            "route_id".into(),
            serde_json::Value::String(first_context.route_id.clone()),
        );
        let subject = serde_json::to_vec(&serde_json::json!({
            "action_id": action_id,
            "requests": entries,
        }))
        .map_err(|e| HostError::Backend(format!("encode petal batch subject: {e}")))?;
        let plan_entries = requests
            .iter()
            .enumerate()
            .map(|(index, request)| {
                format!(
                    "{}. intent `{}`; hash `0x{}`",
                    index + 1,
                    request.purpose,
                    hex::encode(request.hash32)
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let action = SealedAction::new(
            CanonicalEnvelope::new(
                header,
                "petal_sign_hash_batch",
                "bloom.petal.sign_hash_batch_subject.v1",
                subject,
            ),
            format!(
                "# Approve Petal signature batch\n\nPetal: `{}`\nPackage: `{}`\nRoute: `{}` {} `{}`\nWallet: `{}`\n\n{}\n",
                first_context.petal_root,
                first_context.package_hash,
                first_context.route_id,
                first_context.op,
                first_context.path,
                first_wallet,
                plan_entries,
            ),
            vec![PolicyCheckResult {
                rule_id: "petal.route_provenance".into(),
                rule_class: PolicyCheckClass::Informational,
                outcome: "pass".into(),
                message: "ordered signature batch is bound to the resolved Petal package and route".into(),
                step_up_ceiling: None,
            }],
            terms,
            snapshot,
            now_ms,
        )
        .map_err(|e| HostError::Backend(format!("seal petal signing batch: {e}")))?;
        Ok((action, attestations))
    }

    fn audit_http_fetch(
        &self,
        method: &str,
        url: &str,
        outcome: &str,
        status: Option<u16>,
        body_len: Option<usize>,
        error: Option<&str>,
    ) {
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
        if let Err(e) = self.audit.append(AuditRecord {
            ts_ms: 0,
            kind: "petal.http_fetch".into(),
            wallet: None,
            chain: None,
            data,
            prev: String::new(),
            digest: String::new(),
        }) {
            warn!(error = %e, "petal.http_fetch.audit_append_failed");
        }
    }

    fn audit_sign_hash(&self, req: &SignRequest, outcome: &str, error: Option<&str>) {
        let mut data = serde_json::json!({
            "purpose": req.purpose.as_str(),
            "hash32": hex::encode(req.hash32),
            "outcome": outcome,
        });
        if let Some(error) = error {
            data["error"] = serde_json::json!(error);
        }
        if let Err(e) = self.audit.append(AuditRecord {
            ts_ms: 0,
            kind: "petal.sign_hash".into(),
            wallet: Some(req.wallet.clone()),
            chain: None,
            data,
            prev: String::new(),
            digest: String::new(),
        }) {
            warn!(wallet = %req.wallet, error = %e, "petal.sign_hash.audit_append_failed");
        }
    }
}

#[async_trait::async_trait]
impl PetalHost for DaemonPetalHost {
    async fn vfs_lookup(&self, path: &str) -> Result<HostVfsEntry, HostError> {
        self.vfs.vfs_lookup(path).await
    }

    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
        self.vfs.vfs_read(path).await
    }

    async fn vfs_list(&self, path: &str) -> Result<Vec<HostVfsEntry>, HostError> {
        self.vfs.vfs_list(path).await
    }

    async fn vfs_write(&self, path: &str, bytes: &[u8]) -> Result<(), HostError> {
        self.vfs.vfs_write(path, bytes).await
    }

    async fn http_fetch(
        &self,
        req: HttpRequest,
        policy: NetPolicy,
        max_response_bytes: usize,
    ) -> Result<HttpResponse, HostError> {
        let mut method = req.method;
        let mut url = req.url;
        let mut body = req.body;
        let mut headers = req.headers;
        for redirect_count in 0..=PETAL_HTTP_MAX_REDIRECTS {
            if let Err(e) = policy.check(&method, &url) {
                self.audit_http_fetch(&method, &url, "denied", None, None, Some(&e.to_string()));
                return Err(e);
            }
            let reqwest_method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| {
                let err = HostError::Invalid(format!("http method: {e}"));
                self.audit_http_fetch(&method, &url, "error", None, None, Some(&err.to_string()));
                err
            })?;
            let mut builder = self.http.request(reqwest_method, &url);
            for (name, value) in &headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            let resp = builder.body(body.clone()).send().await.map_err(|e| {
                let err = HostError::Backend(format!("http_fetch send: {e}"));
                self.audit_http_fetch(&method, &url, "error", None, None, Some(&err.to_string()));
                err
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
                    self.audit_http_fetch(
                        &method,
                        &url,
                        "error",
                        Some(status),
                        None,
                        Some(&err.to_string()),
                    );
                    return Err(err);
                };
                if redirect_count == PETAL_HTTP_MAX_REDIRECTS {
                    let err = HostError::Backend("http redirect limit exceeded".into());
                    self.audit_http_fetch(
                        &method,
                        &url,
                        "error",
                        Some(status),
                        None,
                        Some(&err.to_string()),
                    );
                    return Err(err);
                }
                let next_url = match resolve_redirect_target(&url, &location) {
                    Ok(url) => url,
                    Err(e) => {
                        self.audit_http_fetch(
                            &method,
                            &url,
                            "error",
                            Some(status),
                            None,
                            Some(&e.to_string()),
                        );
                        return Err(e);
                    }
                };
                let next_method = redirect_method(&method, status);
                if let Err(e) = policy.check(&next_method, &next_url) {
                    self.audit_http_fetch(
                        &method,
                        &url,
                        "denied_redirect",
                        Some(status),
                        None,
                        Some(&e.to_string()),
                    );
                    return Err(e);
                }
                if let Err(e) =
                    prepare_redirect_request(&url, &next_url, &next_method, &mut headers, &mut body)
                {
                    self.audit_http_fetch(
                        &method,
                        &url,
                        "denied_redirect",
                        Some(status),
                        None,
                        Some(&e.to_string()),
                    );
                    return Err(e);
                }
                self.audit_http_fetch(&method, &url, "redirect", Some(status), None, None);
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
                self.audit_http_fetch(
                    &method,
                    &url,
                    "error",
                    Some(status),
                    None,
                    Some(&err.to_string()),
                );
                return Err(err);
            }
            let mut body = Vec::new();
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| {
                    let err = HostError::Backend(format!("http_fetch body: {e}"));
                    self.audit_http_fetch(
                        &method,
                        &url,
                        "error",
                        Some(status),
                        Some(body.len()),
                        Some(&err.to_string()),
                    );
                    err
                })?;
                if body.len().saturating_add(chunk.len()) > max_response_bytes {
                    let err = HostError::Backend("http response too large".into());
                    self.audit_http_fetch(
                        &method,
                        &url,
                        "error",
                        Some(status),
                        Some(body.len().saturating_add(chunk.len())),
                        Some(&err.to_string()),
                    );
                    return Err(err);
                }
                body.extend_from_slice(&chunk);
            }
            self.audit_http_fetch(&method, &url, "ok", Some(status), Some(body.len()), None);
            return Ok(HttpResponse {
                status,
                headers,
                body,
            });
        }
        unreachable!("bounded redirect loop returns before exhausting iterator")
    }

    async fn sign_hash(&self, req: SignRequest) -> Result<Vec<u8>, HostError> {
        match self.sign_hash_outcome(req).await? {
            SignOutcome::Signature(signature) => Ok(signature),
            SignOutcome::ApprovalRequired(approval) => Err(HostError::Denied(format!(
                "Sealed Approval required for Petal sign_hash; action_id={}; ceremony_url={}",
                approval.action_id, approval.ceremony_url
            ))),
        }
    }

    async fn sign_hash_outcome(&self, req: SignRequest) -> Result<SignOutcome, HostError> {
        let Some(context) = req.context.as_ref() else {
            let err = HostError::Denied(
                "Petal sign_hash requires trusted Petal route context and a Sealed Approval grant"
                    .into(),
            );
            self.audit_sign_hash(&req, "denied", Some(&err.to_string()));
            return Err(err);
        };
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        let (action, attestation) = match self.petal_action(&req, context, now_ms) {
            Ok(value) => value,
            Err(err) => {
                self.audit_sign_hash(&req, "denied", Some(&err.to_string()));
                return Err(err);
            }
        };
        #[cfg(feature = "unsafe-debug-signer")]
        if let Some(signer) = self.unsafe_debug_signer(&req.wallet) {
            tracing::warn!(
                wallet = %req.wallet,
                action_id = %action.action_id(),
                "petal.unsafe_debug_signing_bypass"
            );
            let signature = signer
                .sign_hash_sync(&alloy::primitives::B256::from(req.hash32))
                .map_err(|e| HostError::Backend(format!("debug sign hash: {e}")))?
                .as_bytes()
                .to_vec();
            self.audit_sign_hash(&req, "unsafe_debug_ok", None);
            return Ok(SignOutcome::Signature(signature));
        }
        let active_grant = self
            .auth_services
            .require_grant_store()
            .map_err(|e| HostError::Backend(e.to_string()))?
            .get_active(
                &req.wallet,
                action.action_id(),
                action.petal_id(),
                action.petal_digest(),
                now_ms,
            )
            .await
            .map_err(|e| HostError::Backend(format!("lookup petal sealed grant: {e}")))?;
        if active_grant.is_none() {
            let writer = self
                .auth_services
                .require_writer()
                .map_err(|e| HostError::Backend(e.to_string()))?;
            writer
                .stage_action(action.clone(), now_ms)
                .await
                .map_err(|e| HostError::Backend(format!("stage petal sealed action: {e}")))?;
            let mut nonce = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let challenge = writer
                .issue_challenge(
                    action.surface(),
                    action.action_id(),
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce),
                    action.expires_ms,
                    now_ms,
                )
                .await
                .map_err(|e| HostError::Backend(format!("issue petal approval challenge: {e}")))?
                .with_local_ceremony_url();
            let ceremony_url = challenge
                .ceremony_url
                .unwrap_or_else(|| "unavailable".into());
            let approval = SignOutcome::ApprovalRequired(ApprovalRequired {
                action_id: action.action_id().to_string(),
                ceremony_url,
                expires_ms: action.expires_ms,
            });
            self.audit_sign_hash(&req, "approval_required", None);
            return Ok(approval);
        }

        let signature = self
            .auth_services
            .require_petal_host()
            .map_err(|e| HostError::Backend(e.to_string()))?
            .sign_hash(
                SignHashRequest {
                    wallet: req.wallet.clone(),
                    action_id: action.action_id().to_string(),
                    intent: req.purpose.clone(),
                    hash_hex: format!("0x{}", hex::encode(req.hash32)),
                },
                &attestation,
                now_ms,
            )
            .await
            .map_err(|e| HostError::Denied(format!("petal sealed signing denied: {e}")))?;
        let signature = base64::engine::general_purpose::STANDARD
            .decode(signature.signature_b64)
            .map_err(|e| HostError::Backend(format!("decode petal signature: {e}")))?;
        if signature.len() != 65 {
            let err = HostError::Backend("petal signer returned a non-65-byte signature".into());
            self.audit_sign_hash(&req, "error", Some(&err.to_string()));
            return Err(err);
        }
        self.audit_sign_hash(&req, "ok", None);
        Ok(SignOutcome::Signature(signature))
    }

    async fn sign_hashes_outcome(
        &self,
        req: SignBatchRequest,
    ) -> Result<SignBatchOutcome, HostError> {
        let _guard = self.sign_batch_lock.lock().await;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        let (action, attestations) = self.petal_batch_action(&req.requests, now_ms)?;
        #[cfg(feature = "unsafe-debug-signer")]
        if let Some(signer) = self.unsafe_debug_signer(action.wallet()) {
            tracing::warn!(
                wallet = %action.wallet(),
                action_id = %action.action_id(),
                count = req.requests.len(),
                "petal.unsafe_debug_batch_signing_bypass"
            );
            let mut signatures = Vec::with_capacity(req.requests.len());
            for request in &req.requests {
                signatures.push(
                    signer
                        .sign_hash_sync(&alloy::primitives::B256::from(request.hash32))
                        .map_err(|e| HostError::Backend(format!("debug batch sign hash: {e}")))?
                        .as_bytes()
                        .to_vec(),
                );
            }
            return Ok(SignBatchOutcome::Signatures(signatures));
        }
        let active_grant = self
            .auth_services
            .require_grant_store()
            .map_err(|e| HostError::Backend(e.to_string()))?
            .get_active(
                action.wallet(),
                action.action_id(),
                action.petal_id(),
                action.petal_digest(),
                now_ms,
            )
            .await
            .map_err(|e| HostError::Backend(format!("lookup petal batch grant: {e}")))?;
        if active_grant.is_none() {
            let writer = self
                .auth_services
                .require_writer()
                .map_err(|e| HostError::Backend(e.to_string()))?;
            writer
                .stage_action(action.clone(), now_ms)
                .await
                .map_err(|e| HostError::Backend(format!("stage petal signing batch: {e}")))?;
            let mut nonce = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let challenge = writer
                .issue_challenge(
                    action.surface(),
                    action.action_id(),
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce),
                    action.expires_ms,
                    now_ms,
                )
                .await
                .map_err(|e| HostError::Backend(format!("issue batch challenge: {e}")))?
                .with_local_ceremony_url();
            return Ok(SignBatchOutcome::ApprovalRequired(ApprovalRequired {
                action_id: action.action_id().into(),
                ceremony_url: challenge
                    .ceremony_url
                    .unwrap_or_else(|| "unavailable".into()),
                expires_ms: action.expires_ms,
            }));
        }

        let requests = req
            .requests
            .iter()
            .map(|request| SignHashRequest {
                wallet: request.wallet.clone(),
                action_id: action.action_id().into(),
                intent: request.purpose.clone(),
                hash_hex: format!("0x{}", hex::encode(request.hash32)),
            })
            .collect();
        let sealed = self
            .auth_services
            .require_petal_host()
            .map_err(|e| HostError::Backend(e.to_string()))?
            .sign_hash_batch(requests, &attestations, now_ms)
            .await
            .map_err(|e| HostError::Denied(format!("petal sealed batch signing denied: {e}")))?;
        let mut signatures = Vec::with_capacity(sealed.len());
        for signature in sealed {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(signature.signature_b64)
                .map_err(|e| HostError::Backend(format!("decode batch signature: {e}")))?;
            if bytes.len() != 65 {
                return Err(HostError::Backend(
                    "petal batch signer returned a non-65-byte signature".into(),
                ));
            }
            signatures.push(bytes);
        }
        Ok(SignBatchOutcome::Signatures(signatures))
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
        let wallet = service
            .keystore
            .info(&req.wallet)
            .map_err(|e| HostError::Invalid(format!("wallet: {e}")))?;
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
                wallet.address,
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
                &wallet.policy,
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
        let wallet_info = service
            .keystore
            .info(&wallet)
            .map_err(|e| HostError::Invalid(format!("wallet: {e}")))?;
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
                &wallet_info.policy,
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

/// All wired-up state the daemon owns. Cheap to clone (everything is
/// behind Arc/clone-safe inner types).
#[derive(Clone)]
pub struct Daemon {
    pub home: HomeDir,
    pub config: Config,
    pub chains: ChainRegistry,
    pub keystore: Keystore,
    pub tx_engine: TxEngine,
    pub home_write_permit: Option<Arc<HomeWritePermit>>,
    pub address_book: Arc<AddressBook>,
    pub audit: Arc<AuditLog>,
    pub auth_services: AuthServices,
    pub signer_cache: Arc<bloom_keystore::petal_host::SignerCache>,
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
}

impl Daemon {
    /// Build a fully-wired daemon from the home directory, materialising
    /// any missing subdirs as needed.
    pub fn from_home(home: HomeDir) -> Result<Self, DaemonError> {
        Self::from_home_inner(home, None)
    }

    /// Build a daemon with a held home write permit. VFS write surfaces use
    /// this permit for TxEngine mutations; callers that omit it get a daemon
    /// suitable for reads/tests but not outbox writes.
    pub fn from_home_with_permit(
        home: HomeDir,
        permit: Arc<HomeWritePermit>,
    ) -> Result<Self, DaemonError> {
        Self::from_home_inner(home, Some(permit))
    }

    fn from_home_inner(
        home: HomeDir,
        home_write_permit: Option<Arc<HomeWritePermit>>,
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

        let keystore =
            Keystore::new(home.keystore_dir()).map_err(|e| DaemonError::Keystore(e.to_string()))?;

        #[cfg(feature = "unsafe-debug-signer")]
        let unsafe_debug_signer = match (
            std::env::var("BLOOM_UNSAFE_DEBUG_SIGNER_WALLET").ok(),
            std::env::var("BLOOM_UNSAFE_DEBUG_PRIVATE_KEY_FILE").ok(),
        ) {
            (Some(wallet), Some(path)) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
                    if mode != 0o600 {
                        return Err(DaemonError::Keystore(format!(
                            "unsafe debug private-key file must have mode 0600, got {mode:04o}"
                        )));
                    }
                }
                let key = std::fs::read_to_string(&path)?;
                let signer: PrivateKeySigner = key.trim().parse().map_err(|e| {
                    DaemonError::Keystore(format!("parse unsafe debug private key: {e}"))
                })?;
                let expected = keystore
                    .info(&wallet)
                    .map_err(|e| DaemonError::Keystore(e.to_string()))?
                    .address;
                if signer.address() != expected {
                    return Err(DaemonError::Keystore(format!(
                        "unsafe debug signer address {} does not match wallet {wallet} ({expected})",
                        signer.address()
                    )));
                }
                let signer = Arc::new(signer);
                keystore
                    .install_unsafe_debug_signer(&wallet, signer.clone())
                    .map_err(|e| DaemonError::Keystore(e.to_string()))?;
                warn!(
                    wallet = %wallet,
                    address = %expected,
                    "UNSAFE DEBUG SIGNER ENABLED: interactive approval ceremonies are bypassed"
                );
                Some((wallet, signer))
            }
            (None, None) => None,
            _ => {
                return Err(DaemonError::Keystore(
                    "BLOOM_UNSAFE_DEBUG_SIGNER_WALLET and BLOOM_UNSAFE_DEBUG_PRIVATE_KEY_FILE must be set together"
                        .into(),
                ));
            }
        };

        // Open auth store early so we can also wire the EVM → central
        // outbox projection.  Two connections to the same SQLite file:
        // one for the verifier (owned), one for the projection (behind
        // a Mutex).
        let auth_db_path = home.root().join("auth").join("auth.sqlite");
        let projection_auth = AuthStore::open(&auth_db_path)
            .map_err(|e| DaemonError::Audit(format!("auth store (projection): {e}")))?;
        let central = CentralOutbox::new(home.root().join("central_outbox"));
        let projection: Arc<dyn CentralOutboxProjection> =
            Arc::new(EvmOutboxProjection::new(central, projection_auth));
        let outbox = Outbox::new_with_projection(home.outbox_dir(), projection)
            .map_err(|e| DaemonError::Outbox(e.to_string()))?;
        let mut tx_engine = TxEngine::new(outbox, config.stage_ttl.as_millis());
        #[cfg(feature = "unsafe-debug-signer")]
        if let Some((wallet, signer)) = &unsafe_debug_signer {
            tx_engine = tx_engine.with_unsafe_debug_signer(wallet.clone(), signer.clone());
        }

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

        let audit =
            AuditLog::open(home.audit_path()).map_err(|e| DaemonError::Audit(e.to_string()))?;
        let audit_arc = Arc::new(audit.clone());
        let auth_store = AuthStore::open(&auth_db_path)
            .map_err(|e| DaemonError::Audit(format!("auth store: {e}")))?;
        let auth_verifier = Arc::new(StoreApprovalVerifier::new(
            auth_store,
            KeystoreApprovalSignatureVerifier::new(keystore.clone()),
        ));
        tx_engine = tx_engine.with_auth_services(auth_verifier.clone(), auth_verifier.clone());
        let auth_services = AuthServices::new(
            Some(auth_verifier.clone()),
            Some(auth_verifier.clone()),
            Some(auth_verifier.clone()),
        );
        // WS-1 wiring: in-memory grant store + first-party attestation
        // registry + keystore-backed PetalHost. All three live behind the
        // existing `AuthServices` so VFS handlers and the new `sign_hash`
        // IPC method can call them without going through the old
        // verifier/nfc paths. The concrete store / registry / host impls
        // can be swapped (test doubles, post-MVP venues) by replacing
        // the `Arc<dyn ...>` references.
        let grant_store: Arc<dyn bloom_auth_api::GrantStore> =
            Arc::new(bloom_auth::grant_store::InMemoryGrantStore::default());
        let attestation_registry: Arc<dyn bloom_auth_api::SigningAttestationSchemaRegistry> =
            Arc::new(bloom_auth_api::DefaultAttestationRegistry::new());
        let signer_cache = Arc::new(bloom_keystore::petal_host::SignerCache::new());
        let petal_host: Arc<dyn bloom_auth_api::PetalHost> = Arc::new(
            bloom_keystore::petal_host::KeystorePetalHost::new(
                Arc::new(keystore.clone()),
                grant_store.clone(),
                attestation_registry.clone(),
                audit_arc.clone(),
            )
            .with_signer_cache(signer_cache.clone()),
        );
        tx_engine = tx_engine.with_host_signing_services(grant_store.clone(), petal_host.clone());

        // Wallet registration coordinator: always constructed (so every
        // VFS/IPC caller sees the same instance), but stays unarmed until
        // `ceremony_server::spawn` marks the shared loopback listener bound.
        // Restart reconciliation deliberately does NOT run here: this
        // constructor runs for every `Daemon`, including one-shot read-only
        // CLI commands (`wallet list`, `status`, ...) invoked alongside a
        // live `bloom serve`. Running reconciliation unconditionally would
        // let such a command mark a still-live `bloom serve` registration
        // session `failed` in the shared store purely because this second
        // process has no in-memory session of its own to compare against.
        // `ceremony_server::spawn` runs it instead, gated on this process
        // having just proven exclusive listener ownership via a successful
        // bind.
        let registration_coordinator: Arc<dyn bloom_auth_api::WalletRegistrationCoordinator> =
            Arc::new(registration::RegistrationCoordinator::new(
                keystore.clone(),
                auth_verifier.clone(),
                audit_arc.clone(),
                home.keystore_dir(),
            ));

        let auth_services = auth_services
            .with_grant_store(grant_store)
            .with_attestation_registry(attestation_registry)
            .with_petal_host(petal_host)
            .with_registration_coordinator(registration_coordinator);
        let path_cache = Arc::new(PathCache::new());

        let watch_registry = Arc::new(
            WatchRegistry::new(home.watch_dir()).map_err(|e| DaemonError::Watch(e.to_string()))?,
        );
        let watch_executor = Arc::new(WatchExecutor::new(
            chains.clone(),
            watch_registry.clone(),
            home.clone(),
        ));

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
                keystore.clone(),
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
        let petal_app_host = DaemonPetalHost::new(
            petal_vfs_host.clone(),
            audit_arc.clone(),
            auth_services.clone(),
        )
        .with_tx_outbox(PetalTxOutbox {
            tx_engine: tx_engine.clone(),
            chains: chains.clone(),
            keystore: keystore.clone(),
            address_book: address_book_arc.clone(),
            write_permit: home_write_permit.clone(),
        });
        #[cfg(feature = "unsafe-debug-signer")]
        let petal_app_host = match &unsafe_debug_signer {
            Some((wallet, signer)) => {
                petal_app_host.with_unsafe_debug_signer(wallet.clone(), signer.clone())
            }
            None => petal_app_host,
        };
        let petal_app_host = Arc::new(petal_app_host);
        debug!(root = %petals_root.display(), "daemon.petals_initialised");
        let petals_for_docs = petals.clone();
        let petals_doc_renderer: Arc<dyn Fn() -> Vec<u8> + Send + Sync> =
            Arc::new(move || render_installed_petals_doc(&petals_for_docs));

        let mut vfs_builder = Vfs::builder()
            .mount(
                "petals",
                Arc::new(
                    PetalRouter::new(petals.clone(), petal_app_host)
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

        let hyperliquid_handler: Option<Arc<HyperliquidHandler>> = if let Some(hl_cfg) =
            &config.hyperliquid
        {
            let hl_url = |raw: &str| match url::Url::parse(raw) {
                Ok(u) => Some(u),
                Err(e) => {
                    warn!(url = %raw, error = %e, "daemon.hyperliquid_url_invalid_using_default");
                    None
                }
            };
            let mut mainnet = HyperliquidClient::new(HyperliquidNetwork::Mainnet);
            if let Some(u) = hl_url(&hl_cfg.mainnet_url) {
                mainnet = mainnet.with_base_url(u);
            }
            let mut testnet = HyperliquidClient::new(HyperliquidNetwork::Testnet);
            if let Some(u) = hl_url(&hl_cfg.testnet_url) {
                testnet = testnet.with_base_url(u);
            }
            debug!("daemon.hyperliquid_mounted");
            let handler = Arc::new(
                HyperliquidHandler::new(mainnet, testnet, keystore.clone())
                    .with_auth_services(auth_services.clone())
                    .with_store_root(home.root().join("hyperliquid")),
            );
            handler.clone().start_monitoring();
            Some(handler)
        } else {
            debug!("daemon.hyperliquid_skipped: no [hyperliquid] config");
            None
        };

        if let Some(ref hl) = hyperliquid_handler {
            vfs_builder = vfs_builder.mount("hyperliquid", hl.clone() as _);
        }

        vfs_builder = vfs_builder
            .mount(
                "wallets",
                Arc::new(
                    WalletsHandler::new(
                        keystore.clone(),
                        chains.clone(),
                        tx_engine.clone(),
                        address_book.clone(),
                    )
                    .with_auth_services(auth_services.clone())
                    .with_home_write_permit_opt(home_write_permit.clone())
                    .with_mempool_indexes(mempool_indexes.clone())
                    .with_hyperliquid_handler(hyperliquid_handler.clone()),
                ) as _,
            )
            .mount("tools", Arc::new(ToolsHandler::new()) as _)
            .mount(
                "requests",
                Arc::new(
                    RequestsHandler::new(
                        home.root().to_path_buf(),
                        keystore.clone(),
                        config.default_wallet.clone(),
                    )
                    .with_auth_services(auth_services.clone())
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
        let next_keystore = keystore.clone();
        let next_tx_engine = tx_engine.clone();
        let next_hl = hyperliquid_handler.clone();
        let next_renderer: Arc<dyn Fn() -> Vec<u8> + Send + Sync> = Arc::new(move || {
            let mut md = String::from("# Next Actions\n\n");
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);

            // 1. Unsigned-policy passkey wallets
            let mut unsigned = Vec::new();
            if let Ok(infos) = next_keystore.list() {
                for info in &infos {
                    let status = next_keystore
                        .policy_status(&info.name)
                        .unwrap_or(bloom_keystore::PolicyStatus::NotApplicable);
                    if status == bloom_keystore::PolicyStatus::Unsigned
                        || status == bloom_keystore::PolicyStatus::Stale
                    {
                        unsigned.push(format!(
                            "- `{}`: policy is **{:?}** — run `bloom wallet sign-policy {}` to enable agent trading",
                            info.name, status, info.name
                        ));
                    }
                }
            }
            if !unsigned.is_empty() {
                md.push_str("## Unsigned Policies\n\n");
                for u in &unsigned {
                    md.push_str(u);
                    md.push('\n');
                }
                md.push('\n');
            }

            // 2. Pending outbox confirms
            let mut pending_confirms = Vec::new();
            if let Ok(infos) = next_keystore.list() {
                for info in &infos {
                    let sessions = next_tx_engine.session_store().active(now_ms);
                    let has_session = sessions.iter().any(|s| s.wallet == info.name);
                    if has_session {
                        for s in &sessions {
                            if s.wallet != info.name {
                                continue;
                            }
                            if s.expires_ms > now_ms {
                                pending_confirms.push(format!(
                                    "- `{}`: {} pending tx ids, session `{}` active (expires in {}s)",
                                    info.name,
                                    s.allowed_pending_ids.len(),
                                    s.id,
                                    ((s.expires_ms - now_ms) / 1000)
                                ));
                            }
                        }
                    }
                }
            }
            if !pending_confirms.is_empty() {
                md.push_str("## Pending Outbox Confirms\n\n");
                for p in &pending_confirms {
                    md.push_str(p);
                    md.push('\n');
                }
                md.push('\n');
            }

            // 3. Capability status (HL sessions)
            if let Some(ref hl) = next_hl {
                let mut expired = Vec::new();
                let mut orphaned = Vec::new();
                let mut stale = Vec::new();
                if let Ok(infos) = next_keystore.list() {
                    for info in &infos {
                        let views = hl.capability_views_for(&info.name);
                        for v in &views {
                            match v.status {
                                bloom_proto::CapabilityStatus::Expired => {
                                    expired.push(format!(
                                        "- `{}` session `{}`: **expired** — no new orders accepted",
                                        info.name, v.id
                                    ));
                                }
                                bloom_proto::CapabilityStatus::Orphaned => {
                                    orphaned.push(format!(
                                        "- `{}` session `{}`: **orphaned** — daemon lost the agent key after restart. Owner must recover via `orphan_cancel_all` or `orphan_close_all` at `{}`",
                                        info.name, v.id, v.revoke_path
                                    ));
                                }
                                bloom_proto::CapabilityStatus::Active => {
                                    if let Some(secs) = v.expires_in_secs
                                        && secs < 300
                                    {
                                        stale.push(format!(
                                            "- `{}` session `{}`: expiring in {}s",
                                            info.name, v.id, secs
                                        ));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                if !expired.is_empty() {
                    md.push_str("## Expired Sessions\n\n");
                    for e in &expired {
                        md.push_str(e);
                        md.push('\n');
                    }
                    md.push('\n');
                }
                if !orphaned.is_empty() {
                    md.push_str("## Orphaned Sessions (Needs Owner)\n\n");
                    for o in &orphaned {
                        md.push_str(o);
                        md.push('\n');
                    }
                    md.push('\n');
                }
                if !stale.is_empty() {
                    md.push_str("## Expiring Soon\n\n");
                    for s in &stale {
                        md.push_str(s);
                        md.push('\n');
                    }
                    md.push('\n');
                }
            }

            if unsigned.is_empty() && pending_confirms.is_empty() && next_hl.is_none() {
                md.push_str("No wallets with pending actions.\n\n");
                md.push_str("All policies are signed, no outbox confirms await review, and no Hyperliquid sessions are active.\n");
            }
            md.into_bytes()
        });
        vfs_builder = vfs_builder.with_root_dynamic("next.md", next_renderer);

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
        // Per-wallet `policy.bump.stuck_after_secs` and `basefee_overrun_pct`
        // are honoured via a lookup closure that reads each tx entry's
        // wallet's `policy.toml` at scan time. Unknown wallets fall back
        // to the scanner's global defaults (the same values exposed by
        // `BumpPolicy::default()` — they're kept in sync). Reading on
        // each scan tick (rather than caching at startup) means policy
        // edits take effect on the next pass without a daemon restart.
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
            let ks_for_lookup = keystore.clone();
            let wallet_policy: bloom_tx::bump_scanner::WalletPolicyLookup =
                Arc::new(move |wallet: &str| {
                    match ks_for_lookup.info(wallet) {
                        Ok(info) => (
                            Duration::from_secs(info.policy.bump.stuck_after_secs),
                            info.policy.bump.basefee_overrun_pct,
                        ),
                        // Unknown wallet / missing policy.toml / parse error:
                        // fall back to global defaults rather than skipping
                        // the entry. A bad policy.toml shouldn't disable
                        // bump detection for that wallet's stuck txs.
                        Err(_) => (default_stuck_after, default_overrun),
                    }
                });
            let scanner = Arc::new(
                bloom_tx::bump_scanner::BumpScanner::new(
                    tx_engine.outbox.clone(),
                    shared_indexes,
                    basefee,
                    cfg,
                )
                .with_wallet_policy(wallet_policy),
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
            keystore,
            tx_engine,
            home_write_permit,
            address_book: address_book_arc,
            audit: audit_arc,
            auth_services,
            signer_cache,
            vfs,
            petals,
            watch_registry,
            watch_executor,
            update_checker,
            mempool_shutdown: Arc::new(parking_lot::Mutex::new(mempool_shutdown)),
            bump_shutdown: Arc::new(parking_lot::Mutex::new(bump_shutdown)),
            probe_shutdown: Arc::new(parking_lot::Mutex::new(probe_shutdown)),
            update_shutdown: Arc::new(parking_lot::Mutex::new(Vec::new())),
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
        let registration_coordinator = self.auth_services.registration_coordinator().cloned();
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
                        match outbox.sweep_expired(now_ms) {
                            Ok(0) => tracing::trace!("outbox.sweep_expired.empty"),
                            Ok(n) => info!(swept = n, "outbox.sweep_expired"),
                            Err(e) => warn!(error = %e, "outbox.sweep_expired_failed"),
                        }
                        if let Some(coordinator) = &registration_coordinator {
                            match coordinator.sweep_expired(now_ms as u64).await {
                                Ok(0) => tracing::trace!("wallet_registration.sweep_expired.empty"),
                                Ok(n) => info!(swept = n, "wallet_registration.sweep_expired"),
                                Err(e) => warn!(error = %e, "wallet_registration.sweep_expired_failed"),
                            }
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

/// Handle to background tasks owned by a running [`Daemon`]. Drop to
/// signal shutdown; the spawned tasks read the watch and exit at the
/// next tick. Holding this past daemon lifetime keeps the sweeper alive.
pub struct BackgroundTasks {
    cancel: watch::Sender<bool>,
    handle: Option<JoinHandle<()>>,
}

impl BackgroundTasks {
    /// Trigger graceful shutdown and wait for the sweeper task to exit.
    pub async fn shutdown(mut self) {
        let _ = self.cancel.send(true);
        if let Some(h) = self.handle.take() {
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
    use bloom_vfs::VfsPath;
    use bloom_vfs::handler::Handler;

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
            d.vfs.handler("hyperliquid").is_some(),
            "fresh homes should mount Hyperliquid with public defaults"
        );
        assert!(
            d.vfs.handler("polymarket").is_none(),
            "native Polymarket must not be mounted; use petals/polymarket"
        );
    }

    #[tokio::test]
    async fn daemon_petal_host_sign_hash_rejects_calls_without_trusted_petal_context() {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        let host =
            DaemonPetalHost::new(Arc::new(LateVfsHost::new()), audit, AuthServices::default());
        let err = host
            .sign_hash(SignRequest {
                wallet: "alice".into(),
                hash32: [7; 32],
                purpose: "test.intent".into(),
                context: None,
            })
            .await
            .unwrap_err();
        let HostError::Denied(msg) = err else {
            panic!("expected denied error");
        };
        assert!(msg.contains("trusted Petal route context"), "{msg}");
    }

    #[test]
    fn daemon_petal_host_seals_petal_signing_action_from_trusted_route_context() {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        let host =
            DaemonPetalHost::new(Arc::new(LateVfsHost::new()), audit, AuthServices::default());
        let req = SignRequest {
            wallet: "alice".into(),
            hash32: [7; 32],
            purpose: "portfolio.position.sign".into(),
            context: Some(PetalRouteContext {
                petal_root: "portfolio".into(),
                package_hash: "a".repeat(64),
                route_id: "r000001".into(),
                op: "read".into(),
                path: "/positions".into(),
                params: vec![("account".into(), "main".into())],
                actor: Some("agent-1".into()),
            }),
        };
        let (action, attestation) = host
            .petal_action(&req, req.context.as_ref().unwrap(), 1)
            .unwrap();

        assert_eq!(action.surface(), "petals");
        assert_eq!(action.petal_id(), "petal:portfolio");
        assert_eq!(action.petal_digest(), "a".repeat(64));
        assert_eq!(action.daemon_terms.max_signatures, 1);
        assert_eq!(
            action.daemon_terms.allowed_sign_intents,
            vec![req.purpose.clone()]
        );
        assert!(
            action
                .daemon_terms
                .extra
                .contains_key("required.attestation_facts_digest")
        );
        assert_eq!(
            attestation
                .facts
                .get("route_id")
                .and_then(|value| value.as_str()),
            Some("r000001")
        );
        let expected_hash = format!("0x{}", hex::encode([7; 32]));
        assert_eq!(
            attestation
                .facts
                .get("signing_hash")
                .and_then(|value| value.as_str()),
            Some(expected_hash.as_str())
        );

        let mut root_context = req.context.clone().unwrap();
        root_context.path.clear();
        host.petal_action(&req, &root_context, 1).unwrap();
    }

    #[test]
    fn petal_signing_identity_is_stable_until_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        let host =
            DaemonPetalHost::new(Arc::new(LateVfsHost::new()), audit, AuthServices::default());
        let req = SignRequest {
            wallet: "alice".into(),
            hash32: [7; 32],
            purpose: "example.batch_sign".into(),
            context: Some(PetalRouteContext {
                petal_root: "example".into(),
                package_hash: "a".repeat(64),
                route_id: "r-sign".into(),
                op: "write".into(),
                path: "/sign/alice/begin".into(),
                params: vec![("wallet".into(), "alice".into())],
                actor: None,
            }),
        };

        let (start, _) = host
            .petal_action(&req, req.context.as_ref().unwrap(), 1)
            .unwrap();
        let (end_of_bucket, _) = host
            .petal_action(&req, req.context.as_ref().unwrap(), 59_999)
            .unwrap();
        assert_eq!(start.action_id(), end_of_bucket.action_id());
        assert_eq!(end_of_bucket.expires_ms, 120_001);

        let (next_bucket, _) = host
            .petal_action(&req, req.context.as_ref().unwrap(), 60_000)
            .unwrap();
        assert_eq!(start.action_id(), next_bucket.action_id());
        assert_eq!(next_bucket.expires_ms, start.expires_ms);

        let (last_live_retry, _) = host
            .petal_action(&req, req.context.as_ref().unwrap(), 120_000)
            .unwrap();
        assert_eq!(start.action_id(), last_live_retry.action_id());

        let (after_expiry, _) = host
            .petal_action(&req, req.context.as_ref().unwrap(), 120_001)
            .unwrap();
        assert_ne!(start.action_id(), after_expiry.action_id());
        assert_eq!(after_expiry.expires_ms, 240_001);
    }

    #[test]
    fn petal_signing_identity_binds_the_complete_request_scope() {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        let host =
            DaemonPetalHost::new(Arc::new(LateVfsHost::new()), audit, AuthServices::default());
        let req = SignRequest {
            wallet: "alice".into(),
            hash32: [7; 32],
            purpose: "example.sign".into(),
            context: Some(PetalRouteContext {
                petal_root: "example".into(),
                package_hash: "a".repeat(64),
                route_id: "r-sign".into(),
                op: "write".into(),
                path: "/sign/alice".into(),
                params: vec![("wallet".into(), "alice".into())],
                actor: Some("agent-1".into()),
            }),
        };
        let (original, _) = host
            .petal_action(&req, req.context.as_ref().unwrap(), 1)
            .unwrap();

        let mut changed_hash = req.clone();
        changed_hash.hash32 = [8; 32];
        let (changed_hash, _) = host
            .petal_action(&changed_hash, changed_hash.context.as_ref().unwrap(), 1)
            .unwrap();
        assert_ne!(original.action_id(), changed_hash.action_id());

        let mut changed_context = req.clone();
        changed_context.context.as_mut().unwrap().actor = Some("agent-2".into());
        let (changed_context, _) = host
            .petal_action(
                &changed_context,
                changed_context.context.as_ref().unwrap(),
                1,
            )
            .unwrap();
        assert_ne!(original.action_id(), changed_context.action_id());
    }

    #[test]
    fn daemon_petal_host_seals_exact_ordered_hardened_signing_batch() {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        let host =
            DaemonPetalHost::new(Arc::new(LateVfsHost::new()), audit, AuthServices::default());
        let context = PetalRouteContext {
            petal_root: "polymarket".into(),
            package_hash: "b".repeat(64),
            route_id: "r-onboard".into(),
            op: "write".into(),
            path: "/onboard/alice/begin".into(),
            params: vec![("wallet".into(), "alice".into())],
            actor: None,
        };
        let requests = vec![
            SignRequest {
                wallet: "alice".into(),
                hash32: [1; 32],
                purpose: "polymarket.onboard".into(),
                context: Some(context.clone()),
            },
            SignRequest {
                wallet: "alice".into(),
                hash32: [2; 32],
                purpose: "polymarket.relayer_batch".into(),
                context: Some(context),
            },
        ];
        let (action, attestations) = host.petal_batch_action(&requests, 1).unwrap();
        assert_eq!(action.daemon_terms.assurance, AssuranceLevel::Hardened);
        assert_eq!(action.daemon_terms.max_signatures, 2);
        assert_eq!(attestations.len(), 2);
        let entries: Vec<SealedSignBatchEntry> =
            serde_json::from_value(action.daemon_terms.extra["required.signing_requests"].clone())
                .unwrap();
        assert_eq!(entries[0].hash_hex, format!("0x{}", hex::encode([1; 32])));
        assert_eq!(entries[1].hash_hex, format!("0x{}", hex::encode([2; 32])));
        assert!(
            entries
                .iter()
                .all(|entry| !entry.attestation_facts_digest.is_empty())
        );

        let (across_retry_boundary, _) = host.petal_batch_action(&requests, 60_000).unwrap();
        assert_eq!(action.action_id(), across_retry_boundary.action_id());
        assert_eq!(action.expires_ms, across_retry_boundary.expires_ms);

        let (after_expiry, _) = host
            .petal_batch_action(&requests, action.expires_ms)
            .unwrap();
        assert_ne!(action.action_id(), after_expiry.action_id());

        let mut reversed = requests.clone();
        reversed.reverse();
        let (reversed_action, _) = host.petal_batch_action(&reversed, 1).unwrap();
        assert_ne!(action.action_id(), reversed_action.action_id());
        assert!(
            host.petal_batch_action(&[requests[0].clone(), requests[0].clone()], 1)
                .is_err()
        );
    }

    #[test]
    fn invalid_signing_batches_cannot_consume_identity_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
        let host =
            DaemonPetalHost::new(Arc::new(LateVfsHost::new()), audit, AuthServices::default());
        let context = PetalRouteContext {
            petal_root: "example".into(),
            package_hash: "b".repeat(64),
            route_id: "r-sign".into(),
            op: "write".into(),
            path: "/sign/alice".into(),
            params: vec![("wallet".into(), "alice".into())],
            actor: None,
        };

        for index in 0..MAX_ACTIVE_PETAL_ACTION_IDENTITIES {
            let mut hash32 = [0; 32];
            hash32[..8].copy_from_slice(&(index as u64).to_be_bytes());
            let invalid = SignRequest {
                wallet: "alice".into(),
                hash32,
                purpose: String::new(),
                context: Some(context.clone()),
            };
            assert!(host.petal_batch_action(&[invalid], 1).is_err());
        }
        assert_eq!(
            host.petal_action_identities.lock().unwrap().entries.len(),
            0
        );

        let valid = SignRequest {
            wallet: "alice".into(),
            hash32: [7; 32],
            purpose: "example.sign".into(),
            context: Some(context),
        };
        host.petal_batch_action(&[valid], 1).unwrap();
        assert_eq!(
            host.petal_action_identities.lock().unwrap().entries.len(),
            1
        );
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
        DaemonPetalHost::new(
            Arc::new(LateVfsHost::new()),
            daemon.audit.clone(),
            daemon.auth_services.clone(),
        )
        .with_tx_outbox(PetalTxOutbox {
            tx_engine: daemon.tx_engine.clone(),
            chains: daemon.chains.clone(),
            keystore: daemon.keystore.clone(),
            address_book: daemon.address_book.clone(),
            write_permit: daemon.home_write_permit.clone(),
        })
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

    #[test]
    fn config_without_hyperliquid_keeps_surface_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let home = HomeDir::at(dir.path());
        home.ensure().unwrap();
        let mut config = Config::local_default();
        config.hyperliquid = None;
        config.save(&home.config_path()).unwrap();

        let daemon = Daemon::from_home(home).unwrap();
        assert!(daemon.vfs.handler("hyperliquid").is_none());
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
        let n = d.tx_engine.outbox.sweep_expired(2).unwrap();
        assert_eq!(n, 1);

        // Shutdown completes promptly.
        tokio::time::timeout(std::time::Duration::from_secs(2), tasks.shutdown())
            .await
            .expect("background task did not honour shutdown signal");
    }
}
