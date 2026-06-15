//! `defi/intents/<wallet>/...` — Enso-mediated DeFi intent surface.
//!
//! Writes go through the wallet's normal stage→confirm pipeline; this
//! handler is an "intent compiler" that turns natural-language or JSON
//! Enso intents into a concrete `RawIntent::Raw` and forwards confirms
//! to [`TxEngine::stage`]. The actual broadcast still happens via the
//! wallet outbox.
//!
//! Paths handled:
//! - `defi/`                                        — `[ "intents" ]`
//! - `defi/intents/`                                — wallets with sessions
//! - `defi/intents/<wallet>/`                       — `new` + session ids
//! - `defi/intents/<wallet>/new`                    — write to begin a session
//! - `defi/intents/<wallet>/<session>/intent.txt`   — original intent
//! - `defi/intents/<wallet>/<session>/route.json`   — full Enso response
//! - `defi/intents/<wallet>/<session>/plan.md`      — human narrative
//! - `defi/intents/<wallet>/<session>/tx.json`      — prepared RawIntent
//! - `defi/intents/<wallet>/<session>/simulation.json` — eth_call sim
//! - `defi/intents/<wallet>/<session>/settlement.json` — latest settlement observation
//! - `defi/intents/<wallet>/<session>/wait_settlement` — blocking settlement waiter
//! - `defi/intents/<wallet>/<session>/confirm`      — write to stage into outbox

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, U256, address};
use alloy::rpc::types::eth::TransactionRequest;
use async_trait::async_trait;
use bloom_chain::{ChainClient, ChainRegistry};
use bloom_defi::{
    EnsoClient, EnsoError, RouteRequest, RouteResponse, RoutingStrategy, parse_natural_intent,
    resolve_token_symbol,
};
use bloom_keystore::Keystore;
use bloom_proto::{
    AddressBook, GasStrategy, HomeWritePermit, RawIntent, RawIntentBody, StagedTx,
    checksum_address, format_units,
};
use bloom_revert::{DecodeContext, DecoderChain};
use bloom_tx::tx_engine::TxEngine;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Enso's native-token sentinel; matches `bloom_defi::NATIVE_TOKEN`.
/// When `token_in == NATIVE_TOKEN_ADDR`, no ERC-20 approval is needed.
const NATIVE_TOKEN_ADDR: Address = address!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

/// Cached session: original intent, the Enso route response, and the
/// ordered list of `RawIntent`s we hand to [`TxEngine::stage`] on
/// confirm. For ERC-20 token-in routes the list is `[approve, swap]`
/// when allowance is insufficient; native ETH or pre-approved tokens
/// produce a single `[swap]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefiSession {
    pub id: String,
    pub wallet: String,
    pub chain: String,
    pub destination_chain: Option<String>,
    pub intent_text: String,
    #[serde(default)]
    pub route_request: Option<RouteRequest>,
    pub route: Option<RouteResponse>,
    pub plan_md: String,
    pub intents: Vec<RawIntent>,
    #[serde(default)]
    pub intent_states: Vec<DefiIntentState>,
    pub staged_ids: Vec<String>,
    pub created_ms: u128,
    #[serde(default)]
    pub updated_ms: u128,
    #[serde(default)]
    pub observed_before: Option<String>,
    #[serde(default)]
    pub min_settlement_delta: Option<String>,
    #[serde(default)]
    pub source_tx_hashes: Vec<String>,
    /// `[defi]` route policy checks evaluated at session creation — display
    /// only. Confirm re-evaluates from current policy before staging.
    #[serde(default)]
    pub policy_checks: serde_json::Value,
    /// Receiver classification recorded for review (`wallet_eoa`,
    /// `polymarket_deposit_wallet`, `addressbook_alias`, `unknown`, …).
    #[serde(default)]
    pub receiver_class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DefiIntentStatus {
    Prepared,
    Staged,
    Broadcast,
    Mined,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefiIntentState {
    pub index: usize,
    pub status: DefiIntentStatus,
    #[serde(default)]
    pub outbox_id: Option<String>,
    #[serde(default)]
    pub tx_hash: Option<String>,
    pub updated_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
struct SettlementStatus {
    session: String,
    wallet: String,
    source_chain: String,
    destination_chain: String,
    destination_token: String,
    destination_receiver: Option<String>,
    expected_output: String,
    minimum_delta: String,
    observed_before: Option<String>,
    observed_after: Option<String>,
    observed_delta: Option<String>,
    status: String,
    source_tx_hashes: Vec<String>,
    note: String,
}

/// Body of `new` writes — accepts either a JSON `{intent, chain}` or
/// a single-line natural-language string.
#[derive(Debug, Clone, Deserialize)]
struct NewIntentBody {
    #[serde(default)]
    #[allow(dead_code)]
    kind: Option<String>,
    intent: String,
    #[serde(default)]
    chain: Option<String>,
    #[serde(default)]
    destination_chain: Option<String>,
    #[serde(default)]
    receiver: Option<String>,
    #[serde(default)]
    slippage_bps: Option<u16>,
}

#[derive(Clone)]
pub struct DefiHandler {
    enso: EnsoClient,
    chains: ChainRegistry,
    keystore: Keystore,
    tx_engine: TxEngine,
    address_book: Arc<AddressBook>,
    home_write_permit: Option<Arc<HomeWritePermit>>,
    sessions: Arc<RwLock<HashMap<String, DefiSession>>>,
    store_root: PathBuf,
    /// Default chain when an intent omits one.
    default_chain: String,
    next_id: Arc<RwLock<u64>>,
    /// Tiered revert decoder used to attach a structured `decoded_error`
    /// to simulation/confirm failures. Defaults to an empty chain so the
    /// handler still works in tests; the daemon wires a real chain in.
    revert_decoder: Arc<DecoderChain>,
    /// Polymarket state root (`~/.bloom/polymarket`), wired by the daemon.
    /// Enables `polymarket_deposit_wallet` receiver classification from
    /// durable onboarding state. `None` ⇒ that class is unavailable.
    polymarket_root: Option<PathBuf>,
}

impl DefiHandler {
    pub fn new(
        enso: EnsoClient,
        chains: ChainRegistry,
        keystore: Keystore,
        tx_engine: TxEngine,
        address_book: Arc<AddressBook>,
    ) -> Self {
        Self {
            enso,
            chains,
            keystore,
            tx_engine,
            address_book,
            home_write_permit: None,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            store_root: default_store_root(),
            default_chain: "ethereum".into(),
            next_id: Arc::new(RwLock::new(1)),
            revert_decoder: Arc::new(DecoderChain::new()),
            polymarket_root: None,
        }
    }

    pub fn with_home_write_permit(mut self, permit: Arc<HomeWritePermit>) -> Self {
        self.home_write_permit = Some(permit);
        self
    }

    pub fn with_home_write_permit_opt(mut self, permit: Option<Arc<HomeWritePermit>>) -> Self {
        self.home_write_permit = permit;
        self
    }

    /// Wire the Polymarket state root so cross-chain/funding routes can be
    /// classified as `polymarket_deposit_wallet` from durable onboarding
    /// state (not a hardcoded or locally-derived address).
    pub fn with_polymarket_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.polymarket_root = Some(root.into());
        self
    }

    pub fn with_default_chain(mut self, chain: impl Into<String>) -> Self {
        self.default_chain = chain.into();
        self
    }

    pub fn with_store_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.store_root = root.into();
        self
    }

    fn write_permit(&self) -> Result<&HomeWritePermit, HandlerError> {
        self.home_write_permit.as_deref().ok_or_else(|| {
            HandlerError::backend(
                "defi write surface is not attached to a home write permit; refusing mutation",
            )
        })
    }

    /// Wire a shared revert decoder chain into this handler. Construct
    /// once at daemon startup and clone the `Arc` for every handler that
    /// needs to attribute reverts.
    pub fn with_revert_decoder(mut self, chain: Arc<DecoderChain>) -> Self {
        self.revert_decoder = chain;
        self
    }

    fn allocate_id(&self, wallet: &str) -> String {
        let mut g = self.next_id.write();
        loop {
            let n = *g;
            *g = n.wrapping_add(1);
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() % 1_000_000_000)
                .unwrap_or(0);
            let id = format!("{:04}-{}-{suffix:09}", n, process::id());
            if !self.session_path(wallet, &id).exists() {
                return id;
            }
        }
    }

    fn session_key(wallet: &str, id: &str) -> String {
        format!("{wallet}/{id}")
    }

    fn wallet_dir(&self, wallet: &str) -> PathBuf {
        self.store_root.join(wallet).join("sessions")
    }

    fn session_path(&self, wallet: &str, id: &str) -> PathBuf {
        self.wallet_dir(wallet).join(format!("{id}.json"))
    }

    fn validate_segment(seg: &str) -> Result<(), HandlerError> {
        if seg.is_empty() || seg.contains('/') || seg.contains('\\') || seg == "." || seg == ".." {
            return Err(HandlerError::invalid(format!(
                "invalid path segment '{seg}'"
            )));
        }
        Ok(())
    }

    fn parse_new_body(body: &str) -> Result<NewIntentBody, HandlerError> {
        let s = body.trim();
        if s.is_empty() {
            return Err(HandlerError::invalid("empty intent body"));
        }
        if s.starts_with('{') {
            let v: NewIntentBody =
                serde_json::from_str(s).map_err(|e| HandlerError::invalid(format!("json: {e}")))?;
            if v.intent.trim().is_empty() {
                return Err(HandlerError::invalid("missing 'intent' field"));
            }
            Ok(v)
        } else {
            Ok(NewIntentBody {
                kind: Some("enso".into()),
                intent: s.to_string(),
                chain: None,
                destination_chain: None,
                receiver: None,
                slippage_bps: None,
            })
        }
    }

    fn list_session_wallets(&self) -> Vec<String> {
        let _ = self.load_all_sessions();
        let mut s: Vec<String> = self
            .sessions
            .read()
            .values()
            .map(|sess| sess.wallet.clone())
            .collect();
        if let Ok(entries) = fs::read_dir(&self.store_root) {
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false)
                    && let Some(name) = entry.file_name().to_str()
                {
                    s.push(name.to_string());
                }
            }
        }
        s.sort();
        s.dedup();
        s
    }

    fn list_sessions_for_wallet(&self, wallet: &str) -> Vec<String> {
        let _ = self.load_wallet_sessions(wallet);
        let mut out: Vec<String> = self
            .sessions
            .read()
            .values()
            .filter(|s| s.wallet == wallet)
            .map(|s| s.id.clone())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    fn get_session(&self, wallet: &str, id: &str) -> Result<DefiSession, HandlerError> {
        Self::validate_segment(wallet)?;
        Self::validate_segment(id)?;
        let key = Self::session_key(wallet, id);
        if let Some(sess) = self.sessions.read().get(&key).cloned() {
            return Ok(sess);
        }
        let sess = self.load_session_from_disk(wallet, id)?;
        self.sessions.write().insert(key, sess.clone());
        Ok(sess)
    }

    fn put_session(&self, sess: DefiSession) -> Result<(), HandlerError> {
        let key = Self::session_key(&sess.wallet, &sess.id);
        self.save_session_to_disk(&sess)?;
        self.sessions.write().insert(key, sess);
        Ok(())
    }

    fn load_session_from_disk(&self, wallet: &str, id: &str) -> Result<DefiSession, HandlerError> {
        let path = self.session_path(wallet, id);
        let bytes = fs::read(&path)
            .map_err(|_| HandlerError::not_found(format!("session {wallet}/{id}")))?;
        let mut sess: DefiSession = serde_json::from_slice(&bytes)
            .map_err(|e| HandlerError::backend(format!("session json {}: {e}", path.display())))?;
        if sess.wallet != wallet || sess.id != id {
            return Err(HandlerError::backend(format!(
                "session file {} does not match requested {wallet}/{id}",
                path.display()
            )));
        }
        normalize_session_state(&mut sess);
        Ok(sess)
    }

    fn load_wallet_sessions(&self, wallet: &str) -> Result<(), HandlerError> {
        Self::validate_segment(wallet)?;
        let dir = self.wallet_dir(wallet);
        if !dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let bytes = fs::read(&path)?;
            let mut sess: DefiSession = serde_json::from_slice(&bytes).map_err(|e| {
                HandlerError::backend(format!("session json {}: {e}", path.display()))
            })?;
            normalize_session_state(&mut sess);
            let key = Self::session_key(&sess.wallet, &sess.id);
            self.sessions.write().insert(key, sess);
        }
        Ok(())
    }

    fn load_all_sessions(&self) -> Result<(), HandlerError> {
        if !self.store_root.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(&self.store_root)? {
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && let Some(wallet) = entry.file_name().to_str()
            {
                let _ = self.load_wallet_sessions(wallet);
            }
        }
        Ok(())
    }

    fn save_session_to_disk(&self, sess: &DefiSession) -> Result<(), HandlerError> {
        Self::validate_segment(&sess.wallet)?;
        Self::validate_segment(&sess.id)?;
        let dir = self.wallet_dir(&sess.wallet);
        fs::create_dir_all(&dir)?;
        let path = self.session_path(&sess.wallet, &sess.id);
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(sess).unwrap())?;
        fs::rename(tmp, path)?;
        Ok(())
    }

    fn chain_client(&self, name: &str) -> Result<ChainClient, HandlerError> {
        self.chains
            .get(name)
            .ok_or_else(|| HandlerError::not_found(format!("chain '{name}'")))
    }

    /// Build a RouteRequest from a natural-language intent.
    async fn build_route_request(
        chain: &ChainClient,
        chain_id: u64,
        destination_chain_id: Option<u64>,
        from: Address,
        intent: &str,
        receiver: Option<Address>,
    ) -> Result<RouteRequest, HandlerError> {
        let nat = parse_natural_intent(intent).ok_or_else(|| {
            HandlerError::invalid(format!(
                "could not parse intent '{intent}' (expected `swap <amount> <tok> to <tok>`)"
            ))
        })?;
        // For raw integer amounts against a hex token, prefer the raw value
        // verbatim — that matches our balance views. Otherwise look up
        // decimals: known symbols come from the static table; unknown hex
        // addresses go through an on-chain decimals() call so users can
        // specify amounts in human units (e.g. "1.5 0xabc...").
        let is_hex = nat.token_in.starts_with("0x") || nat.token_in.starts_with("0X");
        let decimals = if is_hex {
            if !nat.amount.contains('.') {
                0
            } else {
                let token_in = resolve_token_symbol(chain_id, &nat.token_in).ok_or_else(|| {
                    HandlerError::invalid(format!("unknown token '{}'", nat.token_in))
                })?;
                chain
                    .erc20_decimals(token_in)
                    .await
                    .map_err(|e| HandlerError::backend(e.to_string()))?
                    .ok_or_else(|| {
                        HandlerError::backend(format!(
                            "could not read decimals for {}",
                            checksum_address(&token_in)
                        ))
                    })?
            }
        } else {
            decimals_for_symbol(chain_id, &nat.token_in)
        };
        Self::compose_route_request(
            chain_id,
            destination_chain_id,
            from,
            &nat,
            decimals,
            receiver,
        )
    }

    /// Pure builder: turns a parsed intent + known decimals into a RouteRequest.
    /// Split out so unit tests can exercise the symbol path without an RPC.
    fn compose_route_request(
        chain_id: u64,
        destination_chain_id: Option<u64>,
        from: Address,
        nat: &bloom_defi::NaturalIntent,
        decimals_in: u8,
        receiver: Option<Address>,
    ) -> Result<RouteRequest, HandlerError> {
        let token_in = resolve_token_symbol(chain_id, &nat.token_in)
            .ok_or_else(|| HandlerError::invalid(format!("unknown token '{}'", nat.token_in)))?;
        let token_out_chain = destination_chain_id.unwrap_or(chain_id);
        let token_out = resolve_token_symbol(token_out_chain, &nat.token_out)
            .ok_or_else(|| HandlerError::invalid(format!("unknown token '{}'", nat.token_out)))?;
        let amount = bloom_proto::parse_units(&nat.amount, decimals_in)
            .map_err(|e| HandlerError::invalid(format!("amount: {e}")))?;
        Ok(RouteRequest {
            from_address: from,
            chain_id,
            destination_chain_id,
            token_in,
            token_out,
            amount_in: amount,
            slippage_bps: 50,
            routing_strategy: Some(RoutingStrategy::Router),
            receiver: receiver.or(destination_chain_id.map(|_| from)),
        })
    }

    /// Classify a route receiver from durable state — never guessed from the
    /// route. Order: owner EOA → polymarket deposit wallet → addressbook
    /// alias → unknown.
    fn classify_receiver(&self, wallet: &str, receiver: Address) -> bloom_proto::ReceiverClass {
        use bloom_proto::ReceiverClass;
        if let Ok(info) = self.keystore.info(wallet)
            && info.address == receiver
        {
            return ReceiverClass::WalletEoa;
        }
        if let Some(root) = &self.polymarket_root
            && let Ok(Some(st)) = bloom_polymarket::OnboardStore::new(root).load(wallet)
            && st
                .deposit_wallet
                .parse::<Address>()
                .map(|dw| dw == receiver)
                .unwrap_or(false)
        {
            return ReceiverClass::PolymarketDepositWallet;
        }
        if self.address_book.alias_for(&receiver).is_some() {
            return ReceiverClass::AddressbookAlias;
        }
        ReceiverClass::Unknown
    }

    /// Build the route-policy context for `evaluate_defi_route`. Sets the B1
    /// verification flags to `false` — the generic handler does not yet decode
    /// router calldata or simulate the balance delta, so it reports unverified
    /// honestly and lets policy decide deny-vs-warn.
    fn build_route_ctx(
        &self,
        wallet: &str,
        source_chain: &str,
        destination_chain: &str,
        req: &RouteRequest,
        route: &RouteResponse,
    ) -> bloom_proto::DefiRouteCtx {
        let receiver = req.receiver.unwrap_or(req.from_address);
        let cross_chain = source_chain != destination_chain;
        let (protocols, protocols_unknown) = route.protocols();
        bloom_proto::DefiRouteCtx {
            wallet: wallet.to_string(),
            source_chain: source_chain.to_string(),
            destination_chain: destination_chain.to_string(),
            cross_chain,
            receiver: format!("0x{:x}", receiver),
            token_out: format!("0x{:x}", req.token_out),
            receiver_class: self.classify_receiver(wallet, receiver),
            router: format!("0x{:x}", route.tx.to),
            protocols,
            protocols_unknown,
            // No USD price oracle wired here; leave input value unknown so a
            // configured max_input_usd fails closed rather than passing blind.
            input_microusd: None,
            native_value_wei: route.tx.value,
            min_out_enforced: false,
            receiver_verified: false,
        }
    }

    async fn create_session(
        &self,
        wallet: &str,
        body: NewIntentBody,
    ) -> Result<DefiSession, HandlerError> {
        let info = self
            .keystore
            .info(wallet)
            .map_err(|e| HandlerError::backend(e.to_string()))?;
        let chain_name = body
            .chain
            .clone()
            .unwrap_or_else(|| self.default_chain.clone());
        let chain = self.chain_client(&chain_name)?;
        let chain_id = chain
            .chain_id()
            .await
            .map_err(|e| HandlerError::backend(e.to_string()))?;

        let destination_chain_id = if let Some(ref dest_name) = body.destination_chain {
            let dest_chain = self.chain_client(dest_name)?;
            Some(
                dest_chain
                    .chain_id()
                    .await
                    .map_err(|e| HandlerError::backend(e.to_string()))?,
            )
        } else {
            None
        };

        let receiver = match body.receiver.as_deref() {
            Some(s) => Some(
                s.parse::<Address>()
                    .map_err(|_| HandlerError::invalid(format!("invalid receiver '{s}'")))?,
            ),
            None => None,
        };

        let mut req = Self::build_route_request(
            &chain,
            chain_id,
            destination_chain_id,
            info.address,
            &body.intent,
            receiver,
        )
        .await?;
        if let Some(bps) = body.slippage_bps {
            req.slippage_bps = bps;
        }

        let route = self.enso.route(req.clone()).await.map_err(map_enso_err)?;

        // Build the swap (Raw) intent and, when the source token is an
        // ERC-20 with insufficient allowance to the router, a preceding
        // approve intent. Order matters — the approve must broadcast and
        // confirm before the swap, but the outbox preserves stage order
        // and the wallet broadcasts in that order.
        let mut intents: Vec<RawIntent> = Vec::new();
        let needs_approve = req.token_in != NATIVE_TOKEN_ADDR;
        if needs_approve {
            let current = chain
                .erc20_allowance(req.token_in, info.address, route.tx.to)
                .await
                .map_err(|e| HandlerError::backend(e.to_string()))?
                .unwrap_or(U256::ZERO);
            if current < req.amount_in {
                intents.push(RawIntent {
                    body: RawIntentBody::Approve {
                        token: checksum_address(&req.token_in),
                        spender: checksum_address(&route.tx.to),
                        amount: "max".into(),
                    },
                    chain: Some(chain_name.clone()),
                    gas: GasStrategy::Auto,
                    nonce: None,
                    gas_limit_hint: None,
                });
            }
        }
        intents.push(RawIntent {
            body: RawIntentBody::Raw {
                to: checksum_address(&route.tx.to),
                value: route.tx.value.to_string(),
                data: format!("0x{}", hex::encode(route.tx.data.as_ref())),
            },
            chain: Some(chain_name.clone()),
            gas: GasStrategy::Auto,
            nonce: None,
            gas_limit_hint: route.gas.as_deref().and_then(|g| g.parse().ok()),
        });

        // Evaluate `[defi]` route policy for display + review (the hard gate
        // is at confirm, re-evaluated from current policy before staging).
        let dest_chain_name = body
            .destination_chain
            .clone()
            .unwrap_or_else(|| chain_name.clone());
        let route_ctx = self.build_route_ctx(wallet, &chain_name, &dest_chain_name, &req, &route);
        let receiver_class = route_ctx.receiver_class.as_str().to_string();
        let policy_checks = bloom_proto::evaluate_defi_route(&info.policy.defi, &route_ctx);
        let policy_checks_json =
            serde_json::to_value(&policy_checks).unwrap_or(serde_json::Value::Null);

        let token_display = self
            .route_token_display(&chain_name, &dest_chain_name, &req)
            .await;
        let plan = render_plan_md(
            &body.intent,
            &chain_name,
            body.destination_chain.as_deref(),
            &req,
            &route,
            &intents,
            &route_ctx,
            &policy_checks,
            &token_display,
        );
        let id = self.allocate_id(wallet);
        let now_ms = now_ms();
        let intent_states = (0..intents.len())
            .map(|index| DefiIntentState {
                index,
                status: DefiIntentStatus::Prepared,
                outbox_id: None,
                tx_hash: None,
                updated_ms: now_ms,
            })
            .collect();
        let observed_before =
            settlement_balance_for_request(self, body.destination_chain.as_deref(), &req)
                .await
                .ok()
                .flatten()
                .map(|v| v.to_string());
        let sess = DefiSession {
            id,
            wallet: wallet.to_string(),
            chain: chain_name,
            destination_chain: body.destination_chain,
            intent_text: body.intent,
            route_request: Some(req.clone()),
            route: Some(route),
            plan_md: plan,
            intents,
            intent_states,
            staged_ids: Vec::new(),
            created_ms: now_ms,
            updated_ms: now_ms,
            observed_before,
            min_settlement_delta: None,
            source_tx_hashes: Vec::new(),
            policy_checks: policy_checks_json,
            receiver_class: Some(receiver_class),
        };
        self.put_session(sess.clone())?;
        Ok(sess)
    }

    /// Run an `eth_call` simulation of the staged Enso tx. On revert,
    /// attach a structured `decoded_error` produced by the wired
    /// [`DecoderChain`].
    async fn simulate_session(
        &self,
        sess: &DefiSession,
    ) -> Result<serde_json::Value, HandlerError> {
        let route = sess
            .route
            .as_ref()
            .ok_or_else(|| HandlerError::backend("session has no route"))?;
        let chain = self.chain_client(&sess.chain)?;
        let req = TransactionRequest::default()
            .from(route.tx.from)
            .to(route.tx.to)
            .value(route.tx.value)
            .input(route.tx.data.clone().into());
        let to = Some(route.tx.to);
        match chain.eth_call_capture_revert(req, None).await {
            Ok(Ok(bytes)) => {
                tracing::debug!(
                    session = %sess.id,
                    chain = %sess.chain,
                    return_len = bytes.len(),
                    "defi.simulate_ok"
                );
                Ok(serde_json::json!({
                    "success": true,
                    "return_data": format!("0x{}", hex::encode(bytes.as_ref())),
                    "gas_estimate": route.gas,
                }))
            }
            Ok(Err(returndata)) => {
                let chain_id = chain
                    .chain_id()
                    .await
                    .map_err(|e| HandlerError::backend(e.to_string()))?;
                let ctx = DecodeContext {
                    returndata: returndata.clone(),
                    to,
                    chain_id,
                };
                let decoded = self.revert_decoder.decode(&ctx).await;
                tracing::debug!(
                    session = %sess.id,
                    chain = %sess.chain,
                    chain_id,
                    returndata_len = returndata.len(),
                    decoded_signature = ?decoded.signature,
                    decoded_message = ?decoded.message,
                    "defi.simulate_revert"
                );
                Ok(serde_json::json!({
                    "success": false,
                    "decoded_error": decoded,
                    "gas_estimate": route.gas,
                }))
            }
            Err(e) => {
                tracing::debug!(
                    session = %sess.id,
                    chain = %sess.chain,
                    error = %e,
                    "defi.simulate_call_err"
                );
                Ok(serde_json::json!({
                    "success": false,
                    "error": e.to_string(),
                    "gas_estimate": route.gas,
                }))
            }
        }
    }

    async fn confirm_session(&self, wallet: &str, id: &str) -> Result<Vec<StagedTx>, HandlerError> {
        let mut sess = self.get_session(wallet, id)?;
        if sess.wallet != wallet {
            return Err(HandlerError::PermissionDenied);
        }
        normalize_session_state(&mut sess);
        if sess.intents.is_empty() {
            return Err(HandlerError::backend("session has no prepared intents"));
        }
        let info = self
            .keystore
            .info(wallet)
            .map_err(|e| HandlerError::backend(e.to_string()))?;

        // ── route policy gate (B1/B2): re-evaluate from CURRENT policy, not
        // the session snapshot, and refuse on any Deny BEFORE staging. This
        // gate is on the generic defi/intents surface only; the purpose-built
        // `bloom polymarket fund` command stages through its own validated
        // path and is not affected by `[defi] enabled`.
        if let (Some(req), Some(route)) = (sess.route_request.as_ref(), sess.route.as_ref()) {
            let dest = sess
                .destination_chain
                .clone()
                .unwrap_or_else(|| sess.chain.clone());
            let ctx = self.build_route_ctx(wallet, &sess.chain, &dest, req, route);
            let checks = bloom_proto::evaluate_defi_route(&info.policy.defi, &ctx);
            sess.policy_checks = serde_json::to_value(&checks).unwrap_or(serde_json::Value::Null);
            self.put_session(sess.clone())?;
            if let Some(d) = checks
                .iter()
                .find(|c| c.outcome == bloom_proto::PolicyOutcome::Deny)
            {
                return Err(HandlerError::invalid(format!(
                    "DeFi route policy denied [{}]: {} — deny-level policy is not \
                     bypassable; edit the wallet's [defi] policy to change it",
                    d.rule, d.message
                )));
            }
        } else {
            return Err(HandlerError::backend(
                "session has no route to policy-check; refusing to stage",
            ));
        }

        let chain = self.chain_client(&sess.chain)?;
        let mut staged_list = Vec::with_capacity(sess.intents.len());
        for (idx, intent) in sess.intents.iter().cloned().enumerate() {
            if let Some(existing) = sess
                .intent_states
                .get(idx)
                .and_then(|s| s.outbox_id.as_deref())
            {
                match self.tx_engine.outbox.read(wallet, &sess.chain, existing) {
                    Ok(entry) => {
                        if matches!(entry.state, bloom_tx::outbox::OutboxState::Pending) {
                            staged_list.push(entry.staged);
                            continue;
                        }
                        return Err(HandlerError::backend(format!(
                            "intent {idx} already has outbox id {existing} in state {}; refusing to restage automatically",
                            entry.state.dirname()
                        )));
                    }
                    Err(e) => {
                        return Err(HandlerError::backend(format!(
                            "intent {idx} already had outbox id {existing}, but it is not readable: {e}; refusing to duplicate"
                        )));
                    }
                }
            }
            let staged = self
                .tx_engine
                .stage(
                    self.write_permit()?,
                    wallet,
                    info.address,
                    intent,
                    &chain,
                    &info.policy,
                    Some(&self.address_book),
                )
                .await
                .map_err(|e| HandlerError::backend(e.to_string()))?;
            if let Some(state) = sess.intent_states.get_mut(idx) {
                state.status = DefiIntentStatus::Staged;
                state.outbox_id = Some(staged.id.clone());
                state.updated_ms = now_ms();
            }
            sess.staged_ids = sess
                .intent_states
                .iter()
                .filter_map(|s| s.outbox_id.clone())
                .collect();
            sess.updated_ms = now_ms();
            self.put_session(sess.clone())?;
            staged_list.push(staged);
        }
        sess.staged_ids = staged_list.iter().map(|s| s.id.clone()).collect();
        sess.updated_ms = now_ms();
        self.put_session(sess)?;
        Ok(staged_list)
    }

    async fn route_token_display(
        &self,
        source_chain: &str,
        destination_chain: &str,
        req: &RouteRequest,
    ) -> RouteTokenDisplay {
        let token_in = self.token_display(source_chain, req.token_in).await;
        let token_out = self.token_display(destination_chain, req.token_out).await;
        RouteTokenDisplay {
            token_in,
            token_out,
        }
    }

    async fn token_display(&self, chain_name: &str, token: Address) -> TokenDisplay {
        let chain = self.chain_client(chain_name).ok();
        if token == NATIVE_TOKEN_ADDR {
            if let Some(chain) = chain.as_ref() {
                return TokenDisplay {
                    chain: chain_name.to_string(),
                    address: None,
                    symbol: chain.spec().native_symbol.clone(),
                    decimals: chain.spec().native_decimals,
                };
            }
            return TokenDisplay {
                chain: chain_name.to_string(),
                address: None,
                symbol: "native".into(),
                decimals: 18,
            };
        }

        let symbol = if let Some(chain) = chain.as_ref() {
            chain
                .erc20_symbol(token)
                .await
                .ok()
                .flatten()
                .filter(|s| !s.trim().is_empty())
        } else {
            None
        };
        let decimals = if let Some(chain) = chain.as_ref() {
            chain.erc20_decimals(token).await.ok().flatten()
        } else {
            None
        };
        TokenDisplay {
            chain: chain_name.to_string(),
            address: Some(token),
            symbol: symbol.unwrap_or_else(|| checksum_address(&token)),
            decimals: decimals.unwrap_or(18),
        }
    }

    async fn settlement_status(
        &self,
        sess: &DefiSession,
    ) -> Result<SettlementStatus, HandlerError> {
        let route = sess
            .route
            .as_ref()
            .ok_or_else(|| HandlerError::backend("session has no route"))?;
        let destination_chain = sess.destination_chain.as_deref().unwrap_or(&sess.chain);
        let req = route_request_from_session(sess)?;
        let observed_after = settlement_balance_for_request(self, Some(destination_chain), &req)
            .await?
            .map(|v| v.to_string());
        let before = sess
            .observed_before
            .as_deref()
            .and_then(|s| s.parse::<U256>().ok());
        let after = observed_after
            .as_deref()
            .and_then(|s| s.parse::<U256>().ok());
        let delta = match (before, after) {
            (Some(b), Some(a)) => Some(a.saturating_sub(b)),
            _ => None,
        };
        let expected = parse_decimal_u256(&route.amount_out);
        let minimum = sess
            .min_settlement_delta
            .as_deref()
            .and_then(|s| s.parse::<U256>().ok())
            .or(expected);
        let status = if minimum.is_none() {
            "unknown_expected_output"
        } else if sess.destination_chain.is_none() {
            "same_chain_no_bridge"
        } else if delta.is_some_and(|d| d >= minimum.unwrap()) {
            "destination_received"
        } else if sess.staged_ids.is_empty() {
            "not_broadcast"
        } else {
            "destination_pending"
        };
        Ok(SettlementStatus {
            session: sess.id.clone(),
            wallet: sess.wallet.clone(),
            source_chain: sess.chain.clone(),
            destination_chain: destination_chain.to_string(),
            destination_token: checksum_address(&req.token_out),
            destination_receiver: req.receiver.map(|a| checksum_address(&a)),
            expected_output: route.amount_out.clone(),
            minimum_delta: minimum
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".into()),
            observed_before: sess.observed_before.clone(),
            observed_after,
            observed_delta: delta.map(|v| v.to_string()),
            status: status.to_string(),
            source_tx_hashes: self.source_hashes_for_session(sess),
            note: if sess.destination_chain.is_none() {
                "same-chain route; settlement waiter is not required".into()
            } else {
                "source-chain confirmation is not cross-chain completion; wait for destination balance delta before dependent legs".into()
            },
        })
    }

    async fn wait_settlement(
        &self,
        sess: &DefiSession,
        timeout: Duration,
        interval: Duration,
    ) -> Result<SettlementStatus, HandlerError> {
        let started = SystemTime::now();
        loop {
            let status = self.settlement_status(sess).await?;
            if matches!(
                status.status.as_str(),
                "destination_received" | "same_chain_no_bridge"
            ) {
                return Ok(status);
            }
            if started.elapsed().unwrap_or_default() >= timeout {
                return Ok(SettlementStatus {
                    status: "timeout_check_bridge".into(),
                    note: format!(
                        "timed out waiting for destination funds; rerun wait_settlement or inspect bridge/source txs: {}",
                        status.source_tx_hashes.join(",")
                    ),
                    ..status
                });
            }
            tokio::time::sleep(interval).await;
        }
    }

    fn source_hashes_for_session(&self, sess: &DefiSession) -> Vec<String> {
        let mut out = sess.source_tx_hashes.clone();
        for id in &sess.staged_ids {
            if let Ok(entry) = self.tx_engine.outbox.read(&sess.wallet, &sess.chain, id)
                && let Some(hash) = entry.staged.tx_hash
            {
                out.push(hash);
            }
        }
        out.sort();
        out.dedup();
        out
    }
}

#[async_trait]
impl Handler for DefiHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let r = self.lookup_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "defi.lookup_err");
        }
        r
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let r = self.read_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "defi.read_err");
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
                "defi.write_err"
            );
        }
        r
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let r = self.list_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "defi.list_err");
        }
        r
    }
}

impl DefiHandler {
    async fn lookup_inner(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segs = path.segments();
        if segs.is_empty() {
            return Ok(Entry::dir(""));
        }
        match segs[0].as_str() {
            "intents" => match segs.len() {
                1 => Ok(Entry::dir("intents")),
                2 => Ok(Entry::dir(&segs[1])),
                3 if segs[2] == "new" => Ok(Entry::writable_file("new")),
                3 => {
                    // /<wallet>/<session>
                    let _ = self.get_session(&segs[1], &segs[2])?;
                    Ok(Entry::dir(&segs[2]))
                }
                4 => {
                    let _ = self.get_session(&segs[1], &segs[2])?;
                    if is_session_file(&segs[3]) {
                        if segs[3] == "confirm" {
                            Ok(Entry::writable_file(&segs[3]))
                        } else {
                            Ok(Entry::file(&segs[3]))
                        }
                    } else {
                        Err(HandlerError::not_found(path.to_string_path()))
                    }
                }
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn read_inner(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = path.segments();
        if segs.len() != 4 || segs[0] != "intents" {
            return Err(HandlerError::NotAFile(path.to_string_path()));
        }
        let wallet = &segs[1];
        let id = &segs[2];
        let fname = segs[3].as_str();
        let sess = self.get_session(wallet, id)?;
        match fname {
            "intent.txt" => Ok(format!("{}\n", sess.intent_text).into_bytes()),
            "route.json" => {
                let r = sess
                    .route
                    .as_ref()
                    .ok_or_else(|| HandlerError::backend("no route"))?;
                Ok(serde_json::to_vec_pretty(r).unwrap())
            }
            "plan.md" => Ok(sess.plan_md.clone().into_bytes()),
            "policy_check.json" => Ok(serde_json::to_vec_pretty(&sess.policy_checks).unwrap()),
            "tx.json" => {
                if sess.intents.is_empty() {
                    return Err(HandlerError::backend("no tx intents"));
                }
                Ok(serde_json::to_vec_pretty(&sess.intents).unwrap())
            }
            "simulation.json" => {
                let v = self.simulate_session(&sess).await?;
                Ok(serde_json::to_vec_pretty(&v).unwrap())
            }
            "settlement.json" => {
                let v = self.settlement_status(&sess).await?;
                Ok(serde_json::to_vec_pretty(&v).unwrap())
            }
            "wait_settlement" => {
                let v = self
                    .wait_settlement(&sess, Duration::from_secs(300), Duration::from_secs(5))
                    .await?;
                Ok(serde_json::to_vec_pretty(&v).unwrap())
            }
            "destination_chain.txt" => {
                let name = sess.destination_chain.as_deref().unwrap_or("");
                Ok(format!("{name}\n").into_bytes())
            }
            "confirm" => Ok(b"# write any non-empty content to stage into outbox\n".to_vec()),
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn write_inner(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let segs = path.segments();
        if segs.is_empty() || segs[0] != "intents" {
            return Err(HandlerError::PermissionDenied);
        }
        match segs.len() {
            // intents/<wallet>/new
            3 if segs[2] == "new" => {
                let body = std::str::from_utf8(data)
                    .map_err(|_| HandlerError::invalid("non-utf8 intent body"))?;
                let parsed = Self::parse_new_body(body)?;
                let sess = self.create_session(&segs[1], parsed).await?;
                tracing::info!(wallet = %sess.wallet, session = %sess.id, "defi.session.created");
                Ok(())
            }
            // intents/<wallet>/<session>/confirm
            4 if segs[3] == "confirm" => {
                let trimmed = std::str::from_utf8(data).unwrap_or("").trim();
                if trimmed.is_empty() {
                    return Err(HandlerError::invalid("empty confirm"));
                }
                let staged = self.confirm_session(&segs[1], &segs[2]).await?;
                let ids: Vec<&str> = staged.iter().map(|s| s.id.as_str()).collect();
                tracing::info!(
                    wallet = %segs[1],
                    session = %segs[2],
                    staged = ids.join(","),
                    count = staged.len(),
                    "defi.session.confirmed"
                );
                Ok(())
            }
            _ => Err(HandlerError::PermissionDenied),
        }
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segs = path.segments();
        match segs.len() {
            0 => Ok(vec![Entry::dir("intents")]),
            1 if segs[0] == "intents" => Ok(self
                .list_session_wallets()
                .into_iter()
                .map(|w| Entry::dir(&w))
                .collect()),
            2 if segs[0] == "intents" => {
                // List "new" + sessions for this wallet (does not require
                // wallet to exist if no sessions, but if it doesn't exist
                // we show only `new`).
                let mut out = vec![Entry::writable_file("new")];
                for id in self.list_sessions_for_wallet(&segs[1]) {
                    out.push(Entry::dir(&id));
                }
                Ok(out)
            }
            3 if segs[0] == "intents" => {
                let _ = self.get_session(&segs[1], &segs[2])?;
                Ok(vec![
                    Entry::file("intent.txt"),
                    Entry::file("route.json"),
                    Entry::file("plan.md"),
                    Entry::file("policy_check.json"),
                    Entry::file("tx.json"),
                    Entry::file("simulation.json"),
                    Entry::file("settlement.json"),
                    Entry::file("wait_settlement"),
                    Entry::file("destination_chain.txt"),
                    Entry::writable_file("confirm"),
                ])
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }
}

fn is_session_file(s: &str) -> bool {
    matches!(
        s,
        "intent.txt"
            | "route.json"
            | "plan.md"
            | "policy_check.json"
            | "tx.json"
            | "simulation.json"
            | "settlement.json"
            | "wait_settlement"
            | "destination_chain.txt"
            | "confirm"
    )
}

fn map_enso_err(e: EnsoError) -> HandlerError {
    match e {
        EnsoError::Disabled | EnsoError::MissingKey => {
            HandlerError::Unsupported("Enso is disabled (no API key)".into())
        }
        EnsoError::InvalidIntent(s) => HandlerError::invalid(s),
        other => HandlerError::backend(other.to_string()),
    }
}

fn decimals_for_symbol(chain_id: u64, sym: &str) -> u8 {
    let upper = sym.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "ETH" | "ETHER" | "WETH" | "MATIC" | "BNB" | "AVAX"
    ) {
        return 18;
    }
    match (chain_id, upper.as_str()) {
        (_, "USDC" | "USDT") => 6,
        (1, "DAI") => 18,
        (1, "WBTC") => 8,
        _ => 18,
    }
}

#[derive(Debug, Clone)]
struct RouteTokenDisplay {
    token_in: TokenDisplay,
    token_out: TokenDisplay,
}

#[derive(Debug, Clone)]
struct TokenDisplay {
    chain: String,
    address: Option<Address>,
    symbol: String,
    decimals: u8,
}

fn render_token_amount(token: &TokenDisplay, raw: U256) -> String {
    let human = format_units(raw, token.decimals);
    let location = if token.address.is_some() {
        format!("{} on {}", token.symbol, token.chain)
    } else {
        format!("{} native on {}", token.symbol, token.chain)
    };
    let address = token
        .address
        .map(|addr| format!("  address={}", checksum_address(&addr)))
        .unwrap_or_else(|| "  address=native".to_string());
    format!("{location}  amount={human} (raw {raw}){address}")
}

fn render_token_quote(token: &TokenDisplay, raw: &str) -> String {
    let raw_u256 = raw.parse::<U256>().ok();
    let human = raw_u256
        .map(|value| format_units(value, token.decimals))
        .unwrap_or_else(|| raw.to_string());
    let location = if token.address.is_some() {
        format!("{} on {}", token.symbol, token.chain)
    } else {
        format!("{} native on {}", token.symbol, token.chain)
    };
    let address = token
        .address
        .map(|addr| format!("  address={}", checksum_address(&addr)))
        .unwrap_or_else(|| "  address=native".to_string());
    format!("{location}  amountOut≈{human} (raw {raw}, Enso quote, not an enforced floor){address}")
}

#[allow(clippy::too_many_arguments)]
fn render_plan_md(
    intent: &str,
    chain: &str,
    destination_chain: Option<&str>,
    req: &RouteRequest,
    route: &RouteResponse,
    intents: &[RawIntent],
    ctx: &bloom_proto::DefiRouteCtx,
    checks: &[bloom_proto::PolicyCheck],
    token_display: &RouteTokenDisplay,
) -> String {
    let mut s = String::new();
    s.push_str("# DeFi intent\n\n");
    s.push_str(&format!("Intent:    {intent}\n"));
    s.push_str(&format!("Chain:     {chain} (id {})\n", req.chain_id));
    if let Some(ref dest) = destination_chain {
        s.push_str(&format!("Dest chain:{dest}"));
        if let Some(dest_id) = req.destination_chain_id {
            s.push_str(&format!(" (id {dest_id})"));
        }
        s.push('\n');
    }
    s.push_str(&format!(
        "From:      {}\n",
        checksum_address(&req.from_address)
    ));
    // High-risk fields up top: receiver + classification, router, protocols.
    let receiver = req.receiver.unwrap_or(req.from_address);
    s.push_str(&format!("Receiver:  {}\n", checksum_address(&receiver)));
    s.push_str(&format!("Receiver type: {}\n", ctx.receiver_class.as_str()));
    s.push_str(&format!(
        "Token in:  {}\n",
        render_token_amount(&token_display.token_in, req.amount_in)
    ));
    s.push_str(&format!(
        "Token out: {}\n",
        render_token_quote(&token_display.token_out, &route.amount_out)
    ));
    s.push_str(&format!("Slippage:  {} bps\n", req.slippage_bps));
    s.push_str(&format!("Router:    {}\n", checksum_address(&route.tx.to)));
    if ctx.protocols_unknown {
        s.push_str("Protocols: <unparsed>\n");
    } else if !ctx.protocols.is_empty() {
        s.push_str(&format!("Protocols: {}\n", ctx.protocols.join(" -> ")));
    }
    if let Some(ref g) = route.gas {
        s.push_str(&format!("Gas:       {g}\n"));
    }
    if let Some(p) = route.price_impact {
        s.push_str(&format!(
            "Impact:    {p} (Enso-reported; unit unverified)\n"
        ));
    }
    s.push_str(&format!("Tx value:  {} wei\n", route.tx.value));
    s.push_str(&format!("Tx data:   {} bytes\n", route.tx.data.len()));

    // ## Policy — every check, with the deny rule's fix already in its message.
    s.push_str("\n## Policy\n");
    for c in checks {
        let tag = match c.outcome {
            bloom_proto::PolicyOutcome::Pass => "PASS",
            bloom_proto::PolicyOutcome::Warn => "WARN",
            bloom_proto::PolicyOutcome::Deny => "DENY",
        };
        s.push_str(&format!("{tag} {}: {}\n", c.rule, c.message));
    }
    if checks
        .iter()
        .any(|c| c.outcome == bloom_proto::PolicyOutcome::Deny)
    {
        s.push_str("\nThis route is DENIED by policy and will refuse at confirm. Fix the cited [defi] policy keys above.\n");
    }

    let auto_approve = intents
        .iter()
        .any(|i| matches!(i.body, RawIntentBody::Approve { .. }));
    if auto_approve {
        s.push_str(&format!(
            "\n## Auto-approve\n\
             Existing allowance for {} → {} is below {} (raw). An \
             ERC-20 `approve(spender, max)` will be staged ahead of the \
             swap and must broadcast first; both sit in the same outbox \
             and will be reviewed before sending.\n",
            checksum_address(&req.token_in),
            checksum_address(&route.tx.to),
            req.amount_in,
        ));
    }
    s.push_str("\n## Confirm\n");
    s.push_str(&format!(
        "Write any non-empty content to `confirm` to stage {} tx{} \
         through the wallet's outbox; review there before \
         broadcasting.\n",
        intents.len(),
        if intents.len() == 1 { "" } else { "s" },
    ));
    s
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn default_store_root() -> PathBuf {
    if let Ok(home) = std::env::var("BLOOM_HOME") {
        return PathBuf::from(home).join("defi");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".bloom").join("defi");
    }
    PathBuf::from(".bloom").join("defi")
}

fn normalize_session_state(sess: &mut DefiSession) {
    if sess.updated_ms == 0 {
        sess.updated_ms = sess.created_ms;
    }
    if sess.intent_states.len() != sess.intents.len() {
        let now = now_ms();
        sess.intent_states = (0..sess.intents.len())
            .map(|index| DefiIntentState {
                index,
                status: DefiIntentStatus::Prepared,
                outbox_id: sess.staged_ids.get(index).cloned(),
                tx_hash: None,
                updated_ms: now,
            })
            .collect();
    }
    sess.staged_ids = sess
        .intent_states
        .iter()
        .filter_map(|s| s.outbox_id.clone())
        .collect();
}

fn route_request_from_session(sess: &DefiSession) -> Result<RouteRequest, HandlerError> {
    sess.route_request
        .clone()
        .ok_or_else(|| HandlerError::backend("session has no persisted route request"))
}

fn parse_decimal_u256(s: &str) -> Option<U256> {
    if s.contains('.') {
        return None;
    }
    s.parse::<U256>().ok()
}

async fn settlement_balance_for_request(
    handler: &DefiHandler,
    destination_chain: Option<&str>,
    req: &RouteRequest,
) -> Result<Option<U256>, HandlerError> {
    let receiver = match req.receiver {
        Some(r) => r,
        None => return Ok(None),
    };
    let chain_name = destination_chain.ok_or_else(|| {
        HandlerError::backend("cross-chain route has no destination chain name in session")
    })?;
    let chain = handler.chain_client(chain_name)?;
    chain
        .erc20_balance(req.token_out, receiver)
        .await
        .map_err(|e| HandlerError::backend(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_tx::outbox::Outbox;

    fn test_handler(root: &std::path::Path) -> DefiHandler {
        let keystore = Keystore::new(root.join("keystore")).unwrap();
        let outbox = Outbox::new(root.join("outbox")).unwrap();
        let tx_engine = TxEngine::new(outbox, 60_000, false);
        DefiHandler::new(
            EnsoClient::new(""),
            ChainRegistry::default(),
            keystore,
            tx_engine,
            Arc::new(AddressBook::default()),
        )
        .with_store_root(root.join("defi"))
    }

    /// Minimal route ctx for plan-render tests (unknown receiver, unverified —
    /// the honest default).
    fn test_route_ctx(req: &RouteRequest, route: &RouteResponse) -> bloom_proto::DefiRouteCtx {
        let receiver = req.receiver.unwrap_or(req.from_address);
        let (protocols, protocols_unknown) = route.protocols();
        bloom_proto::DefiRouteCtx {
            wallet: "alice".into(),
            source_chain: "ethereum".into(),
            destination_chain: "ethereum".into(),
            cross_chain: false,
            receiver: format!("0x{:x}", receiver),
            token_out: format!("0x{:x}", req.token_out),
            receiver_class: bloom_proto::ReceiverClass::Unknown,
            router: format!("0x{:x}", route.tx.to),
            protocols,
            protocols_unknown,
            input_microusd: None,
            native_value_wei: route.tx.value,
            min_out_enforced: false,
            receiver_verified: false,
        }
    }

    fn test_token_display(
        source_chain: &str,
        source_symbol: &str,
        source_decimals: u8,
        dest_chain: &str,
        dest_symbol: &str,
        dest_decimals: u8,
    ) -> RouteTokenDisplay {
        RouteTokenDisplay {
            token_in: TokenDisplay {
                chain: source_chain.into(),
                address: Some(Address::ZERO),
                symbol: source_symbol.into(),
                decimals: source_decimals,
            },
            token_out: TokenDisplay {
                chain: dest_chain.into(),
                address: Some(Address::ZERO),
                symbol: dest_symbol.into(),
                decimals: dest_decimals,
            },
        }
    }

    fn fake_session(wallet: &str, id: &str) -> DefiSession {
        let req = RouteRequest {
            from_address: Address::ZERO,
            chain_id: 1,
            destination_chain_id: Some(137),
            token_in: Address::ZERO,
            token_out: Address::ZERO,
            amount_in: U256::from(1u64),
            slippage_bps: 50,
            routing_strategy: Some(RoutingStrategy::Router),
            receiver: Some(Address::ZERO),
        };
        let route = RouteResponse {
            tx: bloom_defi::RouteTx {
                from: Address::ZERO,
                to: Address::ZERO,
                data: Default::default(),
                value: U256::ZERO,
            },
            amount_out: "1".into(),
            gas: None,
            route: serde_json::Value::Null,
            price_impact: None,
            destination_chain_id: Some(137),
        };
        let intents = vec![RawIntent {
            body: RawIntentBody::Raw {
                to: checksum_address(&Address::ZERO),
                value: "0".into(),
                data: "0x".into(),
            },
            chain: Some("ethereum".into()),
            gas: GasStrategy::Auto,
            nonce: None,
            gas_limit_hint: None,
        }];
        let now = now_ms();
        DefiSession {
            id: id.into(),
            wallet: wallet.into(),
            chain: "ethereum".into(),
            destination_chain: Some("polygon".into()),
            intent_text: "swap 1 ETH to USDC".into(),
            route_request: Some(req),
            route: Some(route),
            plan_md: "# plan".into(),
            intents,
            intent_states: vec![DefiIntentState {
                index: 0,
                status: DefiIntentStatus::Prepared,
                outbox_id: None,
                tx_hash: None,
                updated_ms: now,
            }],
            staged_ids: Vec::new(),
            created_ms: now,
            updated_ms: now,
            observed_before: Some("0".into()),
            min_settlement_delta: Some("1".into()),
            source_tx_hashes: Vec::new(),
            policy_checks: serde_json::Value::Null,
            receiver_class: None,
        }
    }

    #[test]
    fn parse_new_body_json() {
        let b = DefiHandler::parse_new_body(
            r#"{"kind":"enso","intent":"swap 1 ETH to USDC","chain":"ethereum","destination_chain":"polygon","receiver":"0x0000000000000000000000000000000000000001"}"#,
        )
        .unwrap();
        assert_eq!(b.intent, "swap 1 ETH to USDC");
        assert_eq!(b.chain.as_deref(), Some("ethereum"));
        assert_eq!(b.destination_chain.as_deref(), Some("polygon"));
        assert_eq!(
            b.receiver.as_deref(),
            Some("0x0000000000000000000000000000000000000001")
        );
    }

    #[test]
    fn parse_new_body_plain() {
        let b = DefiHandler::parse_new_body("swap 1 ETH to USDC on ethereum").unwrap();
        assert_eq!(b.intent, "swap 1 ETH to USDC on ethereum");
        assert!(b.chain.is_none());
    }

    #[test]
    fn parse_new_body_empty_errors() {
        assert!(DefiHandler::parse_new_body("").is_err());
        assert!(DefiHandler::parse_new_body("{}").is_err());
    }

    #[test]
    fn build_route_request_resolves_eth_to_usdc() {
        let from: Address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
            .parse()
            .unwrap();
        let nat = bloom_defi::parse_natural_intent("swap 1 ETH to USDC").unwrap();
        let req = DefiHandler::compose_route_request(1, None, from, &nat, 18, None).unwrap();
        assert_eq!(req.chain_id, 1);
        assert_eq!(req.amount_in, U256::from(1_000_000_000_000_000_000u128));
        // USDC mainnet
        assert_eq!(
            req.token_out.to_checksum(None),
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        );
    }

    #[test]
    fn build_route_request_unknown_token_errors() {
        let from = Address::ZERO;
        let nat = bloom_defi::parse_natural_intent("swap 1 FOO to BAR").unwrap();
        let err = DefiHandler::compose_route_request(1, None, from, &nat, 18, None).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn cross_chain_route_sets_receiver() {
        let from: Address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
            .parse()
            .unwrap();
        let receiver: Address = "0x1000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let nat = bloom_defi::parse_natural_intent(
            "swap 1 USDC to 0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB",
        )
        .unwrap();

        let explicit =
            DefiHandler::compose_route_request(8453, Some(137), from, &nat, 6, Some(receiver))
                .unwrap();
        assert_eq!(explicit.destination_chain_id, Some(137));
        assert_eq!(explicit.receiver, Some(receiver));

        let defaulted =
            DefiHandler::compose_route_request(8453, Some(137), from, &nat, 6, None).unwrap();
        assert_eq!(defaulted.receiver, Some(from));
    }

    #[test]
    fn render_plan_md_includes_key_fields() {
        let req = RouteRequest {
            from_address: Address::ZERO,
            chain_id: 1,
            destination_chain_id: None,
            token_in: Address::ZERO,
            token_out: Address::ZERO,
            amount_in: U256::from(1u64),
            slippage_bps: 50,
            routing_strategy: None,
            receiver: None,
        };
        let route = RouteResponse {
            tx: bloom_defi::RouteTx {
                from: Address::ZERO,
                to: Address::ZERO,
                data: Default::default(),
                value: U256::ZERO,
            },
            amount_out: "100".into(),
            gas: Some("21000".into()),
            route: serde_json::Value::Null,
            price_impact: Some(0.1),
            destination_chain_id: None,
        };
        let intents = vec![RawIntent {
            body: RawIntentBody::Raw {
                to: checksum_address(&route.tx.to),
                value: route.tx.value.to_string(),
                data: "0x".into(),
            },
            chain: Some("ethereum".into()),
            gas: GasStrategy::Auto,
            nonce: None,
            gas_limit_hint: None,
        }];
        let ctx = test_route_ctx(&req, &route);
        let checks = bloom_proto::evaluate_defi_route(&bloom_proto::DefiPolicy::default(), &ctx);
        let token_display = test_token_display("ethereum", "ETH", 18, "ethereum", "USDC", 6);
        let md = render_plan_md(
            "swap 1 ETH to USDC",
            "ethereum",
            None,
            &req,
            &route,
            &intents,
            &ctx,
            &checks,
            &token_display,
        );
        assert!(md.contains("swap 1 ETH to USDC"));
        assert!(md.contains("Token in:  ETH on ethereum"));
        assert!(md.contains("(raw 1)"));
        assert!(md.contains("Token out: USDC on ethereum"));
        assert!(md.contains("Slippage:  50 bps"));
        assert!(md.contains("Confirm"));
        assert!(!md.contains("Auto-approve"));
    }

    #[test]
    fn render_plan_md_shows_auto_approve_when_present() {
        let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();
        let router: Address = "0xF75584eF6673aD213a685a1B58Cc0330B8eA22Cf"
            .parse()
            .unwrap();
        let req = RouteRequest {
            from_address: Address::ZERO,
            chain_id: 1,
            destination_chain_id: None,
            token_in: usdc,
            token_out: Address::ZERO,
            amount_in: U256::from(1_000_000u64),
            slippage_bps: 50,
            routing_strategy: None,
            receiver: None,
        };
        let route = RouteResponse {
            tx: bloom_defi::RouteTx {
                from: Address::ZERO,
                to: router,
                data: Default::default(),
                value: U256::ZERO,
            },
            amount_out: "0".into(),
            gas: None,
            route: serde_json::Value::Null,
            price_impact: None,
            destination_chain_id: None,
        };
        let intents = vec![
            RawIntent {
                body: RawIntentBody::Approve {
                    token: checksum_address(&usdc),
                    spender: checksum_address(&router),
                    amount: "max".into(),
                },
                chain: Some("ethereum".into()),
                gas: GasStrategy::Auto,
                nonce: None,
                gas_limit_hint: None,
            },
            RawIntent {
                body: RawIntentBody::Raw {
                    to: checksum_address(&router),
                    value: "0".into(),
                    data: "0x".into(),
                },
                chain: Some("ethereum".into()),
                gas: GasStrategy::Auto,
                nonce: None,
                gas_limit_hint: None,
            },
        ];
        let ctx = test_route_ctx(&req, &route);
        let checks = bloom_proto::evaluate_defi_route(&bloom_proto::DefiPolicy::default(), &ctx);
        let token_display = test_token_display("ethereum", "USDC", 6, "ethereum", "ETH", 18);
        let md = render_plan_md(
            "swap 1 USDC to ETH",
            "ethereum",
            None,
            &req,
            &route,
            &intents,
            &ctx,
            &checks,
            &token_display,
        );
        assert!(md.contains("Auto-approve"));
        assert!(md.contains("approve(spender, max)"));
        assert!(md.contains("stage 2 txs"));
    }

    #[tokio::test]
    async fn confirm_refuses_on_default_deny_policy() {
        // A wallet with default policy ([defi] disabled) must refuse to stage
        // a route at confirm — before any TxEngine::stage.
        let td = tempfile::tempdir().unwrap();
        let h = test_handler(td.path());
        h.keystore.create_local("alice", "pw").unwrap();
        let mut sess = fake_session("alice", "s1");
        sess.chain = "ethereum".into();
        sess.destination_chain = None;
        h.put_session(sess).unwrap();
        let err = h.confirm_session("alice", "s1").await.unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("defi.enabled") || msg.to_lowercase().contains("disabled"),
            "default-deny must cite the defi gate, got: {msg}"
        );
    }

    #[test]
    fn classify_receiver_resolves_owner_eoa() {
        let td = tempfile::tempdir().unwrap();
        let h = test_handler(td.path());
        let info = h.keystore.create_local("alice", "pw").unwrap();
        assert_eq!(
            h.classify_receiver("alice", info.address),
            bloom_proto::ReceiverClass::WalletEoa
        );
        // a random address is unknown
        let other: Address = "0x000000000000000000000000000000000000dEaD"
            .parse()
            .unwrap();
        assert_eq!(
            h.classify_receiver("alice", other),
            bloom_proto::ReceiverClass::Unknown
        );
    }

    #[test]
    fn durable_session_round_trips_through_store() {
        let td = tempfile::tempdir().unwrap();
        let h1 = test_handler(td.path());
        let sess = fake_session("alice", "s1");
        h1.put_session(sess.clone()).unwrap();

        let h2 = test_handler(td.path());
        let loaded = h2.get_session("alice", "s1").unwrap();
        assert_eq!(loaded.wallet, "alice");
        assert_eq!(loaded.id, "s1");
        assert_eq!(
            loaded.route_request.unwrap().destination_chain_id,
            Some(137)
        );
        assert_eq!(loaded.intent_states.len(), 1);
    }

    #[test]
    fn normalize_session_state_lifts_legacy_staged_ids() {
        let mut sess = fake_session("alice", "s1");
        sess.intent_states.clear();
        sess.staged_ids = vec!["0001-old".into()];
        normalize_session_state(&mut sess);
        assert_eq!(sess.intent_states.len(), 1);
        assert_eq!(sess.intent_states[0].outbox_id.as_deref(), Some("0001-old"));
        assert_eq!(sess.staged_ids, vec!["0001-old"]);
    }

    #[test]
    fn allocate_id_does_not_reuse_existing_session_file() {
        let td = tempfile::tempdir().unwrap();
        let h = test_handler(td.path());
        let first = h.allocate_id("alice");
        let mut sess = fake_session("alice", &first);
        h.put_session(sess.clone()).unwrap();
        let second = h.allocate_id("alice");
        assert_ne!(first, second);
        sess.id = second.clone();
        h.put_session(sess).unwrap();
        assert!(h.session_path("alice", &second).exists());
    }
}
