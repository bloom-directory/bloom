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
//! - `defi/intents/<wallet>/<session>/confirm`      — write to stage into outbox
//!
//! Sessions live in memory (RwLock<HashMap<id, DefiSession>>) only; they
//! evaporate on daemon restart by design — the staged outbox entry is
//! the durable artefact.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, U256, address};
use alloy::rpc::types::eth::TransactionRequest;
use async_trait::async_trait;
use bloom_chain::{ChainClient, ChainRegistry};
use bloom_defi::{
    EnsoClient, EnsoError, RouteRequest, RouteResponse, RoutingStrategy, parse_natural_intent,
    resolve_token_symbol,
};
use bloom_keystore::Keystore;
use bloom_proto::{AddressBook, GasStrategy, RawIntent, RawIntentBody, StagedTx, checksum_address};
use bloom_revert::{DecodeContext, DecoderChain};
use bloom_tx::tx_engine::TxEngine;
use parking_lot::RwLock;
use serde::Deserialize;

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
#[derive(Debug, Clone)]
pub struct DefiSession {
    pub id: String,
    pub wallet: String,
    pub chain: String,
    pub intent_text: String,
    pub route: Option<RouteResponse>,
    pub plan_md: String,
    pub intents: Vec<RawIntent>,
    pub staged_ids: Vec<String>,
    pub created_ms: u128,
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
    slippage_bps: Option<u16>,
}

#[derive(Clone)]
pub struct DefiHandler {
    enso: EnsoClient,
    chains: ChainRegistry,
    keystore: Keystore,
    tx_engine: TxEngine,
    address_book: Arc<AddressBook>,
    sessions: Arc<RwLock<HashMap<String, DefiSession>>>,
    /// Default chain when an intent omits one.
    default_chain: String,
    next_id: Arc<RwLock<u64>>,
    /// Tiered revert decoder used to attach a structured `decoded_error`
    /// to simulation/confirm failures. Defaults to an empty chain so the
    /// handler still works in tests; the daemon wires a real chain in.
    revert_decoder: Arc<DecoderChain>,
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
            sessions: Arc::new(RwLock::new(HashMap::new())),
            default_chain: "ethereum".into(),
            next_id: Arc::new(RwLock::new(1)),
            revert_decoder: Arc::new(DecoderChain::new()),
        }
    }

    pub fn with_default_chain(mut self, chain: impl Into<String>) -> Self {
        self.default_chain = chain.into();
        self
    }

    /// Wire a shared revert decoder chain into this handler. Construct
    /// once at daemon startup and clone the `Arc` for every handler that
    /// needs to attribute reverts.
    pub fn with_revert_decoder(mut self, chain: Arc<DecoderChain>) -> Self {
        self.revert_decoder = chain;
        self
    }

    fn allocate_id(&self) -> String {
        let mut g = self.next_id.write();
        let n = *g;
        *g = n.wrapping_add(1);
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() % 100_000)
            .unwrap_or(0);
        format!("{:04}-{:05}", n, suffix)
    }

    fn session_key(wallet: &str, id: &str) -> String {
        format!("{wallet}/{id}")
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
                slippage_bps: None,
            })
        }
    }

    fn list_session_wallets(&self) -> Vec<String> {
        let mut s: Vec<String> = self
            .sessions
            .read()
            .values()
            .map(|sess| sess.wallet.clone())
            .collect();
        s.sort();
        s.dedup();
        s
    }

    fn list_sessions_for_wallet(&self, wallet: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .sessions
            .read()
            .values()
            .filter(|s| s.wallet == wallet)
            .map(|s| s.id.clone())
            .collect();
        out.sort();
        out
    }

    fn get_session(&self, wallet: &str, id: &str) -> Result<DefiSession, HandlerError> {
        let key = Self::session_key(wallet, id);
        self.sessions
            .read()
            .get(&key)
            .cloned()
            .ok_or_else(|| HandlerError::not_found(format!("session {wallet}/{id}")))
    }

    fn put_session(&self, sess: DefiSession) {
        let key = Self::session_key(&sess.wallet, &sess.id);
        self.sessions.write().insert(key, sess);
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
        from: Address,
        intent: &str,
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
        Self::compose_route_request(chain_id, from, &nat, decimals)
    }

    /// Pure builder: turns a parsed intent + known decimals into a RouteRequest.
    /// Split out so unit tests can exercise the symbol path without an RPC.
    fn compose_route_request(
        chain_id: u64,
        from: Address,
        nat: &bloom_defi::NaturalIntent,
        decimals_in: u8,
    ) -> Result<RouteRequest, HandlerError> {
        let token_in = resolve_token_symbol(chain_id, &nat.token_in)
            .ok_or_else(|| HandlerError::invalid(format!("unknown token '{}'", nat.token_in)))?;
        let token_out = resolve_token_symbol(chain_id, &nat.token_out)
            .ok_or_else(|| HandlerError::invalid(format!("unknown token '{}'", nat.token_out)))?;
        let amount = bloom_proto::parse_units(&nat.amount, decimals_in)
            .map_err(|e| HandlerError::invalid(format!("amount: {e}")))?;
        Ok(RouteRequest {
            from_address: from,
            chain_id,
            token_in,
            token_out,
            amount_in: amount,
            slippage_bps: 50,
            routing_strategy: Some(RoutingStrategy::Router),
            receiver: None,
        })
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
        let mut req =
            Self::build_route_request(&chain, chain_id, info.address, &body.intent).await?;
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
        });

        let plan = render_plan_md(&body.intent, &chain_name, &req, &route, &intents);
        let id = self.allocate_id();
        let now_ms = now_ms();
        let sess = DefiSession {
            id,
            wallet: wallet.to_string(),
            chain: chain_name,
            intent_text: body.intent,
            route: Some(route),
            plan_md: plan,
            intents,
            staged_ids: Vec::new(),
            created_ms: now_ms,
        };
        self.put_session(sess.clone());
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
        let sess = self.get_session(wallet, id)?;
        if sess.intents.is_empty() {
            return Err(HandlerError::backend("session has no prepared intents"));
        }
        let info = self
            .keystore
            .info(wallet)
            .map_err(|e| HandlerError::backend(e.to_string()))?;
        let chain = self.chain_client(&sess.chain)?;
        let mut staged_list = Vec::with_capacity(sess.intents.len());
        for intent in sess.intents.iter().cloned() {
            let staged = self
                .tx_engine
                .stage(
                    wallet,
                    info.address,
                    intent,
                    &chain,
                    &info.policy,
                    Some(&self.address_book),
                )
                .await
                .map_err(|e| HandlerError::backend(e.to_string()))?;
            staged_list.push(staged);
        }
        let mut updated = sess;
        updated.staged_ids = staged_list.iter().map(|s| s.id.clone()).collect();
        self.put_session(updated);
        Ok(staged_list)
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
                    Entry::file("tx.json"),
                    Entry::file("simulation.json"),
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
        "intent.txt" | "route.json" | "plan.md" | "tx.json" | "simulation.json" | "confirm"
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

fn render_plan_md(
    intent: &str,
    chain: &str,
    req: &RouteRequest,
    route: &RouteResponse,
    intents: &[RawIntent],
) -> String {
    let mut s = String::new();
    s.push_str("# DeFi intent\n\n");
    s.push_str(&format!("Intent:    {intent}\n"));
    s.push_str(&format!("Chain:     {chain} (id {})\n", req.chain_id));
    s.push_str(&format!(
        "From:      {}\n",
        checksum_address(&req.from_address)
    ));
    s.push_str(&format!(
        "Token in:  0x{:x}  amount={} (raw)\n",
        req.token_in, req.amount_in
    ));
    s.push_str(&format!(
        "Token out: 0x{:x}  amountOut≈{}\n",
        req.token_out, route.amount_out
    ));
    s.push_str(&format!("Slippage:  {} bps\n", req.slippage_bps));
    if let Some(ref g) = route.gas {
        s.push_str(&format!("Gas:       {g}\n"));
    }
    if let Some(p) = route.price_impact {
        s.push_str(&format!("Impact:    {p}%\n"));
    }
    s.push_str(&format!("Tx to:     {}\n", checksum_address(&route.tx.to)));
    s.push_str(&format!("Tx value:  {} wei\n", route.tx.value));
    s.push_str(&format!("Tx data:   {} bytes\n", route.tx.data.len()));

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_new_body_json() {
        let b = DefiHandler::parse_new_body(
            r#"{"kind":"enso","intent":"swap 1 ETH to USDC","chain":"ethereum"}"#,
        )
        .unwrap();
        assert_eq!(b.intent, "swap 1 ETH to USDC");
        assert_eq!(b.chain.as_deref(), Some("ethereum"));
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
        let req = DefiHandler::compose_route_request(1, from, &nat, 18).unwrap();
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
        let err = DefiHandler::compose_route_request(1, from, &nat, 18).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn render_plan_md_includes_key_fields() {
        let req = RouteRequest {
            from_address: Address::ZERO,
            chain_id: 1,
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
        }];
        let md = render_plan_md("swap 1 ETH to USDC", "ethereum", &req, &route, &intents);
        assert!(md.contains("swap 1 ETH to USDC"));
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
            },
        ];
        let md = render_plan_md("swap 1 USDC to ETH", "ethereum", &req, &route, &intents);
        assert!(md.contains("Auto-approve"));
        assert!(md.contains("approve(spender, max)"));
        assert!(md.contains("stage 2 txs"));
    }
}
