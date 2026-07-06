//! `simulate/<session>/...` — tx simulation sandbox.
//!
//! Sessions are write-then-read:
//!
//! 1. Agent writes a JSON intent (with optional `state_override` field) to
//!    `simulate/new`. The handler allocates a `sim-NNNN` session id, parses
//!    the intent, and immediately runs an `eth_call` (with overrides if
//!    requested). Result + plan are stashed in memory.
//! 2. Agent then reads `simulate/<session>/intent.json`,
//!    `simulate/<session>/simulation.json`, `simulate/<session>/plan.md`, etc.
//! 3. Writing replacement bytes to `simulate/<session>/state-override.json`
//!    re-runs the simulation against the original intent with new overrides.
//!
//! No tx is ever signed or broadcast through this subtree. Trace is
//! best-effort: if the upstream provider doesn't support `debug_traceCall`,
//! the file contains `{"unsupported": "..."}` instead.
//!
//! Paths handled:
//! - `simulate/`                                — root dir; lists sessions + `new`
//! - `simulate/new`                             — write JSON intent → allocate session
//! - `simulate/<id>/`                           — session dir
//! - `simulate/<id>/intent.json`                — read parsed intent
//! - `simulate/<id>/state-override.json`        — read+write overrides; write re-runs
//! - `simulate/<id>/simulation.json`            — read SimResult
//! - `simulate/<id>/plan.md`                    — read human summary
//! - `simulate/<id>/trace.json`                 — read debug_traceCall output
//!   (or `{"unsupported": "..."}` when the upstream RPC doesn't support it)
//! - `simulate/last`                            — read most-recently-allocated id

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::rpc::types::eth::TransactionRequest;
use alloy::rpc::types::eth::state::{AccountOverride, StateOverride};
use async_trait::async_trait;
use bloom_chain::ChainRegistry;
use bloom_proto::{AddressBook, RawIntent, RawIntentBody, checksum_address, parse_eth};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

/// Result of a simulated `eth_call`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimResult {
    pub success: bool,
    pub gas_used: u64,
    pub return_data_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_reason: Option<String>,
    /// Logs are not exposed by `eth_call`; left empty for v1.
    pub logs: Vec<serde_json::Value>,
    /// The chain the simulation ran against, for debugging.
    pub chain: String,
}

/// One in-memory simulation session.
#[derive(Debug, Clone)]
pub struct SimSession {
    pub id: String,
    pub intent: Option<RawIntent>,
    /// Optional `from` address for the simulated call (so that overrides
    /// targeting the sender's balance / nonce actually bind). When unset,
    /// `eth_call` runs from the zero address.
    pub from: Option<Address>,
    pub state_override: Option<serde_json::Value>,
    pub result: Option<SimResult>,
    pub plan_md: Option<String>,
    pub trace_json: Option<serde_json::Value>,
    pub created_ms: u128,
}

/// The simulate handler. Holds an in-memory session map.
pub struct SimulateHandler {
    pub chains: ChainRegistry,
    pub sessions: RwLock<HashMap<String, SimSession>>,
    pub addr_book: Arc<AddressBook>,
    pub next_id: AtomicU64,
}

impl SimulateHandler {
    pub fn new(chains: ChainRegistry, addr_book: Arc<AddressBook>) -> Self {
        Self {
            chains,
            sessions: RwLock::new(HashMap::new()),
            addr_book,
            next_id: AtomicU64::new(1),
        }
    }

    /// Allocate a fresh `sim-NNNN` id.
    fn allocate_id(&self) -> String {
        let n = self.next_id.fetch_add(1, Ordering::SeqCst);
        format!("sim-{:04}", n)
    }
}

/// JSON envelope accepted by `simulate/new`. Either an inline `intent` or a
/// flat shape. A `state_override` field is recognised on the envelope.
#[derive(Debug, Clone, Deserialize)]
struct NewSimEnvelope {
    /// Optional structured intent body — pass-through.
    #[serde(default)]
    state_override: Option<serde_json::Value>,
    /// The remaining fields are flattened into the intent itself.
    #[serde(flatten)]
    rest: serde_json::Value,
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn err_be(e: impl std::fmt::Display) -> HandlerError {
    HandlerError::backend(e.to_string())
}

fn pick_chain(intent: &RawIntent) -> String {
    intent.chain.clone().unwrap_or_else(|| "anvil".to_string())
}

/// Convert a JSON state override (`{ "0xaddr": { "balance": "0x..", ... } }`)
/// into alloy's typed `StateOverride`. Tolerates "balance" expressed either as
/// a decimal string, a "0x"-hex string, or a positive integer; "code" as
/// 0x-hex; "storage" / "stateDiff" as `{ slot: value }`.
fn build_state_override(v: &serde_json::Value) -> Result<StateOverride, HandlerError> {
    let map = v
        .as_object()
        .ok_or_else(|| HandlerError::invalid("state_override must be an object"))?;
    let mut out = StateOverride::default();
    for (k, acc) in map {
        let addr: Address = k.parse().map_err(|e: alloy::hex::FromHexError| {
            HandlerError::invalid(format!("bad override addr {}: {}", k, e))
        })?;
        let mut ov = AccountOverride::default();
        if let Some(bal) = acc.get("balance") {
            let u = parse_u256(bal)?;
            ov.balance = Some(u);
        }
        if let Some(nonce) = acc.get("nonce") {
            let n = nonce
                .as_u64()
                .ok_or_else(|| HandlerError::invalid("override nonce must be u64"))?;
            ov.nonce = Some(n);
        }
        if let Some(code) = acc.get("code") {
            let s = code
                .as_str()
                .ok_or_else(|| HandlerError::invalid("override code must be hex string"))?;
            ov.code = Some(decode_hex(s)?);
        }
        if let Some(storage) = acc.get("storage").or_else(|| acc.get("stateDiff")) {
            let so = storage
                .as_object()
                .ok_or_else(|| HandlerError::invalid("storage must be object"))?;
            let mut entries: std::collections::HashMap<
                alloy::primitives::B256,
                alloy::primitives::B256,
            > = std::collections::HashMap::default();
            for (slot, value) in so {
                let s_b256 = parse_b256(slot)?;
                let v_b256_str = value
                    .as_str()
                    .ok_or_else(|| HandlerError::invalid("storage value must be 0x-hex string"))?;
                let v_b256 = parse_b256(v_b256_str)?;
                entries.insert(s_b256, v_b256);
            }
            // Note: we apply via state_diff by default (does not wipe the rest of storage).
            ov.state_diff = Some(entries.into_iter().collect());
        }
        out.insert(addr, ov);
    }
    Ok(out)
}

fn parse_u256(v: &serde_json::Value) -> Result<U256, HandlerError> {
    if let Some(s) = v.as_str() {
        let s = s.trim();
        if let Some(stripped) = s.strip_prefix("0x") {
            return U256::from_str_radix(stripped, 16)
                .map_err(|e| HandlerError::invalid(format!("hex u256 '{}': {}", s, e)));
        }
        return U256::from_str_radix(s, 10)
            .map_err(|e| HandlerError::invalid(format!("dec u256 '{}': {}", s, e)));
    }
    if let Some(n) = v.as_u64() {
        return Ok(U256::from(n));
    }
    Err(HandlerError::invalid("u256 must be string or u64"))
}

fn parse_b256(s: &str) -> Result<B256, HandlerError> {
    let stripped = s.trim().trim_start_matches("0x");
    // Pad to 32 bytes.
    let mut padded = String::with_capacity(64);
    if stripped.len() < 64 {
        for _ in 0..(64 - stripped.len()) {
            padded.push('0');
        }
    }
    padded.push_str(stripped);
    let bytes = hex::decode(&padded)
        .map_err(|e| HandlerError::invalid(format!("b256 hex '{}': {}", s, e)))?;
    if bytes.len() != 32 {
        return Err(HandlerError::invalid(format!(
            "b256 must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(B256::from_slice(&bytes))
}

fn decode_hex(s: &str) -> Result<Bytes, HandlerError> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let v = hex::decode(s).map_err(|e| HandlerError::invalid(format!("hex: {}", e)))?;
    Ok(Bytes::from(v))
}

/// Build the `TransactionRequest` we'll feed to `eth_call`.
fn build_tx_request(
    intent: &RawIntent,
    addr_book: &AddressBook,
) -> Result<TransactionRequest, HandlerError> {
    use alloy::network::TransactionBuilder;

    let (to, value_wei, data_hex) = match &intent.body {
        RawIntentBody::Send {
            to,
            value,
            token,
            amount,
            data,
        } => {
            let to_addr = resolve_addr(to, addr_book)?;
            if token.is_some() {
                if amount.trim().is_empty() {
                    return Err(HandlerError::invalid(
                        "token sends require amount; value is only for native sends",
                    ));
                }
                if !value.trim().is_empty() && value.trim() != "0" {
                    return Err(HandlerError::invalid(
                        "token sends must use amount; value is reserved for native sends",
                    ));
                }
                return Err(HandlerError::Unsupported(
                    "ERC-20 token simulation requires a contract-call intent".into(),
                ));
            }
            if !amount.trim().is_empty() {
                return Err(HandlerError::invalid(
                    "native sends must use value; amount is only for token sends",
                ));
            }
            let v = resolve_value(value, token)?;
            let d = data.clone().unwrap_or_else(|| "0x".into());
            (to_addr, v, d)
        }
        RawIntentBody::Raw { to, value, data } => {
            let to_addr = resolve_addr(to, addr_book)?;
            let v = if value.is_empty() {
                U256::ZERO
            } else {
                parse_eth(value).map_err(|e| HandlerError::invalid(e.to_string()))?
            };
            (to_addr, v, data.clone())
        }
        RawIntentBody::Call {
            contract,
            method,
            args,
            value,
        } => {
            let contract_addr = resolve_addr(contract, addr_book)?;
            let v = if value.is_empty() {
                U256::ZERO
            } else {
                parse_eth(value).map_err(|e| HandlerError::invalid(e.to_string()))?
            };
            let data = bloom_tools::encode_call(method, &serde_json::json!(args))
                .map_err(|e| HandlerError::invalid(format!("encode_call: {e}")))?;
            (contract_addr, v, data)
        }
        RawIntentBody::Approve {
            token,
            spender,
            amount,
        } => {
            use alloy::sol_types::SolCall;
            use bloom_chain::IERC20;
            let token_addr = resolve_addr(token, addr_book)?;
            let spender_addr = resolve_addr(spender, addr_book)?;
            let amount_u = if amount.trim().is_empty() || amount.eq_ignore_ascii_case("max") {
                U256::MAX
            } else {
                U256::from_str_radix(amount.trim(), 10)
                    .map_err(|e| HandlerError::invalid(format!("approve amount: {e}")))?
            };
            let call = IERC20::approveCall {
                spender: spender_addr,
                amount: amount_u,
            };
            let data = format!("0x{}", hex::encode(call.abi_encode()));
            (token_addr, U256::ZERO, data)
        }
        RawIntentBody::NftTransfer { .. }
        | RawIntentBody::NftApprove { .. }
        | RawIntentBody::NftApproveAll { .. } => {
            // /simulate intentionally has no chain client at this layer
            // (no ERC-165 detection). NFT writes flow through the wallet
            // outbox where detection + encoding live; surface a clear
            // unsupported here rather than mis-encoding.
            return Err(HandlerError::Unsupported(
                "NFT intents are simulated via the wallet outbox stage path (see wallets/<w>/chains/<c>/outbox/new.tx)".into(),
            ));
        }
        RawIntentBody::Enso { .. } => {
            return Err(HandlerError::Unsupported(
                "Enso intents are not simulated through /simulate (use defi/intents/)".into(),
            ));
        }
    };

    let data_bytes = decode_hex(&data_hex)?;
    let mut req = TransactionRequest::default()
        .with_to(to)
        .with_value(value_wei)
        .with_input(data_bytes);
    if let Some(n) = intent.nonce {
        req = req.with_nonce(n);
    }
    Ok(req)
}

fn resolve_addr(s: &str, book: &AddressBook) -> Result<Address, HandlerError> {
    if s.starts_with("0x") {
        return s
            .parse::<Address>()
            .map_err(|e| HandlerError::invalid(format!("addr '{}': {}", s, e)));
    }
    if let Some(a) = book.resolve(s) {
        return Ok(a);
    }
    Err(HandlerError::invalid(format!(
        "unresolved recipient '{}' (ENS not wired in /simulate)",
        s
    )))
}

fn resolve_value(value: &str, token: &Option<String>) -> Result<U256, HandlerError> {
    if value.is_empty() {
        return Ok(U256::ZERO);
    }
    if let Some(t) = token.as_deref() {
        match t.to_ascii_lowercase().as_str() {
            "eth" | "ether" | "wei" | "gwei" => {
                parse_eth(value).map_err(|e| HandlerError::invalid(e.to_string()))
            }
            other => Err(HandlerError::Unsupported(format!(
                "ERC-20 token '{other}' simulation requires a contract-call intent"
            ))),
        }
    } else {
        parse_eth(value).map_err(|e| HandlerError::invalid(e.to_string()))
    }
}

/// Render a tiny plan.md. We don't have a full StagedTx in /simulate (no
/// gas estimate, no policy), so this is a deliberately simpler markdown.
fn render_sim_plan(session: &SimSession) -> String {
    let mut s = String::new();
    s.push_str(&format!("# Simulated tx {}\n\n", session.id));
    if let Some(intent) = &session.intent {
        s.push_str(&format!(
            "Chain: {}\n",
            intent.chain.clone().unwrap_or_else(|| "(default)".into())
        ));
        match &intent.body {
            RawIntentBody::Send {
                to,
                value,
                token,
                amount,
                ..
            } => {
                s.push_str("Kind:  send\n");
                s.push_str(&format!("To:    {}\n", to));
                if let Some(token) = token {
                    s.push_str(&format!("Amount: {} {}\n", amount, token));
                    if !value.trim().is_empty() && value.trim() != "0" {
                        s.push_str(&format!("Native value: {}\n", value));
                    }
                } else {
                    s.push_str(&format!(
                        "Value: {}\n",
                        if value.is_empty() { "0" } else { value }
                    ));
                }
            }
            RawIntentBody::Raw { to, value, data } => {
                s.push_str("Kind:  raw\n");
                s.push_str(&format!("To:    {}\n", to));
                s.push_str(&format!("Value: {}\n", value));
                s.push_str(&format!(
                    "Data:  {} bytes\n",
                    data.trim_start_matches("0x").len() / 2
                ));
            }
            RawIntentBody::Call {
                contract,
                method,
                args,
                value,
            } => {
                s.push_str("Kind:    call\n");
                s.push_str(&format!("Contract:{}\n", contract));
                s.push_str(&format!("Method:  {}\n", method));
                s.push_str(&format!("Args:    {}\n", serde_json::json!(args)));
                if !value.is_empty() {
                    s.push_str(&format!("Value:   {}\n", value));
                }
            }
            RawIntentBody::Approve {
                token,
                spender,
                amount,
            } => {
                s.push_str("Kind:    approve\n");
                s.push_str(&format!("Token:   {}\n", token));
                s.push_str(&format!("Spender: {}\n", spender));
                s.push_str(&format!("Amount:  {}\n", amount));
            }
            RawIntentBody::NftTransfer {
                contract,
                to,
                token_id,
                amount,
                ..
            } => {
                s.push_str("Kind:    nft_transfer\n");
                s.push_str(&format!("Contract:{}\n", contract));
                s.push_str(&format!("TokenId: {}\n", token_id));
                s.push_str(&format!("To:      {}\n", to));
                if let Some(a) = amount.as_deref() {
                    s.push_str(&format!("Amount:  {}\n", a));
                }
            }
            RawIntentBody::NftApprove {
                contract,
                operator,
                token_id,
            } => {
                s.push_str("Kind:    nft_approve\n");
                s.push_str(&format!("Contract:{}\n", contract));
                s.push_str(&format!("Operator:{}\n", operator));
                s.push_str(&format!("TokenId: {}\n", token_id));
            }
            RawIntentBody::NftApproveAll {
                contract,
                operator,
                approved,
            } => {
                s.push_str("Kind:    nft_approve_all\n");
                s.push_str(&format!("Contract:{}\n", contract));
                s.push_str(&format!("Operator:{}\n", operator));
                s.push_str(&format!("Approved:{}\n", approved));
            }
            RawIntentBody::Enso { intent } => {
                s.push_str("Kind:   enso\n");
                s.push_str(&format!("Intent: {}\n", intent));
            }
        }
    }
    if session.state_override.is_some() {
        s.push_str("Overrides: yes\n");
    } else {
        s.push_str("Overrides: none\n");
    }
    s.push_str("\n## Result\n");
    if let Some(r) = &session.result {
        s.push_str(&format!("Success:  {}\n", r.success));
        s.push_str(&format!("Gas used: {}\n", r.gas_used));
        if let Some(rev) = &r.revert_reason {
            s.push_str(&format!("Revert:   {}\n", rev));
        }
        s.push_str(&format!("Return:   {}\n", r.return_data_hex));
    } else {
        s.push_str("Not yet simulated.\n");
    }
    s.push_str("\nThis is a dry-run; nothing was broadcast.\n");
    s
}

impl SimulateHandler {
    /// Resolve a chain client for an intent, falling back to the only
    /// registered chain if exactly one is registered.
    fn pick_client(&self, intent: &RawIntent) -> Result<bloom_chain::ChainClient, HandlerError> {
        let preferred = pick_chain(intent);
        if let Some(c) = self.chains.get(&preferred) {
            return Ok(c);
        }
        // Soft fallback for tests / single-chain setups.
        let names = self.chains.list_names();
        if names.len() == 1 {
            return self
                .chains
                .get(&names[0])
                .ok_or_else(|| HandlerError::not_found(format!("chain '{}'", preferred)));
        }
        Err(HandlerError::not_found(format!(
            "chain '{}' not registered (have: {:?})",
            preferred, names
        )))
    }

    /// Run the simulation against the chain and stash the result.
    async fn run_simulation(&self, id: &str) -> Result<(), HandlerError> {
        // Snapshot the inputs while holding the read lock briefly.
        let (intent, override_json, from) = {
            let g = self.sessions.read();
            let s = g
                .get(id)
                .ok_or_else(|| HandlerError::not_found(id.to_string()))?;
            (
                s.intent
                    .clone()
                    .ok_or_else(|| HandlerError::invalid("session has no intent"))?,
                s.state_override.clone(),
                s.from,
            )
        };
        let client = self.pick_client(&intent)?;
        let mut req = build_tx_request(&intent, &self.addr_book)?;
        if let Some(addr) = from {
            use alloy::network::TransactionBuilder;
            req = req.with_from(addr);
        }

        // Estimate gas separately (eth_call doesn't include it). This is
        // best-effort: simulate keeps going on failure to capture the revert.
        let gas_used: u64 = client.estimate_gas(&req).await.unwrap_or_default();

        // Apply chain id (`call` doesn't strictly require it, but be polite).
        if let Ok(cid) = client.chain_id().await {
            use alloy::network::TransactionBuilder;
            req = req.with_chain_id(cid);
        }

        let overrides = match override_json {
            Some(v) => Some(build_state_override(&v)?),
            None => None,
        };

        let chain_name = client.spec().name.clone();
        let call_result = client
            .eth_call_with_overrides(req.clone(), overrides.clone())
            .await;

        let (success, return_data_hex, revert_reason) = match call_result {
            Ok(b) => (true, format!("0x{}", hex::encode(&b)), None),
            Err(e) => {
                let msg = e.to_string();
                (false, "0x".to_string(), Some(msg))
            }
        };

        let result = SimResult {
            success,
            gas_used,
            return_data_hex,
            revert_reason,
            logs: vec![],
            chain: chain_name,
        };

        // Best-effort tracing.
        let trace = match client.debug_trace_call(req, overrides).await {
            Ok(v) => v,
            Err(e) => serde_json::json!({ "unsupported": e.to_string() }),
        };

        let mut g = self.sessions.write();
        let s = g
            .get_mut(id)
            .ok_or_else(|| HandlerError::not_found(id.to_string()))?;
        s.result = Some(result);
        s.trace_json = Some(trace);
        s.plan_md = Some(render_sim_plan(s));
        Ok(())
    }

    /// Handle a write to `simulate/new`: parse, allocate, run, store.
    async fn handle_new(&self, data: &[u8]) -> Result<String, HandlerError> {
        let body = std::str::from_utf8(data)
            .map_err(|_| HandlerError::invalid("non-utf8 sim intent"))?
            .trim();
        if body.is_empty() {
            return Err(HandlerError::invalid("empty sim intent"));
        }
        // First parse as an envelope to lift `state_override` off, then
        // re-serialise the rest and run it through the intent_parser.
        let envelope: NewSimEnvelope = serde_json::from_str(body)
            .map_err(|e| HandlerError::invalid(format!("sim envelope: {e}")))?;
        // Pull `from` off the rest if present (intent_parser ignores it).
        let from: Option<Address> = envelope
            .rest
            .as_object()
            .and_then(|o| o.get("from"))
            .and_then(|v| v.as_str())
            .map(|s| s.parse::<Address>())
            .transpose()
            .map_err(|e| HandlerError::invalid(format!("from addr: {e}")))?;
        let intent_json = serde_json::to_string(&envelope.rest)
            .map_err(|e| HandlerError::invalid(format!("re-serialise: {e}")))?;
        let intent = bloom_tx::intent_parser::parse(&intent_json)
            .map_err(|e| HandlerError::invalid(e.to_string()))?;

        let id = self.allocate_id();
        {
            let mut g = self.sessions.write();
            g.insert(
                id.clone(),
                SimSession {
                    id: id.clone(),
                    intent: Some(intent),
                    from,
                    state_override: envelope.state_override,
                    result: None,
                    plan_md: None,
                    trace_json: None,
                    created_ms: now_ms(),
                },
            );
        }

        // Run synchronously inside the write call so the agent's next read
        // sees a populated session.
        self.run_simulation(&id).await?;
        Ok(id)
    }

    /// Handle a write to `simulate/<id>/state-override.json`: replace the
    /// override and re-run.
    async fn handle_override_write(&self, id: &str, data: &[u8]) -> Result<(), HandlerError> {
        let v: serde_json::Value = if data.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(data)
                .map_err(|e| HandlerError::invalid(format!("override json: {e}")))?
        };
        {
            let mut g = self.sessions.write();
            let s = g
                .get_mut(id)
                .ok_or_else(|| HandlerError::not_found(id.to_string()))?;
            s.state_override = if v.is_null() { None } else { Some(v) };
        }
        self.run_simulation(id).await
    }

    fn session_dir_entries(_s: &SimSession) -> Vec<Entry> {
        // state-override.json is always listed as writable so agents can
        // drop overrides in even before the first one has been provided.
        vec![
            Entry::file("intent.json"),
            Entry::writable_file("state-override.json"),
            Entry::file("simulation.json"),
            Entry::file("plan.md"),
            Entry::file("trace.json"),
        ]
    }

    fn read_session_file(&self, id: &str, fname: &str) -> Result<Vec<u8>, HandlerError> {
        let g = self.sessions.read();
        let s = g
            .get(id)
            .ok_or_else(|| HandlerError::not_found(id.to_string()))?;
        match fname {
            "intent.json" => {
                let v = serde_json::to_vec_pretty(&s.intent).map_err(err_be)?;
                Ok(v)
            }
            "state-override.json" => {
                let v = match &s.state_override {
                    Some(o) => serde_json::to_vec_pretty(o).map_err(err_be)?,
                    None => b"{}\n".to_vec(),
                };
                Ok(v)
            }
            "simulation.json" => {
                let v = serde_json::to_vec_pretty(&s.result).map_err(err_be)?;
                Ok(v)
            }
            "plan.md" => Ok(s.plan_md.clone().unwrap_or_default().into_bytes()),
            "trace.json" => {
                let v = match &s.trace_json {
                    Some(t) => serde_json::to_vec_pretty(t).map_err(err_be)?,
                    None => serde_json::to_vec_pretty(&serde_json::json!({
                        "unsupported": "trace not yet captured"
                    }))
                    .unwrap(),
                };
                Ok(v)
            }
            _ => Err(HandlerError::not_found(format!("{}/{}", id, fname))),
        }
    }
}

#[async_trait]
impl Handler for SimulateHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let r = self.lookup_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "simulate.lookup_err");
        }
        r
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let r = self.read_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "simulate.read_err");
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
                "simulate.write_err"
            );
        }
        r
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let r = self.list_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "simulate.list_err");
        }
        r
    }
}

impl SimulateHandler {
    async fn lookup_inner(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segs = path.segments();
        match segs.len() {
            0 => Ok(Entry::dir("")),
            1 => match segs[0].as_str() {
                "new" => Ok(Entry::writable_file("new")),
                "last" => Ok(Entry::file("last")),
                id => {
                    let g = self.sessions.read();
                    if g.contains_key(id) {
                        Ok(Entry::dir(id))
                    } else {
                        Err(HandlerError::not_found(path.to_string_path()))
                    }
                }
            },
            2 => {
                let id = &segs[0];
                let g = self.sessions.read();
                if !g.contains_key(id) {
                    return Err(HandlerError::not_found(path.to_string_path()));
                }
                drop(g);
                match segs[1].as_str() {
                    "state-override.json" => Ok(Entry::writable_file("state-override.json")),
                    "intent.json" | "simulation.json" | "plan.md" | "trace.json" => {
                        Ok(Entry::file(&segs[1]))
                    }
                    _ => Err(HandlerError::not_found(path.to_string_path())),
                }
            }
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn read_inner(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = path.segments();
        match segs.len() {
            1 if segs[0] == "new" => {
                Ok(b"# write a JSON simulate envelope to allocate a session\n# example:\n#   echo '{\"intent\":{\"chain\":\"anvil\",\"to\":\"0x...\",\"data\":\"0x...\"}}' > /bloom/simulate/new\n# read the resulting session id from /bloom/simulate/last\n".to_vec())
            }
            1 if segs[0] == "last" => {
                let g = self.sessions.read();
                let mut ids: Vec<&String> = g.keys().collect();
                ids.sort();
                let last = ids.last().map(|s| s.as_str()).unwrap_or("");
                Ok(format!("{}\n", last).into_bytes())
            }
            2 => {
                let id = &segs[0];
                self.read_session_file(id, &segs[1])
            }
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn write_inner(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let segs = path.segments();
        match segs.len() {
            1 if segs[0] == "new" => {
                let id = self.handle_new(data).await?;
                tracing::info!(id = %id, "simulate.new");
                Ok(())
            }
            2 if segs[1] == "state-override.json" => {
                let id = &segs[0];
                self.handle_override_write(id, data).await
            }
            _ => Err(HandlerError::PermissionDenied),
        }
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segs = path.segments();
        match segs.len() {
            0 => {
                let mut out = vec![Entry::writable_file("new"), Entry::file("last")];
                let g = self.sessions.read();
                let mut ids: Vec<&String> = g.keys().collect();
                ids.sort();
                for id in ids {
                    out.push(Entry::dir(id));
                }
                Ok(out)
            }
            1 => {
                let g = self.sessions.read();
                let s = g
                    .get(&segs[0])
                    .ok_or_else(|| HandlerError::not_found(path.to_string_path()))?;
                Ok(Self::session_dir_entries(s))
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }
}

// keep the `checksum_address` import alive even if unused outside tests
const _CSA: fn(&Address) -> String = checksum_address;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::process::Stdio;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::{Child, Command};
    use tokio::time::timeout;

    use bloom_chain::{ChainClient, ChainRegistry};
    use bloom_proto::ChainSpec;

    const ANVIL_BIN_DEFAULT: &str = "/Users/joshua/.foundry/bin/anvil";
    const CAST_BIN_DEFAULT: &str = "/Users/joshua/.foundry/bin/cast";
    /// Pre-funded anvil account #0 private key (deterministic).
    const FUNDER_PRIV_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    fn anvil_bin() -> String {
        std::env::var("ANVIL_BIN").unwrap_or_else(|_| ANVIL_BIN_DEFAULT.to_string())
    }
    fn cast_bin() -> String {
        std::env::var("CAST_BIN").unwrap_or_else(|_| CAST_BIN_DEFAULT.to_string())
    }

    fn anvil_available() -> bool {
        std::path::Path::new(&anvil_bin()).exists()
    }

    struct AnvilGuard {
        child: Option<Child>,
        port: u16,
    }
    impl AnvilGuard {
        fn rpc_url(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }
    }
    impl Drop for AnvilGuard {
        fn drop(&mut self) {
            if let Some(mut c) = self.child.take() {
                let _ = c.start_kill();
            }
        }
    }

    fn pick_free_port() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    async fn spawn_anvil() -> AnvilGuard {
        let port = pick_free_port();
        let mut cmd = Command::new(anvil_bin());
        cmd.arg("--port")
            .arg(port.to_string())
            .arg("--host")
            .arg("127.0.0.1")
            .arg("--chain-id")
            .arg("31337")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn().expect("spawn anvil");
        let stdout = child.stdout.take().expect("anvil stdout");
        let mut reader = BufReader::new(stdout).lines();
        let wait = async {
            loop {
                match reader.next_line().await.unwrap() {
                    Some(line) if line.contains("Listening on") => break,
                    Some(_) => continue,
                    None => panic!("anvil exited before becoming ready"),
                }
            }
        };
        timeout(Duration::from_secs(15), wait)
            .await
            .expect("anvil ready timeout");
        AnvilGuard {
            child: Some(child),
            port,
        }
    }

    async fn fund(rpc_url: &str, to_addr: &str, value_eth: u64) {
        let out = Command::new(cast_bin())
            .arg("send")
            .arg("--private-key")
            .arg(FUNDER_PRIV_KEY)
            .arg("--rpc-url")
            .arg(rpc_url)
            .arg(to_addr)
            .arg("--value")
            .arg(format!("{}ether", value_eth))
            .output()
            .await
            .expect("invoke cast send");
        assert!(
            out.status.success(),
            "cast send failed: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn registry_for(rpc_url: &str) -> ChainRegistry {
        let mut spec = ChainSpec::anvil_default();
        spec.rpc_urls = vec![rpc_url.to_string()];
        let client = ChainClient::new(spec).unwrap();
        let r = ChainRegistry::new();
        r.add(client);
        r
    }

    #[tokio::test]
    async fn allocate_id_format() {
        let r = ChainRegistry::new();
        let h = SimulateHandler::new(r, Arc::new(AddressBook::default()));
        let a = h.allocate_id();
        let b = h.allocate_id();
        assert!(a.starts_with("sim-"));
        assert!(b.starts_with("sim-"));
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn root_lists_new_and_last() {
        let r = ChainRegistry::new();
        let h = SimulateHandler::new(r, Arc::new(AddressBook::default()));
        let entries = h.list(&VfsPath::root()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"new"));
        assert!(names.contains(&"last"));
    }

    #[tokio::test]
    async fn write_new_invalid_json_errors() {
        let r = ChainRegistry::new();
        let h = SimulateHandler::new(r, Arc::new(AddressBook::default()));
        let p = VfsPath::parse("/new").unwrap();
        let err = h.write(&p, b"not json").await.err().unwrap();
        match err {
            HandlerError::Invalid(_) => {}
            other => panic!("expected Invalid, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn read_new_returns_help_text() {
        // The mount adapter calls read at GETATTR time to size the file.
        // Returning an error caused noisy `render_failed_falling_back_to_size_0`
        // warnings on every getattr. Help text gives kernel a stable size
        // and gives users something useful when they `cat` the path.
        let r = ChainRegistry::new();
        let h = SimulateHandler::new(r, Arc::new(AddressBook::default()));
        let p = VfsPath::parse("/new").unwrap();
        let bytes = h.read(&p).await.unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(
            s.contains("simulate"),
            "help text should mention simulate: {s}"
        );
        assert!(s.contains("intent"), "help text should mention intent: {s}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn anvil_native_send_simulation() {
        if !anvil_available() {
            eprintln!("anvil not found at {}; skipping", anvil_bin());
            return;
        }
        let anvil = spawn_anvil().await;
        let rpc = anvil.rpc_url();
        // alice = anvil prefunded #1.
        let alice = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
        // recipient = anvil prefunded #2.
        let recip = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
        fund(&rpc, alice, 1).await;
        let registry = registry_for(&rpc);
        let h = SimulateHandler::new(registry, Arc::new(AddressBook::default()));

        // 1. write a sim intent.
        let intent = serde_json::json!({
            "kind": "send",
            "from": alice,
            "to": recip,
            "value": "0.1 eth",
            "chain": "anvil",
        });
        let new_path = VfsPath::parse("/new").unwrap();
        h.write(&new_path, intent.to_string().as_bytes())
            .await
            .expect("write new");

        // 2. last should now point at our session.
        let last_bytes = h
            .read(&VfsPath::parse("/last").unwrap())
            .await
            .expect("read last");
        let id = String::from_utf8(last_bytes).unwrap().trim().to_string();
        assert!(id.starts_with("sim-"), "id was {:?}", id);

        // 3. simulation.json should be success=true with gas_used > 0.
        let sim_path = VfsPath::parse(&format!("/{}/simulation.json", id)).unwrap();
        let sim_bytes = h.read(&sim_path).await.expect("read simulation.json");
        let sim: SimResult = serde_json::from_slice(&sim_bytes).unwrap();
        assert!(sim.success, "expected success=true, got {:?}", sim);
        assert!(
            sim.gas_used > 0,
            "expected gas_used>0, got {}",
            sim.gas_used
        );

        // 4. plan.md should not be empty.
        let plan_bytes = h
            .read(&VfsPath::parse(&format!("/{}/plan.md", id)).unwrap())
            .await
            .expect("read plan.md");
        let plan = String::from_utf8(plan_bytes).unwrap();
        assert!(!plan.is_empty());
        assert!(plan.contains("Simulated tx"));

        // 5. trace.json should always exist (either real or unsupported).
        let trace_bytes = h
            .read(&VfsPath::parse(&format!("/{}/trace.json", id)).unwrap())
            .await
            .expect("read trace.json");
        let trace: serde_json::Value = serde_json::from_slice(&trace_bytes).unwrap();
        // either an object with "unsupported" or with real trace data.
        assert!(trace.is_object());

        drop(anvil);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn anvil_state_override_zero_balance_fails() {
        if !anvil_available() {
            eprintln!("anvil not found at {}; skipping", anvil_bin());
            return;
        }
        let anvil = spawn_anvil().await;
        let rpc = anvil.rpc_url();
        let alice = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
        let recip = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
        fund(&rpc, alice, 1).await;
        let registry = registry_for(&rpc);
        let h = SimulateHandler::new(registry, Arc::new(AddressBook::default()));

        // Override alice's balance to 0 and try to send 0.1 ETH from her.
        // eth_call should now fail with "insufficient funds".
        let overrides = serde_json::json!({
            alice: { "balance": "0x0" }
        });
        let intent = serde_json::json!({
            "kind": "send",
            "from": alice,
            "to": recip,
            "value": "0.1 eth",
            "chain": "anvil",
            "state_override": overrides,
        });
        let new_path = VfsPath::parse("/new").unwrap();
        h.write(&new_path, intent.to_string().as_bytes())
            .await
            .expect("write new");

        let id = String::from_utf8(h.read(&VfsPath::parse("/last").unwrap()).await.unwrap())
            .unwrap()
            .trim()
            .to_string();
        let sim_bytes = h
            .read(&VfsPath::parse(&format!("/{}/simulation.json", id)).unwrap())
            .await
            .unwrap();
        let sim: SimResult = serde_json::from_slice(&sim_bytes).unwrap();
        assert!(!sim.success, "expected revert, got {:?}", sim);
        assert!(
            sim.revert_reason.is_some(),
            "expected revert_reason, got {:?}",
            sim
        );

        drop(anvil);
    }
}
