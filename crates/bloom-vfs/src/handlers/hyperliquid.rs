//! `hyperliquid/...` VFS surface for HyperCore reads and signed Exchange writes.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bloom_hyperliquid::{
    CancelWire, ExchangeAction, Grouping, HyperliquidClient, HyperliquidNetwork, HyperliquidSigner,
    LimitOrderType, OrderTypeWire, OrderWire, SignSubmit, SignedSubmit, TimeInForce,
    UsdSendRequest, parse_address, pretty_json, sign_submit_payload, signed_payload,
    user_signed_payload,
};
use bloom_keystore::{Keystore, ephemeral::EphemeralAgentKey};
use bloom_proto::hyperliquid_policy::HyperliquidPolicy;
use bloom_proto::{
    BreachAction, CapabilityStatus, CapabilityViewEntry, HyperliquidSession, SessionStatus,
    SigningModel, Venue, parse_units, prelude::U256, resolve_hyperliquid_agent_session_name,
};
use parking_lot::Mutex;
use rand::RngCore;
use serde_json::{Value, json};

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

const NETWORKS: [&str; 2] = ["mainnet", "testnet"];
const ROOT_FILES: [&str; 2] = ["README.md", "asset_ids.md"];
const NETWORK_FILES: [&str; 7] = [
    "status.json",
    "mids.json",
    "perp_meta.json",
    "perp_contexts.json",
    "predicted_fundings.json",
    "spot_meta.json",
    "spot_contexts.json",
];
const USER_FILES: [&str; 8] = [
    "clearinghouse.json",
    "spot_state.json",
    "open_orders.json",
    "frontend_open_orders.json",
    "fills.json",
    "portfolio.json",
    "rate_limit.json",
    "extra_agents.json",
];
const EXCHANGE_WRITE_FILES: [&str; 6] = [
    "order.json",
    "cancel.json",
    "schedule_cancel.json",
    "update_leverage.json",
    "raw_signed.json",
    "send_asset.json",
];
const EXCHANGE_READ_FILES: [&str; 1] = ["last_response.json"];
const SESSION_ROOT_FILES: [&str; 1] = ["new.json"];
const SESSION_FILES: [&str; 12] = [
    "status.json",
    "session.json",
    "last_response.json",
    "order.json",
    "cancel.json",
    "schedule_cancel.json",
    "stop",
    "cancel_all",
    "close_all",
    "orphan_cancel_all",
    "orphan_close_all",
    "audit.jsonl",
];
const SEALED_AGENT_KEY_FILE: &str = ".agent_key.sealed";
const AGENT_KEY_KEK_FILE: &str = ".agent_key_kek";

const README: &[u8] = br#"# Hyperliquid VFS

Read-only:
- /hyperliquid/mainnet/mids.json
- /hyperliquid/mainnet/perp_meta.json
- /hyperliquid/mainnet/perp_contexts.json
- /hyperliquid/mainnet/predicted_fundings.json
- /hyperliquid/mainnet/spot_meta.json
- /hyperliquid/mainnet/spot_contexts.json
- /hyperliquid/mainnet/books/BTC.json
- /hyperliquid/mainnet/candles/BTC/1m.json
- /hyperliquid/mainnet/recent_trades/BTC.json
- /hyperliquid/mainnet/asset_contexts/BTC.json
- /hyperliquid/mainnet/funding_history/BTC.json
- /hyperliquid/mainnet/users/<account>/clearinghouse.json
- /hyperliquid/mainnet/users/<account>/spot_state.json
- /hyperliquid/mainnet/users/<account>/open_orders.json
- /hyperliquid/mainnet/users/<account>/frontend_open_orders.json
- /hyperliquid/mainnet/users/<account>/fills.json
- /hyperliquid/mainnet/users/<account>/portfolio.json
- /hyperliquid/mainnet/users/<account>/rate_limit.json
- /hyperliquid/mainnet/users/<account>/extra_agents.json
- /hyperliquid/mainnet/users/<account>/funding/BTC.json

Signed writes:
- /hyperliquid/<network>/exchange/<wallet>/order.json
- /hyperliquid/<network>/exchange/<wallet>/cancel.json
- /hyperliquid/<network>/exchange/<wallet>/schedule_cancel.json
- /hyperliquid/<network>/exchange/<wallet>/update_leverage.json
- /hyperliquid/<network>/exchange/<wallet>/raw_signed.json
- /hyperliquid/<network>/exchange/<wallet>/send_asset.json  (usdSend: internal USDC transfer, owner-signed)

Agent sessions:
- /hyperliquid/<network>/agent_sessions/<wallet>/new.json
- /hyperliquid/<network>/agent_sessions/<wallet>/<session>/status.json
- /hyperliquid/<network>/agent_sessions/<wallet>/<session>/order.json
- /hyperliquid/<network>/agent_sessions/<wallet>/<session>/cancel.json
- /hyperliquid/<network>/agent_sessions/<wallet>/<session>/schedule_cancel.json
- /hyperliquid/<network>/agent_sessions/<wallet>/<session>/stop
- /hyperliquid/<network>/agent_sessions/<wallet>/<session>/cancel_all
- /hyperliquid/<network>/agent_sessions/<wallet>/<session>/close_all
- /hyperliquid/<network>/agent_sessions/<wallet>/<session>/orphan_cancel_all  (owner-signed recovery)
- /hyperliquid/<network>/agent_sessions/<wallet>/<session>/orphan_close_all   (owner-signed recovery)

Writes submit immediately. Use an unlocked Bloom wallet. For sub-accounts or
vaults, include vaultAddress; the master wallet signs and Hyperliquid applies
the action to that account.

Safety model:
- Read-only paths never need wallet unlock.
- Signed exchange writes submit immediately after signing.
- Bounded test writes have in-code caps and cleanup checks, but they are not a
  general policy engine.
- Policy sessions and ephemeral API wallets should grant a short-lived agent
  signer, enforce duration/notional/leverage/loss/asset caps locally, deny
  withdrawals and third-party transfers by default, and cancel/close at expiry.
- Hyperliquid API wallets are standing signing authority until expired or
  replaced; do not treat approveAgent as a normal order signature.

Known limitations (this is a functional integration, not a hardened surface):
- Reads are best-effort: the client retries transport failures with bounded
  jittered backoff (3x) but has no stale-cache, so `POST /info`-backed reads
  (mids, books, candles, portfolio, ...) can still transiently fail even while
  signed writes succeed. Retry at the caller for anything critical. (Writes only
  retry pre-send connection failures, never after a possible submit.)
- The session monitor is fail-stale, not fail-safe: if it cannot read a risk
  snapshot, it keeps last-known risk, so the loss stop may not trip until the
  session expires (expiry-driven cancel/close still fires). It will not
  auto-flatten on a transient read failure. The session status surfaces this so
  it is observable, not silent:
    - `stale`: true when the most recent risk-snapshot read failed; the risk
      figures (account value, drawdown, loss) are then last-known, not live.
    - `last_snapshot_ok_ms`: unix-ms of the last successful snapshot read.
    - `stale_since_ms`: unix-ms when the current stale streak began (null when
      fresh). These are observability only -- behavior is unchanged.
- After a daemon restart/crash an in-flight session is orphaned (its ephemeral
  agent key was in memory). Active-session cleanup is automatic via the agent;
  ORPHAN cleanup requires an explicit owner action -- write to the orphaned
  session's `orphan_cancel_all` / `orphan_close_all` with the owner wallet
  unlocked, which cancels/flattens using the owner key.
"#;

const ASSET_IDS: &[u8] = br#"# Hyperliquid Asset IDs

- Perp asset: index in `perp_meta.json` universe. BTC is normally 0 on mainnet.
- Builder perp asset: `100000 + perp_dex_index * 10000 + index_in_meta`.
- Spot asset: `10000 + spotMeta.universe[index].index`.
- Outcome asset: `100000000 + 10 * outcome + side`, side is 0 or 1.

Order compact keys:
- a: numeric asset id
- b: is buy
- p: price string
- s: size string
- r: reduce only
- t: order type
- c: optional 128-bit client order id

Cancel compact keys:
- a: numeric asset id
- o: order id
- f: fast flag; omit it when false.

Common read paths:
- `perp_meta.json` maps perp symbols to numeric asset ids.
- `perp_contexts.json` returns `[meta, asset_ctxs]`; asset context indices
  match `perp_meta.json` universe indices.
- `asset_contexts/<coin>.json` returns one perp market's metadata and asset
  context by symbol, derived from `metaAndAssetCtxs`.
- `books/<coin>.json` returns the current L2 book snapshot.
- `recent_trades/<coin>.json` returns the recent trade snapshot when supported
  by the Hyperliquid Info endpoint.
- `funding_history/<coin>.json` returns recent public funding history.
- `predicted_fundings.json` returns predicted funding data for markets.
"#;

#[derive(Clone)]
pub struct HyperliquidHandler {
    mainnet: HyperliquidClient,
    testnet: HyperliquidClient,
    keystore: Keystore,
    store_root: Option<PathBuf>,
    sessions: Arc<Mutex<HashMap<String, Arc<Mutex<ActiveHlSession>>>>>,
    pending_sessions: Arc<Mutex<HashSet<String>>>,
}

impl HyperliquidHandler {
    pub fn new(mainnet: HyperliquidClient, testnet: HyperliquidClient, keystore: Keystore) -> Self {
        Self {
            mainnet,
            testnet,
            keystore,
            store_root: None,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            pending_sessions: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn with_store_root(mut self, root: PathBuf) -> Self {
        self.store_root = Some(root);
        self.warn_pre_approval_markers();
        self
    }

    pub fn start_monitoring(self: Arc<Self>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::warn!("hyperliquid.agent_sessions.monitor_skipped: no tokio runtime");
            return;
        };
        handle.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            loop {
                tick.tick().await;
                self.monitor_sessions_once().await;
            }
        });
    }

    pub fn capability_views_for(&self, wallet: &str) -> Vec<CapabilityViewEntry> {
        let mut entries = Vec::new();
        // In-memory sessions. Track (network, id) so the on-disk scan below can
        // skip anything already represented here.
        let mut in_memory: HashSet<(String, String)> = HashSet::new();
        {
            let sessions = self.sessions.lock();
            for guard in sessions.values() {
                let active = guard.lock();
                if active.wallet != wallet {
                    continue;
                }
                let s = &active.session;
                in_memory.insert((active.network.clone(), s.id.clone()));
                let status = if s.status == SessionStatus::Expired {
                    CapabilityStatus::Expired
                } else if s.status == SessionStatus::Halted {
                    CapabilityStatus::Halted
                } else if active.stopped {
                    CapabilityStatus::Revoked
                } else if active.stale_since_ms.is_some() {
                    // Still in memory (key intact) but the risk snapshot is
                    // stale — NOT an orphaned/lost key.
                    CapabilityStatus::Stale
                } else {
                    CapabilityStatus::Active
                };
                entries.push(hl_capability_entry(
                    &active.network,
                    wallet,
                    &s.id,
                    &s.bounds,
                    s.created_ms,
                    s.expires_ms,
                    status,
                ));
            }
        }
        // Persisted sessions left behind by a daemon restart (key not in the
        // in-memory map) are genuinely orphaned and would otherwise be invisible
        // here. Surface them so the owner sees they need recovery.
        entries.extend(self.persisted_orphan_capability_views(wallet, &in_memory));
        entries
    }

    /// Scan the on-disk session store for this wallet's still-active persisted
    /// sessions that are NOT in the in-memory map, and render them as orphaned
    /// capability entries needing owner recovery.
    fn persisted_orphan_capability_views(
        &self,
        wallet: &str,
        in_memory: &HashSet<(String, String)>,
    ) -> Vec<CapabilityViewEntry> {
        let Some(root) = &self.store_root else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for network in ["mainnet", "testnet"] {
            let wallet_dir = root.join("agent_sessions").join(network).join(wallet);
            let Ok(read_dir) = std::fs::read_dir(&wallet_dir) else {
                continue;
            };
            for entry in read_dir.flatten() {
                if !entry.path().is_dir() {
                    continue;
                }
                let Some(id) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                if in_memory.contains(&(network.to_string(), id.clone())) {
                    continue;
                }
                let session_path = entry.path().join("session.json");
                let Ok(bytes) = std::fs::read(&session_path) else {
                    continue;
                };
                let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
                    continue;
                };
                // Only surface sessions that are still live (not stopped /
                // cleaned up / expired); finished ones are not pending recovery.
                let stopped = value
                    .get("stopped")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let cleaned = optional_u64(&value, "cleanup_completed_ms").is_some();
                let status_str = value.get("status").and_then(Value::as_str).unwrap_or("");
                if stopped || cleaned || status_str != "Active" {
                    continue;
                }
                let Some(bounds) = value
                    .get("bounds")
                    .cloned()
                    .and_then(|b| serde_json::from_value::<HyperliquidPolicy>(b).ok())
                else {
                    continue;
                };
                let created_ms = value
                    .get("created_ms")
                    .and_then(Value::as_u64)
                    .map(u128::from)
                    .unwrap_or(0);
                let expires_ms = value
                    .get("expires_ms")
                    .and_then(Value::as_u64)
                    .map(u128::from)
                    .unwrap_or(0);
                out.push(hl_capability_entry(
                    network,
                    wallet,
                    &id,
                    &bounds,
                    created_ms,
                    expires_ms,
                    CapabilityStatus::Orphaned,
                ));
            }
        }
        out
    }

    fn client(&self, network: &str) -> Result<&HyperliquidClient, HandlerError> {
        match network {
            "mainnet" => Ok(&self.mainnet),
            "testnet" => Ok(&self.testnet),
            _ => Err(HandlerError::NotFound(network.into())),
        }
    }

    fn network(network: &str) -> Result<HyperliquidNetwork, HandlerError> {
        match network {
            "mainnet" => Ok(HyperliquidNetwork::Mainnet),
            "testnet" => Ok(HyperliquidNetwork::Testnet),
            _ => Err(HandlerError::NotFound(network.into())),
        }
    }

    fn session_key(network: &str, wallet: &str, session: &str) -> String {
        format!("{network}:{wallet}:{session}")
    }

    async fn info_file(
        &self,
        client: &HyperliquidClient,
        file: &str,
    ) -> Result<Value, HandlerError> {
        let req = match file {
            "status.json" => json!({
                "network": client.network(),
                "api_url": client.base_url().as_str(),
                "info_endpoint": client.base_url().join("info").map(|u| u.to_string()).unwrap_or_default(),
                "exchange_endpoint": client.base_url().join("exchange").map(|u| u.to_string()).unwrap_or_default()
            }),
            "mids.json" => client
                .info(json!({"type": "allMids"}))
                .await
                .map_err(err_be)?,
            "perp_meta.json" => client.info(json!({"type": "meta"})).await.map_err(err_be)?,
            "perp_contexts.json" => client
                .info(json!({"type": "metaAndAssetCtxs"}))
                .await
                .map_err(err_be)?,
            "predicted_fundings.json" => client
                .info(json!({"type": "predictedFundings"}))
                .await
                .map_err(err_be)?,
            "spot_meta.json" => client
                .info(json!({"type": "spotMeta"}))
                .await
                .map_err(err_be)?,
            "spot_contexts.json" => client
                .info(json!({"type": "spotMetaAndAssetCtxs"}))
                .await
                .map_err(err_be)?,
            _ => return Err(HandlerError::NotAFile(file.into())),
        };
        Ok(req)
    }

    async fn user_file(
        &self,
        client: &HyperliquidClient,
        user: &str,
        file: &str,
    ) -> Result<Value, HandlerError> {
        let address = parse_address(user).map_err(err_invalid)?;
        let user = format!("{address:#x}");
        let body = match file {
            "clearinghouse.json" => json!({"type": "clearinghouseState", "user": user}),
            "spot_state.json" => json!({"type": "spotClearinghouseState", "user": user}),
            "open_orders.json" => json!({"type": "openOrders", "user": user}),
            "frontend_open_orders.json" => json!({"type": "frontendOpenOrders", "user": user}),
            "fills.json" => json!({"type": "userFills", "user": user}),
            "portfolio.json" => json!({"type": "portfolio", "user": user}),
            "rate_limit.json" => json!({"type": "userRateLimit", "user": user}),
            "extra_agents.json" => json!({"type": "extraAgents", "user": user}),
            _ => return Err(HandlerError::NotAFile(file.into())),
        };
        client.info(body).await.map_err(err_be)
    }

    async fn book_file(
        &self,
        client: &HyperliquidClient,
        coin_file: &str,
    ) -> Result<Value, HandlerError> {
        let coin = coin_from_json_file(coin_file)?;
        client
            .info(json!({"type": "l2Book", "coin": coin}))
            .await
            .map_err(err_be)
    }

    async fn recent_trades_file(
        &self,
        client: &HyperliquidClient,
        coin_file: &str,
    ) -> Result<Value, HandlerError> {
        let coin = coin_from_json_file(coin_file)?;
        client
            .info(json!({"type": "recentTrades", "coin": coin}))
            .await
            .map_err(err_be)
    }

    async fn asset_context_file(
        &self,
        client: &HyperliquidClient,
        coin_file: &str,
    ) -> Result<Value, HandlerError> {
        let coin = coin_from_json_file(coin_file)?;
        let value = client
            .info(json!({"type": "metaAndAssetCtxs"}))
            .await
            .map_err(err_be)?;
        asset_context_by_coin(value, &coin)
    }

    async fn funding_history_file(
        &self,
        client: &HyperliquidClient,
        coin_file: &str,
    ) -> Result<Value, HandlerError> {
        let coin = coin_from_json_file(coin_file)?;
        let end = bloom_hyperliquid::now_ms();
        let start = end.saturating_sub(24 * 60 * 60 * 1000);
        client
            .info(json!({
                "type": "fundingHistory",
                "coin": coin,
                "startTime": start,
                "endTime": end,
            }))
            .await
            .map_err(err_be)
    }

    async fn candle_file(
        &self,
        client: &HyperliquidClient,
        coin: &str,
        interval_file: &str,
    ) -> Result<Value, HandlerError> {
        let interval = interval_from_json_file(interval_file)?;
        let end = bloom_hyperliquid::now_ms();
        let start = end.saturating_sub(60 * 60 * 1000);
        client
            .info(json!({
                "type": "candleSnapshot",
                "req": {
                    "coin": coin,
                    "interval": interval,
                    "startTime": start,
                    "endTime": end,
                }
            }))
            .await
            .map_err(err_be)
    }

    async fn funding_file(
        &self,
        client: &HyperliquidClient,
        user: &str,
        coin_file: &str,
    ) -> Result<Value, HandlerError> {
        let address = parse_address(user).map_err(err_invalid)?;
        let user = format!("{address:#x}");
        let coin = coin_from_json_file(coin_file)?;
        let end = bloom_hyperliquid::now_ms();
        let start = end.saturating_sub(60 * 60 * 1000);
        client
            .info(json!({
                "type": "userFunding",
                "user": user,
                "coin": coin,
                "startTime": start,
                "endTime": end,
            }))
            .await
            .map_err(err_be)
    }

    async fn create_agent_session(
        &self,
        client: &HyperliquidClient,
        network: HyperliquidNetwork,
        network_name: &str,
        wallet: &str,
        req: AgentSessionCreate,
    ) -> Result<(), HandlerError> {
        let nonce = bloom_hyperliquid::now_ms();
        let id = req.id.unwrap_or_else(|| format!("hl-{}", nonce));
        safe_segment(&id)?;
        let reservation = self.reserve_session_slot(network_name, wallet, &id)?;
        let info = self
            .keystore
            .info(wallet)
            .map_err(|e| HandlerError::backend(e.to_string()))?;
        let policy = info.policy.hyperliquid.clone();
        if !policy.is_session_capable() {
            return Err(HandlerError::invalid(
                "refusing to create Hyperliquid agent session: wallet [hyperliquid] policy must set allowed_assets, max_notional_usd, max_position_usd, and max_loss_usd",
            ));
        }
        let owner_signer = self.keystore.signer(wallet).map_err(|e| {
            HandlerError::PermissionDenied
                .with_context(format!("wallet '{wallet}' is locked or unavailable: {e}"))
        })?;
        let owner = HyperliquidSigner::new(owner_signer);
        let agent = EphemeralAgentKey::generate();
        let agent_address = agent.address();
        let agent_name = resolve_hyperliquid_agent_session_name(req.agent_name.as_deref());
        let agent_key_persisted = self.persist_agent_key(network_name, wallet, &id, &agent)?;
        // Risk is monitored on the account the session actually trades: the vault
        // when one is requested, otherwise the master wallet.
        let vault_address = req.vault_address.clone();
        let user = match vault_address.as_deref() {
            Some(v) => v.to_string(),
            None => format!("{:#x}", info.address),
        };
        let clearinghouse = client
            .info(json!({"type": "clearinghouseState", "user": user}))
            .await
            .map_err(err_be)?;
        let snapshot = HlSnapshot::from_clearinghouse(&clearinghouse);
        let (action, signature) = owner
            .sign_approve_agent(network, agent_address, Some(&agent_name), nonce)
            .await
            .map_err(err_be)?;
        let payload = user_signed_payload(action.clone(), nonce, signature.clone());
        self.write_pre_approval_marker(
            network_name,
            wallet,
            &id,
            &format!("{agent_address:#x}"),
            &agent_name,
        )?;
        let approve_response = match client.exchange(payload.clone()).await {
            Ok(response) => response,
            Err(e) => {
                if agent_key_persisted
                    && let Ok(path) = self.sealed_agent_key_path(network_name, wallet, &id)
                {
                    let _ = std::fs::remove_file(&path);
                }
                let extra_agents = client
                    .info(json!({"type": "extraAgents", "user": format!("{:#x}", info.address)}))
                    .await
                    .ok();
                let mut msg = e.to_string();
                if let Some(extra_agents) = extra_agents {
                    msg.push_str(&format!(
                        " | current extraAgents: {}",
                        serde_json::to_string(&extra_agents)
                            .unwrap_or_else(|_| "<unserializable>".into())
                    ));
                }
                return Err(HandlerError::backend(msg));
            }
        };
        let now = u128::from(nonce);
        let mut session = HyperliquidSession::new(
            id.clone(),
            wallet.to_string(),
            format!("{agent_address:#x}"),
            policy,
            snapshot.account_value,
            now,
        );
        session.update_risk(
            snapshot.account_value,
            snapshot.unrealized_loss.unwrap_or(0),
            snapshot.open_orders,
            snapshot.open_positions,
        );
        let active = ActiveHlSession {
            network: network_name.to_string(),
            wallet: wallet.to_string(),
            agent,
            vault_address,
            session,
            stopped: false,
            cleanup_started_ms: None,
            cleanup_completed_ms: None,
            last_cleanup_error: None,
            last_snapshot_ok_ms: Some(nonce),
            stale_since_ms: None,
            agent_key_persisted,
        };
        let key = Self::session_key(network_name, wallet, &id);
        let active = Arc::new(Mutex::new(active));
        self.sessions.lock().insert(key, active.clone());
        drop(reservation);
        {
            let guard = active.lock();
            self.persist_session_metadata(&guard, false)?;
        }
        self.append_session_audit(
            network_name,
            wallet,
            &id,
            &json!({
                "event": "created",
                "agent_address": format!("{agent_address:#x}"),
                "agent_name": agent_name,
                "approve_payload": payload,
                "approve_response": approve_response,
                "starting_account_value_micro": snapshot.account_value,
                "agent_key_persisted": agent_key_persisted,
            }),
        )?;
        self.persist_response(
            network_name,
            wallet,
            "agent_session_new.json",
            &json!({
                "session_id": id,
                "agent_address": format!("{agent_address:#x}"),
                "agent_name": agent_name,
                "approve_response": approve_response,
                "starting_account_value_micro": snapshot.account_value,
                "agent_key_persisted": agent_key_persisted,
            }),
        )?;
        self.clear_pre_approval_marker(network_name, wallet, &id)?;
        Ok(())
    }

    fn reserve_session_slot(
        &self,
        network_name: &str,
        wallet: &str,
        id: &str,
    ) -> Result<SessionSlotReservation, HandlerError> {
        let key = Self::session_key(network_name, wallet, id);
        let prefix = format!("{network_name}:{wallet}:");
        let now = u128::from(bloom_hyperliquid::now_ms());
        {
            let sessions = self.sessions.lock();
            if sessions.iter().any(|(key, active)| {
                key.starts_with(&prefix) && session_blocks_create(&active.lock(), now)
            }) {
                return Err(HandlerError::invalid(format!(
                    "refusing to create a second Hyperliquid agent session for wallet '{wallet}' on {network_name}; stop the active session first"
                )));
            }
            let mut pending = self.pending_sessions.lock();
            if pending.iter().any(|key| key.starts_with(&prefix)) {
                return Err(HandlerError::invalid(format!(
                    "refusing to create a second Hyperliquid agent session for wallet '{wallet}' on {network_name}; another session create is already pending"
                )));
            }
            pending.insert(key.clone());
        }
        let reservation = SessionSlotReservation {
            pending_sessions: self.pending_sessions.clone(),
            key,
        };
        if let Some(conflict) = self.persisted_live_session_id(network_name, wallet)? {
            drop(reservation);
            return Err(HandlerError::invalid(format!(
                "refusing to create Hyperliquid agent session while persisted session '{conflict}' for wallet '{wallet}' on {network_name} remains live/orphaned; recover or rotate that session first"
            )));
        }
        Ok(reservation)
    }

    #[cfg(test)]
    fn ensure_session_create_allowed(
        &self,
        network_name: &str,
        wallet: &str,
    ) -> Result<(), HandlerError> {
        let id = format!("guard-{}", bloom_hyperliquid::now_ms());
        drop(self.reserve_session_slot(network_name, wallet, &id)?);
        Ok(())
    }

    async fn session_status_value(
        &self,
        client: &HyperliquidClient,
        network_name: &str,
        wallet: &str,
        id: &str,
    ) -> Result<Value, HandlerError> {
        let active = match self.active_session_if_present(network_name, wallet, id) {
            Some(active) => active,
            None => match self
                .try_recover_persisted_session(client, network_name, wallet, id)
                .await?
            {
                Some(active) => active,
                None => return self.read_orphaned_session_status(network_name, wallet, id),
            },
        };
        self.refresh_session_snapshot(client, &active, false)
            .await?;
        let mut guard = active.lock();
        let action = if guard.stopped {
            BreachAction::None
        } else {
            guard
                .session
                .evaluate(u128::from(bloom_hyperliquid::now_ms()))
        };
        Ok(session_status_json(&guard, action))
    }

    fn apply_snapshot_to_session(
        &self,
        guard: &mut ActiveHlSession,
        snapshot: Option<&HlSnapshot>,
    ) {
        // KNOWN LIMITATION (fail-stale, not fail-safe): on a persistent snapshot
        // read failure the monitor keeps last-known risk, so the `max_loss` stop
        // can't trip until expiry. We deliberately do NOT auto-flatten on a read
        // error — a transient RPC blip must not liquidate a healthy position.
        // Expiry-driven cleanup still fires regardless of snapshot availability.
        let now = bloom_hyperliquid::now_ms();
        if let Some(s) = snapshot {
            guard.session.update_risk(
                s.account_value,
                s.unrealized_loss.unwrap_or(0),
                s.open_orders,
                s.open_positions,
            );
            guard.last_snapshot_ok_ms = Some(now);
            guard.stale_since_ms = None;
        } else {
            // First failure since the last success stamps stale_since; subsequent
            // failures keep the original timestamp so callers can see staleness age.
            guard.stale_since_ms.get_or_insert(now);
        }
    }

    async fn refresh_session_snapshot(
        &self,
        client: &HyperliquidClient,
        active: &Arc<Mutex<ActiveHlSession>>,
        orphaned: bool,
    ) -> Result<Option<HlSnapshot>, HandlerError> {
        let (owner, vault_address) = {
            let guard = active.lock();
            (guard.wallet.clone(), guard.vault_address.clone())
        };
        let snapshot = self
            .hl_account_snapshot(client, &owner, vault_address.as_deref())
            .await;
        let mut guard = active.lock();
        self.apply_snapshot_to_session(&mut guard, snapshot.as_ref());
        self.persist_session_metadata(&guard, orphaned)?;
        Ok(snapshot)
    }

    fn active_session(
        &self,
        network: &str,
        wallet: &str,
        id: &str,
    ) -> Result<Arc<Mutex<ActiveHlSession>>, HandlerError> {
        self.active_session_if_present(network, wallet, id)
            .ok_or_else(|| HandlerError::NotFound(format!("agent session {id}")))
    }

    fn active_session_if_present(
        &self,
        network: &str,
        wallet: &str,
        id: &str,
    ) -> Option<Arc<Mutex<ActiveHlSession>>> {
        self.sessions
            .lock()
            .get(&Self::session_key(network, wallet, id))
            .cloned()
    }

    async fn active_session_or_recover(
        &self,
        client: &HyperliquidClient,
        network: &str,
        wallet: &str,
        id: &str,
    ) -> Result<Arc<Mutex<ActiveHlSession>>, HandlerError> {
        if let Some(active) = self.active_session_if_present(network, wallet, id) {
            return Ok(active);
        }
        self.try_recover_persisted_session(client, network, wallet, id)
            .await?
            .ok_or_else(|| HandlerError::NotFound(format!("agent session {id}")))
    }

    async fn submit_session_action(
        &self,
        client: &HyperliquidClient,
        network: HyperliquidNetwork,
        target: SessionActionTarget<'_>,
        req: SignSubmit,
    ) -> Result<(), HandlerError> {
        validate_write_file_matches_action(target.file, req.action.kind())?;
        let active = self
            .active_session_or_recover(client, target.network, target.wallet, target.id)
            .await?;
        // A submit must target the same account the session is scoped to, so it
        // can't route orders to an account the monitor/cleanup won't cover.
        {
            let guard = active.lock();
            if !vault_matches(guard.vault_address.as_deref(), req.vault_address.as_deref()) {
                return Err(HandlerError::invalid(format!(
                    "submit vaultAddress {:?} does not match the session's account {:?}",
                    req.vault_address, guard.vault_address
                )));
            }
        }
        {
            let mut guard = active.lock();
            if guard.stopped || guard.session.status != SessionStatus::Active {
                return Err(HandlerError::invalid(
                    "Hyperliquid agent session is not active",
                ));
            }
            match guard
                .session
                .evaluate(u128::from(bloom_hyperliquid::now_ms()))
            {
                BreachAction::None => {}
                action => {
                    self.append_session_audit(
                        target.network,
                        target.wallet,
                        target.id,
                        &json!({"event": "blocked_by_session_state", "breach_action": format!("{action:?}")}),
                    )?;
                    return Err(HandlerError::invalid(format!(
                        "Hyperliquid agent session is not tradable: {action:?}"
                    )));
                }
            }
        }
        let bounds = active.lock().session.bounds.clone();
        self.enforce_hyperliquid_policy(
            client,
            target.wallet,
            &req.action,
            req.vault_address.as_deref(),
            Some(&bounds),
        )
        .await?;
        let signer = {
            let guard = active.lock();
            HyperliquidSigner::new(guard.agent.signer())
        };
        let payload = sign_submit_payload(&signer, network, req.clone())
            .await
            .map_err(err_be)?;
        let response = client.exchange(payload.clone()).await.map_err(err_be)?;
        let notional = action_notional_micro(&req.action);
        {
            let mut guard = active.lock();
            if let Some(notional) = notional {
                guard.session.record_order(notional);
            }
            self.persist_session_metadata(&guard, false)?;
        }
        let post_submit = self
            .refresh_session_snapshot(client, &active, false)
            .await?;
        self.append_session_audit(
            target.network,
            target.wallet,
            target.id,
            &json!({
                "event": "submitted",
                "file": target.file,
                "action_kind": req.action.kind(),
                "notional_micro": notional,
                "payload": payload,
                "response": response,
                "post_submit": snapshot_json(post_submit.as_ref()),
            }),
        )?;
        self.persist_session_response(
            SessionResponseTarget {
                network: target.network,
                wallet: target.wallet,
                session: target.id,
                file: target.file,
            },
            Some(&payload),
            &response,
            post_submit.as_ref(),
        )?;
        self.persist_response(target.network, target.wallet, target.file, &response)?;
        Ok(())
    }

    async fn stop_session(
        &self,
        network_name: &str,
        wallet: &str,
        id: &str,
    ) -> Result<(), HandlerError> {
        let active = self.active_session(network_name, wallet, id)?;
        {
            let mut guard = active.lock();
            guard.stopped = true;
            guard.session.status = SessionStatus::Expired;
            self.persist_session_metadata(&guard, false)?;
        }
        self.append_session_audit(network_name, wallet, id, &json!({"event": "stopped"}))?;
        Ok(())
    }

    /// Build `CancelWire`s for every open order on `user`'s account. Shared by
    /// the agent-session and owner-signed orphan cleanup paths.
    async fn collect_cancel_wires(
        &self,
        client: &HyperliquidClient,
        user: &str,
    ) -> Result<Vec<CancelWire>, HandlerError> {
        let open_orders = client
            .info(json!({"type": "openOrders", "user": user}))
            .await
            .map_err(err_be)?;
        let meta = client.info(json!({"type": "meta"})).await.map_err(err_be)?;
        let coin_to_asset: HashMap<String, u32> = meta
            .get("universe")
            .and_then(|u| u.as_array())
            .map(|arr| {
                arr.iter()
                    .enumerate()
                    .filter_map(|(idx, entry)| {
                        let coin = entry.get("name")?.as_str()?.to_string();
                        let asset = u32::try_from(idx).ok()?;
                        Some((coin, asset))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut cancels = Vec::new();
        if let Some(orders) = open_orders.as_array() {
            for order in orders {
                let Some(oid) = order.get("oid").and_then(Value::as_u64) else {
                    continue;
                };
                let asset = match order.get("asset").and_then(Value::as_u64) {
                    Some(asset) => Some(asset as u32),
                    None => order
                        .get("coin")
                        .and_then(Value::as_str)
                        .and_then(|c| coin_to_asset.get(c).copied()),
                };
                if let Some(asset) = asset {
                    cancels.push(CancelWire { asset, oid });
                }
            }
        }
        Ok(cancels)
    }

    /// Build reduce-only IOC close orders for every open position on `user`'s
    /// account. Shared by the agent-session and owner-signed orphan paths.
    async fn collect_reduce_only_closes(
        &self,
        client: &HyperliquidClient,
        user: &str,
    ) -> Result<Vec<OrderWire>, HandlerError> {
        let clearinghouse = client
            .info(json!({"type": "clearinghouseState", "user": user}))
            .await
            .map_err(err_be)?;
        let meta = client.info(json!({"type": "meta"})).await.map_err(err_be)?;
        let coin_info: HashMap<String, (u32, usize)> = meta
            .get("universe")
            .and_then(|u| u.as_array())
            .map(|arr| {
                arr.iter()
                    .enumerate()
                    .filter_map(|(idx, entry)| {
                        let coin = entry.get("name")?.as_str()?.to_string();
                        let asset = u32::try_from(idx).ok()?;
                        let sz_decimals = entry
                            .get("szDecimals")?
                            .as_u64()
                            .and_then(|n| usize::try_from(n).ok())
                            .unwrap_or(5);
                        Some((coin, (asset, sz_decimals)))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut closes = Vec::new();
        if let Some(positions) = clearinghouse
            .get("assetPositions")
            .and_then(Value::as_array)
        {
            for pos in positions {
                let Some(position) = pos.get("position") else {
                    continue;
                };
                let Some(coin) = position.get("coin").and_then(Value::as_str) else {
                    continue;
                };
                let Some(szi) = position
                    .get("szi")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<f64>().ok())
                else {
                    continue;
                };
                if szi == 0.0 {
                    continue;
                }
                let Some(&(asset, sz_decimals)) = coin_info.get(coin) else {
                    continue;
                };
                let book = client
                    .info(json!({"type": "l2Book", "coin": coin}))
                    .await
                    .map_err(err_be)?;
                let close_is_buy = szi < 0.0;
                let px = if close_is_buy {
                    best_book_px(&book, 1)? * 1.005
                } else {
                    best_book_px(&book, 0)? * 0.995
                };
                closes.push(OrderWire {
                    asset,
                    is_buy: close_is_buy,
                    price: format_hl_close_price(px)?,
                    size: format_decimal(szi.abs(), sz_decimals),
                    reduce_only: true,
                    order_type: OrderTypeWire {
                        limit: Some(LimitOrderType {
                            tif: TimeInForce::Ioc,
                        }),
                        trigger: None,
                    },
                    cloid: None,
                });
            }
        }
        Ok(closes)
    }

    // ── owner-signed orphan recovery ──────────────────────────────────────────
    // A bounded session's ephemeral agent key lives only in daemon memory, so
    // after a restart/crash an orphaned session can no longer self-clean. These
    // entry points let the **owner** key cancel/flatten the orphaned exposure.
    // Deliberately narrow: only when the session is orphaned, owner-unlocked, and
    // only `Cancel` / reduce-only-close actions are constructible here — there is
    // no generic owner-signed action route.

    /// Owner L1 signer for orphan recovery; rejects unless the session is
    /// orphaned (persisted but not in the in-memory map) and the owner is unlocked.
    async fn orphan_owner_signer(
        &self,
        network_name: &str,
        wallet: &str,
        id: &str,
    ) -> Result<HyperliquidSigner, HandlerError> {
        if self.active_session(network_name, wallet, id).is_ok() {
            return Err(HandlerError::invalid(
                "session is still active; use cancel_all/close_all — orphan recovery is only for \
                 sessions left behind by a daemon restart",
            ));
        }
        let session_path = self
            .session_store_dir(network_name, wallet, id)?
            .join("session.json");
        if !session_path.exists() {
            return Err(HandlerError::NotFound(format!("agent session {id}")));
        }
        let session = persisted_orphan_recovery_session(&session_path, id)?;
        tracing::debug!(
            network = network_name,
            wallet,
            session = id,
            agent_address = %session.agent_address,
            "hyperliquid.orphan_recovery_owner_signer"
        );
        let signer = self.keystore.signer(wallet).map_err(|e| {
            HandlerError::PermissionDenied.with_context(format!(
                "owner wallet '{wallet}' must be unlocked for orphan recovery: {e}"
            ))
        })?;
        Ok(HyperliquidSigner::new(signer))
    }

    /// The vault/subaccount a persisted (orphaned) session traded on, recovered
    /// from its `session.json` so owner-signed cleanup flattens the right account.
    fn orphan_session_vault(
        &self,
        network_name: &str,
        wallet: &str,
        id: &str,
    ) -> Result<Option<String>, HandlerError> {
        let session_path = self
            .session_store_dir(network_name, wallet, id)?
            .join("session.json");
        Ok(persisted_orphan_recovery_session(&session_path, id)?.vault_address)
    }

    /// Account address to query for orphan recovery: the session's vault when
    /// set, else the owner wallet (address-only → unverified accessor).
    fn orphan_recovery_user(
        &self,
        wallet: &str,
        vault_address: Option<&str>,
    ) -> Result<String, HandlerError> {
        match vault_address {
            Some(v) => Ok(v.to_string()),
            None => Ok(format!(
                "{:#x}",
                self.keystore
                    .info_unverified(wallet)
                    .map_err(|e| HandlerError::backend(e.to_string()))?
                    .address
            )),
        }
    }

    /// Sign a Cancel / reduce-only-close action with the OWNER key and submit,
    /// recording an explicit owner-recovery audit event.
    #[allow(clippy::too_many_arguments)]
    async fn submit_owner_orphan(
        &self,
        client: &HyperliquidClient,
        network: HyperliquidNetwork,
        network_name: &str,
        wallet: &str,
        id: &str,
        owner: &HyperliquidSigner,
        action: ExchangeAction,
        vault_address: Option<String>,
        event: &str,
    ) -> Result<Value, HandlerError> {
        let payload = sign_submit_payload(
            owner,
            network,
            SignSubmit {
                action,
                nonce: Some(bloom_hyperliquid::now_ms()),
                vault_address,
                expires_after: Some(bloom_hyperliquid::now_ms() + 60_000),
            },
        )
        .await
        .map_err(err_be)?;
        let response = client.exchange(payload.clone()).await.map_err(err_be)?;
        self.append_session_audit(
            network_name,
            wallet,
            id,
            &json!({"event": event, "recovery": "owner_signed_orphan_recovery", "response": response}),
        )?;
        Ok(response)
    }

    async fn orphan_cancel_all(
        &self,
        client: &HyperliquidClient,
        network: HyperliquidNetwork,
        network_name: &str,
        wallet: &str,
        id: &str,
    ) -> Result<Value, HandlerError> {
        let owner_signer = self.orphan_owner_signer(network_name, wallet, id).await?;
        let vault_address = self.orphan_session_vault(network_name, wallet, id)?;
        let user = self.orphan_recovery_user(wallet, vault_address.as_deref())?;
        let cancels = self.collect_cancel_wires(client, &user).await?;
        if cancels.is_empty() {
            let response = json!({"status": "noop", "reason": "no open orders"});
            self.append_session_audit(
                network_name,
                wallet,
                id,
                &json!({"event": "orphan_cancel_all", "recovery": "owner_signed_orphan_recovery", "response": response}),
            )?;
            self.finish_persisted_orphan_recovery(network_name, wallet, id, "orphan_cancel_all")?;
            return Ok(response);
        }
        let action = ExchangeAction::Cancel {
            cancels,
            fast: Some(true),
        };
        let response = self
            .submit_owner_orphan(
                client,
                network,
                network_name,
                wallet,
                id,
                &owner_signer,
                action,
                vault_address,
                "orphan_cancel_all",
            )
            .await?;
        self.finish_persisted_orphan_recovery(network_name, wallet, id, "orphan_cancel_all")?;
        Ok(response)
    }

    fn finish_persisted_orphan_recovery(
        &self,
        network: &str,
        wallet: &str,
        id: &str,
        recovery: &str,
    ) -> Result<(), HandlerError> {
        let dir = self.session_store_dir(network, wallet, id)?;
        let path = dir.join("session.json");
        let bytes = std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                HandlerError::NotFound(format!("agent session {id}"))
            } else {
                HandlerError::Io(e)
            }
        })?;
        let mut value: Value = serde_json::from_slice(&bytes).map_err(err_json)?;
        let Some(obj) = value.as_object_mut() else {
            return Err(HandlerError::invalid(format!(
                "persisted agent session {id} is not a JSON object"
            )));
        };
        let now = bloom_hyperliquid::now_ms();
        obj.insert("status".into(), Value::String("Expired".into()));
        obj.insert("stopped".into(), Value::Bool(true));
        obj.insert("orphaned".into(), Value::Bool(false));
        obj.insert("tradable".into(), Value::Bool(false));
        obj.insert("breach_action".into(), Value::String("None".into()));
        obj.insert(
            "cleanup_completed_ms".into(),
            Value::Number(serde_json::Number::from(now)),
        );
        obj.insert("last_cleanup_error".into(), Value::Null);
        obj.insert(
            "recovery".into(),
            Value::String("owner_signed_orphan_recovery".into()),
        );
        obj.insert("recovery_action".into(), Value::String(recovery.into()));
        obj.insert(
            "recovered_ms".into(),
            Value::Number(serde_json::Number::from(now)),
        );
        std::fs::write(path, pretty_json(&value))?;
        Ok(())
    }

    async fn orphan_close_all(
        &self,
        client: &HyperliquidClient,
        network: HyperliquidNetwork,
        network_name: &str,
        wallet: &str,
        id: &str,
    ) -> Result<Value, HandlerError> {
        let owner_signer = self.orphan_owner_signer(network_name, wallet, id).await?;
        let vault_address = self.orphan_session_vault(network_name, wallet, id)?;
        let user = self.orphan_recovery_user(wallet, vault_address.as_deref())?;
        // Cancel resting orders first, then reduce-only-close positions.
        let cancels = self.collect_cancel_wires(client, &user).await?;
        let cancel_response = if cancels.is_empty() {
            json!({"status": "noop", "reason": "no open orders"})
        } else {
            self.submit_owner_orphan(
                client,
                network,
                network_name,
                wallet,
                id,
                &owner_signer,
                ExchangeAction::Cancel {
                    cancels,
                    fast: Some(true),
                },
                vault_address.clone(),
                "orphan_cancel_all",
            )
            .await?
        };
        let closes = self.collect_reduce_only_closes(client, &user).await?;
        if closes.is_empty() {
            let response = json!({"status": "noop", "reason": "no open positions", "cancel_all": cancel_response});
            self.append_session_audit(
                network_name,
                wallet,
                id,
                &json!({"event": "orphan_close_all", "recovery": "owner_signed_orphan_recovery", "response": response}),
            )?;
            self.finish_persisted_orphan_recovery(network_name, wallet, id, "orphan_close_all")?;
            return Ok(response);
        }
        let action = ExchangeAction::Order {
            orders: closes,
            grouping: Grouping::Na,
            builder: None,
        };
        let response = self
            .submit_owner_orphan(
                client,
                network,
                network_name,
                wallet,
                id,
                &owner_signer,
                action,
                vault_address,
                "orphan_close_all",
            )
            .await?;
        self.finish_persisted_orphan_recovery(network_name, wallet, id, "orphan_close_all")?;
        Ok(response)
    }

    /// `forced` = monitor-initiated safety cleanup (expiry/breach). A forced
    /// cleanup is the bounded outcome of an already-approved session, not a new
    /// trade, so it must NOT re-run trading policy — otherwise a later policy
    /// edit could block the monitor from flattening the very position it is
    /// containing. Manual (user-invoked) cleanup keeps the policy gate.
    async fn cancel_all_session_orders(
        &self,
        client: &HyperliquidClient,
        network: HyperliquidNetwork,
        network_name: &str,
        wallet: &str,
        id: &str,
        forced: bool,
    ) -> Result<Value, HandlerError> {
        let active = self
            .active_session_or_recover(client, network_name, wallet, id)
            .await?;
        let (agent_signer, user, vault_address) = {
            let guard = active.lock();
            if guard.stopped {
                return Err(HandlerError::invalid(
                    "Hyperliquid agent session is stopped",
                ));
            }
            // Cancel orders on the account the session trades (vault or master).
            // Address-only → unverified accessor (a tampered policy sig must not
            // block safety cleanup).
            let user = match guard.vault_address.as_deref() {
                Some(v) => v.to_string(),
                None => format!(
                    "{:#x}",
                    self.keystore
                        .info_unverified(&guard.wallet)
                        .map_err(|e| HandlerError::backend(e.to_string()))?
                        .address
                ),
            };
            (
                HyperliquidSigner::new(guard.agent.signer()),
                user,
                guard.vault_address.clone(),
            )
        };
        let cancels = self.collect_cancel_wires(client, &user).await?;
        if cancels.is_empty() {
            if forced {
                let post_submit = self
                    .refresh_session_snapshot(client, &active, false)
                    .await?;
                require_forced_cancel_clean(post_submit.as_ref())?;
            }
            let response = json!({"status": "noop", "reason": "no open orders"});
            self.append_session_audit(
                network_name,
                wallet,
                id,
                &json!({"event": "cancel_all", "response": response}),
            )?;
            return Ok(response);
        }
        let action = ExchangeAction::Cancel {
            cancels,
            fast: Some(true),
        };
        if !forced {
            let bounds = active.lock().session.bounds.clone();
            self.enforce_hyperliquid_policy(client, wallet, &action, None, Some(&bounds))
                .await?;
        }
        let payload = sign_submit_payload(
            &agent_signer,
            network,
            SignSubmit {
                action,
                nonce: Some(bloom_hyperliquid::now_ms()),
                vault_address: vault_address.clone(),
                expires_after: Some(bloom_hyperliquid::now_ms() + 60_000),
            },
        )
        .await
        .map_err(err_be)?;
        let response = client.exchange(payload.clone()).await.map_err(err_be)?;
        let post_submit = self
            .refresh_session_snapshot(client, &active, false)
            .await?;
        if forced {
            require_forced_cancel_clean(post_submit.as_ref())?;
        }
        self.append_session_audit(
            network_name,
            wallet,
            id,
            &json!({
                "event": "cancel_all",
                "response": response,
                "post_submit": snapshot_json(post_submit.as_ref()),
            }),
        )?;
        self.persist_session_response(
            SessionResponseTarget {
                network: network_name,
                wallet,
                session: id,
                file: "cancel_all",
            },
            Some(&payload),
            &response,
            post_submit.as_ref(),
        )?;
        Ok(response)
    }

    async fn close_all_session_positions(
        &self,
        client: &HyperliquidClient,
        network: HyperliquidNetwork,
        network_name: &str,
        wallet: &str,
        id: &str,
        forced: bool,
    ) -> Result<Value, HandlerError> {
        let cancel_response = self
            .cancel_all_session_orders(client, network, network_name, wallet, id, forced)
            .await?;
        let active = self
            .active_session_or_recover(client, network_name, wallet, id)
            .await?;
        let (agent_signer, user, vault_address) = {
            let guard = active.lock();
            // Flatten positions on the account the session trades (vault or
            // master). Address-only → unverified accessor.
            let user = match guard.vault_address.as_deref() {
                Some(v) => v.to_string(),
                None => format!(
                    "{:#x}",
                    self.keystore
                        .info_unverified(&guard.wallet)
                        .map_err(|e| HandlerError::backend(e.to_string()))?
                        .address
                ),
            };
            (
                HyperliquidSigner::new(guard.agent.signer()),
                user,
                guard.vault_address.clone(),
            )
        };
        let closes = self.collect_reduce_only_closes(client, &user).await?;
        if closes.is_empty() {
            if forced {
                let post_submit = self
                    .refresh_session_snapshot(client, &active, false)
                    .await?;
                require_forced_close_clean(post_submit.as_ref())?;
            }
            let response = json!({"status": "noop", "reason": "no open positions", "cancel_all": cancel_response});
            self.append_session_audit(
                network_name,
                wallet,
                id,
                &json!({"event": "close_all", "response": response}),
            )?;
            return Ok(response);
        }
        let action = ExchangeAction::Order {
            orders: closes,
            grouping: Grouping::Na,
            builder: None,
        };
        // Forced = monitor safety flatten of an already-approved session; skip
        // trading policy so a later policy edit can't block the close.
        if !forced {
            let bounds = active.lock().session.bounds.clone();
            self.enforce_hyperliquid_policy(client, wallet, &action, None, Some(&bounds))
                .await?;
        }
        let payload = sign_submit_payload(
            &agent_signer,
            network,
            SignSubmit {
                action,
                nonce: Some(bloom_hyperliquid::now_ms()),
                vault_address: vault_address.clone(),
                expires_after: Some(bloom_hyperliquid::now_ms() + 60_000),
            },
        )
        .await
        .map_err(err_be)?;
        let close_response = client.exchange(payload.clone()).await.map_err(err_be)?;
        let post_submit = self
            .refresh_session_snapshot(client, &active, false)
            .await?;
        if forced {
            require_forced_close_clean(post_submit.as_ref())?;
        }
        let response = json!({"cancel_all": cancel_response, "close": close_response});
        self.append_session_audit(
            network_name,
            wallet,
            id,
            &json!({
                "event": "close_all",
                "response": response,
                "post_submit": snapshot_json(post_submit.as_ref()),
            }),
        )?;
        self.persist_session_response(
            SessionResponseTarget {
                network: network_name,
                wallet,
                session: id,
                file: "close_all",
            },
            Some(&payload),
            &response,
            post_submit.as_ref(),
        )?;
        Ok(response)
    }

    async fn monitor_sessions_once(&self) {
        let sessions = self.sessions.lock().clone();
        for (key, active) in sessions {
            let (network_name, wallet, id) = {
                let guard = active.lock();
                (
                    guard.network.clone(),
                    guard.wallet.clone(),
                    guard.session.id.clone(),
                )
            };
            let Ok(network) = Self::network(&network_name) else {
                continue;
            };
            let Ok(client) = self.client(&network_name) else {
                continue;
            };
            let _ = self
                .session_status_value(client, &network_name, &wallet, &id)
                .await;
            let action = {
                let mut guard = active.lock();
                if guard.stopped || guard.cleanup_completed_ms.is_some() {
                    BreachAction::None
                } else {
                    guard
                        .session
                        .evaluate(u128::from(bloom_hyperliquid::now_ms()))
                }
            };
            if matches!(action, BreachAction::None) {
                continue;
            }
            {
                let mut guard = active.lock();
                guard
                    .cleanup_started_ms
                    .get_or_insert_with(bloom_hyperliquid::now_ms);
                guard.last_cleanup_error = None;
                let _ = self.persist_session_metadata(&guard, false);
            }
            let result = match action {
                BreachAction::None => continue,
                BreachAction::CancelAll => {
                    self.cancel_all_session_orders(
                        client,
                        network,
                        &network_name,
                        &wallet,
                        &id,
                        true,
                    )
                    .await
                }
                BreachAction::CloseAll => {
                    self.close_all_session_positions(
                        client,
                        network,
                        &network_name,
                        &wallet,
                        &id,
                        true,
                    )
                    .await
                }
            };
            match result {
                Ok(response) => {
                    let mut guard = active.lock();
                    guard.cleanup_completed_ms = Some(bloom_hyperliquid::now_ms());
                    guard.stopped = true;
                    guard.session.status = SessionStatus::Expired;
                    let _ = self.persist_session_metadata(&guard, false);
                    let _ = self.append_session_audit(
                        &network_name,
                        &wallet,
                        &id,
                        &json!({
                            "event": "monitor_cleanup_completed",
                            "session_key": key,
                            "breach_action": format!("{action:?}"),
                            "response": response,
                        }),
                    );
                }
                Err(e) => {
                    let error = e.to_string();
                    {
                        let mut guard = active.lock();
                        guard.last_cleanup_error = Some(error.clone());
                        let _ = self.persist_session_metadata(&guard, false);
                    }
                    let _ = self.append_session_audit(
                        &network_name,
                        &wallet,
                        &id,
                        &json!({"event": "monitor_cleanup_failed", "session_key": key, "error": error}),
                    );
                }
            }
        }
    }

    async fn sign_submit_request(
        &self,
        client: &HyperliquidClient,
        network: HyperliquidNetwork,
        network_name: &str,
        wallet: &str,
        file: &str,
        req: SignSubmit,
    ) -> Result<(), HandlerError> {
        // Policy boundary: no exchange action signs just because the wallet is
        // unlocked. Evaluate the verified per-wallet [hyperliquid] policy first.
        self.enforce_hyperliquid_policy(
            client,
            wallet,
            &req.action,
            req.vault_address.as_deref(),
            None,
        )
        .await?;
        let signer = self.keystore.signer(wallet).map_err(|e| {
            HandlerError::PermissionDenied
                .with_context(format!("wallet '{wallet}' is locked or unavailable: {e}"))
        })?;
        let signer = HyperliquidSigner::new(signer);
        let payload = sign_submit_payload(&signer, network, req)
            .await
            .map_err(err_be)?;
        let response = client.exchange(payload).await.map_err(err_be)?;
        self.persist_response(network_name, wallet, file, &response)?;
        Ok(())
    }

    /// Sign and submit a `usdSend` (internal USDC transfer) using the **owner**
    /// wallet key — user-signed EIP-712, not an L1 action. Agent session keys
    /// cannot authorize `usdSend` on the Hyperliquid side.
    async fn submit_usd_send(
        &self,
        client: &HyperliquidClient,
        network: HyperliquidNetwork,
        network_name: &str,
        wallet: &str,
        req: UsdSendRequest,
    ) -> Result<(), HandlerError> {
        use bloom_proto::{HyperliquidActionCtx, HyperliquidPolicy};
        let dest = parse_address(&req.destination).map_err(err_invalid)?;
        // Parse amount exactly to micro-USDC for the policy cap comparison.
        let amount_micro = Some(parse_usdc_micro_amount(&req.amount)?);
        let policy: HyperliquidPolicy = self
            .keystore
            .info(wallet)
            .map_err(|e| HandlerError::backend(e.to_string()))?
            .policy
            .hyperliquid;
        if !policy.is_configured() {
            return Err(HandlerError::invalid(
                "usdSend requires a configured [hyperliquid] policy block with transfer_cap_usd",
            ));
        }
        let ctx = HyperliquidActionCtx {
            wallet: wallet.to_string(),
            action_kind: "usdSend".to_string(),
            notional_microusd: amount_micro,
            snapshot_readable: true,
            ..Default::default()
        };
        use bloom_proto::{PolicyOutcome, evaluate_hyperliquid_action};
        let checks = evaluate_hyperliquid_action(&policy, &ctx);
        if let Some(deny) = checks.iter().find(|c| c.outcome == PolicyOutcome::Deny) {
            return Err(HandlerError::invalid(format!(
                "Hyperliquid policy denied [{}]: {}",
                deny.rule, deny.message
            )));
        }
        let signer = self.keystore.signer(wallet).map_err(|e| {
            HandlerError::PermissionDenied
                .with_context(format!("wallet '{wallet}' is locked or unavailable: {e}"))
        })?;
        let signer = HyperliquidSigner::new(signer);
        let nonce = req.nonce.unwrap_or_else(bloom_hyperliquid::now_ms);
        let (action, signature) = signer
            .sign_usd_send(network, dest, &req.amount, nonce)
            .await
            .map_err(err_be)?;
        let payload = user_signed_payload(action, nonce, signature);
        let response = client.exchange(payload).await.map_err(err_be)?;
        self.persist_response(network_name, wallet, "send_asset.json", &response)?;
        Ok(())
    }

    /// Evaluate the wallet's verified `[hyperliquid]` policy against an exchange
    /// action before signing. Denies on any hard violation. Snapshot-derived
    /// caps (position/loss) fetch live clearinghouse state only when configured,
    /// and fail closed if it can't be read.
    async fn enforce_hyperliquid_policy(
        &self,
        client: &HyperliquidClient,
        wallet: &str,
        action: &ExchangeAction,
        vault_address: Option<&str>,
        bounds: Option<&HyperliquidPolicy>,
    ) -> Result<(), HandlerError> {
        use bloom_proto::{HyperliquidActionCtx, PolicyOutcome, evaluate_hyperliquid_action};
        // For agent sessions, the security envelope is the bounds approved at the
        // session ceremony (persisted on the session) — NOT the wallet's current
        // [hyperliquid] policy, which an operator could widen after approval. The
        // one-shot owner-signed paths pass `None` and use the verified live
        // policy (a passkey wallet's unsigned/tampered policy must not authorize
        // trades).
        let policy: HyperliquidPolicy = match bounds {
            Some(b) => b.clone(),
            None => {
                self.keystore
                    .info(wallet)
                    .map_err(|e| HandlerError::backend(e.to_string()))?
                    .policy
                    .hyperliquid
            }
        };
        // Trading is opt-in: an unconfigured [hyperliquid] policy denies all
        // signed actions, matching the agent-session ceremony (which already
        // requires a configured policy). No silent permissive default.
        if !policy.is_trading_configured() {
            return Err(HandlerError::invalid(
                "Hyperliquid trading is not enabled for this wallet — add a [hyperliquid] policy \
                 block (allowed_assets / max_notional_usd / …) to its policy.toml",
            ));
        }
        let kind = action.kind().to_string();
        let vault = vault_address.is_some();

        let mut ctxs: Vec<HyperliquidActionCtx> = Vec::new();
        match action {
            ExchangeAction::Order {
                orders, builder, ..
            } => {
                let builder_fee = builder.is_some();
                let need_snapshot =
                    policy.max_position_usd.is_some() || policy.max_loss_usd.is_some();
                let snapshot = if need_snapshot {
                    self.hl_account_snapshot(client, wallet, vault_address)
                        .await
                } else {
                    None
                };
                let meta = client.info(json!({"type": "meta"})).await.ok();
                let asset_to_coin = perp_asset_to_coin_map(meta.as_ref());
                let mut projected_by_coin: HashMap<String, u64> = HashMap::new();
                for o in orders {
                    let order_type = if o.order_type.trigger.is_some() {
                        "trigger"
                    } else {
                        "limit"
                    };
                    let coin = asset_to_coin.get(&o.asset).cloned();
                    let notional = notional_micro(&o.size, &o.price);
                    let position = coin.as_ref().and_then(|c| {
                        if let Some(projected) = projected_by_coin.get(c) {
                            Some(*projected)
                        } else {
                            snapshot.as_ref().and_then(|s| s.position_micro(c))
                        }
                    });
                    let resting = snapshot
                        .as_ref()
                        .and_then(|s| coin.as_deref().and_then(|c| s.resting_micro(c)));
                    ctxs.push(HyperliquidActionCtx {
                        wallet: wallet.to_string(),
                        action_kind: kind.clone(),
                        asset: coin.clone(),
                        reduce_only: o.reduce_only,
                        order_type: Some(order_type.to_string()),
                        builder_fee,
                        vault_or_subaccount: vault,
                        notional_microusd: notional,
                        position_microusd: position,
                        resting_notional_microusd: resting,
                        est_unrealized_loss_microusd: snapshot
                            .as_ref()
                            .and_then(|s| s.unrealized_loss),
                        snapshot_readable: !need_snapshot || snapshot.is_some(),
                        ..Default::default()
                    });
                    if !o.reduce_only
                        && let (Some(coin), Some(notional)) = (coin, notional)
                    {
                        let current = position.unwrap_or(0);
                        projected_by_coin.insert(coin, current.saturating_add(notional));
                    }
                }
            }
            ExchangeAction::UpdateLeverage {
                asset, leverage, ..
            } => {
                let meta = client.info(json!({"type": "meta"})).await.ok();
                let asset_to_coin = perp_asset_to_coin_map(meta.as_ref());
                ctxs.push(HyperliquidActionCtx {
                    wallet: wallet.to_string(),
                    action_kind: kind.clone(),
                    asset: asset_to_coin.get(asset).cloned(),
                    leverage: Some(*leverage),
                    vault_or_subaccount: vault,
                    snapshot_readable: true,
                    ..Default::default()
                });
            }
            // Cancels (risk-reducing) and any future action variant: a minimal
            // ctx carrying only the kind. The evaluator passes cancels and
            // default-denies unrecognized/withdraw-transfer kinds.
            _ => ctxs.push(HyperliquidActionCtx {
                wallet: wallet.to_string(),
                action_kind: kind.clone(),
                vault_or_subaccount: vault,
                snapshot_readable: true,
                ..Default::default()
            }),
        }

        for ctx in &ctxs {
            let checks = evaluate_hyperliquid_action(&policy, ctx);
            if let Some(deny) = checks.iter().find(|c| c.outcome == PolicyOutcome::Deny) {
                return Err(HandlerError::invalid(format!(
                    "Hyperliquid policy denied [{}]: {} — edit the wallet's [hyperliquid] policy to change it",
                    deny.rule, deny.message
                )));
            }
        }
        Ok(())
    }

    /// Fetch + parse the wallet's clearinghouse snapshot for the stateful caps.
    /// `None` when unreadable → callers fail closed.
    async fn hl_account_snapshot(
        &self,
        client: &HyperliquidClient,
        wallet: &str,
        vault_address: Option<&str>,
    ) -> Option<HlSnapshot> {
        // Snapshot the account the session trades on: the vault when set, else
        // the master wallet. Address-only, so use the unverified accessor — a
        // tampered policy signature must not silently blind risk monitoring.
        let user = match vault_address {
            Some(v) => v.to_string(),
            None => format!("{:#x}", self.keystore.info_unverified(wallet).ok()?.address),
        };
        let v = client
            .info(json!({"type": "clearinghouseState", "user": user}))
            .await
            .ok()?;
        let mut snapshot = HlSnapshot::from_clearinghouse(&v);
        // Resting open-order notional feeds the position cap. Fail closed if it
        // can't be read: leave `resting_notional` = None so the evaluator denies
        // a risk-adding order while a position cap is configured.
        if let Ok(orders) = client
            .info(json!({"type": "openOrders", "user": user}))
            .await
        {
            snapshot.apply_open_orders(&orders);
        }
        Some(snapshot)
    }

    fn persist_response(
        &self,
        network: &str,
        wallet: &str,
        file: &str,
        response: &Value,
    ) -> Result<(), HandlerError> {
        let Some(root) = &self.store_root else {
            return Ok(());
        };
        let network = safe_segment(network)?;
        let wallet = safe_segment(wallet)?;
        let dir = root.join("exchange").join(&network).join(&wallet);
        std::fs::create_dir_all(&dir)?;
        let body = json!({
            "network": network,
            "wallet": wallet,
            "submitted_file": file,
            "updated_ms": bloom_hyperliquid::now_ms(),
            "response": response,
        });
        std::fs::write(dir.join("last_response.json"), pretty_json(&body))?;
        Ok(())
    }

    fn persist_session_response(
        &self,
        target: SessionResponseTarget<'_>,
        payload: Option<&Value>,
        response: &Value,
        post_submit: Option<&HlSnapshot>,
    ) -> Result<(), HandlerError> {
        let Some(_) = &self.store_root else {
            return Ok(());
        };
        let dir = self.session_store_dir(target.network, target.wallet, target.session)?;
        std::fs::create_dir_all(&dir)?;
        let body = json!({
            "network": target.network,
            "wallet": target.wallet,
            "session": target.session,
            "submitted_file": target.file,
            "updated_ms": bloom_hyperliquid::now_ms(),
            "payload": payload,
            "response": response,
            "post_submit": snapshot_json(post_submit),
            "note": "Immediate submit result plus Bloom's best-effort post-submit account snapshot."
        });
        std::fs::write(dir.join("last_response.json"), pretty_json(&body))?;
        Ok(())
    }

    fn append_session_audit(
        &self,
        network: &str,
        wallet: &str,
        session: &str,
        event: &Value,
    ) -> Result<(), HandlerError> {
        let Some(root) = &self.store_root else {
            return Ok(());
        };
        let network = safe_segment(network)?;
        let wallet = safe_segment(wallet)?;
        let session = safe_segment(session)?;
        let dir = root
            .join("agent_sessions")
            .join(&network)
            .join(&wallet)
            .join(&session);
        std::fs::create_dir_all(&dir)?;
        let mut line = json!({
            "updated_ms": bloom_hyperliquid::now_ms(),
            "network": network,
            "wallet": wallet,
            "session": session,
        });
        if let (Some(dst), Some(src)) = (line.as_object_mut(), event.as_object()) {
            for (k, v) in src {
                dst.insert(k.clone(), v.clone());
            }
        }
        let mut bytes = serde_json::to_vec(&line).map_err(err_json)?;
        bytes.push(b'\n');
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("audit.jsonl"))?
            .write_all(&bytes)?;
        Ok(())
    }

    fn session_store_dir(
        &self,
        network: &str,
        wallet: &str,
        session: &str,
    ) -> Result<PathBuf, HandlerError> {
        let Some(root) = &self.store_root else {
            return Err(HandlerError::NotFound("agent session store".into()));
        };
        Ok(root
            .join("agent_sessions")
            .join(safe_segment(network)?)
            .join(safe_segment(wallet)?)
            .join(safe_segment(session)?))
    }

    fn write_pre_approval_marker(
        &self,
        network: &str,
        wallet: &str,
        session: &str,
        agent_address: &str,
        agent_name: &str,
    ) -> Result<(), HandlerError> {
        let Some(_) = &self.store_root else {
            return Ok(());
        };
        let dir = self.session_store_dir(network, wallet, session)?;
        std::fs::create_dir_all(&dir)?;
        let body = json!({
            "network": network,
            "wallet": wallet,
            "session": session,
            "agent_address": agent_address,
            "agent_name": agent_name,
            "created_ms": bloom_hyperliquid::now_ms(),
            "note": "Bloom wrote this immediately before submitting approveAgent. If session.json is missing, verify/revoke this agent on Hyperliquid."
        });
        std::fs::write(dir.join(".pre_approval.json"), pretty_json(&body))?;
        Ok(())
    }

    fn clear_pre_approval_marker(
        &self,
        network: &str,
        wallet: &str,
        session: &str,
    ) -> Result<(), HandlerError> {
        let Some(_) = &self.store_root else {
            return Ok(());
        };
        let path = self
            .session_store_dir(network, wallet, session)?
            .join(".pre_approval.json");
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(HandlerError::Io(e)),
        }
    }

    fn agent_key_kek_path(&self) -> Result<PathBuf, HandlerError> {
        let Some(root) = &self.store_root else {
            return Err(HandlerError::NotFound("agent key store".into()));
        };
        Ok(root.join(AGENT_KEY_KEK_FILE))
    }

    fn load_or_create_agent_key_kek(&self) -> Result<Option<[u8; 32]>, HandlerError> {
        let Some(root) = &self.store_root else {
            return Ok(None);
        };
        std::fs::create_dir_all(root)?;
        let path = self.agent_key_kek_path()?;
        match std::fs::read(&path) {
            Ok(bytes) => {
                let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    HandlerError::invalid(format!(
                        "Hyperliquid agent key KEK at {} must be exactly 32 bytes",
                        path.display()
                    ))
                })?;
                Ok(Some(arr))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut arr = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut arr);
                write_secret_file(&path, &arr)?;
                Ok(Some(arr))
            }
            Err(e) => Err(HandlerError::Io(e)),
        }
    }

    fn load_agent_key_kek(&self) -> Result<Option<[u8; 32]>, HandlerError> {
        let Some(_) = &self.store_root else {
            return Ok(None);
        };
        let path = self.agent_key_kek_path()?;
        match std::fs::read(&path) {
            Ok(bytes) => {
                let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    HandlerError::invalid(format!(
                        "Hyperliquid agent key KEK at {} must be exactly 32 bytes",
                        path.display()
                    ))
                })?;
                Ok(Some(arr))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(HandlerError::Io(e)),
        }
    }

    fn sealed_agent_key_path(
        &self,
        network: &str,
        wallet: &str,
        session: &str,
    ) -> Result<PathBuf, HandlerError> {
        Ok(self
            .session_store_dir(network, wallet, session)?
            .join(SEALED_AGENT_KEY_FILE))
    }

    fn persist_agent_key(
        &self,
        network: &str,
        wallet: &str,
        session: &str,
        agent: &EphemeralAgentKey,
    ) -> Result<bool, HandlerError> {
        let Some(kek) = self.load_or_create_agent_key_kek()? else {
            return Ok(false);
        };
        let path = self.sealed_agent_key_path(network, wallet, session)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let blob = agent
            .seal(&kek)
            .map_err(|e| HandlerError::backend(e.to_string()))?;
        write_secret_file(&path, &blob)?;
        Ok(true)
    }

    fn open_persisted_agent_key(
        &self,
        network: &str,
        wallet: &str,
        session: &str,
        expected_address: &str,
    ) -> Result<Option<EphemeralAgentKey>, HandlerError> {
        let path = self.sealed_agent_key_path(network, wallet, session)?;
        let blob = match std::fs::read(&path) {
            Ok(blob) => blob,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(HandlerError::Io(e)),
        };
        let Some(kek) = self.load_agent_key_kek()? else {
            return Ok(None);
        };
        let agent = EphemeralAgentKey::open(&blob, &kek).map_err(|e| {
            HandlerError::invalid(format!(
                "sealed Hyperliquid agent key for session '{session}' could not be opened: {e}"
            ))
        })?;
        let actual_address = format!("{:#x}", agent.address());
        if actual_address.eq_ignore_ascii_case(expected_address) {
            Ok(Some(agent))
        } else {
            Err(HandlerError::invalid(format!(
                "sealed Hyperliquid agent key address {actual_address} does not match persisted session agent {expected_address}",
            )))
        }
    }

    fn warn_pre_approval_markers(&self) {
        let Some(root) = &self.store_root else {
            return;
        };
        let sessions_root = root.join("agent_sessions");
        let Ok(networks) = std::fs::read_dir(&sessions_root) else {
            return;
        };
        for network in networks.flatten() {
            let Ok(wallets) = std::fs::read_dir(network.path()) else {
                continue;
            };
            for wallet in wallets.flatten() {
                let Ok(sessions) = std::fs::read_dir(wallet.path()) else {
                    continue;
                };
                for session in sessions.flatten() {
                    let marker = session.path().join(".pre_approval.json");
                    if marker.exists() {
                        tracing::warn!(
                            marker = %marker.display(),
                            "hyperliquid.agent_sessions.pre_approval_marker_found"
                        );
                    }
                }
            }
        }
    }

    fn session_wallet_store_dir(
        &self,
        network: &str,
        wallet: &str,
    ) -> Result<Option<PathBuf>, HandlerError> {
        let Some(root) = &self.store_root else {
            return Ok(None);
        };
        Ok(Some(
            root.join("agent_sessions")
                .join(safe_segment(network)?)
                .join(safe_segment(wallet)?),
        ))
    }

    fn persisted_live_session_id(
        &self,
        network: &str,
        wallet: &str,
    ) -> Result<Option<String>, HandlerError> {
        let Some(dir) = self.session_wallet_store_dir(network, wallet)? else {
            return Ok(None);
        };
        let read = match std::fs::read_dir(&dir) {
            Ok(read) => read,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(HandlerError::Io(e)),
        };
        for entry in read {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let session_id = entry.file_name().to_string_lossy().into_owned();
            let bytes = match std::fs::read(entry.path().join("session.json")) {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(HandlerError::Io(e)),
            };
            let value: Value = serde_json::from_slice(&bytes).map_err(err_json)?;
            let stopped = value
                .get("stopped")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let orphaned = value
                .get("orphaned")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let tradable = value
                .get("tradable")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let status = value.get("status").and_then(Value::as_str).unwrap_or("");
            let live = orphaned || tradable || (!stopped && status == "Active");
            if live {
                return Ok(Some(session_id));
            }
        }
        Ok(None)
    }

    fn persist_session_metadata(
        &self,
        active: &ActiveHlSession,
        orphaned: bool,
    ) -> Result<(), HandlerError> {
        let Some(_) = &self.store_root else {
            return Ok(());
        };
        let dir = self.session_store_dir(&active.network, &active.wallet, &active.session.id)?;
        std::fs::create_dir_all(&dir)?;
        let action = active
            .session
            .clone()
            .evaluate(u128::from(bloom_hyperliquid::now_ms()));
        let body = session_status_json_with_orphaned(active, action, orphaned);
        std::fs::write(dir.join("session.json"), pretty_json(&body))?;
        Ok(())
    }

    fn read_orphaned_session_status(
        &self,
        network: &str,
        wallet: &str,
        session: &str,
    ) -> Result<Value, HandlerError> {
        let mut value = self
            .persisted_session_status_value(network, wallet, session)?
            .ok_or_else(|| HandlerError::NotFound(format!("agent session {session}")))?;
        let sealed_key_present = self
            .sealed_agent_key_path(network, wallet, session)
            .map(|path| path.exists())
            .unwrap_or(false);
        let has_bounds = value.get("bounds").is_some();
        if let Some(obj) = value.as_object_mut() {
            obj.insert("orphaned".into(), Value::Bool(true));
            obj.insert("tradable".into(), Value::Bool(false));
            obj.insert("breach_action".into(), Value::String("None".into()));
            obj.insert(
                "agent_key_persisted".into(),
                Value::Bool(sealed_key_present),
            );
            obj.insert(
                "key_persistence".into(),
                Value::String(if sealed_key_present {
                    "sealed_local".into()
                } else {
                    "memory_only".into()
                }),
            );
            obj.insert(
                "orphan_reason".into(),
                Value::String(if sealed_key_present && !has_bounds {
                    "sealed agent key is present, but this session was created before policy bounds were persisted; owner-signed orphan cleanup is required".into()
                } else if sealed_key_present {
                    "sealed agent key is present, but Bloom could not verify recovery; check daemon KEK and Hyperliquid extraAgents".into()
                } else {
                    "ephemeral agent key was in daemon memory and is unavailable after restart".into()
                }),
            );
        }
        Ok(value)
    }

    fn persisted_session_status_value(
        &self,
        network: &str,
        wallet: &str,
        session: &str,
    ) -> Result<Option<Value>, HandlerError> {
        let dir = self.session_store_dir(network, wallet, session)?;
        let bytes = match std::fs::read(dir.join("session.json")) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(HandlerError::Io(e)),
        };
        let value: Value = serde_json::from_slice(&bytes).map_err(err_json)?;
        Ok(Some(value))
    }

    async fn try_recover_persisted_session(
        &self,
        client: &HyperliquidClient,
        network: &str,
        wallet: &str,
        id: &str,
    ) -> Result<Option<Arc<Mutex<ActiveHlSession>>>, HandlerError> {
        if let Some(active) = self.active_session_if_present(network, wallet, id) {
            return Ok(Some(active));
        }
        let Some(value) = self.persisted_session_status_value(network, wallet, id)? else {
            return Ok(None);
        };
        let persisted = match persisted_active_session_from_value(network, wallet, id, &value) {
            Ok(persisted) => persisted,
            Err(e) => {
                tracing::warn!(
                    network,
                    wallet,
                    session = id,
                    error = %e,
                    "hyperliquid.agent_sessions.recovery_metadata_invalid"
                );
                return Ok(None);
            }
        };
        let Some(agent) =
            self.open_persisted_agent_key(network, wallet, id, &persisted.session.agent_address)?
        else {
            return Ok(None);
        };
        // Address-only: a safety-cleanup / recovery path needs the identity, not
        // the trading policy. Use the unverified accessor so a stale/edited
        // passkey policy signature can't block owner-signed cancel/close.
        let owner = self
            .keystore
            .info_unverified(wallet)
            .map_err(|e| HandlerError::backend(e.to_string()))?
            .address;
        let extra_agents = match client
            .info(json!({"type": "extraAgents", "user": format!("{owner:#x}")}))
            .await
        {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!(
                    network,
                    wallet,
                    session = id,
                    error = %e,
                    "hyperliquid.agent_sessions.recovery_extra_agents_failed"
                );
                return Ok(None);
            }
        };
        if !extra_agents_contains_agent(&extra_agents, &persisted.session.agent_address) {
            tracing::warn!(
                network,
                wallet,
                session = id,
                agent = persisted.session.agent_address,
                "hyperliquid.agent_sessions.recovery_agent_not_approved"
            );
            return Ok(None);
        }
        let key = Self::session_key(network, wallet, id);
        let recovered = Arc::new(Mutex::new(ActiveHlSession {
            network: network.to_string(),
            wallet: wallet.to_string(),
            agent,
            vault_address: persisted.vault_address,
            session: persisted.session,
            stopped: persisted.stopped,
            cleanup_started_ms: persisted.cleanup_started_ms,
            cleanup_completed_ms: persisted.cleanup_completed_ms,
            last_cleanup_error: persisted.last_cleanup_error,
            last_snapshot_ok_ms: persisted.last_snapshot_ok_ms,
            stale_since_ms: persisted.stale_since_ms,
            agent_key_persisted: true,
        }));
        let mut sessions = self.sessions.lock();
        let active = sessions
            .entry(key)
            .or_insert_with(|| recovered.clone())
            .clone();
        drop(sessions);
        self.append_session_audit(
            network,
            wallet,
            id,
            &json!({
                "event": "recovered_sealed_agent_key",
                "agent_address": active.lock().session.agent_address,
            }),
        )?;
        Ok(Some(active))
    }

    fn list_agent_session_wallets(&self, network: &str) -> Result<Vec<Entry>, HandlerError> {
        let mut names = BTreeSet::new();
        if let Some(root) = &self.store_root {
            let dir = root.join("agent_sessions").join(safe_segment(network)?);
            extend_safe_dir_names(&mut names, &dir)?;
        }
        for key in self.sessions.lock().keys() {
            let mut parts = key.splitn(3, ':');
            if parts.next() == Some(network)
                && let Some(wallet) = parts.next()
            {
                names.insert(wallet.to_string());
            }
        }
        Ok(names.into_iter().map(|name| Entry::dir(&name)).collect())
    }

    fn list_agent_session_ids(
        &self,
        network: &str,
        wallet: &str,
    ) -> Result<Vec<Entry>, HandlerError> {
        let mut names = BTreeSet::new();
        if let Some(root) = &self.store_root {
            let dir = root
                .join("agent_sessions")
                .join(safe_segment(network)?)
                .join(safe_segment(wallet)?);
            extend_safe_dir_names(&mut names, &dir)?;
        }
        for key in self.sessions.lock().keys() {
            let mut parts = key.splitn(3, ':');
            if parts.next() == Some(network)
                && parts.next() == Some(wallet)
                && let Some(session) = parts.next()
            {
                names.insert(session.to_string());
            }
        }
        Ok(SESSION_ROOT_FILES
            .iter()
            .map(|f| Entry::writable_file(f))
            .chain(names.into_iter().map(|name| Entry::dir(&name)))
            .collect())
    }

    fn read_session_audit(
        &self,
        network: &str,
        wallet: &str,
        session: &str,
    ) -> Result<Vec<u8>, HandlerError> {
        let Some(root) = &self.store_root else {
            return Err(HandlerError::NotFound("audit.jsonl".into()));
        };
        let path = root
            .join("agent_sessions")
            .join(safe_segment(network)?)
            .join(safe_segment(wallet)?)
            .join(safe_segment(session)?)
            .join("audit.jsonl");
        std::fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                HandlerError::NotFound("audit.jsonl".into())
            } else {
                HandlerError::Io(e)
            }
        })
    }

    fn read_session_last_response(
        &self,
        network: &str,
        wallet: &str,
        session: &str,
    ) -> Result<Vec<u8>, HandlerError> {
        let path = self
            .session_store_dir(network, wallet, session)?
            .join("last_response.json");
        std::fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                HandlerError::NotFound("last_response.json".into())
            } else {
                HandlerError::Io(e)
            }
        })
    }

    fn read_last_response(&self, network: &str, wallet: &str) -> Result<Vec<u8>, HandlerError> {
        let Some(root) = &self.store_root else {
            return Err(HandlerError::NotFound("last_response.json".into()));
        };
        let network = safe_segment(network)?;
        let wallet = safe_segment(wallet)?;
        let path = root
            .join("exchange")
            .join(network)
            .join(wallet)
            .join("last_response.json");
        std::fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                HandlerError::NotFound("last_response.json".into())
            } else {
                HandlerError::Io(e)
            }
        })
    }
}

#[async_trait]
impl Handler for HyperliquidHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segs = path.segments();
        match segs.len() {
            0 => Ok(Entry::dir("")),
            1 if ROOT_FILES.contains(&segs[0].as_str()) => Ok(Entry::file(&segs[0])),
            1 if NETWORKS.contains(&segs[0].as_str()) => Ok(Entry::dir(&segs[0])),
            2 if NETWORKS.contains(&segs[0].as_str()) => match segs[1].as_str() {
                "users" | "exchange" | "books" | "candles" | "recent_trades" | "asset_contexts"
                | "funding_history" | "agent_sessions" => Ok(Entry::dir(&segs[1])),
                f if NETWORK_FILES.contains(&f) => Ok(Entry::file(&segs[1])),
                _ => Err(HandlerError::NotFound(path.to_string_path())),
            },
            3 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "books" => {
                coin_from_json_file(&segs[2])?;
                Ok(Entry::file(&segs[2]))
            }
            3 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "recent_trades" => {
                coin_from_json_file(&segs[2])?;
                Ok(Entry::file(&segs[2]))
            }
            3 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "asset_contexts" => {
                coin_from_json_file(&segs[2])?;
                Ok(Entry::file(&segs[2]))
            }
            3 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "funding_history" => {
                coin_from_json_file(&segs[2])?;
                Ok(Entry::file(&segs[2]))
            }
            3 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "candles" => {
                Ok(Entry::dir(&segs[2]))
            }
            4 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "candles" => {
                interval_from_json_file(&segs[3])?;
                Ok(Entry::file(&segs[3]))
            }
            3 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "users" => {
                let user = &segs[2];
                parse_address(user).map_err(err_invalid)?;
                Ok(Entry::dir(user))
            }
            4 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "users" => {
                let user = &segs[2];
                let file = &segs[3];
                parse_address(user).map_err(err_invalid)?;
                if USER_FILES.contains(&file.as_str()) {
                    Ok(Entry::file(file))
                } else if file == "funding" {
                    Ok(Entry::dir(file))
                } else {
                    Err(HandlerError::NotFound(path.to_string_path()))
                }
            }
            5 if NETWORKS.contains(&segs[0].as_str())
                && segs[1] == "users"
                && segs[3] == "funding" =>
            {
                parse_address(&segs[2]).map_err(err_invalid)?;
                coin_from_json_file(&segs[4])?;
                Ok(Entry::file(&segs[4]))
            }
            2 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "exchange" => {
                Ok(Entry::dir("exchange"))
            }
            3 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "exchange" => {
                let wallet = &segs[2];
                Ok(Entry::dir(wallet))
            }
            4 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "exchange" => {
                let file = &segs[3];
                if EXCHANGE_WRITE_FILES.contains(&file.as_str()) {
                    Ok(Entry::writable_file(file))
                } else if EXCHANGE_READ_FILES.contains(&file.as_str()) {
                    Ok(Entry::file(file))
                } else {
                    Err(HandlerError::NotFound(path.to_string_path()))
                }
            }
            2 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "agent_sessions" => {
                Ok(Entry::dir("agent_sessions"))
            }
            3 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "agent_sessions" => {
                Ok(Entry::dir(&segs[2]))
            }
            4 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "agent_sessions" => {
                let file = &segs[3];
                if SESSION_ROOT_FILES.contains(&file.as_str()) {
                    Ok(Entry::writable_file(file))
                } else {
                    Ok(Entry::dir(file))
                }
            }
            5 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "agent_sessions" => {
                let file = &segs[4];
                if SESSION_FILES.contains(&file.as_str()) {
                    match file.as_str() {
                        "status.json" | "session.json" | "audit.jsonl" | "last_response.json" => {
                            Ok(Entry::file(file))
                        }
                        _ => Ok(Entry::writable_file(file)),
                    }
                } else {
                    Err(HandlerError::NotFound(path.to_string_path()))
                }
            }
            _ => Err(HandlerError::NotFound(path.to_string_path())),
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = path.segments();
        match segs.len() {
            1 if segs[0] == "README.md" => Ok(README.to_vec()),
            1 if segs[0] == "asset_ids.md" => Ok(ASSET_IDS.to_vec()),
            2 => {
                let network = &segs[0];
                let file = &segs[1];
                let client = self.client(network)?;
                let value = self.info_file(client, file).await?;
                Ok(pretty_json(&value))
            }
            3 if segs[1] == "books" => {
                let client = self.client(&segs[0])?;
                let value = self.book_file(client, &segs[2]).await?;
                Ok(pretty_json(&value))
            }
            3 if segs[1] == "recent_trades" => {
                let client = self.client(&segs[0])?;
                let value = self.recent_trades_file(client, &segs[2]).await?;
                Ok(pretty_json(&value))
            }
            3 if segs[1] == "asset_contexts" => {
                let client = self.client(&segs[0])?;
                let value = self.asset_context_file(client, &segs[2]).await?;
                Ok(pretty_json(&value))
            }
            3 if segs[1] == "funding_history" => {
                let client = self.client(&segs[0])?;
                let value = self.funding_history_file(client, &segs[2]).await?;
                Ok(pretty_json(&value))
            }
            4 if segs[1] == "candles" => {
                let client = self.client(&segs[0])?;
                let value = self.candle_file(client, &segs[2], &segs[3]).await?;
                Ok(pretty_json(&value))
            }
            4 if segs[1] == "users" => {
                let network = &segs[0];
                let user = &segs[2];
                let file = &segs[3];
                let client = self.client(network)?;
                let value = self.user_file(client, user, file).await?;
                Ok(pretty_json(&value))
            }
            5 if segs[1] == "users" && segs[3] == "funding" => {
                let client = self.client(&segs[0])?;
                let value = self.funding_file(client, &segs[2], &segs[4]).await?;
                Ok(pretty_json(&value))
            }
            4 if segs[1] == "exchange" && EXCHANGE_WRITE_FILES.contains(&segs[3].as_str()) => {
                let file = &segs[3];
                Ok(exchange_hint(file))
            }
            4 if segs[1] == "exchange" && segs[3] == "last_response.json" => {
                self.read_last_response(&segs[0], &segs[2])
            }
            4 if segs[1] == "agent_sessions" && segs[3] == "new.json" => {
                Ok(agent_session_new_hint())
            }
            5 if segs[1] == "agent_sessions" && segs[4] == "status.json" => {
                let client = self.client(&segs[0])?;
                let value = self
                    .session_status_value(client, &segs[0], &segs[2], &segs[3])
                    .await?;
                Ok(pretty_json(&value))
            }
            5 if segs[1] == "agent_sessions" && segs[4] == "session.json" => {
                let client = self.client(&segs[0])?;
                let value = self
                    .session_status_value(client, &segs[0], &segs[2], &segs[3])
                    .await?;
                Ok(pretty_json(&value))
            }
            5 if segs[1] == "agent_sessions" && segs[4] == "audit.jsonl" => {
                self.read_session_audit(&segs[0], &segs[2], &segs[3])
            }
            5 if segs[1] == "agent_sessions" && segs[4] == "last_response.json" => {
                self.read_session_last_response(&segs[0], &segs[2], &segs[3])
            }
            5 if segs[1] == "agent_sessions" && SESSION_FILES.contains(&segs[4].as_str()) => {
                Ok(agent_session_file_hint(&segs[4]))
            }
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let segs = path.segments();
        if segs.len() == 4 && segs[1] == "agent_sessions" && segs[3] == "new.json" {
            let network_raw = &segs[0];
            let wallet = &segs[2];
            let network = Self::network(network_raw)?;
            let client = self.client(network_raw)?;
            let req: AgentSessionCreate = serde_json::from_slice(data)
                .map_err(|e| HandlerError::invalid(format!("request json: {e}")))?;
            return self
                .create_agent_session(client, network, network_raw, wallet, req)
                .await;
        }
        if segs.len() == 5 && segs[1] == "agent_sessions" {
            let network_raw = &segs[0];
            let wallet = &segs[2];
            let id = &segs[3];
            let file = &segs[4];
            let network = Self::network(network_raw)?;
            let client = self.client(network_raw)?;
            return match file.as_str() {
                "order.json" | "cancel.json" | "schedule_cancel.json" => {
                    let req: SignSubmit = serde_json::from_slice(data)
                        .map_err(|e| HandlerError::invalid(format!("request json: {e}")))?;
                    self.submit_session_action(
                        client,
                        network,
                        SessionActionTarget {
                            network: network_raw,
                            wallet,
                            id,
                            file,
                        },
                        req,
                    )
                    .await
                }
                "stop" => self.stop_session(network_raw, wallet, id).await,
                "cancel_all" => {
                    let response = self
                        .cancel_all_session_orders(client, network, network_raw, wallet, id, false)
                        .await?;
                    self.persist_response(
                        network_raw,
                        wallet,
                        "agent_session_cancel_all",
                        &response,
                    )
                }
                "close_all" => {
                    let response = self
                        .close_all_session_positions(
                            client,
                            network,
                            network_raw,
                            wallet,
                            id,
                            false,
                        )
                        .await?;
                    self.persist_response(network_raw, wallet, "agent_session_close_all", &response)
                }
                "orphan_cancel_all" => {
                    let response = self
                        .orphan_cancel_all(client, network, network_raw, wallet, id)
                        .await?;
                    self.persist_response(network_raw, wallet, "orphan_cancel_all", &response)
                }
                "orphan_close_all" => {
                    let response = self
                        .orphan_close_all(client, network, network_raw, wallet, id)
                        .await?;
                    self.persist_response(network_raw, wallet, "orphan_close_all", &response)
                }
                _ => Err(HandlerError::PermissionDenied),
            };
        }
        if segs.len() != 4 || segs[1] != "exchange" {
            return Err(HandlerError::PermissionDenied);
        }
        let network_raw = &segs[0];
        let wallet = &segs[2];
        let file = &segs[3];
        let network = Self::network(network_raw)?;
        let client = self.client(network_raw)?;
        match file.as_str() {
            "order.json" | "cancel.json" | "schedule_cancel.json" | "update_leverage.json" => {
                let req: SignSubmit = serde_json::from_slice(data)
                    .map_err(|e| HandlerError::invalid(format!("request json: {e}")))?;
                validate_write_file_matches_action(file, req.action.kind())?;
                self.sign_submit_request(client, network, network_raw, wallet, file, req)
                    .await
            }
            "raw_signed.json" => {
                let req: SignedSubmit = serde_json::from_slice(data)
                    .map_err(|e| HandlerError::invalid(format!("request json: {e}")))?;
                // Even a caller-signed payload must pass the policy boundary —
                // raw_signed must not be an escape hatch around it. Malformed
                // JSON is rejected before policy evaluation because there is no
                // typed action to inspect, but that is still a hard refuse.
                self.enforce_hyperliquid_policy(
                    client,
                    wallet,
                    &req.action,
                    req.vault_address.as_deref(),
                    None,
                )
                .await?;
                let payload = signed_payload(
                    req.action,
                    req.nonce,
                    req.signature,
                    req.vault_address,
                    req.expires_after,
                )
                .map_err(err_be)?;
                let response = client.exchange(payload).await.map_err(err_be)?;
                self.persist_response(network_raw, wallet, file, &response)?;
                Ok(())
            }
            "send_asset.json" => {
                let req: UsdSendRequest = serde_json::from_slice(data)
                    .map_err(|e| HandlerError::invalid(format!("request json: {e}")))?;
                self.submit_usd_send(client, network, network_raw, wallet, req)
                    .await
            }
            _ => Err(HandlerError::PermissionDenied),
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segs = path.segments();
        match segs.len() {
            0 => Ok(ROOT_FILES
                .iter()
                .map(|f| Entry::file(f))
                .chain(NETWORKS.iter().map(|n| Entry::dir(n)))
                .collect()),
            1 if NETWORKS.contains(&segs[0].as_str()) => Ok(NETWORK_FILES
                .iter()
                .map(|f| Entry::file(f))
                .chain([
                    Entry::dir("users"),
                    Entry::dir("exchange"),
                    Entry::dir("books"),
                    Entry::dir("candles"),
                    Entry::dir("recent_trades"),
                    Entry::dir("asset_contexts"),
                    Entry::dir("funding_history"),
                    Entry::dir("agent_sessions"),
                ])
                .collect()),
            2 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "users" => Ok(Vec::new()),
            3 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "users" => {
                let user = &segs[2];
                parse_address(user).map_err(err_invalid)?;
                Ok(USER_FILES
                    .iter()
                    .map(|f| Entry::file(f))
                    .chain([Entry::dir("funding")])
                    .collect())
            }
            4 if NETWORKS.contains(&segs[0].as_str())
                && segs[1] == "users"
                && segs[3] == "funding" =>
            {
                parse_address(&segs[2]).map_err(err_invalid)?;
                Ok(Vec::new())
            }
            2 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "books" => Ok(Vec::new()),
            2 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "recent_trades" => {
                Ok(Vec::new())
            }
            2 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "asset_contexts" => {
                Ok(Vec::new())
            }
            2 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "funding_history" => {
                Ok(Vec::new())
            }
            2 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "candles" => Ok(Vec::new()),
            3 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "candles" => Ok(Vec::new()),
            2 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "exchange" => Ok(Vec::new()),
            2 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "agent_sessions" => {
                self.list_agent_session_wallets(&segs[0])
            }
            3 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "agent_sessions" => {
                self.list_agent_session_ids(&segs[0], &segs[2])
            }
            4 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "agent_sessions" => {
                Ok(SESSION_FILES
                    .iter()
                    .map(|f| match *f {
                        "status.json" | "session.json" | "audit.jsonl" | "last_response.json" => {
                            Entry::file(f)
                        }
                        _ => Entry::writable_file(f),
                    })
                    .collect())
            }
            3 if NETWORKS.contains(&segs[0].as_str()) && segs[1] == "exchange" => {
                Ok(EXCHANGE_WRITE_FILES
                    .iter()
                    .map(|f| Entry::writable_file(f))
                    .chain(EXCHANGE_READ_FILES.iter().map(|f| Entry::file(f)))
                    .collect())
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }

    fn cache_ttl(&self, path: &VfsPath) -> Option<Duration> {
        let segs = path.segments();
        let one_second_market_data = (segs.len() == 2 && segs[1] == "mids.json")
            || (segs.len() == 3
                && matches!(
                    segs[1].as_str(),
                    "books" | "recent_trades" | "asset_contexts"
                ));
        let two_second_live_state = (segs.len() == 2
            && matches!(
                segs[1].as_str(),
                "perp_contexts.json" | "spot_contexts.json" | "predicted_fundings.json"
            ))
            || (segs.len() == 4 && segs[1] == "users")
            || (segs.len() == 3 && segs[1] == "funding_history");

        if one_second_market_data {
            Some(Duration::from_secs(1))
        } else if segs.len() == 2 && matches!(segs[1].as_str(), "perp_meta.json" | "spot_meta.json")
        {
            Some(Duration::from_secs(60))
        } else if two_second_live_state {
            Some(Duration::from_secs(2))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct AgentSessionCreate {
    id: Option<String>,
    agent_name: Option<String>,
    /// Vault/subaccount this session trades on. When set, the session's risk
    /// monitoring and cleanup target this account (not the master wallet), and
    /// every submit must carry a matching `vaultAddress`.
    #[serde(default)]
    vault_address: Option<String>,
}

struct ActiveHlSession {
    network: String,
    wallet: String,
    agent: EphemeralAgentKey,
    /// Vault/subaccount address (hex) this session trades on, or `None` for the
    /// master wallet account. Determines which account is monitored and flattened.
    vault_address: Option<String>,
    session: HyperliquidSession,
    stopped: bool,
    cleanup_started_ms: Option<u64>,
    cleanup_completed_ms: Option<u64>,
    last_cleanup_error: Option<String>,
    /// Unix-ms of the last successful risk snapshot read.
    last_snapshot_ok_ms: Option<u64>,
    /// Unix-ms since which risk snapshots have been failing (None when fresh).
    /// `stale = stale_since_ms.is_some()`.
    stale_since_ms: Option<u64>,
    /// True when the agent key was sealed to disk and can be recovered after
    /// daemon restart with the local Hyperliquid agent-key KEK.
    agent_key_persisted: bool,
}

struct PersistedActiveSession {
    session: HyperliquidSession,
    vault_address: Option<String>,
    stopped: bool,
    cleanup_started_ms: Option<u64>,
    cleanup_completed_ms: Option<u64>,
    last_cleanup_error: Option<String>,
    last_snapshot_ok_ms: Option<u64>,
    stale_since_ms: Option<u64>,
}

struct SessionSlotReservation {
    pending_sessions: Arc<Mutex<HashSet<String>>>,
    key: String,
}

impl Drop for SessionSlotReservation {
    fn drop(&mut self) {
        self.pending_sessions.lock().remove(&self.key);
    }
}

fn session_blocks_create(active: &ActiveHlSession, now_ms: u128) -> bool {
    !active.stopped
        && active.session.status == SessionStatus::Active
        && !active.session.is_expired(now_ms)
        && active.cleanup_completed_ms.is_none()
}

fn persisted_active_session_from_value(
    network: &str,
    wallet: &str,
    id: &str,
    value: &Value,
) -> Result<PersistedActiveSession, HandlerError> {
    let stopped = value
        .get("stopped")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let cleanup_completed_ms = optional_u64(value, "cleanup_completed_ms");
    if stopped || cleanup_completed_ms.is_some() {
        return Err(HandlerError::invalid(format!(
            "persisted agent session {id} is stopped or already cleaned up"
        )));
    }
    let persisted_network = value
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or(network);
    if persisted_network != network {
        return Err(HandlerError::invalid(format!(
            "persisted agent session {id} belongs to network {persisted_network}, not {network}"
        )));
    }
    let persisted_wallet = value
        .get("wallet")
        .and_then(Value::as_str)
        .unwrap_or(wallet);
    if persisted_wallet != wallet {
        return Err(HandlerError::invalid(format!(
            "persisted agent session {id} belongs to wallet {persisted_wallet}, not {wallet}"
        )));
    }
    let persisted_id = value.get("id").and_then(Value::as_str).unwrap_or(id);
    if persisted_id != id {
        return Err(HandlerError::invalid(format!(
            "persisted agent session id mismatch: expected {id}, got {persisted_id}"
        )));
    }
    let status = parse_session_status(value.get("status").and_then(Value::as_str).unwrap_or(""))?;
    let agent_address = required_str(value, "agent_address")?.to_string();
    let bounds_value = value.get("bounds").cloned().ok_or_else(|| {
        HandlerError::invalid(format!(
            "persisted agent session {id} cannot be recovered because session.json does not include policy bounds"
        ))
    })?;
    let bounds: HyperliquidPolicy = serde_json::from_value(bounds_value).map_err(err_json)?;
    let created_ms = required_u128(value, "created_ms")?;
    let starting_account_value_micro = optional_u64(value, "starting_account_value_micro");
    let mut session = HyperliquidSession::new(
        id.to_string(),
        wallet.to_string(),
        agent_address,
        bounds,
        starting_account_value_micro,
        created_ms,
    );
    session.expires_ms = required_u128(value, "expires_ms")?;
    session.account_value_micro = optional_u64(value, "account_value_micro");
    session.unrealized_loss_micro = optional_u64(value, "unrealized_loss_micro").unwrap_or(0);
    session.cumulative_notional_micro =
        optional_u64(value, "cumulative_notional_micro").unwrap_or(0);
    session.open_orders = optional_u64(value, "open_orders")
        .unwrap_or(0)
        .try_into()
        .unwrap_or(u32::MAX);
    session.open_positions = optional_u64(value, "open_positions")
        .unwrap_or(0)
        .try_into()
        .unwrap_or(u32::MAX);
    session.status = status;
    let vault_address = value
        .get("vault_address")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Ok(PersistedActiveSession {
        session,
        vault_address,
        stopped,
        cleanup_started_ms: optional_u64(value, "cleanup_started_ms"),
        cleanup_completed_ms,
        last_cleanup_error: value
            .get("last_cleanup_error")
            .and_then(Value::as_str)
            .map(str::to_string),
        last_snapshot_ok_ms: optional_u64(value, "last_snapshot_ok_ms"),
        stale_since_ms: optional_u64(value, "stale_since_ms"),
    })
}

fn parse_session_status(status: &str) -> Result<SessionStatus, HandlerError> {
    match status {
        "Active" => Ok(SessionStatus::Active),
        "Expired" => Ok(SessionStatus::Expired),
        "Halted" => Ok(SessionStatus::Halted),
        other => Err(HandlerError::invalid(format!(
            "unknown Hyperliquid session status '{other}'"
        ))),
    }
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, HandlerError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| HandlerError::invalid(format!("persisted session is missing {key}")))
}

fn required_u128(value: &Value, key: &str) -> Result<u128, HandlerError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map(u128::from)
        .ok_or_else(|| HandlerError::invalid(format!("persisted session is missing {key}")))
}

fn optional_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn parse_usdc_micro_amount(amount: &str) -> Result<u64, HandlerError> {
    let parsed = bloom_proto::parse_units(amount.trim(), 6)
        .map_err(|e| HandlerError::invalid(format!("invalid USDC amount '{amount}': {e}")))?;
    u64::try_from(parsed)
        .map_err(|_| HandlerError::invalid(format!("USDC amount '{amount}' is too large")))
}

struct PersistedOrphanRecoverySession {
    agent_address: String,
    /// Vault/subaccount the session traded on, recovered so owner-signed cleanup
    /// flattens the right account.
    vault_address: Option<String>,
}

fn persisted_orphan_recovery_session(
    path: &std::path::Path,
    id: &str,
) -> Result<PersistedOrphanRecoverySession, HandlerError> {
    let bytes = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            HandlerError::NotFound(format!("agent session {id}"))
        } else {
            HandlerError::Io(e)
        }
    })?;
    let value: Value = serde_json::from_slice(&bytes).map_err(err_json)?;
    let stopped = value
        .get("stopped")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let status = value.get("status").and_then(Value::as_str).unwrap_or("");
    let cleanup_completed_ms = optional_u64(&value, "cleanup_completed_ms");
    if stopped || cleanup_completed_ms.is_some() || status != "Active" {
        return Err(HandlerError::invalid(format!(
            "persisted agent session {id} is not eligible for orphan recovery"
        )));
    }
    let agent_address = value
        .get("agent_address")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            HandlerError::invalid(format!(
                "persisted agent session {id} is missing agent_address"
            ))
        })?
        .to_ascii_lowercase();
    let vault_address = value
        .get("vault_address")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Ok(PersistedOrphanRecoverySession {
        agent_address,
        vault_address,
    })
}

fn extra_agents_contains_agent(extra_agents: &Value, agent_address: &str) -> bool {
    let needle = agent_address.to_ascii_lowercase();
    fn visit(value: &Value, needle: &str) -> bool {
        match value {
            Value::String(s) => s.eq_ignore_ascii_case(needle),
            Value::Array(items) => items.iter().any(|item| visit(item, needle)),
            Value::Object(map) => map.values().any(|item| visit(item, needle)),
            _ => false,
        }
    }
    visit(extra_agents, &needle)
}

fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), HandlerError> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)?;
        Ok(())
    }
}

struct SessionActionTarget<'a> {
    network: &'a str,
    wallet: &'a str,
    id: &'a str,
    file: &'a str,
}

struct SessionResponseTarget<'a> {
    network: &'a str,
    wallet: &'a str,
    session: &'a str,
    file: &'a str,
}

fn session_status_json(active: &ActiveHlSession, breach_action: BreachAction) -> Value {
    session_status_json_with_orphaned(active, breach_action, false)
}

/// Build a Hyperliquid capability view entry from a session's bounds. Shared by
/// the in-memory roll-up and the persisted-orphan scan so both render identically.
fn hl_capability_entry(
    network: &str,
    wallet: &str,
    id: &str,
    bounds: &HyperliquidPolicy,
    created_ms: u128,
    expires_ms: u128,
    status: CapabilityStatus,
) -> CapabilityViewEntry {
    let now = bloom_proto::capability::now_ms_u128();
    let mut allowed = vec![format!(
        "place orders on {}",
        if bounds.allowed_assets.is_empty() {
            "all assets"
        } else {
            "allowed assets"
        }
    )];
    if !bounds.allowed_assets.is_empty() {
        allowed.push(format!(
            "assets: {}",
            bounds
                .allowed_assets
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if let Some(n) = bounds.max_notional_usd {
        allowed.push(format!("max order: ${:.2}", n as f64 / 1_000_000.0));
    }
    if let Some(p) = bounds.max_position_usd {
        allowed.push(format!("max position: ${:.2}", p as f64 / 1_000_000.0));
    }
    if let Some(lev) = bounds.max_leverage {
        allowed.push(format!("max leverage: {lev}x"));
    }
    let mut denied = Vec::new();
    if bounds.withdrawal_cap_usd.is_some() || bounds.transfer_cap_usd.is_some() {
        denied.push("withdrawals and transfers are denied for agent sessions".into());
    }
    CapabilityViewEntry {
        id: id.to_string(),
        wallet: wallet.to_string(),
        venue: Venue::Hyperliquid,
        signing_model: SigningModel::HoldsDelegatedKey,
        created_ms,
        expires_ms: Some(expires_ms),
        expires_in_secs: if expires_ms > now {
            Some(((expires_ms - now) / 1000) as u64)
        } else {
            None
        },
        status,
        limits: serde_json::json!({
            "max_notional_usd": bounds.max_notional_usd,
            "max_position_usd": bounds.max_position_usd,
            "max_loss_usd": bounds.max_loss_usd,
            "max_leverage": bounds.max_leverage,
            "allowed_assets": bounds.allowed_assets,
        }),
        next_write_path: format!("/hyperliquid/{network}/agent_sessions/{wallet}/{id}/order.json"),
        revoke_path: format!("/hyperliquid/{network}/agent_sessions/{wallet}/{id}/stop"),
        audit_ref: format!("/hyperliquid/{network}/agent_sessions/{wallet}/{id}/audit.jsonl"),
        review_ref: format!("/hyperliquid/{network}/agent_sessions/{wallet}/{id}/session.json"),
        allowed,
        denied,
    }
}

fn session_is_tradable(
    active: &ActiveHlSession,
    breach_action: BreachAction,
    orphaned: bool,
) -> bool {
    !orphaned
        && !active.stopped
        && active.session.status == SessionStatus::Active
        && matches!(breach_action, BreachAction::None)
        && active.cleanup_started_ms.is_none()
        && active.cleanup_completed_ms.is_none()
}

fn session_status_json_with_orphaned(
    active: &ActiveHlSession,
    breach_action: BreachAction,
    orphaned: bool,
) -> Value {
    json!({
        "id": active.session.id,
        "network": active.network,
        "wallet": active.wallet,
        "agent_address": active.session.agent_address,
        "vault_address": active.vault_address,
        "bounds": active.session.bounds,
        "status": format!("{:?}", active.session.status),
        "stopped": active.stopped,
        "orphaned": orphaned,
        "tradable": session_is_tradable(active, breach_action, orphaned),
        "created_ms": active.session.created_ms,
        "expires_ms": active.session.expires_ms,
        "starting_account_value_micro": active.session.starting_account_value_micro,
        "account_value_micro": active.session.account_value_micro,
        "drawdown_micro": active.session.drawdown_micro(),
        "unrealized_loss_micro": active.session.unrealized_loss_micro,
        "cumulative_notional_micro": active.session.cumulative_notional_micro,
        "open_orders": active.session.open_orders,
        "open_positions": active.session.open_positions,
        "cleanup_started_ms": active.cleanup_started_ms,
        "cleanup_completed_ms": active.cleanup_completed_ms,
        "last_cleanup_error": active.last_cleanup_error,
        // Risk-snapshot freshness. `stale` means the most recent refresh failed,
        // so the figures above are last-known (see the fail-stale note on the
        // monitor). Expiry-driven cleanup still fires regardless.
        "stale": active.stale_since_ms.is_some(),
        "last_snapshot_ok_ms": active.last_snapshot_ok_ms,
        "stale_since_ms": active.stale_since_ms,
        "agent_key_persisted": active.agent_key_persisted,
        "key_persistence": if active.agent_key_persisted { "sealed_local" } else { "memory_only" },
        "breach_action": format!("{breach_action:?}"),
    })
}

fn snapshot_json(snapshot: Option<&HlSnapshot>) -> Value {
    match snapshot {
        Some(snapshot) => json!({
            "account_value_micro": snapshot.account_value,
            "unrealized_loss_micro": snapshot.unrealized_loss,
            "open_orders": snapshot.open_orders,
            "open_positions": snapshot.open_positions,
            "positions_micro": snapshot.positions,
        }),
        None => Value::Null,
    }
}

fn require_forced_cancel_clean(snapshot: Option<&HlSnapshot>) -> Result<(), HandlerError> {
    let Some(snapshot) = snapshot else {
        return Err(HandlerError::backend(
            "forced cancel cleanup could not verify post-submit account state",
        ));
    };
    if snapshot.open_orders != 0 {
        return Err(HandlerError::backend(format!(
            "forced cancel cleanup left {} open order(s)",
            snapshot.open_orders
        )));
    }
    Ok(())
}

fn require_forced_close_clean(snapshot: Option<&HlSnapshot>) -> Result<(), HandlerError> {
    let Some(snapshot) = snapshot else {
        return Err(HandlerError::backend(
            "forced close cleanup could not verify post-submit account state",
        ));
    };
    if snapshot.open_orders != 0 || snapshot.open_positions != 0 {
        return Err(HandlerError::backend(format!(
            "forced close cleanup left {} open order(s) and {} open position(s)",
            snapshot.open_orders, snapshot.open_positions
        )));
    }
    Ok(())
}

fn coin_from_json_file(file: &str) -> Result<String, HandlerError> {
    let coin = file
        .strip_suffix(".json")
        .ok_or_else(|| HandlerError::invalid("coin files must end in .json"))?;
    if coin.is_empty()
        || coin.len() > 32
        || !coin
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'#' | b'@' | b'/'))
    {
        return Err(HandlerError::invalid("invalid Hyperliquid coin segment"));
    }
    Ok(coin.to_string())
}

fn interval_from_json_file(file: &str) -> Result<String, HandlerError> {
    let interval = file
        .strip_suffix(".json")
        .ok_or_else(|| HandlerError::invalid("interval files must end in .json"))?;
    if !matches!(
        interval,
        "1m" | "3m" | "5m" | "15m" | "30m" | "1h" | "2h" | "4h" | "8h" | "12h" | "1d"
    ) {
        return Err(HandlerError::invalid(
            "unsupported Hyperliquid candle interval",
        ));
    }
    Ok(interval.to_string())
}

fn best_book_px(book: &Value, side_index: usize) -> Result<f64, HandlerError> {
    book.pointer(&format!("/levels/{side_index}/0/px"))
        .and_then(Value::as_str)
        .ok_or_else(|| HandlerError::invalid("l2Book missing best price"))?
        .parse::<f64>()
        .map_err(|e| HandlerError::invalid(format!("parse best price: {e}")))
}

fn asset_context_by_coin(value: Value, coin: &str) -> Result<Value, HandlerError> {
    let meta = value
        .get(0)
        .ok_or_else(|| HandlerError::invalid("metaAndAssetCtxs missing meta"))?;
    let contexts = value
        .get(1)
        .and_then(Value::as_array)
        .ok_or_else(|| HandlerError::invalid("metaAndAssetCtxs missing asset contexts"))?;
    let universe = meta
        .get("universe")
        .and_then(Value::as_array)
        .ok_or_else(|| HandlerError::invalid("metaAndAssetCtxs missing universe"))?;
    let asset = universe
        .iter()
        .position(|entry| {
            entry
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name == coin)
        })
        .ok_or_else(|| HandlerError::NotFound(format!("asset context for {coin}")))?;
    let context = contexts
        .get(asset)
        .ok_or_else(|| HandlerError::invalid(format!("asset context index {asset} missing")))?;
    Ok(json!({
        "coin": coin,
        "asset": asset,
        "meta": universe[asset].clone(),
        "context": context.clone(),
    }))
}

#[cfg(test)]
fn sz_decimals_by_coin(meta: &Value, coin: &str) -> Option<usize> {
    meta.get("universe")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("name").and_then(Value::as_str) == Some(coin))?
        .get("szDecimals")?
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
}

fn format_decimal(value: f64, decimals: usize) -> String {
    let mut s = if decimals == 0 {
        format!("{value:.0}")
    } else {
        format!("{value:.decimals$}")
    };
    if s.contains('.') {
        while s.ends_with('0') {
            s.pop();
        }
        if s.ends_with('.') {
            s.pop();
        }
    }
    s
}

fn format_hl_close_price(value: f64) -> Result<String, HandlerError> {
    if !value.is_finite() || value <= 0.0 {
        return Err(HandlerError::invalid(format!(
            "close price must be finite and > 0, got {value}"
        )));
    }
    for decimals in [8_usize, 10, 12] {
        let rendered = format_decimal(value, decimals);
        if rendered.parse::<f64>().ok().is_some_and(|v| v > 0.0) {
            return Ok(rendered);
        }
    }
    Err(HandlerError::invalid(format!(
        "close price underflowed formatting bounds: {value}"
    )))
}

fn exchange_hint(file: &str) -> Vec<u8> {
    let value = match file {
        "send_asset.json" => json!({
            "description": "internal USDC transfer (usdSend): owner-signed EIP-712, requires transfer_cap_usd in [hyperliquid] policy",
            "required": ["destination", "amount"],
            "optional": ["nonce"],
            "example": {
                "destination": "0x0000000000000000000000000000000000000000",
                "amount": "100"
            }
        }),
        "raw_signed.json" => json!({
            "description": "write a fully signed Hyperliquid exchange payload; Bloom rejects malformed request bodies, validates the typed action against policy, then validates nested statuses",
            "required": ["action", "nonce", "signature"],
            "optional": ["vaultAddress", "expiresAfter"]
        }),
        _ => json!({
            "description": "write JSON with action, optional nonce, optional vaultAddress, optional expiresAfter; Bloom signs with this wallet and submits immediately",
            "example": {
                "action": {
                    "type": "order",
                    "orders": [{
                        "a": 0,
                        "b": true,
                        "p": "1000",
                        "s": "0.01",
                        "r": false,
                        "t": {"limit": {"tif": "Gtc"}}
                    }],
                    "grouping": "na"
                }
            }
        }),
    };
    pretty_json(&value)
}

fn agent_session_new_hint() -> Vec<u8> {
    pretty_json(&json!({
        "description": "write JSON to approve a fresh Hyperliquid API wallet and start a bounded in-memory agent session",
        "required": [],
        "optional": ["id", "agent_name"],
        "example": {
            "id": "btc-smoke-1",
            "agent_name": "bloom-session"
        },
        "requirements": [
            "the owner wallet must be unlocked for this one approveAgent signature",
            "the wallet policy must include a configured [hyperliquid] boundary"
        ],
        "notes": [
            "the ephemeral API wallet key is held in memory by the daemon",
            "the default flow reuses one stable named Hyperliquid agent slot",
            "only one bounded agent session may be active per wallet/network at a time",
            "subsequent session order/cancel writes do not need another passkey ceremony",
            "session actions still pass the wallet Hyperliquid policy and lifecycle checks"
        ]
    }))
}

fn agent_session_file_hint(file: &str) -> Vec<u8> {
    let value = match file {
        "order.json" => json!({
            "description": "write a Hyperliquid order SignSubmit body; the session's API wallet signs after policy/lifecycle checks",
            "example": {
                "action": {
                    "type": "order",
                    "orders": [{
                        "a": 0,
                        "b": true,
                        "p": "1000",
                        "s": "0.01",
                        "r": false,
                        "t": {"limit": {"tif": "Alo"}}
                    }],
                    "grouping": "na"
                }
            }
        }),
        "cancel.json" => json!({
            "description": "write a Hyperliquid cancel SignSubmit body; the session's API wallet signs after lifecycle checks",
            "example": {
                "action": {
                    "type": "cancel",
                    "cancels": [{"a": 0, "o": 123}],
                    "f": true
                }
            }
        }),
        "update_leverage.json" => json!({
            "description": "write a Hyperliquid updateLeverage SignSubmit body; gated by the [hyperliquid] max_leverage policy before signing",
            "example": {
                "action": {
                    "type": "updateLeverage",
                    "asset": 0,
                    "isCross": true,
                    "leverage": 5
                }
            }
        }),
        "schedule_cancel.json" => json!({
            "description": "write a Hyperliquid scheduleCancel SignSubmit body (dead-man's switch); time is ms or omit to clear. Passes the [hyperliquid] policy gate as a risk-reducing action (like cancels) — no asset/notional check applies",
            "example": {"action": {"type": "scheduleCancel", "time": 1700000000000_i64}}
        }),
        "stop" => {
            json!({"description": "write anything to mark the session stopped; no new risk will be signed"})
        }
        "cancel_all" => {
            json!({"description": "write anything to cancel all open orders for the session owner using the API wallet"})
        }
        "close_all" => {
            json!({"description": "write anything to cancel open orders and close positions reduce-only using the API wallet"})
        }
        "orphan_cancel_all" => {
            json!({"description": "owner-signed recovery: cancel all open orders for an ORPHANED session (after daemon restart); requires the owner wallet unlocked"})
        }
        "orphan_close_all" => {
            json!({"description": "owner-signed recovery: cancel orders + reduce-only close positions for an ORPHANED session; requires the owner wallet unlocked"})
        }
        _ => json!({"description": "agent session file"}),
    };
    pretty_json(&value)
}

fn validate_write_file_matches_action(file: &str, action_kind: &str) -> Result<(), HandlerError> {
    let ok = match file {
        "order.json" => action_kind == "order",
        "cancel.json" => matches!(action_kind, "cancel" | "cancelByCloid"),
        "schedule_cancel.json" => action_kind == "scheduleCancel",
        "update_leverage.json" => action_kind == "updateLeverage",
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(HandlerError::invalid(format!(
            "{file} cannot submit action type {action_kind}"
        )))
    }
}

fn safe_segment(raw: &str) -> Result<String, HandlerError> {
    if raw.is_empty()
        || raw == "."
        || raw == ".."
        || raw.len() > 128
        || !raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(HandlerError::invalid("unsafe hyperliquid store segment"));
    }
    Ok(raw.to_string())
}

fn extend_safe_dir_names(
    names: &mut BTreeSet<String>,
    dir: &std::path::Path,
) -> Result<(), HandlerError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(HandlerError::Io(e)),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if safe_segment(&name).is_ok() {
            names.insert(name);
        }
    }
    Ok(())
}

fn err_be(e: bloom_hyperliquid::HyperliquidError) -> HandlerError {
    match e {
        bloom_hyperliquid::HyperliquidError::Invalid(s) => HandlerError::invalid(s),
        other => HandlerError::backend(other.to_string()),
    }
}

fn err_json(e: serde_json::Error) -> HandlerError {
    HandlerError::backend(e.to_string())
}

fn action_notional_micro(action: &ExchangeAction) -> Option<u64> {
    match action {
        ExchangeAction::Order { orders, .. } => orders
            .iter()
            .filter(|order| !order.reduce_only)
            .filter_map(|order| notional_micro(&order.size, &order.price))
            .try_fold(0u64, |acc, n| acc.checked_add(n)),
        _ => None,
    }
}

fn perp_asset_to_coin_map(meta: Option<&Value>) -> HashMap<u32, String> {
    meta.and_then(|m| m.get("universe"))
        .and_then(|u| u.as_array())
        .map(|arr| {
            arr.iter()
                .enumerate()
                .filter_map(|(idx, entry)| {
                    let coin = entry.get("name")?.as_str()?.to_string();
                    let asset = u32::try_from(idx).ok()?;
                    Some((asset, coin))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Order notional = size × price, in micro-USD (perps are USD-margined).
/// `None` when either is unparseable, which the evaluator treats as fail-closed
/// when a notional cap is configured.
/// Whether a submit's `vaultAddress` matches the session's scoped account.
/// Both `None` (master account) matches; addresses compare case-insensitively
/// since hex casing is not significant.
fn vault_matches(session: Option<&str>, req: Option<&str>) -> bool {
    match (session, req) {
        (None, None) => true,
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    }
}

fn notional_micro(size: &str, price: &str) -> Option<u64> {
    let size_micro: U256 = parse_units(size.trim(), 6).ok()?; // size in micro-base
    let price_micro: U256 = parse_units(price.trim(), 6).ok()?; // price in micro-USD
    let notional_micro = size_micro * price_micro; // (size * 1e6) * (price * 1e6) = size*price * 1e12
    let notional_micro: u64 = (notional_micro / U256::from(1_000_000)).try_into().ok()?; // / 1e6 = size*price * 1e6
    Some(notional_micro)
}

/// Parsed slice of a wallet's `clearinghouseState` for the stateful caps.
struct HlSnapshot {
    account_value: Option<u64>,
    /// Sum of negative unrealized PnL across positions (a loss magnitude), micro-USD.
    unrealized_loss: Option<u64>,
    /// Per-coin absolute position notional, micro-USD.
    positions: std::collections::HashMap<String, u64>,
    positions_readable: bool,
    /// Per-coin resting (unfilled) open-order notional, micro-USD. `None` until
    /// the `openOrders` query is applied — the position cap fails closed while
    /// this is unavailable so a burst of resting orders can't slip the cap.
    resting_notional: Option<std::collections::HashMap<String, u64>>,
    open_orders: u32,
    open_positions: u32,
}

impl HlSnapshot {
    fn from_clearinghouse(v: &Value) -> Self {
        let str_to_micro = |s: &str| -> Option<u64> {
            parse_units(s.trim(), 6)
                .ok()
                .and_then(|u| u.try_into().ok())
        };
        let account_value = v
            .get("marginSummary")
            .and_then(|m| m.get("accountValue"))
            .and_then(|a| a.as_str())
            .and_then(str_to_micro);

        let mut positions = std::collections::HashMap::new();
        let mut loss_sum = U256::ZERO;
        let mut loss_readable = false;
        let mut positions_readable = false;
        let mut open_positions = 0u32;
        if let Some(arr) = v.get("assetPositions").and_then(|p| p.as_array()) {
            positions_readable = true;
            loss_readable = true;
            for ap in arr {
                let Some(pos) = ap.get("position") else {
                    positions_readable = false;
                    loss_readable = false;
                    continue;
                };
                if let (Some(coin), Some(pv)) = (
                    pos.get("coin").and_then(Value::as_str),
                    pos.get("positionValue").and_then(Value::as_str),
                ) {
                    if let Some(micro) = str_to_micro(pv) {
                        positions.insert(coin.to_string(), micro);
                        if micro != 0 {
                            open_positions = open_positions.saturating_add(1);
                        }
                    } else {
                        positions_readable = false;
                    }
                } else {
                    positions_readable = false;
                }
                match pos.get("unrealizedPnl").and_then(|p| p.as_str()) {
                    Some(upnl_str) if upnl_str.starts_with('-') => {
                        if let Some(loss_micro) = str_to_micro(&upnl_str[1..]) {
                            loss_sum = loss_sum.saturating_add(U256::from(loss_micro));
                        } else {
                            loss_readable = false;
                        }
                    }
                    Some(upnl_str) => {
                        if str_to_micro(upnl_str).is_none() {
                            loss_readable = false;
                        }
                    }
                    None => loss_readable = false,
                }
            }
        }
        let unrealized_loss: Option<u64> = if loss_readable {
            loss_sum.try_into().ok()
        } else {
            None
        };
        HlSnapshot {
            account_value,
            unrealized_loss,
            positions,
            positions_readable,
            resting_notional: None,
            open_orders: v
                .get("openOrders")
                .and_then(Value::as_array)
                .map_or(0, |orders| orders.len() as u32),
            open_positions,
        }
    }

    /// Fold a HyperCore `openOrders` response into per-coin resting notional
    /// (`sz × limitPx`). Sets `resting_notional` to `Some(..)` even when there
    /// are no orders, so the position cap can distinguish "no resting orders"
    /// from "orders unknown" (which fails closed).
    fn apply_open_orders(&mut self, v: &Value) {
        let mut resting: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        let mut count = 0u32;
        if let Some(arr) = v.as_array() {
            for o in arr {
                count = count.saturating_add(1);
                let (Some(coin), Some(sz), Some(px)) = (
                    o.get("coin").and_then(Value::as_str),
                    o.get("sz").and_then(Value::as_str),
                    o.get("limitPx").and_then(Value::as_str),
                ) else {
                    continue;
                };
                if let Some(micro) = notional_micro(sz, px) {
                    *resting.entry(coin.to_string()).or_insert(0) = resting
                        .get(coin)
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(micro);
                }
            }
        }
        self.open_orders = count;
        self.resting_notional = Some(resting);
    }

    fn position_micro(&self, coin: &str) -> Option<u64> {
        self.positions_readable
            .then(|| self.positions.get(coin).copied().unwrap_or(0))
    }

    /// Resting open-order notional for `coin`. `None` when open orders were not
    /// successfully fetched (caller fails the position cap closed); `Some(0)`
    /// when fetched but the coin has no resting orders.
    fn resting_micro(&self, coin: &str) -> Option<u64> {
        self.resting_notional
            .as_ref()
            .map(|m| m.get(coin).copied().unwrap_or(0))
    }
}

fn err_invalid(e: bloom_hyperliquid::HyperliquidError) -> HandlerError {
    HandlerError::invalid(e.to_string())
}

trait HandlerErrorContext {
    fn with_context(self, context: String) -> Self;
}

impl HandlerErrorContext for HandlerError {
    fn with_context(self, context: String) -> Self {
        match self {
            HandlerError::PermissionDenied => HandlerError::invalid(context),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_hyperliquid::{MAINNET_API_URL, TESTNET_API_URL};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    fn unique_test_dir(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "{}-{}",
            prefix,
            NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn active_for_status(
        last_snapshot_ok_ms: Option<u64>,
        stale_since_ms: Option<u64>,
    ) -> ActiveHlSession {
        let session = HyperliquidSession::new(
            "s1",
            "alice",
            "0x000000000000000000000000000000000000a9e7",
            bloom_proto::HyperliquidPolicy::default(),
            Some(1_000_000),
            0,
        );
        ActiveHlSession {
            network: "mainnet".into(),
            wallet: "alice".into(),
            agent: EphemeralAgentKey::generate(),
            vault_address: None,
            session,
            stopped: false,
            cleanup_started_ms: None,
            cleanup_completed_ms: None,
            last_cleanup_error: None,
            last_snapshot_ok_ms,
            stale_since_ms,
            agent_key_persisted: false,
        }
    }

    #[test]
    fn write_file_action_mapping_is_strict() {
        // New update_leverage surface only accepts updateLeverage.
        assert!(
            validate_write_file_matches_action("update_leverage.json", "updateLeverage").is_ok()
        );
        assert!(validate_write_file_matches_action("update_leverage.json", "order").is_err());
        // schedule_cancel only accepts scheduleCancel (covers the session path too).
        assert!(
            validate_write_file_matches_action("schedule_cancel.json", "scheduleCancel").is_ok()
        );
        assert!(validate_write_file_matches_action("schedule_cancel.json", "cancel").is_err());
    }

    #[test]
    fn status_exposes_snapshot_staleness() {
        // Fresh: a recent successful read, not stale.
        let fresh = active_for_status(Some(123), None);
        let v = session_status_json_with_orphaned(&fresh, BreachAction::None, false);
        assert_eq!(v["stale"], false);
        assert_eq!(v["last_snapshot_ok_ms"], 123);
        assert!(v["stale_since_ms"].is_null());

        // Stale: a failed read stamped stale_since_ms; the flag flips.
        let stale = active_for_status(Some(123), Some(456));
        let v = session_status_json_with_orphaned(&stale, BreachAction::None, false);
        assert_eq!(v["stale"], true);
        assert_eq!(v["stale_since_ms"], 456);
        assert_eq!(v["last_snapshot_ok_ms"], 123);
    }

    #[test]
    fn expired_session_is_not_tradable() {
        let mut active = active_for_status(Some(123), None);
        active.session.status = SessionStatus::Expired;
        active.stopped = false;
        let v = session_status_json_with_orphaned(&active, BreachAction::None, false);
        assert_eq!(v["status"], "Expired");
        assert_eq!(v["tradable"], false);
    }

    #[test]
    fn past_expiry_window_is_not_tradable_even_before_status_flips() {
        let mut active = active_for_status(Some(123), None);
        active.session.expires_ms = 0;
        active.session.status = SessionStatus::Active;
        let action = active.session.evaluate(1);
        assert_eq!(action, BreachAction::CancelAll);
        let v = session_status_json_with_orphaned(&active, action, false);
        assert_eq!(v["status"], "Expired");
        assert_eq!(v["tradable"], false);
    }

    #[test]
    fn cleanup_in_progress_is_not_tradable() {
        let mut active = active_for_status(Some(123), None);
        active.cleanup_started_ms = Some(789);
        let v = session_status_json_with_orphaned(&active, BreachAction::None, false);
        assert_eq!(v["tradable"], false);
    }

    #[test]
    fn session_status_persists_bounds_needed_for_recovery() {
        let mut active = active_for_status(Some(123), None);
        active.session.bounds.max_notional_usd = Some(12_000_000);
        active.agent_key_persisted = true;
        let v = session_status_json_with_orphaned(&active, BreachAction::None, false);
        assert_eq!(v["bounds"]["max_notional_usd"], "12");
        assert_eq!(v["agent_key_persisted"], true);
        assert_eq!(v["key_persistence"], "sealed_local");

        let recovered = persisted_active_session_from_value("mainnet", "alice", "s1", &v).unwrap();
        assert_eq!(recovered.session.bounds.max_notional_usd, Some(12_000_000));
        assert_eq!(
            recovered.session.agent_address,
            active.session.agent_address
        );
        assert_eq!(recovered.session.status, SessionStatus::Active);
    }

    #[test]
    fn usd_send_amount_policy_parse_is_exact_micro_usdc() {
        assert_eq!(parse_usdc_micro_amount("0.001").unwrap(), 1_000);
        assert_eq!(parse_usdc_micro_amount("4.95").unwrap(), 4_950_000);
        assert_eq!(parse_usdc_micro_amount("1.000001").unwrap(), 1_000_001);
        assert!(parse_usdc_micro_amount("1.0000001").is_err());
        assert!(parse_usdc_micro_amount("-1").is_err());
        assert!(parse_usdc_micro_amount("18446744073710").is_err());
    }

    fn handler() -> HyperliquidHandler {
        let dir = unique_test_dir("bloom-hl-test");
        HyperliquidHandler::new(
            HyperliquidClient::new(HyperliquidNetwork::Mainnet)
                .with_base_url(url::Url::parse(MAINNET_API_URL).unwrap()),
            HyperliquidClient::new(HyperliquidNetwork::Testnet)
                .with_base_url(url::Url::parse(TESTNET_API_URL).unwrap()),
            Keystore::new(dir).unwrap(),
        )
    }

    #[test]
    fn persisted_agent_key_round_trips_and_rejects_wrong_address() {
        let h = handler().with_store_root(unique_test_dir("bloom-hl-key-store"));
        let agent = EphemeralAgentKey::generate();
        let expected = format!("{:#x}", agent.address());
        assert!(
            h.persist_agent_key("mainnet", "minnow", "session-1", &agent)
                .unwrap()
        );
        let recovered = h
            .open_persisted_agent_key("mainnet", "minnow", "session-1", &expected)
            .unwrap()
            .expect("sealed key");
        assert_eq!(format!("{:#x}", recovered.address()), expected);

        match h.open_persisted_agent_key(
            "mainnet",
            "minnow",
            "session-1",
            "0x0000000000000000000000000000000000000000",
        ) {
            Err(HandlerError::Invalid(msg)) => assert!(msg.contains("does not match")),
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("wrong persisted agent address should be rejected"),
        }
    }

    #[tokio::test]
    async fn root_lists_networks_and_docs() {
        let h = handler();
        let entries = h.list(&VfsPath::root()).await.unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"mainnet"));
        assert!(names.contains(&"testnet"));
        assert!(names.contains(&"README.md"));
    }

    #[tokio::test]
    async fn user_path_requires_real_address_shape() {
        let h = handler();
        let bad = VfsPath::parse("/mainnet/users/not-an-agent-wallet/open_orders.json").unwrap();
        assert!(matches!(
            h.lookup(&bad).await,
            Err(HandlerError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn exchange_files_are_writable() {
        let h = handler();
        let p = VfsPath::parse("/testnet/exchange/trader/order.json").unwrap();
        let entry = h.lookup(&p).await.unwrap();
        assert_eq!(entry.mode, 0o644);

        let p = VfsPath::parse("/testnet/exchange/trader/last_response.json").unwrap();
        let entry = h.lookup(&p).await.unwrap();
        assert_eq!(entry.mode, 0o444);
    }

    #[tokio::test]
    async fn readme_documents_safe_reads_and_api_wallet_risk() {
        let h = handler();
        let body = h
            .read(&VfsPath::parse("/README.md").unwrap())
            .await
            .unwrap();
        let text = String::from_utf8(body).unwrap();
        for expected in [
            "/hyperliquid/mainnet/predicted_fundings.json",
            "/hyperliquid/mainnet/recent_trades/BTC.json",
            "/hyperliquid/mainnet/asset_contexts/BTC.json",
            "/hyperliquid/mainnet/funding_history/BTC.json",
            "/hyperliquid/mainnet/users/<account>/frontend_open_orders.json",
            "/hyperliquid/mainnet/users/<account>/rate_limit.json",
            "Policy sessions and ephemeral API wallets",
            "Hyperliquid API wallets are standing signing authority",
        ] {
            assert!(text.contains(expected), "missing {expected}");
        }
    }

    #[tokio::test]
    async fn market_data_paths_lookup_without_wallet_unlock() {
        let h = handler();
        for path in [
            "/mainnet/predicted_fundings.json",
            "/mainnet/recent_trades/BTC.json",
            "/mainnet/asset_contexts/BTC.json",
            "/mainnet/funding_history/BTC.json",
        ] {
            let entry = h.lookup(&VfsPath::parse(path).unwrap()).await.unwrap();
            assert_eq!(entry.mode, 0o444, "{path}");
        }
    }

    #[tokio::test]
    async fn network_list_surfaces_market_data_dirs() {
        let h = handler();
        let entries = h.list(&VfsPath::parse("/mainnet").unwrap()).await.unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        for expected in [
            "predicted_fundings.json",
            "recent_trades",
            "asset_contexts",
            "funding_history",
            "agent_sessions",
        ] {
            assert!(names.contains(&expected), "missing {expected}");
        }
    }

    #[tokio::test]
    async fn agent_session_surface_is_discoverable() {
        let h = handler();
        let entries = h
            .list(&VfsPath::parse("/testnet/agent_sessions/minnow").unwrap())
            .await
            .unwrap();
        assert_eq!(entries[0].name, "new.json");
        assert_eq!(entries[0].mode, 0o644);

        let entries = h
            .list(
                &VfsPath::parse("/testnet/agent_sessions/minnow/session-1")
                    .expect("valid session path"),
            )
            .await
            .unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        for expected in [
            "status.json",
            "session.json",
            "last_response.json",
            "order.json",
            "cancel.json",
            "schedule_cancel.json",
            "stop",
            "cancel_all",
            "close_all",
            "audit.jsonl",
        ] {
            assert!(names.contains(&expected), "missing {expected}");
        }

        let hint = h
            .read(
                &VfsPath::parse("/testnet/agent_sessions/minnow/new.json").expect("valid new path"),
            )
            .await
            .unwrap();
        let hint: Value = serde_json::from_slice(&hint).unwrap();
        assert!(hint["description"].as_str().unwrap().contains("API wallet"));
        assert_eq!(hint["example"]["agent_name"], "bloom-session");
    }

    #[tokio::test]
    async fn persisted_agent_sessions_are_discoverable_after_restart() {
        let store = unique_test_dir("bloom-hl-store");
        let h = handler().with_store_root(store.clone());
        let session_dir = store
            .join("agent_sessions")
            .join("mainnet")
            .join("minnow")
            .join("session-1");
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::write(
            session_dir.join("session.json"),
            br#"{"id":"session-1","wallet":"minnow","orphaned":false,"tradable":true}"#,
        )
        .unwrap();

        let wallets = h
            .list(&VfsPath::parse("/mainnet/agent_sessions").unwrap())
            .await
            .unwrap();
        assert!(wallets.iter().any(|entry| entry.name == "minnow"));

        let sessions = h
            .list(&VfsPath::parse("/mainnet/agent_sessions/minnow").unwrap())
            .await
            .unwrap();
        assert!(sessions.iter().any(|entry| entry.name == "new.json"));
        assert!(sessions.iter().any(|entry| entry.name == "session-1"));

        let status = h
            .read(
                &VfsPath::parse("/mainnet/agent_sessions/minnow/session-1/status.json")
                    .expect("valid status path"),
            )
            .await
            .unwrap();
        let status: Value = serde_json::from_slice(&status).unwrap();
        assert_eq!(status["orphaned"], true);
        assert_eq!(status["tradable"], false);
        assert!(status["orphan_reason"].is_string());
    }

    #[tokio::test]
    async fn live_status_wins_over_persisted_orphaned_copy() {
        let store = unique_test_dir("bloom-hl-store");
        let h = handler().with_store_root(store.clone());
        let session_dir = store
            .join("agent_sessions")
            .join("mainnet")
            .join("minnow")
            .join("session-1");
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::write(
            session_dir.join("session.json"),
            br#"{"id":"session-1","wallet":"minnow","status":"Active","stopped":false,"orphaned":true,"tradable":false}"#,
        )
        .unwrap();

        let session = HyperliquidSession::new(
            "session-1",
            "minnow",
            "0x1234",
            Default::default(),
            Some(1_000_000),
            u128::from(bloom_hyperliquid::now_ms()),
        );
        let active = ActiveHlSession {
            network: "mainnet".into(),
            wallet: "minnow".into(),
            agent: EphemeralAgentKey::generate(),
            vault_address: None,
            session,
            stopped: false,
            cleanup_started_ms: None,
            cleanup_completed_ms: None,
            last_cleanup_error: None,
            last_snapshot_ok_ms: None,
            stale_since_ms: None,
            agent_key_persisted: false,
        };
        h.sessions.lock().insert(
            HyperliquidHandler::session_key("mainnet", "minnow", "session-1"),
            Arc::new(Mutex::new(active)),
        );

        let status = h
            .session_status_value(&h.mainnet, "mainnet", "minnow", "session-1")
            .await
            .unwrap();
        assert_eq!(status["orphaned"], false);
        assert_eq!(status["tradable"], true);
    }

    #[test]
    fn persisted_session_last_response_includes_payload() {
        let store = unique_test_dir("bloom-hl-store");
        let h = handler().with_store_root(store.clone());
        let payload = json!({
            "action": {
                "type": "order",
                "grouping": "na",
                "orders": [{"a":0,"b":false,"p":"63325","s":"0.00017","r":true,"t":{"limit":{"tif":"Alo"}}}]
            },
            "nonce": 123,
            "signature": {"r":"0x1","s":"0x2","v":27}
        });
        let response = json!({"status":"ok","response":{"type":"order","data":{"statuses":[{"resting":{"oid":1}}]}}});
        h.persist_session_response(
            SessionResponseTarget {
                network: "mainnet",
                wallet: "minnow",
                session: "session-1",
                file: "order.json",
            },
            Some(&payload),
            &response,
            None,
        )
        .unwrap();
        let bytes = std::fs::read(
            store
                .join("agent_sessions")
                .join("mainnet")
                .join("minnow")
                .join("session-1")
                .join("last_response.json"),
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["payload"], payload);
        assert_eq!(value["submitted_file"], "order.json");
    }

    #[test]
    fn create_guard_rejects_live_persisted_session() {
        let store = unique_test_dir("bloom-hl-store");
        let h = handler().with_store_root(store.clone());
        let session_dir = store
            .join("agent_sessions")
            .join("mainnet")
            .join("minnow")
            .join("session-1");
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::write(
            session_dir.join("session.json"),
            br#"{"id":"session-1","wallet":"minnow","status":"Active","stopped":false,"orphaned":true,"tradable":false}"#,
        )
        .unwrap();

        let err = h
            .ensure_session_create_allowed("mainnet", "minnow")
            .unwrap_err();
        match err {
            HandlerError::Invalid(msg) => assert!(msg.contains("session-1")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn create_guard_rejects_second_live_in_memory_session() {
        let h = handler();
        let session = HyperliquidSession::new(
            "session-1",
            "minnow",
            "0x1234",
            Default::default(),
            Some(1_000_000),
            u128::from(bloom_hyperliquid::now_ms()),
        );
        let active = ActiveHlSession {
            network: "mainnet".into(),
            wallet: "minnow".into(),
            agent: EphemeralAgentKey::generate(),
            vault_address: None,
            session,
            stopped: false,
            cleanup_started_ms: None,
            cleanup_completed_ms: None,
            last_cleanup_error: None,
            last_snapshot_ok_ms: None,
            stale_since_ms: None,
            agent_key_persisted: false,
        };
        h.sessions.lock().insert(
            HyperliquidHandler::session_key("mainnet", "minnow", "session-1"),
            Arc::new(Mutex::new(active)),
        );

        let err = h
            .ensure_session_create_allowed("mainnet", "minnow")
            .unwrap_err();
        match err {
            HandlerError::Invalid(msg) => assert!(msg.contains("second Hyperliquid agent session")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn create_guard_allows_stopped_in_memory_session() {
        let h = handler();
        let mut session = HyperliquidSession::new(
            "session-1",
            "minnow",
            "0x1234",
            Default::default(),
            Some(1_000_000),
            0,
        );
        session.status = SessionStatus::Expired;
        let active = ActiveHlSession {
            network: "mainnet".into(),
            wallet: "minnow".into(),
            agent: EphemeralAgentKey::generate(),
            vault_address: None,
            session,
            stopped: true,
            cleanup_started_ms: None,
            cleanup_completed_ms: Some(1),
            last_cleanup_error: None,
            last_snapshot_ok_ms: None,
            stale_since_ms: None,
            agent_key_persisted: false,
        };
        h.sessions.lock().insert(
            HyperliquidHandler::session_key("mainnet", "minnow", "session-1"),
            Arc::new(Mutex::new(active)),
        );

        h.ensure_session_create_allowed("mainnet", "minnow")
            .unwrap();
    }

    #[test]
    fn create_guard_rejects_pending_session_create() {
        let h = handler();
        let reservation = h
            .reserve_session_slot("mainnet", "minnow", "session-1")
            .unwrap();

        let err = h
            .ensure_session_create_allowed("mainnet", "minnow")
            .unwrap_err();
        match err {
            HandlerError::Invalid(msg) => assert!(msg.contains("pending")),
            other => panic!("unexpected error: {other:?}"),
        }

        drop(reservation);
        h.ensure_session_create_allowed("mainnet", "minnow")
            .unwrap();
    }

    #[test]
    fn orphan_recovery_releases_persisted_create_guard() {
        let store = unique_test_dir("bloom-hl-store");
        let h = handler().with_store_root(store.clone());
        let session_dir = store
            .join("agent_sessions")
            .join("mainnet")
            .join("minnow")
            .join("session-1");
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::write(
            session_dir.join("session.json"),
            br#"{"id":"session-1","wallet":"minnow","status":"Active","stopped":false,"orphaned":true,"tradable":false}"#,
        )
        .unwrap();

        let err = h
            .ensure_session_create_allowed("mainnet", "minnow")
            .unwrap_err();
        match err {
            HandlerError::Invalid(msg) => assert!(msg.contains("session-1")),
            other => panic!("unexpected error: {other:?}"),
        }

        h.finish_persisted_orphan_recovery("mainnet", "minnow", "session-1", "orphan_close_all")
            .unwrap();

        h.ensure_session_create_allowed("mainnet", "minnow")
            .unwrap();

        let bytes = std::fs::read(session_dir.join("session.json")).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["status"], "Expired");
        assert_eq!(value["stopped"], true);
        assert_eq!(value["orphaned"], false);
        assert_eq!(value["tradable"], false);
        assert_eq!(value["recovery"], "owner_signed_orphan_recovery");
        assert_eq!(value["recovery_action"], "orphan_close_all");
    }

    #[test]
    fn orphan_recovery_requires_live_orphan_persisted_state() {
        let dir = unique_test_dir("bloom-hl-orphan-state");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session.json");
        std::fs::write(
            &path,
            br#"{"id":"session-1","wallet":"minnow","agent_address":"0xabc","status":"Active","stopped":false,"orphaned":true,"tradable":false}"#,
        )
        .unwrap();
        let session = persisted_orphan_recovery_session(&path, "session-1").unwrap();
        assert_eq!(session.agent_address, "0xabc");

        std::fs::write(
            &path,
            br#"{"id":"session-1","wallet":"minnow","agent_address":"0xabc","status":"Active","stopped":false,"orphaned":false,"tradable":true}"#,
        )
        .unwrap();
        let session = persisted_orphan_recovery_session(&path, "session-1").unwrap();
        assert_eq!(session.agent_address, "0xabc");

        std::fs::write(
            &path,
            br#"{"id":"session-1","wallet":"minnow","agent_address":"0xabc","status":"Expired","stopped":true,"orphaned":false,"tradable":false}"#,
        )
        .unwrap();
        assert!(matches!(
            persisted_orphan_recovery_session(&path, "session-1"),
            Err(HandlerError::Invalid(_))
        ));
    }

    #[test]
    fn extra_agents_matcher_finds_agent_address() {
        let extra_agents = json!([
            {"address": "0x1111111111111111111111111111111111111111", "name": "old"},
            {"agentAddress": "0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD", "name": "bloom"}
        ]);
        assert!(extra_agents_contains_agent(
            &extra_agents,
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        ));
        assert!(!extra_agents_contains_agent(
            &extra_agents,
            "0x2222222222222222222222222222222222222222"
        ));
    }

    #[test]
    fn action_file_mismatch_is_rejected() {
        let err = validate_write_file_matches_action("order.json", "cancel").unwrap_err();
        assert!(matches!(err, HandlerError::Invalid(_)));
        validate_write_file_matches_action("cancel.json", "cancelByCloid").unwrap();
    }

    #[test]
    fn asset_context_extractor_matches_symbol_to_index() {
        let value = json!([
            {
                "universe": [
                    {"name": "BTC", "szDecimals": 5},
                    {"name": "ETH", "szDecimals": 4}
                ]
            },
            [
                {"markPx": "60000.0"},
                {"markPx": "3000.0"}
            ]
        ]);
        let ctx = asset_context_by_coin(value, "ETH").unwrap();
        assert_eq!(ctx["asset"], 1);
        assert_eq!(ctx["meta"]["szDecimals"], 4);
        assert_eq!(ctx["context"]["markPx"], "3000.0");
    }

    #[test]
    fn close_price_formatter_keeps_subdollar_prices_positive() {
        assert_eq!(format_hl_close_price(0.00001234).unwrap(), "0.00001234");
        assert_eq!(
            format_hl_close_price(0.00000000123).unwrap(),
            "0.0000000012"
        );
        assert!(format_hl_close_price(0.0).is_err());
    }

    #[test]
    fn sz_decimals_extractor_matches_symbol() {
        let meta = json!({
            "universe": [
                {"name": "BTC", "szDecimals": 5},
                {"name": "ETH", "szDecimals": 4}
            ]
        });

        assert_eq!(sz_decimals_by_coin(&meta, "ETH"), Some(4));
        assert_eq!(sz_decimals_by_coin(&meta, "DOGE"), None);
    }

    #[test]
    fn safe_store_segments_reject_path_like_values() {
        assert!(safe_segment("mainnet").is_ok());
        assert!(safe_segment("wallet_1").is_ok());
        assert!(safe_segment("../wallet").is_err());
        assert!(safe_segment("wallet/name").is_err());
    }

    #[test]
    fn notional_micro_multiplies_size_by_price() {
        assert_eq!(notional_micro("0.01", "60000"), Some(600_000_000)); // 600 USD
        assert_eq!(notional_micro("2", "1.5"), Some(3_000_000)); // 3 USD
        assert_eq!(notional_micro("x", "1"), None);
    }

    #[test]
    fn snapshot_parses_account_value_position_and_loss() {
        let v = json!({
            "marginSummary": { "accountValue": "1000.0" },
            "assetPositions": [
                { "position": { "coin": "BTC", "positionValue": "500.0", "unrealizedPnl": "-25.5" } },
                { "position": { "coin": "ETH", "positionValue": "100.0", "unrealizedPnl": "10.0" } }
            ]
        });
        let s = HlSnapshot::from_clearinghouse(&v);
        assert_eq!(s.account_value, Some(1_000_000_000));
        assert_eq!(s.position_micro("BTC"), Some(500_000_000));
        assert_eq!(s.position_micro("ETH"), Some(100_000_000));
        assert_eq!(s.position_micro("SOL"), Some(0));
        // Only the negative uPnL counts as loss (25.5), the +10 is ignored.
        assert_eq!(s.unrealized_loss, Some(25_500_000));
    }

    #[test]
    fn snapshot_marks_unrealized_loss_unreadable_when_pnl_missing() {
        let v = json!({
            "marginSummary": { "accountValue": "1000.0" },
            "assetPositions": [
                { "position": { "coin": "BTC", "positionValue": "500.0" } }
            ]
        });
        let s = HlSnapshot::from_clearinghouse(&v);
        assert_eq!(s.unrealized_loss, None);

        let s = HlSnapshot::from_clearinghouse(&json!({}));
        assert_eq!(s.unrealized_loss, None);
    }

    #[test]
    fn snapshot_marks_positions_unreadable_when_position_value_missing() {
        let v = json!({
            "assetPositions": [
                { "position": { "coin": "BTC", "unrealizedPnl": "0" } }
            ]
        });
        let s = HlSnapshot::from_clearinghouse(&v);
        assert_eq!(s.position_micro("BTC"), None);
        assert_eq!(s.position_micro("SOL"), None);
    }

    #[test]
    fn snapshot_treats_valid_empty_positions_as_zero() {
        let s = HlSnapshot::from_clearinghouse(&json!({ "assetPositions": [] }));
        assert_eq!(s.position_micro("BTC"), Some(0));
    }
}
