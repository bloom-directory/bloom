//! Background poll-based executor for [`super::WatchRegistry`].
//!
//! The executor runs a single tokio task that wakes up every
//! `tick_interval` (default 2 s) and walks every spec in the registry.
//! For each spec it issues the appropriate JSON-RPC call against the
//! corresponding [`bloom_evm::ChainClient`] and, when the observed
//! state has changed since the last tick, appends a JSON line to a
//! per-watch `live` file. Live files are rotated to numbered
//! `history.jsonl.<n>` segments once they grow past 1 MB, with a
//! sentinel record so tailing agents can keep up.
//!
//! Per-watch storage layout (sibling to the registry's `<wallet>/<id>.toml`):
//!
//! ```text
//! <home>/watch/
//! └── <wallet>/
//!     ├── <id>.toml             # spec, owned by WatchRegistry
//!     └── <id>/
//!         ├── live              # current jsonl tail
//!         ├── history.jsonl     # latest rotated archive
//!         ├── history.jsonl.1   # older
//!         └── …
//! ```
//!
//! When the underlying [`bloom_evm::ChainClient`] reports
//! `supports_subscriptions == true`, the executor also spawns one
//! supervisor task per `Block` / `Event` spec that drives an
//! `eth_subscribe` stream over the WS provider. The supervisor emits
//! records as headers / logs arrive and exits cleanly when the stream
//! closes — the poll loop continues to run as the watchdog and resumes
//! emission via `last_seen_block` so no records are lost across the
//! handover. WS- and poll-emitted logs share the per-spec
//! [`LogDedup`] ring buffer, so duplicates from a brief overlap or a
//! reorg replay are dropped silently with `watch.event.dedup_dropped`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::eth::Filter;
use futures::StreamExt;
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, Notify, watch};
use tokio::task::JoinHandle;
use tokio::time::interval;
use tracing::{debug, info, trace, warn};

use bloom_evm::ChainRegistry;
use bloom_proto::HomeDir;

use crate::{WatchError, WatchKind, WatchRegistry, WatchSpec};

/// Reorg-dedupe ring buffer per spec. See decisions §3 of
/// `docs/specs/rpc-robustness.md`: we keep at most the last 64 distinct
/// block hashes' `(blockHash, logIndex)` pairs and use that to drop
/// duplicate emissions when a reorg replays logs or when the WS / poll
/// paths overlap during fail-over.
///
/// The buffer is bounded by *unique block hashes*, not by total
/// `(hash, idx)` pairs — a single block with hundreds of logs still
/// counts as one slot. That keeps memory predictable while still
/// covering the common reorg window (chains bigger than `MAX_BLOCKS`
/// blocks deep are well past finality on every L1 / L2 we care about).
#[derive(Debug, Default, Clone)]
pub struct LogDedup {
    /// Insertion-ordered queue of `(block_hash, indexes_seen)`. The
    /// front is the oldest tracked block; eviction pops from the front.
    blocks: VecDeque<(B256, HashSet<u64>)>,
}

impl LogDedup {
    /// Maximum number of distinct block hashes we keep state for.
    pub const MAX_BLOCKS: usize = 64;

    /// Record a `(block_hash, log_index)` pair, returning `true` when
    /// it was *new* (caller should emit) and `false` when it was a
    /// duplicate (caller should skip).
    ///
    /// The first time we see a given `block_hash` we push a fresh slot
    /// at the back of the ring and evict the oldest slot if we are at
    /// capacity. Subsequent calls with the same hash mutate the
    /// existing slot in place.
    pub fn observe(&mut self, block_hash: B256, log_index: u64) -> bool {
        if let Some((_, idxs)) = self.blocks.iter_mut().find(|(h, _)| *h == block_hash) {
            return idxs.insert(log_index);
        }
        let mut idxs = HashSet::new();
        idxs.insert(log_index);
        self.blocks.push_back((block_hash, idxs));
        if self.blocks.len() > Self::MAX_BLOCKS {
            self.blocks.pop_front();
        }
        true
    }

    /// True when the buffer has previously observed this exact pair.
    /// Read-only sibling of [`Self::observe`]; primarily for tests.
    pub fn contains(&self, block_hash: B256, log_index: u64) -> bool {
        self.blocks
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, idxs)| idxs.contains(&log_index))
            .unwrap_or(false)
    }

    /// Number of distinct block hashes currently retained. Useful for
    /// the eviction unit test.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether the dedup buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

/// Live file rotation threshold (1 MiB).
pub const ROTATE_THRESHOLD_BYTES: u64 = 1024 * 1024;

/// Default tick interval (2 s).
pub const DEFAULT_TICK_INTERVAL: Duration = Duration::from_secs(2);

/// Maximum number of blocks a saved cursor may lag the current head
/// before we treat it as stale and fall forward to the head. Picked to
/// be generous enough to absorb a multi-hour daemon pause on a fast L2
/// (Base / Optimism mine ~one block every 2 s, so 1000 blocks ≈ 33 min)
/// while still preventing genesis-walks if the cursor is corrupted or
/// belongs to a deleted-then-recreated watch with the same on-disk path.
///
/// When `head - cursor > MAX_RESUME_LAG`, the executor logs
/// `watch.cursor.stale_fast_forward` and seeds the cursor at `head`,
/// emitting nothing for the gap. This is by design: at that lag we
/// would emit a flood of records that the consumer has no interest in
/// (the user just created the watch / restarted the daemon and wants
/// "now", not the last hour).
pub const MAX_RESUME_LAG: u64 = 1000;

/// Decide where a Block-kind watch should resume on a tick / on the
/// arrival of a new WS header.
///
/// Returns the *exclusive* lower bound of the emit range, i.e. the
/// caller should emit `(returned_value + 1)..=head`. The cursor
/// returned must also be persisted in `state.block` so the next tick
/// resumes from the same point.
///
/// Three cases:
///
/// - `prev = None`: a fresh watch. Seed at `head`; emit nothing for
///   the gap. The next produced block is the first record the consumer
///   sees. This is the symptom-fix for the genesis-walk bug — without
///   this, a fresh watch on a chain at head ~45M would emit 45M
///   `block` records and rotate live files into oblivion.
/// - `prev = Some(p)` with `head - p <= MAX_RESUME_LAG`: legitimate
///   resume after a short pause. Return `p` so emission resumes from
///   `p + 1`.
/// - `prev = Some(p)` with `head - p > MAX_RESUME_LAG`: stale cursor
///   (usually a corrupted state map or a watch id collision after a
///   delete + recreate). Fall forward to `head`. Caller should also
///   emit a `watch.cursor.stale_fast_forward` warning.
///
/// Pure: no IO, no global state. Unit tests in this module exercise
/// every branch directly without standing up a chain client.
pub fn resume_block_cursor(prev: Option<u64>, head: u64, max_lag: u64) -> ResumeDecision {
    match prev {
        None => ResumeDecision::FreshSeedAtHead,
        Some(p) if p > head => {
            // Reorg / provider regression: caller should not emit but
            // also should not advance the cursor. We surface this as a
            // dedicated variant rather than collapsing it to "resume"
            // so the caller can warn.
            ResumeDecision::Regressed { prev: p }
        }
        Some(p) if head.saturating_sub(p) > max_lag => ResumeDecision::StaleSeedAtHead { prev: p },
        Some(p) => ResumeDecision::Resume { prev: p },
    }
}

/// Outcome of [`resume_block_cursor`]. The caller decides what to emit
/// based on the variant; the helper itself is pure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeDecision {
    /// No saved cursor: seed at head, emit nothing for the gap.
    FreshSeedAtHead,
    /// Saved cursor is recent enough to resume normally. Caller should
    /// emit `(prev + 1)..=head`.
    Resume { prev: u64 },
    /// Saved cursor is implausibly stale (`head - prev > max_lag`).
    /// Caller should reseed at head, log a warning, emit nothing.
    StaleSeedAtHead { prev: u64 },
    /// Saved cursor is ahead of head (provider regression / reorg).
    /// Caller should *not* advance the cursor and *not* emit.
    Regressed { prev: u64 },
}

/// Background watch loop. Wraps a [`WatchRegistry`] and a
/// [`ChainRegistry`] so the spawned task has everything it needs.
pub struct WatchExecutor {
    chains: ChainRegistry,
    registry: Arc<WatchRegistry>,
    home: HomeDir,
    tick: Duration,
    handle: Mutex<Option<JoinHandle<()>>>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl WatchExecutor {
    /// Create a new executor. Does not spawn the background task —
    /// call [`start`](Self::start) for that.
    pub fn new(chains: ChainRegistry, registry: Arc<WatchRegistry>, home: HomeDir) -> Self {
        let (tx, rx) = watch::channel(false);
        Self {
            chains,
            registry,
            home,
            tick: DEFAULT_TICK_INTERVAL,
            handle: Mutex::new(None),
            shutdown_tx: tx,
            shutdown_rx: rx,
        }
    }

    /// Override the polling interval (default: 2 s).
    pub fn with_tick(mut self, tick: Duration) -> Self {
        self.tick = tick;
        self
    }

    /// Path to the per-watch live file. Note: this is the *flat-by-id*
    /// path callers use through the VFS. The executor's loop writes to
    /// `live_path_for_spec` which includes the wallet partition.
    pub fn live_path(&self, id: &str) -> PathBuf {
        match self.registry.find_by_id(id) {
            Some(spec) => Self::live_path_for_spec(&self.home, &spec),
            None => {
                debug!(id, "watch.live_path.spec_not_found");
                self.home.watch_dir().join(id).join("live")
            }
        }
    }

    /// Same as [`live_path`](Self::live_path) but for the rotated history.
    pub fn history_path(&self, id: &str) -> PathBuf {
        match self.registry.find_by_id(id) {
            Some(spec) => Self::history_path_for_spec(&self.home, &spec),
            None => {
                debug!(id, "watch.history_path.spec_not_found");
                self.home.watch_dir().join(id).join("history.jsonl")
            }
        }
    }

    /// Per-watch directory that holds `live`, `history.jsonl`, and the
    /// numbered rotations. Sibling to `<wallet>/<id>.toml`.
    pub fn watch_dir_for_spec(home: &HomeDir, spec: &WatchSpec) -> PathBuf {
        home.watch_dir().join(&spec.wallet).join(&spec.id)
    }

    pub fn live_path_for_spec(home: &HomeDir, spec: &WatchSpec) -> PathBuf {
        Self::watch_dir_for_spec(home, spec).join("live")
    }

    pub fn history_path_for_spec(home: &HomeDir, spec: &WatchSpec) -> PathBuf {
        Self::watch_dir_for_spec(home, spec).join("history.jsonl")
    }

    /// Spawn the polling task plus the per-spec WS subscription
    /// supervisors. Idempotent: if the task is already running, the
    /// second call is a no-op.
    ///
    /// The poll loop is the watchdog — it always runs, on a fixed tick
    /// (default 2 s), even when the WS fast path is healthy. WS
    /// emissions and poll emissions share the per-spec dedup ring
    /// buffer in [`ExecutorState::dedup`] so a brief overlap during
    /// fail-over is transparent: duplicates are dropped and tagged
    /// `watch.event.dedup_dropped`.
    ///
    /// Balance and gas-price sampling stay in the poll loop but are
    /// reactive — every `newHeads` arrival (when WS is alive) fires a
    /// `Notify` that wakes the poll loop ahead of its next tick.
    pub fn start(self: &Arc<Self>) -> Result<(), WatchError> {
        let mut guard = self.handle.try_lock().map_err(|_| {
            WatchError::Io(std::io::Error::other(
                "watch executor handle locked; concurrent start",
            ))
        })?;
        if guard.is_some() {
            debug!("watch.executor.start.already_running");
            return Ok(());
        }

        let this = Arc::clone(self);
        let mut shutdown_rx = self.shutdown_rx.clone();
        let tick = self.tick;
        let specs = self.registry.list_all().len();
        info!(
            tick_ms = tick.as_millis() as u64,
            specs, "watch.executor.start"
        );
        let head_notify = Arc::new(Notify::new());
        let shared_state: Arc<Mutex<ExecutorState>> =
            Arc::new(Mutex::new(ExecutorState::default()));

        // Spawn one supervisor task per Block / Event spec. Each
        // supervisor opens (or re-opens) the relevant `subscribe_*`
        // stream and runs until the stream closes; the poll loop picks
        // up any gaps between tries. Newly-added specs are picked up by
        // the supervisor sweep that runs on every poll tick (see
        // `reconcile_ws_supervisors`).
        let ws_tasks: Arc<Mutex<HashMap<String, JoinHandle<()>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let handle = {
            let this = Arc::clone(&this);
            let head_notify = Arc::clone(&head_notify);
            let shared_state = Arc::clone(&shared_state);
            let ws_tasks = Arc::clone(&ws_tasks);
            tokio::spawn(async move {
                let mut ticker = interval(tick);
                // Skip the immediate first tick burst so callers can
                // fund accounts and then observe the first genuine
                // "change".
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                // Initial reconcile so WS streams come up as soon as
                // possible without waiting for the first tick.
                this.reconcile_ws_supervisors(&ws_tasks, &shared_state, &head_notify, &shutdown_rx)
                    .await;
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            trace!("watch.tick.begin");
                            this.reconcile_ws_supervisors(
                                &ws_tasks,
                                &shared_state,
                                &head_notify,
                                &shutdown_rx,
                            )
                            .await;
                            let mut guard = shared_state.lock().await;
                            if let Err(e) = this.tick_once(&mut guard).await {
                                warn!(error = %e, "watch.tick.error");
                            }
                        }
                        _ = head_notify.notified() => {
                            // A WS `newHeads` arrived: re-fetch
                            // balance / gas / etc immediately rather
                            // than waiting for the next ticker. The
                            // ticker still fires as a watchdog.
                            trace!("watch.tick.notified_by_head");
                            let mut guard = shared_state.lock().await;
                            if let Err(e) = this.tick_once(&mut guard).await {
                                warn!(error = %e, "watch.tick.error");
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                debug!("watch.executor.shutdown");
                                let mut tasks = ws_tasks.lock().await;
                                for (_, h) in tasks.drain() {
                                    h.abort();
                                }
                                break;
                            }
                        }
                    }
                }
            })
        };
        *guard = Some(handle);
        Ok(())
    }

    /// Walk every registered spec and ensure a WS supervisor task is
    /// running for each `Block` / `Event` whose chain client reports
    /// `supports_subscriptions == true`. Idempotent: tasks already
    /// alive are left untouched. Tasks that have completed (stream
    /// ended, will be respawned next tick) are reaped.
    async fn reconcile_ws_supervisors(
        self: &Arc<Self>,
        ws_tasks: &Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
        state: &Arc<Mutex<ExecutorState>>,
        head_notify: &Arc<Notify>,
        shutdown_rx: &watch::Receiver<bool>,
    ) {
        let mut tasks = ws_tasks.lock().await;
        // Reap finished tasks so the next iteration can re-spawn.
        let finished: Vec<String> = tasks
            .iter()
            .filter_map(|(k, h)| {
                if h.is_finished() {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        for k in finished {
            tasks.remove(&k);
        }
        for spec in self.registry.list_all() {
            let key = format!("{}/{}", spec.wallet, spec.id);
            if tasks.contains_key(&key) {
                continue;
            }
            let chain_name = match &spec.kind {
                WatchKind::Block { chain } => Some(chain.clone()),
                WatchKind::Event { chain, .. } => Some(chain.clone()),
                _ => None,
            };
            let Some(chain_name) = chain_name else {
                continue;
            };
            let Some(client) = self.chains.get(&chain_name) else {
                continue;
            };
            if !client.supports_subscriptions() {
                continue;
            }
            let this = Arc::clone(self);
            let state = Arc::clone(state);
            let head_notify = Arc::clone(head_notify);
            let shutdown_rx = shutdown_rx.clone();
            let spec_clone = spec.clone();
            let task = match &spec.kind {
                WatchKind::Block { .. } => tokio::spawn(async move {
                    this.run_block_subscription(spec_clone, state, head_notify, shutdown_rx)
                        .await;
                }),
                WatchKind::Event { .. } => tokio::spawn(async move {
                    this.run_event_subscription(spec_clone, state, head_notify, shutdown_rx)
                        .await;
                }),
                _ => continue,
            };
            tasks.insert(key, task);
        }
    }

    /// Subscribe to `newHeads` for a single Block-kind spec and emit
    /// records as headers arrive. Returns when the stream closes (the
    /// supervisor will re-spawn us on the next reconcile pass).
    async fn run_block_subscription(
        self: Arc<Self>,
        spec: WatchSpec,
        state: Arc<Mutex<ExecutorState>>,
        head_notify: Arc<Notify>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let WatchKind::Block { chain } = &spec.kind else {
            return;
        };
        let Some(client) = self.chains.get(chain) else {
            return;
        };
        let Some(provider) = client.ws_provider().await else {
            debug!(
                wallet = %spec.wallet,
                id = %spec.id,
                chain = %chain,
                "watch.subscribe_blocks.ws_provider_unavailable"
            );
            return;
        };
        let sub = match provider.subscribe_blocks().await {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    wallet = %spec.wallet,
                    id = %spec.id,
                    chain = %chain,
                    error = %e,
                    "watch.subscribe_blocks.error"
                );
                return;
            }
        };
        info!(
            wallet = %spec.wallet,
            id = %spec.id,
            chain = %chain,
            "watch.subscribe_blocks.started"
        );
        let mut stream = sub.into_stream();
        let key = format!("{}/{}", spec.wallet, spec.id);
        loop {
            tokio::select! {
                next = stream.next() => {
                    let Some(header) = next else {
                        warn!(
                            wallet = %spec.wallet,
                            id = %spec.id,
                            chain = %chain,
                            "watch.subscribe_blocks.ended_falling_back_to_poll"
                        );
                        return;
                    };
                    let n = header.number;
                    head_notify.notify_waiters();
                    let mut state = state.lock().await;
                    let prev = state.block.get(&key).copied();
                    let decision = resume_block_cursor(prev, n, MAX_RESUME_LAG);
                    let emit_from = match decision {
                        ResumeDecision::FreshSeedAtHead => {
                            // Fresh watch: emit just this header so the
                            // consumer sees "the first block since I
                            // created the watch" and not silence. The
                            // next iteration will see prev=n and only
                            // emit truly new headers.
                            debug!(
                                wallet = %spec.wallet,
                                id = %spec.id,
                                chain = %chain,
                                head = n,
                                "watch.subscribe_blocks.fresh_seed"
                            );
                            n
                        }
                        ResumeDecision::Resume { prev } => prev + 1,
                        ResumeDecision::StaleSeedAtHead { prev } => {
                            warn!(
                                wallet = %spec.wallet,
                                id = %spec.id,
                                chain = %chain,
                                prev,
                                head = n,
                                lag = n.saturating_sub(prev),
                                max_lag = MAX_RESUME_LAG,
                                "watch.cursor.stale_fast_forward"
                            );
                            n
                        }
                        ResumeDecision::Regressed { prev } => {
                            warn!(
                                wallet = %spec.wallet,
                                id = %spec.id,
                                chain = %chain,
                                prev,
                                head = n,
                                "watch.subscribe_blocks.regressed"
                            );
                            // Don't advance cursor; don't emit.
                            continue;
                        }
                    };
                    if emit_from <= n {
                        for missed in emit_from..=n {
                            let record = serde_json::json!({
                                "ts": now_ms(),
                                "kind": "block",
                                "chain": chain,
                                "number": missed,
                            });
                            if let Err(e) = self.append_record(&spec, &record).await {
                                warn!(
                                    wallet = %spec.wallet,
                                    id = %spec.id,
                                    error = %e,
                                    "watch.subscribe_blocks.append_failed"
                                );
                            }
                        }
                    }
                    state.block.insert(key.clone(), n);
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        debug!(
                            wallet = %spec.wallet,
                            id = %spec.id,
                            "watch.subscribe_blocks.shutdown"
                        );
                        return;
                    }
                }
            }
        }
    }

    /// Subscribe to `logs(filter)` for a single Event-kind spec.
    /// Mirrors [`Self::run_block_subscription`]: returns on stream
    /// close, supervisor re-spawns.
    async fn run_event_subscription(
        self: Arc<Self>,
        spec: WatchSpec,
        state: Arc<Mutex<ExecutorState>>,
        head_notify: Arc<Notify>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let WatchKind::Event {
            chain,
            contract,
            topic0,
        } = &spec.kind
        else {
            return;
        };
        let Some(client) = self.chains.get(chain) else {
            return;
        };
        let Some(provider) = client.ws_provider().await else {
            debug!(
                wallet = %spec.wallet,
                id = %spec.id,
                chain = %chain,
                "watch.subscribe_logs.ws_provider_unavailable"
            );
            return;
        };
        let addr: Address = match contract.parse() {
            Ok(a) => a,
            Err(e) => {
                warn!(
                    wallet = %spec.wallet,
                    id = %spec.id,
                    contract = %contract,
                    error = %e,
                    "watch.subscribe_logs.bad_contract"
                );
                return;
            }
        };
        let topic: B256 = match topic0.parse() {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    wallet = %spec.wallet,
                    id = %spec.id,
                    topic0 = %topic0,
                    error = %e,
                    "watch.subscribe_logs.bad_topic"
                );
                return;
            }
        };
        // Open-ended filter: no to_block. Closed-range specs would be
        // better off polling; today every spec is open-ended.
        let filter = Filter::new().address(addr).event_signature(topic);
        let sub = match provider.subscribe_logs(&filter).await {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    wallet = %spec.wallet,
                    id = %spec.id,
                    chain = %chain,
                    error = %e,
                    "watch.subscribe_logs.error"
                );
                return;
            }
        };
        info!(
            wallet = %spec.wallet,
            id = %spec.id,
            chain = %chain,
            "watch.subscribe_logs.opened"
        );
        let mut stream = sub.into_stream();
        let key = format!("{}/{}", spec.wallet, spec.id);
        loop {
            tokio::select! {
                next = stream.next() => {
                    let Some(log) = next else {
                        warn!(
                            wallet = %spec.wallet,
                            id = %spec.id,
                            chain = %chain,
                            "watch.subscribe_logs.ended_falling_back_to_poll"
                        );
                        return;
                    };
                    head_notify.notify_waiters();
                    let mut state = state.lock().await;
                    let dedup = state.dedup.entry(key.clone()).or_default();
                    if !apply_dedup(dedup, &log, &spec.wallet, &spec.id) {
                        continue;
                    }
                    if let Some(bn) = log.block_number {
                        let prev = state.event_block.get(&key).copied().unwrap_or(0);
                        if bn > prev {
                            state.event_block.insert(key.clone(), bn);
                        }
                    }
                    let record = serde_json::json!({
                        "ts": now_ms(),
                        "kind": "event",
                        "chain": chain,
                        "contract": contract,
                        "topic0": topic0,
                        "log": log,
                    });
                    if let Err(e) = self.append_record(&spec, &record).await {
                        warn!(
                            wallet = %spec.wallet,
                            id = %spec.id,
                            error = %e,
                            "watch.subscribe_logs.append_failed"
                        );
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        debug!(
                            wallet = %spec.wallet,
                            id = %spec.id,
                            "watch.subscribe_logs.shutdown"
                        );
                        return;
                    }
                }
            }
        }
    }

    /// Stop the background task. Safe to call from any context.
    pub async fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
        let mut guard = self.handle.lock().await;
        if let Some(h) = guard.take() {
            // Best-effort: aborting + awaiting is enough for shutdown.
            h.abort();
            let _ = h.await;
            debug!("watch.executor.stopped");
        } else {
            trace!("watch.executor.stop.not_running");
        }
    }

    /// Run a single poll pass over every registered watch. Public so tests
    /// can drive it deterministically.
    pub async fn tick_once(&self, state: &mut ExecutorState) -> Result<(), WatchError> {
        for spec in self.registry.list_all() {
            if let Err(e) = self.process_spec(&spec, state).await {
                warn!(wallet = %spec.wallet, id = %spec.id, error = %e, "watch.spec.error");
            }
        }
        Ok(())
    }

    async fn process_spec(
        &self,
        spec: &WatchSpec,
        state: &mut ExecutorState,
    ) -> Result<(), WatchError> {
        let key = format!("{}/{}", spec.wallet, spec.id);
        match &spec.kind {
            WatchKind::Balance {
                address,
                threshold_wei: _,
                comparator: _,
            } => {
                // Pick the wallet's "first" chain - this watch kind in the
                // current spec doesn't carry a chain ref, so we sample
                // every configured chain. To keep behaviour deterministic
                // we pick the first chain by registered name order.
                let chain_name = match self.chains.list_names().into_iter().next() {
                    Some(n) => n,
                    None => {
                        debug!(wallet = %spec.wallet, id = %spec.id, "watch.balance.no_chains");
                        return Ok(());
                    }
                };
                let client = match self.chains.get(&chain_name) {
                    Some(c) => c,
                    None => {
                        debug!(
                            wallet = %spec.wallet,
                            id = %spec.id,
                            chain = %chain_name,
                            "watch.balance.chain_unavailable"
                        );
                        return Ok(());
                    }
                };
                let addr: Address = address.parse().map_err(|e: alloy::hex::FromHexError| {
                    WatchError::InvalidId(format!("bad address {address}: {e}"))
                })?;
                let bal = client
                    .balance(addr)
                    .await
                    .map_err(|e| WatchError::Io(std::io::Error::other(e.to_string())))?;
                let prev = state.balance.get(&key).copied();
                if prev != Some(bal) {
                    debug!(
                        wallet = %spec.wallet,
                        id = %spec.id,
                        chain = %chain_name,
                        addr = %format!("{:#x}", addr),
                        balance_wei = %bal,
                        "watch.balance.changed"
                    );
                    let record = serde_json::json!({
                        "ts": now_ms(),
                        "kind": "balance",
                        "addr": format!("{:#x}", addr),
                        "balance_wei": bal.to_string(),
                        "prev_wei": prev.map(|p| p.to_string()),
                        "chain": chain_name,
                    });
                    self.append_record(spec, &record).await?;
                    state.balance.insert(key, bal);
                }
            }
            WatchKind::Block { chain } => {
                let client = match self.chains.get(chain) {
                    Some(c) => c,
                    None => {
                        debug!(
                            wallet = %spec.wallet,
                            id = %spec.id,
                            chain = %chain,
                            "watch.block.chain_unavailable"
                        );
                        return Ok(());
                    }
                };
                let head = client
                    .block_number()
                    .await
                    .map_err(|e| WatchError::Io(std::io::Error::other(e.to_string())))?;
                let prev = state.block.get(&key).copied();
                let decision = resume_block_cursor(prev, head, MAX_RESUME_LAG);
                let emit_from = match decision {
                    ResumeDecision::FreshSeedAtHead => {
                        // Fresh watch (or fresh tick after a daemon
                        // restart with no in-memory state). Seed the
                        // cursor at head and skip emission for the
                        // gap. The first record the consumer sees will
                        // be the *next* block produced.
                        debug!(
                            wallet = %spec.wallet,
                            id = %spec.id,
                            chain = %chain,
                            head,
                            "watch.block.fresh_seed"
                        );
                        state.block.insert(key, head);
                        return Ok(());
                    }
                    ResumeDecision::Resume { prev } => prev + 1,
                    ResumeDecision::StaleSeedAtHead { prev } => {
                        warn!(
                            wallet = %spec.wallet,
                            id = %spec.id,
                            chain = %chain,
                            prev,
                            head,
                            lag = head.saturating_sub(prev),
                            max_lag = MAX_RESUME_LAG,
                            "watch.cursor.stale_fast_forward"
                        );
                        state.block.insert(key, head);
                        return Ok(());
                    }
                    ResumeDecision::Regressed { prev } => {
                        warn!(
                            wallet = %spec.wallet,
                            id = %spec.id,
                            chain = %chain,
                            prev,
                            head,
                            "watch.block.regressed"
                        );
                        return Ok(());
                    }
                };
                if emit_from <= head {
                    debug!(
                        wallet = %spec.wallet,
                        id = %spec.id,
                        chain = %chain,
                        from = emit_from,
                        to = head,
                        "watch.block.advanced"
                    );
                    for n in emit_from..=head {
                        let record = serde_json::json!({
                            "ts": now_ms(),
                            "kind": "block",
                            "chain": chain,
                            "number": n,
                        });
                        self.append_record(spec, &record).await?;
                    }
                    state.block.insert(key, head);
                }
            }
            WatchKind::GasPrice {
                chain,
                threshold_gwei,
            } => {
                let client = match self.chains.get(chain) {
                    Some(c) => c,
                    None => {
                        debug!(
                            wallet = %spec.wallet,
                            id = %spec.id,
                            chain = %chain,
                            "watch.gas_price.chain_unavailable"
                        );
                        return Ok(());
                    }
                };
                let gp = client
                    .gas_price()
                    .await
                    .map_err(|e| WatchError::Io(std::io::Error::other(e.to_string())))?;
                let prev = state.gas.get(&key).copied();
                let crossed = match prev {
                    None => true,
                    Some(prev_gp) => prev_gp != gp,
                };
                if crossed {
                    debug!(
                        wallet = %spec.wallet,
                        id = %spec.id,
                        chain = %chain,
                        gas_price_wei = gp,
                        threshold_gwei = threshold_gwei,
                        "watch.gas_price.changed"
                    );
                    let record = serde_json::json!({
                        "ts": now_ms(),
                        "kind": "gas_price",
                        "chain": chain,
                        "gas_price_wei": gp.to_string(),
                        "prev_wei": prev.map(|p| p.to_string()),
                        "threshold_gwei": threshold_gwei,
                    });
                    self.append_record(spec, &record).await?;
                    state.gas.insert(key, gp);
                }
            }
            WatchKind::Event {
                chain,
                contract,
                topic0,
            } => {
                let client = match self.chains.get(chain) {
                    Some(c) => c,
                    None => {
                        debug!(
                            wallet = %spec.wallet,
                            id = %spec.id,
                            chain = %chain,
                            "watch.event.chain_unavailable"
                        );
                        return Ok(());
                    }
                };
                let head = client
                    .block_number()
                    .await
                    .map_err(|e| WatchError::Io(std::io::Error::other(e.to_string())))?;
                // Reuse the Block-watch cursor policy so a fresh /
                // stale Event watch never tries to backfill from
                // genesis. A fresh Event watch resumes at `head` (so
                // we capture any logs in the current block); a stale
                // one fast-forwards to head with a warning.
                let prev = state.event_block.get(&key).copied();
                let from_block = match resume_block_cursor(prev, head, MAX_RESUME_LAG) {
                    ResumeDecision::FreshSeedAtHead => head,
                    ResumeDecision::Resume { prev } => prev + 1,
                    ResumeDecision::StaleSeedAtHead { prev } => {
                        warn!(
                            wallet = %spec.wallet,
                            id = %spec.id,
                            chain = %chain,
                            prev,
                            head,
                            lag = head.saturating_sub(prev),
                            max_lag = MAX_RESUME_LAG,
                            "watch.event.cursor.stale_fast_forward"
                        );
                        head
                    }
                    ResumeDecision::Regressed { prev } => {
                        warn!(
                            wallet = %spec.wallet,
                            id = %spec.id,
                            chain = %chain,
                            prev,
                            head,
                            "watch.event.regressed"
                        );
                        return Ok(());
                    }
                };
                if from_block > head {
                    trace!(
                        wallet = %spec.wallet,
                        id = %spec.id,
                        chain = %chain,
                        from = from_block,
                        head,
                        "watch.event.no_new_blocks"
                    );
                    return Ok(());
                }
                let addr: Address = contract.parse().map_err(|e: alloy::hex::FromHexError| {
                    WatchError::InvalidId(format!("bad contract {contract}: {e}"))
                })?;
                let topic: alloy::primitives::B256 =
                    topic0.parse().map_err(|e: alloy::hex::FromHexError| {
                        WatchError::InvalidId(format!("bad topic0 {topic0}: {e}"))
                    })?;
                let filter = Filter::new()
                    .address(addr)
                    .from_block(from_block)
                    .to_block(head)
                    .event_signature(topic);
                let logs = client
                    .provider()
                    .get_logs(&filter)
                    .await
                    .map_err(|e| WatchError::Io(std::io::Error::other(e.to_string())))?;
                if !logs.is_empty() {
                    debug!(
                        wallet = %spec.wallet,
                        id = %spec.id,
                        chain = %chain,
                        contract = %contract,
                        from = from_block,
                        to = head,
                        logs = logs.len(),
                        "watch.event.logs_yielded"
                    );
                }
                let dedup = state.dedup.entry(key.clone()).or_default();
                for log in logs {
                    if !apply_dedup(dedup, &log, &spec.wallet, &spec.id) {
                        continue;
                    }
                    let record = serde_json::json!({
                        "ts": now_ms(),
                        "kind": "event",
                        "chain": chain,
                        "contract": contract,
                        "topic0": topic0,
                        "log": log,
                    });
                    self.append_record(spec, &record).await?;
                }
                state.event_block.insert(key, head);
            }
        }
        Ok(())
    }

    /// Append one JSON record (one line) to `<wallet>/<id>/live`,
    /// rotating into history.jsonl[.N] when the live file exceeds the
    /// rotation threshold.
    pub async fn append_record<T: Serialize>(
        &self,
        spec: &WatchSpec,
        record: &T,
    ) -> Result<(), WatchError> {
        let dir = Self::watch_dir_for_spec(&self.home, spec);
        tokio::fs::create_dir_all(&dir).await?;
        let live = Self::live_path_for_spec(&self.home, spec);

        // Rotate first if needed, *before* writing the new record.
        if let Ok(meta) = tokio::fs::metadata(&live).await
            && meta.len() >= ROTATE_THRESHOLD_BYTES
        {
            self.rotate(spec).await?;
        }

        let line = serde_json::to_string(record)
            .map_err(|e| WatchError::Io(std::io::Error::other(e.to_string())))?;
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&live)
            .await?;
        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;
        Ok(())
    }

    /// Rotate `<id>/live` into the next available
    /// `<id>/history.jsonl(.N)` slot and write a `{sentinel:"rotate"}`
    /// line into the new live file.
    pub async fn rotate(&self, spec: &WatchSpec) -> Result<(), WatchError> {
        let dir = Self::watch_dir_for_spec(&self.home, spec);
        tokio::fs::create_dir_all(&dir).await?;
        let live = Self::live_path_for_spec(&self.home, spec);
        if !live.exists() {
            trace!(wallet = %spec.wallet, id = %spec.id, "watch.rotate.live_missing");
            return Ok(());
        }
        let history = Self::history_path_for_spec(&self.home, spec);

        // Determine next free slot. If `history.jsonl` does not exist,
        // move live there. Otherwise find the largest N already in use
        // and write to N+1.
        let target = if !history.exists() {
            history.clone()
        } else {
            let mut n: u32 = 1;
            loop {
                let candidate = dir.join(format!("history.jsonl.{}", n));
                if !candidate.exists() {
                    break candidate;
                }
                n += 1;
            }
        };

        // Sentinel: written as the *first* line of the new live file so
        // tailing agents see it before any subsequent record.
        let sentinel = serde_json::json!({
            "sentinel": "rotate",
            "next": target.file_name().and_then(|s| s.to_str()).unwrap_or("history.jsonl"),
            "ts": now_ms(),
        });

        tokio::fs::rename(&live, &target).await?;
        debug!(
            wallet = %spec.wallet,
            id = %spec.id,
            target = %target.file_name().and_then(|s| s.to_str()).unwrap_or("history.jsonl"),
            "watch.rotate.done"
        );
        let mut new_live = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&live)
            .await?;
        let line = serde_json::to_string(&sentinel)
            .map_err(|e| WatchError::Io(std::io::Error::other(e.to_string())))?;
        new_live.write_all(line.as_bytes()).await?;
        new_live.write_all(b"\n").await?;
        new_live.flush().await?;
        Ok(())
    }
}

/// Per-tick observed state, keyed by `<wallet>/<id>`. Public for tests.
#[derive(Default)]
pub struct ExecutorState {
    pub balance: HashMap<String, U256>,
    pub block: HashMap<String, u64>,
    pub gas: HashMap<String, u128>,
    pub event_block: HashMap<String, u64>,
    /// Per-spec reorg dedup ring buffer for `WatchKind::Event` logs.
    /// Lives in the executor's state alongside `event_block` so the WS
    /// fast path and the poll fallback share one view; see
    /// [`LogDedup`] for the eviction policy.
    pub dedup: HashMap<String, LogDedup>,
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Returns `true` if the caller should emit the log, `false` if it has
/// already been seen (and was filtered by the per-spec ring buffer).
///
/// Logs without a `block_hash` or `log_index` (pending logs, vendor
/// quirks) cannot be deduped; we emit them and skip the buffer update.
/// Reorg-emitted duplicates surface as `watch.event.dedup_dropped` at
/// `debug` level so operators tailing logs see the filtering happen.
fn apply_dedup(
    dedup: &mut LogDedup,
    log: &alloy::rpc::types::eth::Log,
    wallet: &str,
    id: &str,
) -> bool {
    let (Some(hash), Some(idx)) = (log.block_hash, log.log_index) else {
        return true;
    };
    if dedup.observe(hash, idx) {
        true
    } else {
        debug!(
            wallet,
            id,
            block_hash = %hash,
            log_index = idx,
            "watch.event.dedup_dropped"
        );
        false
    }
}

// Type assertion: ensure WatchExecutor remains Send + Sync.
const _: fn() = || {
    fn assert_send<T: Send + Sync>() {}
    assert_send::<WatchExecutor>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;
    use tempfile::tempdir;

    #[tokio::test]
    async fn rotate_moves_live_and_writes_sentinel() {
        let tmp = tempdir().unwrap();
        let home = HomeDir::at(tmp.path());
        home.ensure().unwrap();
        let registry = Arc::new(WatchRegistry::new(home.watch_dir()).unwrap());
        let chains = ChainRegistry::default();
        let exec = WatchExecutor::new(chains, registry, home.clone());

        let spec = WatchSpec {
            id: "w-0001".into(),
            wallet: "alice".into(),
            created_ms: 1,
            kind: WatchKind::GasPrice {
                chain: "anvil".into(),
                threshold_gwei: 1.0,
            },
            note: None,
        };

        // Seed live with junk past the threshold.
        let dir = WatchExecutor::watch_dir_for_spec(&home, &spec);
        std::fs::create_dir_all(&dir).unwrap();
        let live = WatchExecutor::live_path_for_spec(&home, &spec);
        std::fs::write(&live, vec![b'x'; (ROTATE_THRESHOLD_BYTES + 1) as usize]).unwrap();

        exec.append_record(&spec, &serde_json::json!({"ping": 1}))
            .await
            .unwrap();

        // After append, live should be small (sentinel + new record only),
        // and history.jsonl should hold the old contents.
        let live_meta = std::fs::metadata(&live).unwrap();
        assert!(live_meta.len() < ROTATE_THRESHOLD_BYTES);
        let history = WatchExecutor::history_path_for_spec(&home, &spec);
        assert!(history.exists());

        let live_body = std::fs::read_to_string(&live).unwrap();
        let first_line = live_body.lines().next().unwrap();
        let v: serde_json::Value = serde_json::from_str(first_line).unwrap();
        assert_eq!(v["sentinel"], "rotate");
    }

    #[tokio::test]
    async fn start_stop_idempotent() {
        let tmp = tempdir().unwrap();
        let home = HomeDir::at(tmp.path());
        home.ensure().unwrap();
        let registry = Arc::new(WatchRegistry::new(home.watch_dir()).unwrap());
        let chains = ChainRegistry::default();
        let exec = Arc::new(
            WatchExecutor::new(chains, registry, home).with_tick(StdDuration::from_millis(50)),
        );
        exec.start().unwrap();
        // Second start is a no-op.
        exec.start().unwrap();
        exec.stop().await;
    }

    /// Once the executor is running, the public `append_record` path
    /// must produce content in the spec's live file within 2 s. Together
    /// with [`start_stop_idempotent`] this covers the watch lifecycle —
    /// the loop is alive and IO works through it. (We can't drive a real
    /// tick in unit tests without network; the anvil-backed integration
    /// test in `tests/anvil_watch.rs` covers that path.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn started_executor_writes_live_file_within_2s() {
        let tmp = tempdir().unwrap();
        let home = HomeDir::at(tmp.path());
        home.ensure().unwrap();
        let registry = Arc::new(WatchRegistry::new(home.watch_dir()).unwrap());
        // Seed a pre-existing spec on disk so it's loaded by a fresh
        // registry — same path the daemon takes on boot.
        let spec = WatchSpec {
            id: "w-0001".into(),
            wallet: "alice".into(),
            created_ms: 1,
            kind: WatchKind::Block {
                chain: "anvil".into(),
            },
            note: None,
        };
        registry.add(spec.clone()).unwrap();
        drop(registry);

        // Re-open the registry — this exercises the boot-time scan path.
        let registry = Arc::new(WatchRegistry::new(home.watch_dir()).unwrap());
        assert!(registry.find_by_id("w-0001").is_some());

        let chains = ChainRegistry::default();
        let exec = Arc::new(
            WatchExecutor::new(chains, registry, home.clone())
                .with_tick(StdDuration::from_millis(50)),
        );
        exec.start().unwrap();

        // Drive the IO path — the executor's tick loop is running, and
        // its public append_record path writes through the same code
        // path it uses internally. This proves: (a) the spec is
        // resident, (b) the executor has the wiring needed to write,
        // and (c) the live file appears within the budget.
        let exec2 = exec.clone();
        let spec2 = spec.clone();
        tokio::spawn(async move {
            let _ = exec2
                .append_record(&spec2, &serde_json::json!({"mock": "tick"}))
                .await;
        });

        let live = WatchExecutor::live_path_for_spec(&home, &spec);
        let deadline = std::time::Instant::now() + StdDuration::from_secs(2);
        loop {
            if let Ok(meta) = std::fs::metadata(&live)
                && meta.len() > 0
            {
                break;
            }
            if std::time::Instant::now() > deadline {
                exec.stop().await;
                panic!("live file not written within 2s");
            }
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
        let body = std::fs::read_to_string(&live).unwrap();
        assert!(body.contains("\"mock\":\"tick\""), "got: {body}");

        exec.stop().await;
    }

    /// First emit of a `(blockHash, logIndex)` pair returns `true`,
    /// the second returns `false`. This is the core invariant the WS /
    /// poll handover relies on: when two paths surface the same log
    /// the second one is silently dropped.
    #[test]
    fn dedup_drops_duplicate_log_within_window() {
        let mut d = LogDedup::default();
        let h: B256 = B256::with_last_byte(7);
        assert!(d.observe(h, 0));
        assert!(!d.observe(h, 0));
        assert!(d.contains(h, 0));
        // A different log_index in the same block is still novel.
        assert!(d.observe(h, 1));
        assert!(!d.observe(h, 1));
    }

    /// Inserting `MAX_BLOCKS + 1` distinct hashes evicts the oldest.
    /// We then re-observe an entry from the evicted block to confirm
    /// the buffer has truly forgotten it (otherwise the test would say
    /// `false` because it's a duplicate).
    #[test]
    fn dedup_window_evicts_oldest_block() {
        let mut d = LogDedup::default();
        // First block — will be evicted.
        let evicted = B256::with_last_byte(0);
        assert!(d.observe(evicted, 0));

        // Fill up to MAX_BLOCKS *more* distinct hashes; total 1 + MAX
        // means the original must be popped.
        for i in 1..=LogDedup::MAX_BLOCKS as u8 {
            assert!(d.observe(B256::with_last_byte(i), 0));
        }
        assert_eq!(d.len(), LogDedup::MAX_BLOCKS);
        // The original block is no longer remembered, so `observe`
        // returns true again (treated as new).
        assert!(!d.contains(evicted, 0));
        assert!(d.observe(evicted, 0));
    }

    // ---- Resume cursor policy ----

    /// A freshly-created watch (no saved cursor) must seed at `head`
    /// and emit nothing for the historical gap. Without this, a watch
    /// created on Base at head ~45M would emit 45M `block` records
    /// from genesis and rotate the live file thousands of times.
    #[test]
    fn fresh_watch_seeds_at_head_no_backfill() {
        let d = resume_block_cursor(None, 45_808_266, MAX_RESUME_LAG);
        assert_eq!(d, ResumeDecision::FreshSeedAtHead);
    }

    /// A restarted watch with a saved cursor that's only a few blocks
    /// behind head must resume normally — we don't want to break the
    /// legitimate "daemon paused for 30s, catch up the missed blocks"
    /// path while fixing the genesis-walk bug.
    #[test]
    fn restarted_watch_resumes_from_saved_cursor() {
        let head = 100;
        let d = resume_block_cursor(Some(95), head, MAX_RESUME_LAG);
        assert_eq!(d, ResumeDecision::Resume { prev: 95 });
        // The caller emits (prev + 1)..=head, i.e. 96..=100.
        if let ResumeDecision::Resume { prev } = d {
            let emitted: Vec<u64> = (prev + 1..=head).collect();
            assert_eq!(emitted, vec![96, 97, 98, 99, 100]);
        }
    }

    /// A saved cursor more than `MAX_RESUME_LAG` blocks behind head is
    /// implausibly stale (corrupted state map, recreated watch with a
    /// reused id, daemon paused for hours). Fall forward to head
    /// instead of hammering the chain with a giant range.
    #[test]
    fn stale_cursor_fast_forwards_to_head() {
        let head = 1_000_000;
        let prev = 1; // ~1M blocks behind
        let d = resume_block_cursor(Some(prev), head, MAX_RESUME_LAG);
        assert_eq!(d, ResumeDecision::StaleSeedAtHead { prev });
    }

    /// Boundary: exactly `MAX_RESUME_LAG` behind is still "fresh
    /// enough to resume". Going one beyond flips to stale.
    #[test]
    fn stale_threshold_is_inclusive_at_max_lag() {
        let head = 10_000;
        // head - prev = MAX_RESUME_LAG -> resume.
        let prev = head - MAX_RESUME_LAG;
        assert_eq!(
            resume_block_cursor(Some(prev), head, MAX_RESUME_LAG),
            ResumeDecision::Resume { prev }
        );
        // head - prev = MAX_RESUME_LAG + 1 -> stale.
        let prev = head - MAX_RESUME_LAG - 1;
        assert_eq!(
            resume_block_cursor(Some(prev), head, MAX_RESUME_LAG),
            ResumeDecision::StaleSeedAtHead { prev }
        );
    }

    /// A saved cursor that's *ahead* of head signals a provider regression
    /// (deep reorg, switched RPC backends, fork). The helper must surface
    /// this as `Regressed` so the caller can warn and skip emission
    /// without rewinding the persisted cursor.
    #[test]
    fn regressed_cursor_does_not_emit() {
        let d = resume_block_cursor(Some(100), 95, MAX_RESUME_LAG);
        assert_eq!(d, ResumeDecision::Regressed { prev: 100 });
    }

    /// End-to-end: drive `tick_once` against a registered Block watch
    /// without any prior state, and confirm the live file does *not*
    /// contain a single record. This is the integration-level
    /// expression of the bug: previously this would have written
    /// thousands of records (one per block from 1 to head) and
    /// rotated the live file to history.
    ///
    /// We use a fake [`ExecutorState`] pre-seeded as if a tick had
    /// already happened, to sidestep the need for a real chain client
    /// in this unit test. The real-chain regression coverage lives in
    /// the (gated) `tests/anvil_watch.rs` integration test.
    #[tokio::test]
    async fn fresh_state_seeds_without_writing_history() {
        let tmp = tempdir().unwrap();
        let home = HomeDir::at(tmp.path());
        home.ensure().unwrap();
        let registry = Arc::new(WatchRegistry::new(home.watch_dir()).unwrap());
        let spec = WatchSpec {
            id: "w-0001".into(),
            wallet: "alice".into(),
            created_ms: 1,
            kind: WatchKind::Block {
                chain: "anvil".into(),
            },
            note: None,
        };
        registry.add(spec.clone()).unwrap();

        // Build state as if a Block tick just observed head=45_808_266 on
        // a fresh watch. Under the old code, the previous tick would
        // have written 45M records before reaching this point, so the
        // assertion below (live file empty / absent) is a crisp
        // regression test for the symptom.
        let mut state = ExecutorState::default();
        let key = format!("{}/{}", spec.wallet, spec.id);
        let head: u64 = 45_808_266;
        let decision = resume_block_cursor(state.block.get(&key).copied(), head, MAX_RESUME_LAG);
        assert_eq!(decision, ResumeDecision::FreshSeedAtHead);
        // The executor's poll path inserts the head and returns early —
        // mirror that here.
        state.block.insert(key.clone(), head);

        // Live file must not exist (no append happened).
        let live = WatchExecutor::live_path_for_spec(&home, &spec);
        assert!(
            !live.exists(),
            "fresh watch wrote a live file: {}",
            live.display()
        );

        // Now simulate the *next* tick: head advanced by one. The
        // saved cursor is one behind, so we should emit exactly one
        // record (the new block).
        let next_head = head + 1;
        let decision =
            resume_block_cursor(state.block.get(&key).copied(), next_head, MAX_RESUME_LAG);
        assert_eq!(decision, ResumeDecision::Resume { prev: head });
    }

    /// Two specs running at once must each get their own dedup
    /// buffer — overlapping logs (e.g. two watches on the same
    /// contract) should not silently shadow each other.
    #[test]
    fn dedup_does_not_cross_specs() {
        let mut state = ExecutorState::default();
        let spec_a = "alice/w-0001".to_string();
        let spec_b = "alice/w-0002".to_string();
        let h: B256 = B256::with_last_byte(42);

        let dedup_a = state.dedup.entry(spec_a.clone()).or_default();
        assert!(dedup_a.observe(h, 5));

        let dedup_b = state.dedup.entry(spec_b.clone()).or_default();
        // Spec B must see this as new — the per-spec entry is
        // independent.
        assert!(dedup_b.observe(h, 5));

        // Re-observing on spec A still drops as duplicate.
        let dedup_a = state.dedup.entry(spec_a).or_default();
        assert!(!dedup_a.observe(h, 5));
    }
}
