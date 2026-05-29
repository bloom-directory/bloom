//! Main node run loop (spec §3, §12).
//!
//! Constructs all subsystems from `NodeConfig` and `Genesis`, then runs
//! everything concurrently until graceful shutdown.
//!
//! # Startup sequence
//!
//! 1. Open all storage handles (block store, blob store, state index, mempool persist).
//! 2. Load latest committed block + state from storage (or genesis if empty).
//! 3. Spawn the TCP listener and outbound connectors via `PeerPool`.
//! 4. Spawn the consensus driver task.
//! 5. Spawn the RPC server task.
//! 6. Spawn the 1s block-tick scheduler.
//! 7. Graceful shutdown on Ctrl-C / SIGTERM.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use bloom_chain_consensus::{
    Action, ConsensusEngine, Mempool,
    round_validation::judge_proposer_round,
    state_machine::{Event, TimeoutKind},
};
use bloom_chain_state::State;
use bloom_chain_types::{
    block::{Block, BlockHeader},
    receipt::receipts_root,
    tx::Tx,
    types::{Address, Hash32},
    vote::Commit,
};
use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::{self};
use tracing::{debug, error, info, warn};

use crate::{
    block_store::BlockStore,
    consensus_driver::{
        BLOCK_EMISSION, ConsensusDriver, PetalExecutor, StateAdmissionView, XdsaVerifier,
        compute_txs_root, try_apply_block_state_transitions, validate_block_for_apply,
    },
    genesis::Genesis,
    mempool_persist::MempoolPersist,
    petal_executor::ChainPetalExecutor,
    rpc::RpcServer,
    state_blob::StateBlobStore,
    state_index::StateIndex,
    transport::{Frame, PeerPool, accept_loop},
};

/// Restore node state from durable storage.
///
/// The restore path starts from the latest complete state checkpoint whose
/// indexed blob exists and whose content-addressed hash/root verify, then
/// replays every block after that checkpoint up to the latest stored block.
/// Missing suffix blocks are fatal because skipping them would produce a
/// locally plausible but consensus-divergent state.
pub fn restore_state_from_storage<E: PetalExecutor>(
    genesis: &Genesis,
    block_store: &BlockStore,
    blob_store: &StateBlobStore,
    state_index: &StateIndex,
    executor: &E,
    block_emission: u128,
) -> Result<(State, u64)> {
    let latest_block_height = block_store
        .latest_height()
        .context("query latest block height")?;
    let latest_index_height = state_index
        .latest_height()
        .context("query latest state checkpoint height")?;

    let mut checkpoint: Option<(u64, State)> = None;
    if let Some(index_top) = latest_index_height {
        for h in (0..=index_top).rev() {
            let Some((state_root, blob_hash)) = state_index
                .get(h)
                .with_context(|| format!("read state checkpoint index at height {h}"))?
            else {
                continue;
            };
            let Some(blob) = blob_store
                .get(&blob_hash)
                .with_context(|| format!("read state checkpoint blob at height {h}"))?
            else {
                continue;
            };
            let actual_blob_hash = State::blob_hash(&blob);
            if actual_blob_hash != blob_hash {
                return Err(anyhow::anyhow!(
                    "state checkpoint blob hash mismatch at height {h}: indexed={} actual={}",
                    hex::encode(blob_hash.0),
                    hex::encode(actual_blob_hash.0)
                ));
            }
            let (blob_height, blob_state_root, _) = State::blob_header(&blob)
                .with_context(|| format!("read state checkpoint blob header at height {h}"))?;
            if blob_height != h || blob_state_root != state_root {
                warn!(
                    height = h,
                    blob_height,
                    indexed_root = %hex::encode(state_root.0),
                    blob_root = %hex::encode(blob_state_root.0),
                    "node.startup: skipping incomplete state checkpoint with mismatched blob header"
                );
                continue;
            }
            if h > 0 {
                let Some(block) = block_store
                    .get(h)
                    .with_context(|| format!("read checkpoint block {h}"))?
                else {
                    warn!(
                        height = h,
                        "node.startup: skipping state checkpoint because block is missing"
                    );
                    continue;
                };
                if block.header.state_root != state_root {
                    warn!(
                        height = h,
                        indexed_root = %hex::encode(state_root.0),
                        block_root = %hex::encode(block.header.state_root.0),
                        "node.startup: skipping state checkpoint because block root mismatches"
                    );
                    continue;
                }
            }
            let state = State::from_blob(&blob, state_root)
                .with_context(|| format!("restore state checkpoint at height {h}"))?;
            checkpoint = Some((h, state));
            break;
        }
    }

    let (checkpoint_height, mut state) = match checkpoint {
        Some((height, state)) => {
            info!(height, "node.startup: restored state checkpoint");
            (height, state)
        }
        None => {
            info!("node.startup: no complete state checkpoint, applying genesis");
            let mut state = State::new();
            genesis.apply_to_state(&mut state);
            (0, state)
        }
    };

    let top = latest_block_height.unwrap_or(checkpoint_height);
    if top < checkpoint_height {
        return Err(anyhow::anyhow!(
            "latest block height {top} is behind state checkpoint height {checkpoint_height}"
        ));
    }

    for h in checkpoint_height + 1..=top {
        let block = block_store
            .get(h)
            .with_context(|| format!("read replay block {h}"))?
            .ok_or_else(|| anyhow::anyhow!("required replay block missing at height {h}"))?;
        let (fuel_used, _receipts) = crate::consensus_driver::apply_block_state_transitions(
            &mut state,
            executor,
            &block,
            block_emission,
        );
        if let Some((indexed_root, _)) = state_index
            .get(h)
            .with_context(|| format!("read replay state index at height {h}"))?
        {
            let actual_root = state.state_root();
            if actual_root != indexed_root {
                return Err(anyhow::anyhow!(
                    "replayed state root mismatch at height {h}: indexed={} actual={}",
                    hex::encode(indexed_root.0),
                    hex::encode(actual_root.0)
                ));
            }
        }
        debug!(
            height = h,
            txs = block.txs.len(),
            fuel_used,
            "node.startup.replayed_block"
        );
    }

    Ok((state, top))
}

// ---------------------------------------------------------------------------
// NodeConfig re-export (the full config a caller passes to Node::new)
// ---------------------------------------------------------------------------

/// Full node configuration (validator identity + peer list + paths).
pub struct NodeRunConfig {
    pub chain_id: String,
    pub validator_address: Address,
    /// The validator's xDSA secret key, used to sign outbound Vote / Proposal
    /// messages. Must correspond to the pubkey listed for `validator_address`
    /// in the genesis validator set, or peers will reject our messages as
    /// forgeries.
    pub validator_secret_key: Arc<bloom_keystore::xdsa::XdsaSecretKey>,
    pub genesis: Genesis,
    pub listen_addr: String,
    /// Optional JSON-RPC TCP listener (`host:port`). When `Some`, the node
    /// binds a TCP listener in addition to the UDS socket. Used by the
    /// docker-compose harness where UDS sockets are awkward across hosts.
    pub rpc_tcp_addr: Option<String>,
    pub unsafe_rpc_public_bind: bool,
    pub bloom_home: PathBuf,
    pub fuel_limit: u64,
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

/// The bloom-chain node.
///
/// Call [`Node::run`] to start all background tasks and block until shutdown.
pub struct Node {
    config: NodeRunConfig,
}

impl Node {
    /// Create a new node from the given run config.
    pub fn new(config: NodeRunConfig) -> Self {
        Node { config }
    }

    /// Run the node.  Blocks until graceful shutdown (Ctrl-C or SIGTERM).
    pub async fn run(self) -> Result<()> {
        let cfg = &self.config;
        validate_rpc_tcp_bind_policy(cfg.rpc_tcp_addr.as_deref(), cfg.unsafe_rpc_public_bind)?;
        let chain_dir = cfg.bloom_home.join("chain");
        std::fs::create_dir_all(&chain_dir)?;

        // ── 1. Open storage ──────────────────────────────────────────────────
        let block_store =
            Arc::new(BlockStore::open(&chain_dir.join("blocks")).context("open block_store")?);
        let blob_store = Arc::new(
            StateBlobStore::open(&chain_dir.join("state_blobs")).context("open state_blobs")?,
        );
        let state_index = Arc::new(
            StateIndex::open(&chain_dir.join("state_index.sqlite"))
                .context("open state_index.sqlite")?,
        );
        let mempool_persist = Arc::new(
            MempoolPersist::open(&chain_dir.join("mempool.sled")).context("open mempool.sled")?,
        );
        let receipt_store = Arc::new(
            crate::receipt_store::ReceiptStore::open(&chain_dir.join("receipts"))
                .context("open receipt_store")?,
        );

        // ── 2. Load or build genesis state ───────────────────────────────────
        let replay_executor = crate::petal_executor::ChainPetalExecutor;
        let (state, latest_height) = restore_state_from_storage(
            &cfg.genesis,
            &block_store,
            &blob_store,
            &state_index,
            &replay_executor,
            BLOCK_EMISSION,
        )?;

        let starting_height = latest_height + 1;
        info!(starting_height, "node.consensus.starting");

        // ── 3. Build consensus engine ─────────────────────────────────────────
        let validator_set = cfg.genesis.validator_set.clone();
        let local_address = cfg.validator_address;
        let chain_id = cfg.chain_id.clone();

        // Wrap state in Arc<Mutex<...>> so the block_builder closure and the
        // consensus driver share it.
        let shared_state: Arc<Mutex<State>> = Arc::new(Mutex::new(state));

        // Build the block builder closure.  Captures clones of chain_id /
        // validator_set / local_address and Arcs of state + block_store.
        let bb_chain_id = chain_id.clone();
        let bb_validator_set = validator_set.clone();
        let bb_local_address = local_address;
        let bb_state = Arc::clone(&shared_state);
        let bb_block_store = Arc::clone(&block_store);
        let fuel_limit_cfg = cfg.fuel_limit;
        let block_builder: bloom_chain_consensus::engine::BlockBuilder<XdsaVerifier> = Box::new(
            move |height: u64, mempool: &mut Mempool<XdsaVerifier>, fuel_limit: u64| {
                // parent_hash: previous block's header.block_hash(), or zero at height 1.
                let parent_hash = if height <= 1 {
                    Hash32([0u8; 32])
                } else {
                    bb_block_store
                        .get(height - 1)
                        .ok()
                        .flatten()
                        .map(|b| b.header.block_hash())
                        .unwrap_or(Hash32([0u8; 32]))
                };

                let timestamp_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);

                // Per-sender applied nonces feed `select_for_block_for` so
                // we only emit a contiguous run from `applied + 1` per sender.
                // Mempool admits future-nonce txs from gossip; without this
                // gating the proposer could ship a block whose txs all
                // nonce-mismatch on apply, silently no-opping the block.
                let txs = {
                    let st = bb_state.lock();
                    mempool.select_for_block_for(fuel_limit, |addr| {
                        st.get_account(addr).map(|a| a.nonce).unwrap_or(0)
                    })
                };
                let template = ProposalBlockTemplate {
                    chain_id: bb_chain_id.clone(),
                    height,
                    parent_hash,
                    timestamp_ms,
                    proposer: bb_local_address,
                    validator_set_hash: bb_validator_set.validator_set_hash(),
                    fuel_limit,
                };
                let state = bb_state.lock();
                build_proposal_block_from_candidates(
                    &template,
                    &state,
                    &ChainPetalExecutor,
                    BLOCK_EMISSION,
                    txs,
                )
            },
        );

        // Build the xDSA signer from the validator secret key. Without this,
        // every outbound Vote/Proposal would carry an empty `sig` and peers
        // running the post-2026-05-19 ingress check would drop them all.
        let signer: Arc<dyn bloom_chain_consensus::signer::Signer> = Arc::new(
            crate::consensus_driver::XdsaSigner::new(Arc::clone(&cfg.validator_secret_key)),
        );
        let mut engine: ConsensusEngine<XdsaVerifier> = ConsensusEngine::new(
            starting_height,
            local_address,
            validator_set.clone(),
            XdsaVerifier,
            Some(block_builder),
            fuel_limit_cfg,
            Some(signer),
        );
        reload_persisted_mempool(&mut engine, &shared_state, &mempool_persist, &chain_id)
            .context("reload persisted mempool")?;

        // ── 4. Channels ───────────────────────────────────────────────────────
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<(String, Frame)>(1024);
        // RPC handlers send (tx, reply) and synchronously await the reply so
        // mempool rejections surface to the caller as a JSON-RPC error instead
        // of being silently warn-logged on the validator. Without this the
        // sender has no way to tell whether the tx was actually admitted.
        let (tx_submit_tx, mut tx_submit_rx) = mpsc::channel::<(
            bloom_chain_types::tx::Tx,
            tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
        )>(256);

        // ── 5. TCP transport ──────────────────────────────────────────────────
        let listener = TcpListener::bind(&cfg.listen_addr)
            .await
            .with_context(|| format!("bind {}", cfg.listen_addr))?;
        info!(addr = %cfg.listen_addr, "node.transport.listening");

        let peer_pool = PeerPool::new(cfg.genesis.peer_addrs.clone(), inbound_tx.clone());
        let peer_pool_accept = Arc::clone(&peer_pool);
        tokio::spawn(async move {
            accept_loop(listener, peer_pool_accept).await;
        });

        // ── 6. Build driver ──────────────────────────────────────────────────
        let driver = Arc::new(ConsensusDriver {
            engine: Mutex::new(engine),
            peer_pool: Arc::clone(&peer_pool),
            state: Arc::clone(&shared_state),
            block_store: Arc::clone(&block_store),
            blob_store: Arc::clone(&blob_store),
            state_index: Arc::clone(&state_index),
            mempool_persist: Arc::clone(&mempool_persist),
            receipt_store: Arc::clone(&receipt_store),
            executor: Arc::new(ChainPetalExecutor),
            chain_id: chain_id.clone(),
            local_address,
            block_emission: BLOCK_EMISSION,
        });

        // Timeout delivery channel: `Action::StartTimeout` spawns a task that
        // sleeps then sends `(kind, height, round)` to this channel; a separate
        // task drives the engine via `step(Event::Tick(kind))`.
        //
        // The `(height, round)` pair is the engine state captured at the
        // moment the timer was *scheduled*. The consumer compares it against
        // the engine's *current* `(height, round)` and silently drops the
        // tick if they no longer match. Without this guard, stale timers
        // from earlier rounds/heights bleed across transitions: when a
        // Precommit scheduled at h=N r=R fires 500ms later, the engine may
        // already be at h=N r=R+1 in step Precommit again — `on_tick` would
        // see `step == Precommit` and call `advance_round`, skipping rounds
        // arbitrarily. Caught by the 4-validator docker DEX acceptance test
        // at h=29 (val2 reached r=8+ in milliseconds while other validators
        // were still at r=0–1).
        let (timeout_tx, mut timeout_rx) = mpsc::channel::<(TimeoutKind, u64, u32)>(64);
        let timeout_tx = Arc::new(timeout_tx);

        // ── 7. RPC server ─────────────────────────────────────────────────────
        let rpc_server = RpcServer {
            state: Arc::clone(&shared_state),
            block_store: Arc::clone(&block_store),
            mempool_persist: Arc::clone(&mempool_persist),
            receipt_store: Arc::clone(&receipt_store),
            validator_set: Arc::new(validator_set.clone()),
            chain_id: chain_id.clone(),
            genesis_hash: cfg.genesis.genesis_hash,
            local_address,
            startup_height: latest_height,
            tx_submit: tx_submit_tx.clone(),
        };
        let rpc_socket = chain_dir.join("rpc.sock");
        if rpc_uds_enabled() {
            let rpc_uds = rpc_server.clone();
            tokio::spawn(async move {
                if let Err(e) = rpc_uds.serve(&rpc_socket).await {
                    error!(err = %e, "rpc.serve failed");
                }
            });
        } else {
            info!("rpc.uds.disabled");
        }
        if let Some(tcp_addr) = cfg.rpc_tcp_addr.clone() {
            info!(addr = %tcp_addr, "rpc.tcp.enabled");
            let rpc_tcp = rpc_server.clone();
            tokio::spawn(async move {
                if let Err(e) = rpc_tcp.serve_tcp(&tcp_addr).await {
                    error!(err = %e, "rpc.serve_tcp failed");
                }
            });
        }

        // ── 8. Tx admission from RPC → mempool ───────────────────────────────
        let driver_tx = Arc::clone(&driver);
        tokio::spawn(async move {
            while let Some((tx, reply)) = tx_submit_rx.recv().await {
                let admitted = {
                    let mut eng = driver_tx.engine.lock();
                    let state = driver_tx.state.lock();
                    let view = StateAdmissionView {
                        state: &state,
                        current_block: eng.height(),
                    };
                    submit_tx_for_chain(&mut eng, tx.clone(), &view, &driver_tx.chain_id)
                };
                match admitted {
                    Err(e) => {
                        // Surface the rejection reason to the RPC caller.
                        let msg = e.to_string();
                        warn!(err = %msg, "mempool.admit failed");
                        let _ = reply.send(Err(msg));
                    }
                    Ok(()) => {
                        let _ = driver_tx.mempool_persist.put(&tx);
                        // Acknowledge admission before broadcasting so the caller
                        // isn't blocked on peer fan-out.
                        let _ = reply.send(Ok(()));
                        // Gossip to peers (after releasing all locks).
                        let _ = driver_tx.peer_pool.broadcast(&Frame::Tx(tx)).await;
                    }
                }
            }
        });

        // ── 9. Consensus event loop ───────────────────────────────────────────
        let driver_ev = Arc::clone(&driver);
        let peer_pool_ev = Arc::clone(&peer_pool);
        let timeout_tx_ev = Arc::clone(&timeout_tx);
        tokio::spawn(async move {
            while let Some((peer_addr, frame)) = inbound_rx.recv().await {
                match frame {
                    Frame::Proposal(p) => {
                        debug!(peer = %peer_addr, height = p.height, round = p.round, "frame.proposal recv");
                        // Authentication boundary (review 2026-05-19 #1):
                        // every Proposal must be xDSA-verified against the
                        // proposer's pubkey in the validator set BEFORE it
                        // enters the state machine. Unverified messages would
                        // let a peer forge proposals from any validator.
                        //
                        // Snapshot the validator set out of the engine guard
                        // before verifying — xDSA verify is the slow path and
                        // must not block engine progress on every inbound msg.
                        let my_height = { driver_ev.engine.lock().height() };
                        if p.height > my_height {
                            // We're behind. Ask this peer for the gap.
                            request_missing_blocks(&peer_pool_ev, &peer_addr, my_height, p.height)
                                .await;
                            continue;
                        }
                        if p.height < my_height {
                            debug!(
                                peer = %peer_addr,
                                height = p.height,
                                my_height,
                                "frame.proposal ignored: stale height"
                            );
                            continue;
                        }
                        let validator_set = { driver_ev.engine.lock().validator_set.clone() };
                        if !bloom_chain_consensus::auth::verify_proposal_sig(
                            &p,
                            &validator_set,
                            &crate::consensus_driver::XdsaVerifier,
                        ) {
                            warn!(
                                peer = %peer_addr,
                                height = p.height,
                                round = p.round,
                                proposer = ?p.proposer,
                                "frame.proposal rejected: invalid signature"
                            );
                            continue;
                        }
                        // Same-height proposal whose block we don't have? The
                        // proposer broadcasts the full Block right before the
                        // Proposal frame, but TCP/ordering hiccups can drop
                        // that first frame. Pull it explicitly so we can vote.
                        if p.height == my_height {
                            let block_opt =
                                { driver_ev.engine.lock().get_registered_block(&p.block_hash) };
                            if let Some(block) = block_opt {
                                let Some(header_round) =
                                    proposal_header_round(p.round, p.pol_round)
                                else {
                                    warn!(
                                        peer = %peer_addr,
                                        height = p.height,
                                        round = p.round,
                                        pol_round = p.pol_round,
                                        "frame.proposal rejected: invalid pol_round"
                                    );
                                    continue;
                                };
                                if let Err(e) = driver_ev.validate_proposal_block(
                                    &block,
                                    p.height,
                                    p.round,
                                    header_round,
                                ) {
                                    warn!(
                                        peer = %peer_addr,
                                        height = p.height,
                                        round = p.round,
                                        err = %e,
                                        "frame.proposal rejected: invalid block body"
                                    );
                                    continue;
                                }
                            } else {
                                let _ = peer_pool_ev
                                    .send_to(&peer_addr, &Frame::BlockRequest { height: p.height })
                                    .await;
                            }
                        }
                        let actions = { driver_ev.engine.lock().step(Event::ReceiveProposal(p)) };
                        process_actions(
                            Arc::clone(&driver_ev),
                            Arc::clone(&peer_pool_ev),
                            Arc::clone(&timeout_tx_ev),
                            actions,
                        )
                        .await;
                    }
                    Frame::Vote(v) => {
                        debug!(peer = %peer_addr, height = v.height, round = v.round, kind = ?v.kind, "frame.vote recv");
                        // Authentication boundary (review 2026-05-19 #1):
                        // every Vote (prevote and precommit) must be
                        // xDSA-verified against the voter's pubkey in the
                        // validator set BEFORE it enters the state machine.
                        // Forged votes otherwise count toward quorum totals.
                        //
                        // Snapshot the validator set out of the engine guard
                        // before verifying — xDSA verify is the slow path and
                        // must not block engine progress on every inbound msg.
                        let my_height = { driver_ev.engine.lock().height() };
                        if v.height > my_height {
                            // We're behind. Ask this peer for the gap.
                            request_missing_blocks(&peer_pool_ev, &peer_addr, my_height, v.height)
                                .await;
                            continue;
                        }
                        if v.height < my_height {
                            debug!(
                                peer = %peer_addr,
                                height = v.height,
                                my_height,
                                "frame.vote ignored: stale height"
                            );
                            continue;
                        }
                        let validator_set = { driver_ev.engine.lock().validator_set.clone() };
                        if !bloom_chain_consensus::auth::verify_vote_sig(
                            &v,
                            &validator_set,
                            &crate::consensus_driver::XdsaVerifier,
                        ) {
                            warn!(
                                peer = %peer_addr,
                                height = v.height,
                                round = v.round,
                                kind = ?v.kind,
                                validator = ?v.validator,
                                "frame.vote rejected: invalid signature"
                            );
                            continue;
                        }
                        let actions = { driver_ev.engine.lock().step(Event::ReceiveVote(v)) };
                        process_actions(
                            Arc::clone(&driver_ev),
                            Arc::clone(&peer_pool_ev),
                            Arc::clone(&timeout_tx_ev),
                            actions,
                        )
                        .await;
                    }
                    Frame::Tx(tx) => {
                        // All locking happens inside this block; no locks held at await.
                        let admitted = {
                            let mut eng = driver_ev.engine.lock();
                            let state = driver_ev.state.lock();
                            let view = StateAdmissionView {
                                state: &state,
                                current_block: eng.height(),
                            };
                            submit_tx_for_chain(&mut eng, tx.clone(), &view, &driver_ev.chain_id)
                        };
                        if let Err(e) = admitted {
                            warn!(peer = %peer_addr, err = %e, "mempool.admit from peer failed");
                        } else {
                            let _ = driver_ev.mempool_persist.put(&tx);
                        }
                    }
                    Frame::BlockRequest { height } => {
                        if let Ok(Some(block)) = driver_ev.block_store.get(height) {
                            let _ = peer_pool_ev
                                .send_to(&peer_addr, &Frame::BlockResponse(block))
                                .await;
                        } else if let Ok(Some(snapshot)) =
                            build_state_snapshot_response(driver_ev.as_ref(), height)
                        {
                            let _ = peer_pool_ev.send_to(&peer_addr, &snapshot).await;
                        }
                    }
                    Frame::BlockResponse(block) => {
                        // Always register so consensus can resolve the hash if we
                        // get here via the normal happy-path (proposer broadcast
                        // before us seeing precommits).
                        let block_height = block.header.height;
                        let block_hash = block.header.block_hash();
                        let my_height = { driver_ev.engine.lock().height() };
                        if block_height < my_height {
                            debug!(
                                peer = %peer_addr,
                                height = block_height,
                                my_height,
                                "block_response ignored: stale height"
                            );
                            continue;
                        }
                        if block_height > my_height {
                            request_missing_blocks(
                                &peer_pool_ev,
                                &peer_addr,
                                my_height,
                                block_height.saturating_add(1),
                            )
                            .await;
                            continue;
                        }
                        let has_commit = !block.commit.votes.is_empty();
                        if block_height == my_height {
                            let (round, body_kind) = {
                                let eng = driver_ev.engine.lock();
                                (
                                    eng.round(),
                                    current_height_block_response_body_kind(&eng, &block),
                                )
                            };
                            if has_commit {
                                if let Err(e) =
                                    driver_ev.validate_committed_block(&block, block_height)
                                {
                                    warn!(
                                        peer = %peer_addr,
                                        height = block_height,
                                        round,
                                        err = %e,
                                        "block_response rejected: invalid committed block"
                                    );
                                    continue;
                                }
                            } else {
                                let header_round = match body_kind {
                                    Ok(CurrentHeightBlockBodyKind::Proposal { header_round }) => {
                                        header_round
                                    }
                                    Ok(CurrentHeightBlockBodyKind::Committed) => unreachable!(
                                        "has_commit and block-response body kind disagree"
                                    ),
                                    Err(e) => {
                                        warn!(
                                            peer = %peer_addr,
                                            height = block_height,
                                            round,
                                            err = %e,
                                            "block_response rejected: invalid proposal body context"
                                        );
                                        continue;
                                    }
                                };
                                if let Err(e) = driver_ev.validate_proposal_block(
                                    &block,
                                    block_height,
                                    round,
                                    header_round,
                                ) {
                                    warn!(
                                        peer = %peer_addr,
                                        height = block_height,
                                        round,
                                        err = %e,
                                        "block_response rejected: invalid proposal body"
                                    );
                                    continue;
                                }
                            }
                        }
                        {
                            driver_ev.engine.lock().register_block(block.clone());
                        }
                        // If we stashed a proposal earlier because its block
                        // was unknown (review 2026-05-19 #3 gate), now that
                        // the block is registered the state machine can
                        // resume — emit prevote + arm Prevote timeout.
                        let resume_actions =
                            { driver_ev.engine.lock().try_resume_pending_proposal() };
                        if !resume_actions.is_empty() {
                            process_actions(
                                Arc::clone(&driver_ev),
                                Arc::clone(&peer_pool_ev),
                                Arc::clone(&timeout_tx_ev),
                                resume_actions,
                            )
                            .await;
                        }
                        // If 2f+1 precommits for this block already arrived
                        // before its body did (reordered or proposer's
                        // BlockResponse delayed), the precommit tally has
                        // quorum but `on_vote`'s commit gate was skipped
                        // because `blocks.get(&hash)` returned None. Re-check
                        // now that the body is registered — without this,
                        // a single TCP reorder strands the validator until a
                        // round timeout, and chain-sync only kicks in once
                        // it has fallen multiple blocks behind.
                        let commit_actions =
                            { driver_ev.engine.lock().try_commit_with_block(block_hash) };
                        if !commit_actions.is_empty() {
                            process_actions(
                                Arc::clone(&driver_ev),
                                Arc::clone(&peer_pool_ev),
                                Arc::clone(&timeout_tx_ev),
                                commit_actions,
                            )
                            .await;
                        }
                        // If we received a block ahead of our current height,
                        // re-request the single block we're actually waiting
                        // for. Without this, a BlockResponse for height H+5
                        // while we're at H is silently dropped — and if the
                        // matching response for H was lost (TCP buffer, peer
                        // hiccup), we stall until an unrelated trigger fires
                        // another chain-sync. Single-block re-request is
                        // idempotent and won't amplify traffic the way a fresh
                        // burst would (each future-block drop would otherwise
                        // re-burst the entire gap).
                        {
                            let my_height = { driver_ev.engine.lock().height() };
                            if block_height > my_height {
                                let _ = peer_pool_ev
                                    .send_to(&peer_addr, &Frame::BlockRequest { height: my_height })
                                    .await;
                            }
                        }
                        // Catch-up apply: while the received block is exactly our
                        // current consensus height, apply it and advance. Without
                        // this, a validator that misses a proposal frame (network
                        // glitch, restart, slow start) can never re-join the
                        // network — there's no other mechanism that drives a
                        // behind validator forward.
                        //
                        // Only attempt catch-up if the block carries a real
                        // commit. The proposer's *initial* block dissemination
                        // is broadcast via `Frame::BlockResponse` BEFORE its
                        // commit is built — at that point `block.commit.votes`
                        // is empty, validation correctly rejects it, and the
                        // normal consensus path (Proposal + Votes) is what
                        // drives state forward. Skipping silently keeps the
                        // log clean and avoids noisy "sync.apply_block failed"
                        // entries on the happy path.
                        #[allow(clippy::never_loop)]
                        loop {
                            if !has_commit {
                                break;
                            }
                            let my_height = { driver_ev.engine.lock().height() };
                            if block_height != my_height {
                                break;
                            }
                            if let Err(e) = driver_ev.apply_block(&block) {
                                warn!(err = %e, height = block_height, "sync.apply_block failed");
                                break;
                            }
                            info!(height = block_height, peer = %peer_addr, "sync.block_applied");
                            {
                                driver_ev.engine.lock().mempool.remove_included(&block.txs);
                            }
                            prune_committed_mempool_persist(&driver_ev.mempool_persist, &block.txs);
                            let next_actions =
                                { driver_ev.engine.lock().enter_next_height(block_height + 1) };
                            process_actions(
                                Arc::clone(&driver_ev),
                                Arc::clone(&peer_pool_ev),
                                Arc::clone(&timeout_tx_ev),
                                next_actions,
                            )
                            .await;
                            // Pull the next block in the chain from this peer so
                            // we keep advancing without waiting for the next vote
                            // to trigger another request_missing_blocks.
                            let _ = peer_pool_ev
                                .send_to(
                                    &peer_addr,
                                    &Frame::BlockRequest {
                                        height: block_height + 1,
                                    },
                                )
                                .await;
                            break;
                        }
                    }
                    Frame::Ping => {
                        let _ = peer_pool_ev.send_to(&peer_addr, &Frame::Pong).await;
                    }
                    Frame::StateBlobRequest { hash } => {
                        if let Ok(Some(data)) = driver_ev.blob_store.get(&hash) {
                            let _ = peer_pool_ev
                                .send_to(&peer_addr, &Frame::StateBlobResponse(data))
                                .await;
                        }
                    }
                    Frame::StateBlobResponse(_) => {}
                    Frame::StateSnapshotRequest { min_height } => {
                        if let Ok(Some(snapshot)) =
                            build_state_snapshot_response(driver_ev.as_ref(), min_height)
                        {
                            let _ = peer_pool_ev.send_to(&peer_addr, &snapshot).await;
                        }
                    }
                    Frame::StateSnapshotResponse {
                        block,
                        state_root,
                        blob_hash,
                        blob,
                    } => {
                        match apply_state_snapshot(
                            SnapshotApplyContext {
                                driver: Arc::clone(&driver_ev),
                                peer_pool: Arc::clone(&peer_pool_ev),
                                timeout_tx: Arc::clone(&timeout_tx_ev),
                                peer: &peer_addr,
                            },
                            StateSnapshot {
                                block,
                                state_root,
                                blob_hash,
                                blob,
                            },
                        )
                        .await
                        {
                            Ok(true) => {
                                info!(peer = %peer_addr, "sync.snapshot_applied");
                            }
                            Ok(false) => {}
                            Err(e) => {
                                warn!(peer = %peer_addr, err = %e, "sync.snapshot_rejected");
                            }
                        }
                    }
                    _ => {}
                }
            }
        });

        // ── 10. Block-tick scheduler (1s) ─────────────────────────────────────
        let driver_tick = Arc::clone(&driver);
        let peer_pool_tick = Arc::clone(&peer_pool);
        let timeout_tx_tick = Arc::clone(&timeout_tx);
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                // Trigger the proposer to build a block if it's our turn.
                // Drop the lock before any await.
                let maybe_action = { driver_tick.engine.lock().maybe_propose() };
                if let Some(action) = maybe_action {
                    process_actions(
                        Arc::clone(&driver_tick),
                        Arc::clone(&peer_pool_tick),
                        Arc::clone(&timeout_tx_tick),
                        vec![action],
                    )
                    .await;
                }
            }
        });

        // ── 10b. Timeout delivery loop ────────────────────────────────────────
        let driver_to = Arc::clone(&driver);
        let peer_pool_to = Arc::clone(&peer_pool);
        let timeout_tx_to = Arc::clone(&timeout_tx);
        tokio::spawn(async move {
            while let Some((kind, ts_height, ts_round)) = timeout_rx.recv().await {
                // Drop ticks whose (height, round) no longer match the engine.
                // This handles the case where a timer was scheduled for an
                // earlier round and the engine has since advanced — without
                // this guard, an `on_tick(Precommit)` whose `step==Precommit`
                // would call `advance_round` and skip the current round even
                // though the proposer has not actually timed out.
                let actions = {
                    let mut eng = driver_to.engine.lock();
                    if eng.height() != ts_height || eng.round() != ts_round {
                        debug!(
                            ?kind,
                            ts_height,
                            ts_round,
                            cur_height = eng.height(),
                            cur_round = eng.round(),
                            "consensus.timeout stale, dropping"
                        );
                        continue;
                    }
                    eng.step(Event::Tick(kind))
                };
                process_actions(
                    Arc::clone(&driver_to),
                    Arc::clone(&peer_pool_to),
                    Arc::clone(&timeout_tx_to),
                    actions,
                )
                .await;
                // After a tick (especially Precommit which advances the round),
                // the local validator may now be the proposer for a fresh round.
                // Try to propose immediately so the network doesn't stall while
                // it waits for the 1s tick scheduler.
                let maybe_action = { driver_to.engine.lock().maybe_propose() };
                if let Some(action) = maybe_action {
                    process_actions(
                        Arc::clone(&driver_to),
                        Arc::clone(&peer_pool_to),
                        Arc::clone(&timeout_tx_to),
                        vec![action],
                    )
                    .await;
                }
            }
        });

        // ── 10c. Kick off the first round ─────────────────────────────────────
        // Spawn a delayed kickoff: give the peer pool ~1s to establish all
        // outbound TCP connections, then schedule the Propose timeout and
        // attempt an immediate proposal if we're the first proposer.
        {
            let driver_kick = Arc::clone(&driver);
            let peer_pool_kick = Arc::clone(&peer_pool);
            let timeout_tx_kick = Arc::clone(&timeout_tx);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1000)).await;
                let kickoff = vec![Action::StartTimeout(
                    TimeoutKind::Propose,
                    Duration::from_millis(500),
                )];
                process_actions(
                    Arc::clone(&driver_kick),
                    Arc::clone(&peer_pool_kick),
                    Arc::clone(&timeout_tx_kick),
                    kickoff,
                )
                .await;
                let maybe_action = { driver_kick.engine.lock().maybe_propose() };
                if let Some(action) = maybe_action {
                    process_actions(driver_kick, peer_pool_kick, timeout_tx_kick, vec![action])
                        .await;
                }
            });
        }

        // ── 11. Graceful shutdown ─────────────────────────────────────────────
        info!("node.running: waiting for shutdown signal");
        wait_for_shutdown().await;
        info!("node.shutting_down");
        let _ = mempool_persist.flush();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Action processor
// ---------------------------------------------------------------------------

/// Recursive future helper.
type BoxFut<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Minimum interval between successive block commits (timeout_commit).
/// Enforces 1s block cadence even when consensus rounds complete faster.
const TIMEOUT_COMMIT: Duration = Duration::from_secs(1);

fn process_actions<E: crate::consensus_driver::PetalExecutor>(
    driver: Arc<ConsensusDriver<E>>,
    peer_pool: Arc<PeerPool>,
    timeout_tx: Arc<mpsc::Sender<(TimeoutKind, u64, u32)>>,
    actions: Vec<Action>,
) -> BoxFut<'static, ()> {
    Box::pin(async move {
        for action in actions {
            match action {
                Action::Broadcast(pov) => {
                    match pov {
                        bloom_chain_consensus::state_machine::ProposalOrVote::Proposal(p) => {
                            debug!(height = p.height, round = p.round, "proposing");
                            // First, broadcast the FULL BLOCK so peers can
                            // register it before they receive the Proposal
                            // (otherwise their commit step can't resolve the
                            // block hash).
                            let block_opt =
                                { driver.engine.lock().get_registered_block(&p.block_hash) };
                            if let Some(block) = block_opt
                                && let Err(e) =
                                    peer_pool.broadcast(&Frame::BlockResponse(block)).await
                            {
                                warn!(err = %e, "block broadcast failed");
                            }

                            // Now broadcast the proposal itself + deliver to self.
                            let self_actions =
                                { driver.engine.lock().step(Event::ReceiveProposal(p.clone())) };
                            let f = Frame::Proposal(p);
                            if let Err(e) = peer_pool.broadcast(&f).await {
                                warn!(err = %e, "broadcast failed");
                            }
                            process_actions(
                                Arc::clone(&driver),
                                Arc::clone(&peer_pool),
                                Arc::clone(&timeout_tx),
                                self_actions,
                            )
                            .await;
                        }
                        bloom_chain_consensus::state_machine::ProposalOrVote::Vote(v) => {
                            // Deliver vote to self too.
                            let self_actions =
                                { driver.engine.lock().step(Event::ReceiveVote(v.clone())) };
                            let f = Frame::Vote(v);
                            if let Err(e) = peer_pool.broadcast(&f).await {
                                warn!(err = %e, "broadcast failed");
                            }
                            process_actions(
                                Arc::clone(&driver),
                                Arc::clone(&peer_pool),
                                Arc::clone(&timeout_tx),
                                self_actions,
                            )
                            .await;
                        }
                    }
                }
                Action::Commit(block, commit) => {
                    let height = block.header.height;
                    // Fold the freshly-built Commit (the 2f+1 precommits
                    // that finalised this block) into the block itself
                    // before applying. The state machine builds the
                    // Commit at quorum time, but the proposer-built
                    // block carries an empty commit field — without
                    // this fold, the validation boundary would reject
                    // every block for missing quorum, and peers that
                    // later sync from us would receive uncommitted
                    // blocks (review 2026-05-19 #2).
                    let mut block_with_commit = (*block).clone();
                    block_with_commit.commit = commit;
                    if let Err(e) = driver.apply_block(&block_with_commit) {
                        error!(
                            err = %e,
                            height,
                            "fatal: post-quorum apply_block failed; aborting validator"
                        );
                        std::process::abort();
                    }
                    if let Err(e) = peer_pool
                        .broadcast(&Frame::BlockResponse(block_with_commit.clone()))
                        .await
                    {
                        warn!(err = %e, height, "committed block broadcast failed");
                    }
                    // Drop the just-committed txs from the in-memory mempool
                    // so they aren't re-selected on the next block.
                    {
                        driver
                            .engine
                            .lock()
                            .mempool
                            .remove_included(&block_with_commit.txs);
                    }
                    prune_committed_mempool_persist(
                        &driver.mempool_persist,
                        &block_with_commit.txs,
                    );
                    // Enter the next height IMMEDIATELY. The state machine
                    // returns a `StartTimeout(Propose, 500ms)` we deliberately
                    // discard — we'll arm the propose timer after a full
                    // TIMEOUT_COMMIT (1s) below.
                    //
                    // The previous design slept for TIMEOUT_COMMIT *before*
                    // calling `enter_next_height`, which left the engine at
                    // height H while peers (committed slightly earlier) were
                    // already broadcasting proposals and votes for H+1. The
                    // inbound-frame gate at `frame.vote recv` / `frame.proposal
                    // recv` drops frames whose height > my_height, so an
                    // entire round of votes for H+1 vanished. The validator
                    // then sat in Propose step until its 500ms propose
                    // timeout fired nil-prevote, by which point the rest of
                    // the network had moved on — repeated for every height,
                    // the trailing validator never recovers. Caught by the
                    // 4-validator docker DEX acceptance test (val2 stuck at
                    // height 13).
                    let _drop_propose_timeout =
                        { driver.engine.lock().enter_next_height(height + 1) };
                    // After TIMEOUT_COMMIT: arm the propose timer and let the
                    // local validator (if it's the proposer for h+1 r=0) build
                    // a block. The 1s gap enforces the block cadence; inbound
                    // frames for h+1 arriving during the gap are accepted
                    // because engine.height is already h+1.
                    let driver_c = Arc::clone(&driver);
                    let peer_pool_c = Arc::clone(&peer_pool);
                    let timeout_tx_c = Arc::clone(&timeout_tx);
                    tokio::spawn(async move {
                        tokio::time::sleep(TIMEOUT_COMMIT).await;
                        let kickoff = vec![Action::StartTimeout(
                            TimeoutKind::Propose,
                            Duration::from_millis(500),
                        )];
                        process_actions(
                            Arc::clone(&driver_c),
                            Arc::clone(&peer_pool_c),
                            Arc::clone(&timeout_tx_c),
                            kickoff,
                        )
                        .await;
                        let maybe_action = { driver_c.engine.lock().maybe_propose() };
                        if let Some(action) = maybe_action {
                            process_actions(driver_c, peer_pool_c, timeout_tx_c, vec![action])
                                .await;
                        }
                    });
                }
                Action::StartTimeout(kind, dur) => {
                    // Capture the engine's (height, round) at schedule time so
                    // the consumer can drop the tick if the engine has moved on
                    // by the time the timer fires. See the channel declaration
                    // above for the round-skip failure this guards against.
                    let (h, r) = {
                        let eng = driver.engine.lock();
                        (eng.height(), eng.round())
                    };
                    debug!(?kind, ?dur, h, r, "consensus.timeout scheduled");
                    let tx = Arc::clone(&timeout_tx);
                    tokio::spawn(async move {
                        tokio::time::sleep(dur).await;
                        let _ = tx.send((kind, h, r)).await;
                    });
                }
            }
        }
    })
}

fn reload_persisted_mempool(
    engine: &mut ConsensusEngine<XdsaVerifier>,
    state: &Arc<Mutex<State>>,
    mempool_persist: &MempoolPersist,
    chain_id: &str,
) -> Result<()> {
    let txs = mempool_persist.load_all()?;
    if txs.is_empty() {
        return Ok(());
    }
    let mut admitted = 0usize;
    let mut purged = 0usize;
    for tx in txs {
        let result = {
            let st = state.lock();
            let view = StateAdmissionView {
                state: &st,
                current_block: engine.height(),
            };
            submit_tx_for_chain(engine, tx.clone(), &view, chain_id)
        };
        match result {
            Ok(()) => admitted += 1,
            Err(e) => {
                purged += 1;
                let _ = mempool_persist.remove(&tx.sender, tx.nonce);
                warn!(
                    sender = %hex::encode(tx.sender.0),
                    nonce = tx.nonce,
                    err = %e,
                    "mempool.reload purged stale/invalid tx"
                );
            }
        }
    }
    let _ = mempool_persist.flush();
    info!(admitted, purged, "mempool.reload complete");
    Ok(())
}

fn submit_tx_for_chain(
    engine: &mut ConsensusEngine<XdsaVerifier>,
    tx: bloom_chain_types::tx::Tx,
    view: &dyn bloom_chain_consensus::tx_admission::BalanceView,
    chain_id: &str,
) -> Result<(), bloom_chain_consensus::error::ConsensusError> {
    if tx.chain_id != chain_id {
        return Err(bloom_chain_consensus::error::ConsensusError::WrongChainId {
            expected: chain_id.to_string(),
            got: tx.chain_id,
        });
    }
    engine.submit_tx_with_view(tx, view)
}

fn prune_committed_mempool_persist(
    mempool_persist: &MempoolPersist,
    txs: &[bloom_chain_types::tx::Tx],
) {
    for tx in txs {
        if let Err(e) = mempool_persist.remove(&tx.sender, tx.nonce) {
            warn!(
                sender = %hex::encode(tx.sender.0),
                nonce = tx.nonce,
                err = %e,
                "mempool_persist.remove committed tx failed"
            );
        }
    }
    if let Err(e) = mempool_persist.flush() {
        warn!(err = %e, "mempool_persist.flush after committed prune failed");
    }
}

#[derive(Clone)]
struct ProposalBlockTemplate {
    chain_id: String,
    height: u64,
    parent_hash: Hash32,
    timestamp_ms: u64,
    proposer: Address,
    validator_set_hash: Hash32,
    fuel_limit: u64,
}

fn build_proposal_block_from_candidates<E: PetalExecutor>(
    template: &ProposalBlockTemplate,
    base_state: &State,
    executor: &E,
    block_emission: u128,
    candidates: Vec<Tx>,
) -> Block {
    let mut accepted = Vec::with_capacity(candidates.len());
    let mut accepted_state = base_state.clone();

    for candidate in candidates {
        let view = StateAdmissionView {
            state: &accepted_state,
            current_block: template.height,
        };
        if let bloom_chain_consensus::tx_admission::AdmitOutcome::Reject(reject) =
            bloom_chain_consensus::tx_admission::check_admissible(&candidate, &view, true)
        {
            warn!(
                sender = %hex::encode(candidate.sender.0),
                nonce = candidate.nonce,
                reject = ?reject,
                "proposal.builder dropped inadmissible selected tx"
            );
            continue;
        }

        let mut trial_txs = accepted.clone();
        trial_txs.push(candidate.clone());
        let trial_block = template.block_with_txs(trial_txs);
        let mut scratch = base_state.clone();

        match try_apply_block_state_transitions(&mut scratch, executor, &trial_block, 0) {
            Ok((_fuel, receipts))
                if receipts.len() == trial_block.txs.len()
                    && receipts.last().is_some_and(|receipt| {
                        receipt.tx_hash == candidate.tx_hash() && receipt.fuel_used > 0
                    }) =>
            {
                accepted_state = scratch;
                accepted.push(candidate)
            }
            Ok((_fuel, receipts)) => {
                warn!(
                    sender = %hex::encode(candidate.sender.0),
                    nonce = candidate.nonce,
                    receipts = receipts.len(),
                    txs = trial_block.txs.len(),
                    "proposal.builder dropped selected tx that did not execute"
                );
            }
            Err(e) => {
                warn!(
                    sender = %hex::encode(candidate.sender.0),
                    nonce = candidate.nonce,
                    err = %e,
                    "proposal.builder dropped invalid selected tx"
                );
            }
        }
    }

    match finalize_proposal_block(template, base_state, executor, block_emission, accepted) {
        Ok(block) => block,
        Err(e) => {
            warn!(
                err = %e,
                "proposal.builder fell back to empty block after filtered tx set failed"
            );
            finalize_proposal_block(template, base_state, executor, block_emission, Vec::new())
                .expect("empty proposal block must execute")
        }
    }
}

fn finalize_proposal_block<E: PetalExecutor>(
    template: &ProposalBlockTemplate,
    base_state: &State,
    executor: &E,
    block_emission: u128,
    txs: Vec<Tx>,
) -> std::result::Result<Block, String> {
    let mut block = template.block_with_txs(txs);
    let mut scratch = base_state.clone();
    let (fuel_used, receipts) =
        try_apply_block_state_transitions(&mut scratch, executor, &block, block_emission)?;
    if receipts.len() != block.txs.len() {
        return Err(format!(
            "proposal execution emitted {} receipts for {} txs",
            receipts.len(),
            block.txs.len()
        ));
    }
    if receipts.iter().any(|receipt| receipt.fuel_used == 0) {
        return Err("proposal execution emitted zero-fuel transaction receipt".to_string());
    }
    block.header.state_root = scratch.state_root();
    block.header.receipts_root = receipts_root(&receipts);
    block.header.fuel_used = fuel_used;
    Ok(block)
}

impl ProposalBlockTemplate {
    fn block_with_txs(&self, txs: Vec<Tx>) -> Block {
        Block {
            header: BlockHeader {
                chain_id: self.chain_id.clone(),
                height: self.height,
                parent_hash: self.parent_hash,
                timestamp_ms: self.timestamp_ms,
                proposer: self.proposer,
                txs_root: compute_txs_root(&txs),
                state_root: Hash32([0u8; 32]),
                receipts_root: Hash32([0u8; 32]),
                validator_set_hash: self.validator_set_hash,
                fuel_used: 0,
                fuel_limit: self.fuel_limit,
            },
            txs,
            commit: Commit {
                height: 0,
                round: 0,
                block_hash: Hash32([0u8; 32]),
                votes: vec![],
            },
        }
    }
}

fn proposal_header_round(proposal_round: u32, pol_round: i32) -> Option<u32> {
    let empty_validator_set =
        bloom_chain_consensus::ValidatorSet::new(vec![bloom_chain_consensus::Validator {
            address: Address([0u8; 32]),
            pubkey: bloom_chain_types::types::PubKeyBytes(vec![]),
            voting_power: 1,
        }])
        .expect("single validator set is valid");
    judge_proposer_round(
        0,
        Address([0u8; 32]),
        proposal_round,
        pol_round,
        &empty_validator_set,
        false,
    )
    .ok()
    .map(|judgment| judgment.header_round)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CurrentHeightBlockBodyKind {
    Committed,
    Proposal { header_round: u32 },
}

fn current_height_block_response_body_kind(
    engine: &ConsensusEngine<XdsaVerifier>,
    block: &Block,
) -> std::result::Result<CurrentHeightBlockBodyKind, String> {
    if !block.commit.votes.is_empty() {
        return Ok(CurrentHeightBlockBodyKind::Committed);
    }

    let block_hash = block.header.block_hash();
    let Some(header_round) =
        block_response_header_round(engine, block_hash, engine.round(), block.header.proposer)
    else {
        return Err(format!(
            "no valid proposal context for block hash {} at height {} proposer {}",
            hex::encode(block_hash.0),
            block.header.height,
            hex::encode(block.header.proposer.0)
        ));
    };
    Ok(CurrentHeightBlockBodyKind::Proposal { header_round })
}

fn block_response_header_round(
    engine: &ConsensusEngine<XdsaVerifier>,
    block_hash: Hash32,
    _current_round: u32,
    header_proposer: Address,
) -> Option<u32> {
    if let Some(pending) = engine.state.pending_proposal.as_ref()
        && pending.block_hash == block_hash
    {
        return judge_proposer_round(
            engine.state.height,
            pending.proposer,
            pending.round,
            pending.pol_round,
            engine.state.validator_set(),
            false,
        )
        .ok()
        .filter(|judgment| judgment.proposer_ok)
        .map(|judgment| judgment.header_round);
    }
    if let Some((valid_round, valid_hash)) = engine.state.valid_block
        && valid_hash == block_hash
    {
        return Some(valid_round);
    }
    (0..engine.state.validator_set().len() as u32).find(|&round| {
        judge_proposer_round(
            engine.state.height,
            header_proposer,
            round,
            -1,
            engine.state.validator_set(),
            false,
        )
        .map(|judgment| judgment.proposer_ok)
        .unwrap_or(false)
    })
}

// ---------------------------------------------------------------------------
// Snapshot sync helper
// ---------------------------------------------------------------------------

fn build_state_snapshot_response<E: PetalExecutor>(
    driver: &ConsensusDriver<E>,
    min_height: u64,
) -> Result<Option<Frame>> {
    let Some(height) = driver.state_index.latest_height()? else {
        return Ok(None);
    };
    if height < min_height {
        return Ok(None);
    }
    let Some((state_root, blob_hash)) = driver.state_index.get(height)? else {
        return Ok(None);
    };
    let Some(blob) = driver.blob_store.get(&blob_hash)? else {
        return Ok(None);
    };
    let Some(block) = driver.block_store.get(height)? else {
        return Ok(None);
    };
    Ok(Some(Frame::StateSnapshotResponse {
        block,
        state_root,
        blob_hash,
        blob,
    }))
}

struct SnapshotApplyContext<'a, E: PetalExecutor> {
    driver: Arc<ConsensusDriver<E>>,
    peer_pool: Arc<PeerPool>,
    timeout_tx: Arc<mpsc::Sender<(TimeoutKind, u64, u32)>>,
    peer: &'a str,
}

struct StateSnapshot {
    block: Block,
    state_root: Hash32,
    blob_hash: Hash32,
    blob: Vec<u8>,
}

fn expected_snapshot_parent_hash(block_store: &BlockStore, block: &Block) -> Result<Hash32> {
    let height = block.header.height;
    if height <= 1 {
        return Ok(Hash32([0u8; 32]));
    }
    let parent_height = height - 1;
    if let Some(parent) = block_store
        .get(parent_height)
        .with_context(|| format!("read snapshot parent block at height {parent_height}"))?
    {
        return Ok(parent.header.block_hash());
    }

    // Snapshot catch-up is specifically for peers whose local block window may
    // no longer contain the parent. The quorum-committed snapshot block still
    // binds the parent hash that validators signed.
    Ok(block.header.parent_hash)
}

async fn apply_state_snapshot<E: PetalExecutor>(
    ctx: SnapshotApplyContext<'_, E>,
    snapshot: StateSnapshot,
) -> Result<bool> {
    let SnapshotApplyContext {
        driver,
        peer_pool,
        timeout_tx,
        peer,
    } = ctx;
    let StateSnapshot {
        block,
        state_root,
        blob_hash,
        blob,
    } = snapshot;
    let height = block.header.height;
    let current_height = { driver.engine.lock().height() };
    if height < current_height {
        return Ok(false);
    }
    if block.commit.votes.is_empty() {
        return Err(anyhow::anyhow!("snapshot block has no commit"));
    }
    if block.header.state_root != state_root {
        return Err(anyhow::anyhow!(
            "snapshot state_root {} != block header {}",
            hex::encode(state_root.0),
            hex::encode(block.header.state_root.0)
        ));
    }
    let validator_set = { driver.engine.lock().validator_set.clone() };
    let expected_parent_hash = expected_snapshot_parent_hash(&driver.block_store, &block)?;
    validate_block_for_apply(
        &block,
        height,
        &driver.chain_id,
        expected_parent_hash,
        &validator_set,
        &XdsaVerifier,
    )
    .map_err(|reason| anyhow::anyhow!("snapshot commit validation failed: {reason}"))?;

    let actual_blob_hash = State::blob_hash(&blob);
    if actual_blob_hash != blob_hash {
        return Err(anyhow::anyhow!(
            "snapshot blob hash mismatch: advertised={} actual={}",
            hex::encode(blob_hash.0),
            hex::encode(actual_blob_hash.0)
        ));
    }
    let (blob_height, blob_state_root, blob_parent_hash) =
        State::blob_header(&blob).context("decode snapshot blob header")?;
    if blob_height != height {
        return Err(anyhow::anyhow!(
            "snapshot blob height {blob_height} != block height {height}"
        ));
    }
    if blob_state_root != state_root {
        return Err(anyhow::anyhow!(
            "snapshot blob state_root {} != advertised {}",
            hex::encode(blob_state_root.0),
            hex::encode(state_root.0)
        ));
    }
    if blob_parent_hash != block.header.parent_hash {
        return Err(anyhow::anyhow!(
            "snapshot blob parent hash {} != block parent hash {}",
            hex::encode(blob_parent_hash.0),
            hex::encode(block.header.parent_hash.0)
        ));
    }

    let state = State::from_blob(&blob, state_root)
        .with_context(|| format!("restore snapshot state at height {height}"))?;

    let stored_blob_hash = driver.blob_store.put(&blob)?;
    if stored_blob_hash != blob_hash {
        return Err(anyhow::anyhow!(
            "stored snapshot blob hash mismatch: advertised={} stored={}",
            hex::encode(blob_hash.0),
            hex::encode(stored_blob_hash.0)
        ));
    }
    driver.block_store.put(height, &block)?;
    driver.state_index.put(height, &state_root, &blob_hash)?;
    driver.block_store.prune(height)?;
    driver.blob_store.gc(&[blob_hash])?;
    {
        *driver.state.lock() = state;
    }
    {
        let mut engine = driver.engine.lock();
        engine.register_block(block.clone());
        engine.mempool.remove_included(&block.txs);
    }
    let actions = { driver.engine.lock().enter_next_height(height + 1) };
    process_actions(
        Arc::clone(&driver),
        Arc::clone(&peer_pool),
        Arc::clone(&timeout_tx),
        actions,
    )
    .await;
    let _ = peer_pool
        .send_to(peer, &Frame::BlockRequest { height: height + 1 })
        .await;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Chain-sync helper
// ---------------------------------------------------------------------------

/// Ask `peer` for every block in `[from_height, to_height)` so this validator
/// can catch up. Called when an inbound consensus message references a height
/// we haven't yet reached — without it, a validator that misses any block
/// (TCP buffer drop, restart, slow start, momentary peer hangup) has no path
/// back into consensus, because the state machine ignores events for heights
/// above its current height.
///
/// We cap the burst to keep tx pressure on the peer bounded; the response
/// path advances height which will trigger further requests as needed.
async fn request_missing_blocks(
    peer_pool: &Arc<PeerPool>,
    peer: &str,
    from_height: u64,
    to_height: u64,
) {
    // Cap per-burst breadth to avoid head-of-line blocking on the peer's
    // outbound queue; the response chain keeps advancing one-at-a-time.
    const MAX_BURST: u64 = 64;
    let end = to_height.min(from_height.saturating_add(MAX_BURST));
    for h in from_height..end {
        let _ = peer_pool
            .send_to(peer, &Frame::BlockRequest { height: h })
            .await;
    }
}

fn validate_rpc_tcp_bind_policy(addr: Option<&str>, unsafe_public_bind: bool) -> Result<()> {
    let Some(addr) = addr else {
        return Ok(());
    };
    if is_loopback_rpc_bind(addr)? || unsafe_public_bind {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "rpc_tcp_addr {addr:?} is not loopback-only; set unsafe_rpc_public_bind = true only for controlled docker/private networks"
    ))
}

fn is_loopback_rpc_bind(addr: &str) -> Result<bool> {
    use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

    if let Ok(socket) = addr.parse::<SocketAddr>() {
        return Ok(socket.ip().is_loopback());
    }
    let host = addr
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches(['[', ']']))
        .ok_or_else(|| anyhow::anyhow!("rpc_tcp_addr must be host:port, got {addr:?}"))?;
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(true);
    }
    if host.parse::<IpAddr>().is_err() {
        return Ok(false);
    }
    let mut addrs = addr
        .to_socket_addrs()
        .with_context(|| format!("resolve rpc_tcp_addr {addr:?}"))?;
    Ok(addrs.all(|a| a.ip().is_loopback()))
}

fn rpc_uds_enabled() -> bool {
    std::env::var("BLOOM_RPC_UDS")
        .map(|v| !matches!(v.as_str(), "0" | "false" | "FALSE" | "off" | "OFF"))
        .unwrap_or(true)
}

// ---------------------------------------------------------------------------
// Shutdown signal
// ---------------------------------------------------------------------------

async fn wait_for_shutdown() {
    use tokio::signal;

    #[cfg(unix)]
    {
        let mut sigterm =
            signal::unix::signal(signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus_driver::ExecOutput;
    use bloom_chain_consensus::ConsensusEngine;
    use bloom_chain_state::Account;
    use bloom_chain_types::{
        tx::{Tx, TxKind},
        types::{PubKeyBytes, SigBytes},
        vote::{Vote, VoteKind},
    };
    use bloom_objects::{OWNER_KIND_ADDRESS, Object, ObjectId, Owner, OwnershipIndexKey};
    use bloom_petal_fungible::ops::coin_payload;
    use bloom_script::{
        CORE_FUNGIBLE_PATH, DEFAULT_FUNGIBLE_PETAL_HASH, encode_ptb, loom_coin_type_tag,
        types::{PqSignature, PtbTx},
    };
    use bloom_test_util::{make_validator_set_signed, make_validator_with_keypair};

    fn signed_deploy_tx(
        sk: &bloom_keystore::xdsa::XdsaSecretKey,
        pk: &bloom_keystore::xdsa::XdsaPublicKey,
    ) -> Tx {
        let sender = Address::from_pubkey_bytes(&pk.0);
        let mut tx = Tx {
            chain_id: "bloomchain.test".into(),
            sender,
            nonce: 1,
            max_fuel: 1_000,
            fee_per_unit: 1,
            kind: TxKind::DeployPetal {
                wasm_bytes: b"test-wasm".to_vec(),
            },
            pubkey: PubKeyBytes(pk.0.clone()),
            sig: SigBytes(vec![]),
        };
        let digest = tx.signing_digest();
        tx.sig = SigBytes(sk.sign(&digest.0).to_bytes());
        tx
    }

    #[test]
    fn submit_tx_for_chain_rejects_wrong_chain_id_before_mempool() {
        let (sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
        let mut tx = signed_deploy_tx(&sk, &pk);
        tx.chain_id = "other-chain".into();
        let digest = tx.signing_digest();
        tx.sig = SigBytes(sk.sign(&digest.0).to_bytes());

        let v = make_validator_with_keypair();
        let validator_set = make_validator_set_signed(&[&v], 100);
        let mut engine = ConsensusEngine::new(
            1,
            v.addr,
            validator_set,
            XdsaVerifier,
            None,
            30_000_000,
            None,
        );

        let state = State::new();
        let view = StateAdmissionView {
            state: &state,
            current_block: engine.height(),
        };
        let err = submit_tx_for_chain(&mut engine, tx, &view, "bloomchain.test")
            .expect_err("wrong-chain tx must be rejected");
        assert!(matches!(
            err,
            bloom_chain_consensus::error::ConsensusError::WrongChainId { .. }
        ));
        assert_eq!(engine.mempool.len(), 0);
    }

    #[test]
    fn reload_persisted_mempool_re_admits_valid_tx() {
        let tmp = tempfile::tempdir().unwrap();
        let mempool_persist = MempoolPersist::open(&tmp.path().join("mempool.sled")).unwrap();
        let (sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
        let tx = signed_deploy_tx(&sk, &pk);
        mempool_persist.put(&tx).unwrap();

        let mut state = State::new();
        state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
        state.set_account(
            tx.sender,
            Account {
                nonce: 0,
                code_hash: None,
                storage_root: Hash32([0; 32]),
                manifest_hash: None,
            },
        );
        let coin_id = ObjectId([0xAC; 32]);
        state.set_object(Object {
            id: coin_id,
            type_tag: loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH),
            owner: Owner::Address(tx.sender.0),
            version: 0,
            payload: coin_payload(1_000_000),
        });
        state.set_ownership(
            OwnershipIndexKey {
                owner_kind: OWNER_KIND_ADDRESS,
                owner_id: tx.sender.0,
            },
            vec![coin_id],
        );
        let shared_state = Arc::new(Mutex::new(state));

        let v = make_validator_with_keypair();
        let validator_set = make_validator_set_signed(&[&v], 100);
        let mut engine = ConsensusEngine::new(
            1,
            v.addr,
            validator_set,
            XdsaVerifier,
            None,
            30_000_000,
            None,
        );

        reload_persisted_mempool(
            &mut engine,
            &shared_state,
            &mempool_persist,
            "bloomchain.test",
        )
        .unwrap();
        assert_eq!(engine.mempool.len(), 1);
    }

    #[test]
    fn committed_txs_are_pruned_from_persistent_mempool() {
        let tmp = tempfile::tempdir().unwrap();
        let mempool_persist = MempoolPersist::open(&tmp.path().join("mempool.sled")).unwrap();
        let (sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
        let tx1 = signed_deploy_tx(&sk, &pk);
        let mut tx2 = tx1.clone();
        tx2.nonce = 2;
        let digest = tx2.signing_digest();
        tx2.sig = SigBytes(sk.sign(&digest.0).to_bytes());
        mempool_persist.put(&tx1).unwrap();
        mempool_persist.put(&tx2).unwrap();

        prune_committed_mempool_persist(&mempool_persist, std::slice::from_ref(&tx1));

        let remaining = mempool_persist.load_all().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].sender, tx2.sender);
        assert_eq!(remaining[0].nonce, tx2.nonce);
    }

    struct NonceTwoFreeFailedPtbExecutor;

    impl PetalExecutor for NonceTwoFreeFailedPtbExecutor {
        fn execute_tx(
            &self,
            tx: &Tx,
            state: &mut State,
            _block_number: u64,
            _timestamp_ms: u64,
            _proposer: Address,
            _parent_hash: Hash32,
        ) -> ExecOutput {
            if tx.nonce == 2 {
                return ExecOutput {
                    success: false,
                    fuel_used: 0,
                    return_data: b"missing gas payer".to_vec(),
                    logs: vec![],
                    write_set: None,
                };
            }

            ExecOutput {
                success: true,
                fuel_used: 1,
                return_data: vec![],
                logs: vec![],
                write_set: Some(state.snapshot().commit()),
            }
        }
    }

    fn unsigned_submit_ptb_tx(sender_byte: u8, nonce: u64) -> Tx {
        let pubkey = PubKeyBytes(vec![sender_byte; 32]);
        let ptb_bytes = encode_ptb(&PtbTx {
            signers: vec![[0xC1; 32]],
            gas_budget: 7,
            gas_price: 3,
            expiry_block: 99,
            gas_payer: ObjectId([0xC0; 32]),
            signatures: vec![PqSignature(vec![0u8; 64])],
            ..PtbTx::default()
        })
        .expect("PTB encodes");
        Tx {
            chain_id: "bloomchain.test".into(),
            sender: Address::from_pubkey_bytes(&pubkey.0),
            nonce,
            max_fuel: 7,
            fee_per_unit: 3,
            kind: TxKind::SubmitPtb { ptb_bytes },
            pubkey,
            sig: SigBytes(vec![0u8; 64]),
        }
    }

    #[test]
    fn proposal_block_builder_drops_unauthenticated_ptb_before_execution() {
        let mut base_state = State::new();
        base_state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
        base_state.set_object(Object {
            id: ObjectId([0xC0; 32]),
            type_tag: loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH),
            owner: Owner::Address([0xC1; 32]),
            version: 1,
            payload: coin_payload(1_000_000),
        });
        let proposer = Address([0x44; 32]);
        let template = ProposalBlockTemplate {
            chain_id: "bloomchain.test".into(),
            height: 1,
            parent_hash: Hash32([0u8; 32]),
            timestamp_ms: 123,
            proposer,
            validator_set_hash: Hash32([0x55; 32]),
            fuel_limit: 14,
        };
        let tx1 = unsigned_submit_ptb_tx(0xA1, 1);
        let tx2 = unsigned_submit_ptb_tx(0xA1, 2);
        let tx3 = unsigned_submit_ptb_tx(0xA1, 3);

        let block = build_proposal_block_from_candidates(
            &template,
            &base_state,
            &NonceTwoFreeFailedPtbExecutor,
            0,
            vec![tx1.clone(), tx2, tx3],
        );

        assert!(block.txs.is_empty());
        assert_eq!(block.header.fuel_used, 0);
        assert_eq!(block.header.txs_root, compute_txs_root(&block.txs));
        assert_eq!(block.header.state_root, {
            let mut scratch = base_state.clone();
            try_apply_block_state_transitions(
                &mut scratch,
                &NonceTwoFreeFailedPtbExecutor,
                &block,
                0,
            )
            .expect("filtered proposal executes");
            scratch.state_root()
        });
    }

    #[test]
    fn block_response_header_round_recovers_original_proposer_round() {
        let v1 = make_validator_with_keypair();
        let v2 = make_validator_with_keypair();
        let v3 = make_validator_with_keypair();
        let v4 = make_validator_with_keypair();
        let validator_set = make_validator_set_signed(&[&v1, &v2, &v3, &v4], 100);
        let mut engine = ConsensusEngine::new(
            1,
            v1.addr,
            validator_set.clone(),
            XdsaVerifier,
            None,
            30_000_000,
            None,
        );
        engine.state.round = 0;
        let header_proposer = validator_set.proposer_for(1, 0).address;

        let header_round =
            block_response_header_round(&engine, Hash32([0x42; 32]), 0, header_proposer);

        assert_eq!(header_round, Some(0));
    }

    #[test]
    fn current_height_block_response_rejects_uncommitted_body_without_proposal_context() {
        let v1 = make_validator_with_keypair();
        let v2 = make_validator_with_keypair();
        let v3 = make_validator_with_keypair();
        let v4 = make_validator_with_keypair();
        let validator_set = make_validator_set_signed(&[&v1, &v2, &v3, &v4], 100);
        let engine = ConsensusEngine::new(
            1,
            v1.addr,
            validator_set,
            XdsaVerifier,
            None,
            30_000_000,
            None,
        );
        let mut block = test_block(1, Hash32([0; 32]));
        block.header.proposer = Address([0xFE; 32]);

        let err = current_height_block_response_body_kind(&engine, &block)
            .expect_err("uncommitted body with unscheduled proposer must be rejected");

        assert!(err.contains("no valid proposal context"), "got: {err}");
    }

    #[test]
    fn current_height_block_response_treats_any_nonempty_commit_as_committed() {
        let v1 = make_validator_with_keypair();
        let v2 = make_validator_with_keypair();
        let v3 = make_validator_with_keypair();
        let v4 = make_validator_with_keypair();
        let validator_set = make_validator_set_signed(&[&v1, &v2, &v3, &v4], 100);
        let engine = ConsensusEngine::new(
            1,
            v1.addr,
            validator_set,
            XdsaVerifier,
            None,
            30_000_000,
            None,
        );
        let mut block = test_block(1, Hash32([0; 32]));
        block.commit.height = 999;
        block.commit.votes.push(Vote {
            height: 999,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(block.header.block_hash()),
            validator: v1.addr,
            sig: SigBytes(vec![0u8; 64]),
        });

        let kind = current_height_block_response_body_kind(&engine, &block)
            .expect("nonempty commits must be sent to committed-block validation");

        assert_eq!(kind, CurrentHeightBlockBodyKind::Committed);
    }

    #[test]
    fn proposal_header_round_uses_pol_round_without_local_valid_block() {
        let v1 = make_validator_with_keypair();
        let v2 = make_validator_with_keypair();
        let v3 = make_validator_with_keypair();
        let v4 = make_validator_with_keypair();
        let validator_set = make_validator_set_signed(&[&v1, &v2, &v3, &v4], 100);
        let mut engine = ConsensusEngine::new(
            1,
            v1.addr,
            validator_set,
            XdsaVerifier,
            None,
            30_000_000,
            None,
        );
        engine.state.round = 2;
        engine.state.valid_block = None;

        let header_round = proposal_header_round(2, 0);

        assert_eq!(header_round, Some(0));
    }

    #[test]
    fn proposal_header_round_rejects_future_or_current_pol_round() {
        assert_eq!(proposal_header_round(1, 1), None);
        assert_eq!(proposal_header_round(1, 999), None);
        assert_eq!(proposal_header_round(1, 0), Some(0));
    }

    fn test_block(height: u64, parent_hash: Hash32) -> Block {
        Block {
            header: BlockHeader {
                chain_id: "bloomchain.test".into(),
                height,
                parent_hash,
                timestamp_ms: height,
                proposer: Address([0x11; 32]),
                txs_root: Hash32([0; 32]),
                state_root: Hash32([height as u8; 32]),
                receipts_root: Hash32([0; 32]),
                validator_set_hash: Hash32([0x22; 32]),
                fuel_used: 0,
                fuel_limit: 30_000_000,
            },
            txs: vec![],
            commit: Commit {
                height,
                round: 0,
                block_hash: Hash32([0; 32]),
                votes: vec![],
            },
        }
    }

    #[test]
    fn snapshot_parent_hash_comes_from_local_parent_block() {
        let tmp = tempfile::tempdir().unwrap();
        let block_store = BlockStore::open(&tmp.path().join("blocks")).unwrap();
        let parent = test_block(4, Hash32([0x44; 32]));
        let parent_hash = parent.header.block_hash();
        block_store.put(4, &parent).unwrap();
        let snapshot = test_block(5, Hash32([0xAA; 32]));

        let expected = expected_snapshot_parent_hash(&block_store, &snapshot).unwrap();

        assert_eq!(expected, parent_hash);
        assert_ne!(expected, Hash32([0x44; 32]));
    }

    #[test]
    fn snapshot_parent_hash_falls_back_to_committed_header_when_parent_pruned() {
        let tmp = tempfile::tempdir().unwrap();
        let block_store = BlockStore::open(&tmp.path().join("blocks")).unwrap();
        let snapshot = test_block(5, Hash32([0xAA; 32]));

        let expected = expected_snapshot_parent_hash(&block_store, &snapshot).unwrap();

        assert_eq!(expected, snapshot.header.parent_hash);
    }
}
