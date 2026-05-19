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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use bloom_chain_consensus::{
    Action, ConsensusEngine, Mempool,
    state_machine::{Event, TimeoutKind},
    ValidatorSet,
};
use bloom_chain_state::State;
use bloom_chain_types::{
    block::{Block, BlockHeader},
    digest::blake3_tagged,
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
    consensus_driver::{BLOCK_EMISSION, ConsensusDriver, XdsaVerifier},
    petal_executor::ChainPetalExecutor,
    genesis::{Genesis, NodeConfig},
    mempool_persist::MempoolPersist,
    rpc::{RpcClient, RpcServer},
    state_blob::StateBlobStore,
    state_index::StateIndex,
    transport::{Frame, PeerPool, accept_loop},
};

// ---------------------------------------------------------------------------
// NodeConfig re-export (the full config a caller passes to Node::new)
// ---------------------------------------------------------------------------

/// Full node configuration (validator identity + peer list + paths).
pub struct NodeRunConfig {
    pub chain_id: String,
    pub validator_address: Address,
    pub genesis: Genesis,
    pub listen_addr: String,
    /// Optional JSON-RPC TCP listener (`host:port`). When `Some`, the node
    /// binds a TCP listener in addition to the UDS socket. Used by the
    /// docker-compose harness where UDS sockets are awkward across hosts.
    pub rpc_tcp_addr: Option<String>,
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
        let chain_dir = cfg.bloom_home.join("chain");
        std::fs::create_dir_all(&chain_dir)?;

        // ── 1. Open storage ──────────────────────────────────────────────────
        let block_store = Arc::new(
            BlockStore::open(&chain_dir.join("blocks")).context("open block_store")?,
        );
        let blob_store = Arc::new(
            StateBlobStore::open(&chain_dir.join("state_blobs")).context("open state_blobs")?,
        );
        let state_index = Arc::new(
            StateIndex::open(&chain_dir.join("state_index.sqlite"))
                .context("open state_index.sqlite")?,
        );
        let mempool_persist = Arc::new(
            MempoolPersist::open(&chain_dir.join("mempool.sled"))
                .context("open mempool.sled")?,
        );
        let receipt_store = Arc::new(
            crate::receipt_store::ReceiptStore::open(&chain_dir.join("receipts"))
                .context("open receipt_store")?,
        );

        // ── 2. Load or build genesis state ───────────────────────────────────
        let mut state = State::new();
        let latest_height = block_store.latest_height().context("query latest height")?;

        if latest_height.is_none() {
            info!("node.genesis: applying initial allocations");
            cfg.genesis.apply_to_state(&mut state);
        } else {
            // TODO(v1): reload full state from last state blob.
            // For v0 scaffolding, we rebuild from genesis and replay committed
            // blocks.  This is acceptable for small networks.
            info!(height = ?latest_height, "node.startup: rebuilding state from genesis+blocks");
            cfg.genesis.apply_to_state(&mut state);
            if let Some(top) = latest_height {
                for h in 1..=top {
                    if let Some(block) = block_store.get(h).context("replay block")? {
                        // Simplified replay: just apply emission to proposer.
                        // Full re-execution is handled by the consensus driver.
                        let proposer = block.header.proposer;
                        let mut prop = state.get_account(&proposer).unwrap_or_else(|| {
                            crate::consensus_driver::empty_account()
                        });
                        prop.loom += BLOCK_EMISSION;
                        state.set_account(proposer, prop);
                    }
                }
            }
        }

        let starting_height = latest_height.map(|h| h + 1).unwrap_or(1);
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
        let block_builder: bloom_chain_consensus::engine::BlockBuilder<XdsaVerifier> =
            Box::new(move |height: u64, mempool: &mut Mempool<XdsaVerifier>, fuel_limit: u64| {
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
                let txs_root = compute_txs_root(&txs);
                let state_root = { bb_state.lock().state_root() };
                let validator_set_hash = bb_validator_set.validator_set_hash();

                let header = BlockHeader {
                    chain_id: bb_chain_id.clone(),
                    height,
                    parent_hash,
                    timestamp_ms,
                    proposer: bb_local_address,
                    txs_root,
                    state_root,
                    receipts_root: Hash32([0u8; 32]),
                    validator_set_hash,
                    fuel_used: 0,
                    fuel_limit,
                };

                Block {
                    header,
                    txs,
                    commit: Commit {
                        height: 0,
                        round: 0,
                        block_hash: Hash32([0u8; 32]),
                        votes: vec![],
                    },
                }
            });

        let engine: ConsensusEngine<XdsaVerifier> = ConsensusEngine::new(
            starting_height,
            local_address,
            validator_set.clone(),
            XdsaVerifier::default(),
            Some(block_builder),
            fuel_limit_cfg,
        );

        // ── 4. Channels ───────────────────────────────────────────────────────
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<(String, Frame)>(1024);
        // RPC handlers send (tx, reply) and synchronously await the reply so
        // mempool rejections surface to the caller as a JSON-RPC error instead
        // of being silently warn-logged on the validator. Without this the
        // sender has no way to tell whether the tx was actually admitted.
        let (tx_submit_tx, mut tx_submit_rx) =
            mpsc::channel::<(
                bloom_chain_types::tx::Tx,
                tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
            )>(256);

        // ── 5. TCP transport ──────────────────────────────────────────────────
        let listener = TcpListener::bind(&cfg.listen_addr)
            .await
            .with_context(|| format!("bind {}", cfg.listen_addr))?;
        info!(addr = %cfg.listen_addr, "node.transport.listening");

        let peer_pool = PeerPool::new(cfg.genesis.peer_addrs.clone(), inbound_tx.clone());
        let inbound_tx_accept = inbound_tx.clone();
        tokio::spawn(async move {
            accept_loop(listener, inbound_tx_accept).await;
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

        // Timeout delivery channel: Action::StartTimeout spawns a task that
        // sleeps then sends the kind to this channel; a separate task drives
        // the engine via `step(Event::Tick(kind))`.
        let (timeout_tx, mut timeout_rx) = mpsc::channel::<TimeoutKind>(64);
        let timeout_tx = Arc::new(timeout_tx);

        // ── 7. RPC server ─────────────────────────────────────────────────────
        let rpc_server = RpcServer {
            state: Arc::clone(&shared_state),
            block_store: Arc::clone(&block_store),
            mempool_persist: Arc::clone(&mempool_persist),
            receipt_store: Arc::clone(&receipt_store),
            validator_set: Arc::new(validator_set.clone()),
            tx_submit: tx_submit_tx.clone(),
        };
        let rpc_socket = chain_dir.join("rpc.sock");
        {
            let rpc_uds = rpc_server.clone();
            tokio::spawn(async move {
                if let Err(e) = rpc_uds.serve(&rpc_socket).await {
                    error!(err = %e, "rpc.serve failed");
                }
            });
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
                    let nonce = state.get_account(&tx.sender).map(|a| a.nonce).unwrap_or(0);
                    let balance = state.get_account(&tx.sender).map(|a| a.loom).unwrap_or(0);
                    drop(state);
                    let result = eng.submit_tx(tx.clone(), nonce, balance);
                    drop(eng);
                    result
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
                        let my_height = { driver_ev.engine.lock().height() };
                        if p.height > my_height {
                            // We're behind. Ask this peer for the gap.
                            request_missing_blocks(&peer_pool_ev, &peer_addr, my_height, p.height).await;
                            continue;
                        }
                        // Same-height proposal whose block we don't have? The
                        // proposer broadcasts the full Block right before the
                        // Proposal frame, but TCP/ordering hiccups can drop
                        // that first frame. Pull it explicitly so we can vote.
                        if p.height == my_height {
                            let have = {
                                driver_ev.engine.lock().get_registered_block(&p.block_hash).is_some()
                            };
                            if !have {
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
                        let my_height = { driver_ev.engine.lock().height() };
                        if v.height > my_height {
                            // We're behind. Ask this peer for the gap.
                            request_missing_blocks(&peer_pool_ev, &peer_addr, my_height, v.height).await;
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
                            let nonce = {
                                let state = driver_ev.state.lock();
                                state.get_account(&tx.sender).map(|a| a.nonce).unwrap_or(0)
                            };
                            let balance = {
                                let state = driver_ev.state.lock();
                                state.get_account(&tx.sender).map(|a| a.loom).unwrap_or(0)
                            };
                            eng.submit_tx(tx.clone(), nonce, balance)
                        };
                        if let Err(e) = admitted {
                            // The gossiping peer admitted this tx, so they
                            // are at least as advanced as our view of the
                            // sender's nonce. If our admit failed, we're
                            // behind on something — most often a missing
                            // block. Without this probe, lagging validators
                            // can stall when they aren't the current
                            // proposer: gossiped proposals/votes are how
                            // chain-sync normally fires, and a validator
                            // that's only seeing forwarded mempool txs has
                            // no other catch-up signal.
                            let my_height = {
                                driver_ev
                                    .block_store
                                    .latest_height()
                                    .ok()
                                    .flatten()
                                    .unwrap_or(0)
                            };
                            // We don't know how far we're behind. Burst a
                            // wide window from the peer; the BlockResponse
                            // chain advances us one-at-a-time, and the
                            // engine's per-frame de-dup makes redundant
                            // requests cheap.
                            let target = my_height + 64;
                            request_missing_blocks(
                                &peer_pool_ev,
                                &peer_addr,
                                my_height + 1,
                                target,
                            )
                            .await;
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
                        }
                    }
                    Frame::BlockResponse(block) => {
                        // Always register so consensus can resolve the hash if we
                        // get here via the normal happy-path (proposer broadcast
                        // before us seeing precommits).
                        let block_height = block.header.height;
                        { driver_ev.engine.lock().register_block(block.clone()); }
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
                                    .send_to(
                                        &peer_addr,
                                        &Frame::BlockRequest { height: my_height },
                                    )
                                    .await;
                            }
                        }
                        // Catch-up apply: while the received block is exactly our
                        // current consensus height, apply it and advance. Without
                        // this, a validator that misses a proposal frame (network
                        // glitch, restart, slow start) can never re-join the
                        // network — there's no other mechanism that drives a
                        // behind validator forward.
                        loop {
                            let my_height = { driver_ev.engine.lock().height() };
                            if block_height != my_height {
                                break;
                            }
                            if let Err(e) = driver_ev.apply_block(&block) {
                                warn!(err = %e, height = block_height, "sync.apply_block failed");
                                break;
                            }
                            info!(height = block_height, peer = %peer_addr, "sync.block_applied");
                            { driver_ev.engine.lock().mempool.remove_included(&block.txs); }
                            let next_actions = {
                                driver_ev.engine.lock().enter_next_height(block_height + 1)
                            };
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
                                    &Frame::BlockRequest { height: block_height + 1 },
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
            while let Some(kind) = timeout_rx.recv().await {
                let actions = { driver_to.engine.lock().step(Event::Tick(kind)) };
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
                    process_actions(
                        driver_kick,
                        peer_pool_kick,
                        timeout_tx_kick,
                        vec![action],
                    )
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
    timeout_tx: Arc<mpsc::Sender<TimeoutKind>>,
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
                            let block_opt = {
                                driver.engine.lock().get_registered_block(&p.block_hash)
                            };
                            if let Some(block) = block_opt {
                                if let Err(e) =
                                    peer_pool.broadcast(&Frame::BlockResponse(block)).await
                                {
                                    warn!(err = %e, "block broadcast failed");
                                }
                            }

                            // Now broadcast the proposal itself + deliver to self.
                            let self_actions = {
                                driver.engine.lock().step(Event::ReceiveProposal(p.clone()))
                            };
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
                            let self_actions = {
                                driver.engine.lock().step(Event::ReceiveVote(v.clone()))
                            };
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
                Action::Commit(block, _commit) => {
                    let height = block.header.height;
                    if let Err(e) = driver.apply_block(&block) {
                        error!(err = %e, height, "apply_block failed");
                        continue;
                    }
                    // Drop the just-committed txs from the in-memory mempool
                    // so they aren't re-selected on the next block.
                    {
                        driver.engine.lock().mempool.remove_included(&block.txs);
                    }
                    // Schedule the next height after TIMEOUT_COMMIT.  This
                    // enforces the 1s block cadence: without it, healthy
                    // consensus rounds would commit back-to-back at hundreds
                    // of blocks/sec.  We spawn so the calling task (often
                    // the inbound vote loop) is not blocked for 1s.
                    let driver_c = Arc::clone(&driver);
                    let peer_pool_c = Arc::clone(&peer_pool);
                    let timeout_tx_c = Arc::clone(&timeout_tx);
                    tokio::spawn(async move {
                        tokio::time::sleep(TIMEOUT_COMMIT).await;
                        let next_actions = {
                            driver_c.engine.lock().enter_next_height(height + 1)
                        };
                        process_actions(
                            Arc::clone(&driver_c),
                            Arc::clone(&peer_pool_c),
                            Arc::clone(&timeout_tx_c),
                            next_actions,
                        )
                        .await;
                        let maybe_action = { driver_c.engine.lock().maybe_propose() };
                        if let Some(action) = maybe_action {
                            process_actions(
                                driver_c,
                                peer_pool_c,
                                timeout_tx_c,
                                vec![action],
                            )
                            .await;
                        }
                    });
                }
                Action::StartTimeout(kind, dur) => {
                    debug!(?kind, ?dur, "consensus.timeout scheduled");
                    let tx = Arc::clone(&timeout_tx);
                    tokio::spawn(async move {
                        tokio::time::sleep(dur).await;
                        let _ = tx.send(kind).await;
                    });
                }
            }
        }
    })
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
        let _ = peer_pool.send_to(peer, &Frame::BlockRequest { height: h }).await;
    }
}

// ---------------------------------------------------------------------------
// txs_root helper
// ---------------------------------------------------------------------------

/// Compute a deterministic 32-byte hash committing to the ordered tx list.
///
/// The bloom-chain spec doesn't pin a specific txs_root construction at v0;
/// we use a domain-tagged BLAKE3 of each tx's `tx_hash()` concatenated in order.
fn compute_txs_root(txs: &[bloom_chain_types::tx::Tx]) -> Hash32 {
    let mut buf = Vec::with_capacity(txs.len() * 32);
    for tx in txs {
        buf.extend_from_slice(&tx.tx_hash().0);
    }
    blake3_tagged("bloom-chain.v0.txs_root:", &buf)
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
