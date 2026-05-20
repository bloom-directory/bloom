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
    state_machine::{Event, TimeoutKind},
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
    genesis::Genesis,
    mempool_persist::MempoolPersist,
    rpc::RpcServer,
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
            // For v0 we rebuild from genesis and re-execute every committed
            // block. Master replayed only the proposer LOOM emission and
            // dropped every tx effect (deploys, transfers, storage writes,
            // fees, refunds, receipt-derivable state) — a validator that
            // restarted at height N silently lost all of state H ∈ [1, N]
            // except the cumulative block-emission balance, then diverged
            // from peers on the next state_root (review 2026-05-19 #4).
            //
            // Replay reuses the exact same state-transition path as live
            // apply (`apply_block_state_transitions`), so the rebuilt state
            // is byte-identical to a node that never restarted.
            info!(height = ?latest_height, "node.startup: rebuilding state from genesis+blocks");
            cfg.genesis.apply_to_state(&mut state);
            if let Some(top) = latest_height {
                let replay_executor = crate::petal_executor::ChainPetalExecutor;
                for h in 1..=top {
                    if let Some(block) = block_store.get(h).context("replay block")? {
                        let (fuel_used, _receipts) =
                            crate::consensus_driver::apply_block_state_transitions(
                                &mut state,
                                &replay_executor,
                                &block,
                                BLOCK_EMISSION,
                            );
                        debug!(height = h, txs = block.txs.len(), fuel_used, "node.startup.replayed_block");
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

        // Build the xDSA signer from the validator secret key. Without this,
        // every outbound Vote/Proposal would carry an empty `sig` and peers
        // running the post-2026-05-19 ingress check would drop them all.
        let signer: Arc<dyn bloom_chain_consensus::signer::Signer> =
            Arc::new(crate::consensus_driver::XdsaSigner::new(Arc::clone(
                &cfg.validator_secret_key,
            )));
        let engine: ConsensusEngine<XdsaVerifier> = ConsensusEngine::new(
            starting_height,
            local_address,
            validator_set.clone(),
            XdsaVerifier,
            Some(block_builder),
            fuel_limit_cfg,
            Some(signer),
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
        let (timeout_tx, mut timeout_rx) =
            mpsc::channel::<(TimeoutKind, u64, u32)>(64);
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
                        // Authentication boundary (review 2026-05-19 #1):
                        // every Proposal must be xDSA-verified against the
                        // proposer's pubkey in the validator set BEFORE it
                        // enters the state machine. Unverified messages would
                        // let a peer forge proposals from any validator.
                        //
                        // Snapshot the validator set out of the engine guard
                        // before verifying — xDSA verify is the slow path and
                        // must not block engine progress on every inbound msg.
                        let validator_set =
                            { driver_ev.engine.lock().validator_set.clone() };
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
                        // Authentication boundary (review 2026-05-19 #1):
                        // every Vote (prevote and precommit) must be
                        // xDSA-verified against the voter's pubkey in the
                        // validator set BEFORE it enters the state machine.
                        // Forged votes otherwise count toward quorum totals.
                        //
                        // Snapshot the validator set out of the engine guard
                        // before verifying — xDSA verify is the slow path and
                        // must not block engine progress on every inbound msg.
                        let validator_set =
                            { driver_ev.engine.lock().validator_set.clone() };
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
                        let block_hash = block.header.block_hash();
                        { driver_ev.engine.lock().register_block(block.clone()); }
                        // If we stashed a proposal earlier because its block
                        // was unknown (review 2026-05-19 #3 gate), now that
                        // the block is registered the state machine can
                        // resume — emit prevote + arm Prevote timeout.
                        let resume_actions = {
                            driver_ev.engine.lock().try_resume_pending_proposal()
                        };
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
                        let commit_actions = {
                            driver_ev.engine.lock().try_commit_with_block(block_hash)
                        };
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
                        let has_commit = !block.commit.votes.is_empty()
                            && block.commit.height == block.header.height;
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
                            let block_opt = {
                                driver.engine.lock().get_registered_block(&p.block_hash)
                            };
                            if let Some(block) = block_opt
                                && let Err(e) =
                                    peer_pool.broadcast(&Frame::BlockResponse(block)).await
                                {
                                    warn!(err = %e, "block broadcast failed");
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
                        error!(err = %e, height, "apply_block failed");
                        continue;
                    }
                    // Drop the just-committed txs from the in-memory mempool
                    // so they aren't re-selected on the next block.
                    {
                        driver.engine.lock().mempool.remove_included(&block_with_commit.txs);
                    }
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
                    let _drop_propose_timeout = {
                        driver.engine.lock().enter_next_height(height + 1)
                    };
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
