//! TCP framed codec per chain spec §10.2.
//!
//! Frame layout (network wire format):
//! ```text
//! +---------+----------+----------+----------------+
//! | 4 bytes | 1 byte   | 32 bytes | <len> bytes    |
//! | len     | msg_type | digest   | payload (SSZ)  |
//! +---------+----------+----------+----------------+
//! ```
//!
//! `len` = `1 + 32 + payload.len()` (the body after the 4-byte length field).
//! `digest = blake3("bloom-chain.v0.frame:" || [msg_type] || payload)`.
//!
//! Receivers verify the digest before SSZ-decoding; a corrupted frame is
//! dropped without attempting a parse.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bloom_chain_types::ssz::{Decode, Encode};
use bloom_chain_types::{
    block::Block,
    frame::{MAX_PAYLOAD_LEN, MsgType, encode_wire_frame},
    tx::Tx,
    types::Hash32,
    vote::{Proposal, Vote},
};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tracing::{debug, error, info, warn};

const FRAME_DIGEST_DOMAIN: &[u8] = b"bloom-chain.v0.frame:";
const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(10);
const TRANSPORT_MAX_INBOUND_CONNECTIONS: usize = 128;
pub const TRANSPORT_MAX_TX_BYTES: usize = 1024 * 1024;

/// Inbound message decoded from the wire.
#[derive(Debug, Clone)]
pub enum Frame {
    Proposal(Proposal),
    Vote(Vote),
    Tx(Tx),
    BlockRequest {
        height: u64,
    },
    BlockResponse(Block),
    StateBlobRequest {
        hash: Hash32,
    },
    StateBlobResponse(Vec<u8>),
    StateSnapshotRequest {
        min_height: u64,
    },
    StateSnapshotResponse {
        block: Block,
        state_root: Hash32,
        blob_hash: Hash32,
        blob: Vec<u8>,
    },
    Ping,
    Pong,
}

/// Read one frame from a `TcpStream`.
///
/// Returns `Ok(None)` on clean EOF.  Returns `Err` on malformed frames.
/// Verifies the BLAKE3 digest before SSZ-decoding.
pub async fn read_frame(stream: &mut TcpStream) -> Result<Option<Frame>> {
    let Some((msg_type, payload)) = read_wire_frame(stream, FRAME_READ_TIMEOUT).await? else {
        return Ok(None);
    };
    let frame = decode_payload(msg_type, &payload)?;
    Ok(Some(frame))
}

async fn read_wire_frame<R>(
    reader: &mut R,
    read_timeout: Duration,
) -> Result<Option<(MsgType, Vec<u8>)>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    match tokio::time::timeout(read_timeout, reader.read_exact(&mut len_buf)).await {
        Err(_) => return Err(anyhow!("frame length read timeout")),
        Ok(Ok(_)) => {}
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Ok(Err(e)) => return Err(e.into()),
    }
    let body_len = u32::from_be_bytes(len_buf) as usize;
    if body_len > MAX_PAYLOAD_LEN + 1 + 32 {
        return Err(anyhow!("frame body too large: {body_len}"));
    }

    let mut body = vec![0u8; body_len];
    tokio::time::timeout(read_timeout, reader.read_exact(&mut body))
        .await
        .map_err(|_| anyhow!("frame body read timeout"))?
        .context("read frame body")?;

    if body.len() < 33 {
        return Err(anyhow!("frame body too short: {}", body.len()));
    }

    let msg_type_byte = body[0];
    let digest_bytes = &body[1..33];
    let payload = &body[33..];

    // Verify digest.
    let expected = {
        let mut hasher = blake3::Hasher::new();
        hasher.update(FRAME_DIGEST_DOMAIN);
        hasher.update(&[msg_type_byte]);
        hasher.update(payload);
        *hasher.finalize().as_bytes()
    };
    if digest_bytes != expected {
        return Err(anyhow!("frame digest mismatch — frame dropped"));
    }

    let msg_type = MsgType::from_byte(msg_type_byte)
        .ok_or_else(|| anyhow!("unknown msg_type byte: {msg_type_byte}"))?;

    Ok(Some((msg_type, payload.to_vec())))
}

/// Write one `Frame` to a `TcpStream`.
pub async fn write_frame(stream: &mut TcpStream, frame: &Frame) -> Result<()> {
    let (msg_type, payload) = encode_frame_payload(frame)?;
    let wire = encode_wire_frame(msg_type, &payload).context("encode wire frame")?;
    stream.write_all(&wire).await.context("write frame")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Encode / decode helpers
// ---------------------------------------------------------------------------

fn encode_frame_payload(frame: &Frame) -> Result<(MsgType, Vec<u8>)> {
    match frame {
        Frame::Proposal(p) => Ok((MsgType::Proposal, p.as_ssz_bytes())),
        Frame::Vote(v) => Ok((MsgType::Vote, v.as_ssz_bytes())),
        Frame::Tx(t) => {
            let payload = t.as_ssz_bytes();
            if payload.len() > TRANSPORT_MAX_TX_BYTES {
                return Err(anyhow!(
                    "Tx payload too large: {} > {}",
                    payload.len(),
                    TRANSPORT_MAX_TX_BYTES
                ));
            }
            Ok((MsgType::Tx, payload))
        }
        Frame::BlockRequest { height } => {
            Ok((MsgType::BlockRequest, height.to_be_bytes().to_vec()))
        }
        Frame::BlockResponse(b) => Ok((MsgType::BlockResponse, b.as_ssz_bytes())),
        Frame::StateBlobRequest { hash } => Ok((MsgType::StateBlobRequest, hash.0.to_vec())),
        Frame::StateBlobResponse(data) => Ok((MsgType::StateBlobResponse, data.clone())),
        Frame::StateSnapshotRequest { min_height } => Ok((
            MsgType::StateSnapshotRequest,
            min_height.to_be_bytes().to_vec(),
        )),
        Frame::StateSnapshotResponse {
            block,
            state_root,
            blob_hash,
            blob,
        } => {
            let block_bytes = block.as_ssz_bytes();
            if block_bytes.len() > u32::MAX as usize {
                return Err(anyhow!("snapshot block too large"));
            }
            let mut payload = Vec::with_capacity(4 + block_bytes.len() + 32 + 32 + blob.len());
            payload.extend_from_slice(&(block_bytes.len() as u32).to_be_bytes());
            payload.extend_from_slice(&block_bytes);
            payload.extend_from_slice(&state_root.0);
            payload.extend_from_slice(&blob_hash.0);
            payload.extend_from_slice(blob);
            Ok((MsgType::StateSnapshotResponse, payload))
        }
        Frame::Ping => Ok((MsgType::Ping, vec![])),
        Frame::Pong => Ok((MsgType::Pong, vec![])),
    }
}

fn decode_payload(msg_type: MsgType, payload: &[u8]) -> Result<Frame> {
    match msg_type {
        MsgType::Proposal => {
            let p = Proposal::from_ssz_bytes(payload)
                .map_err(|e| anyhow!("Proposal SSZ decode: {:?}", e))?;
            Ok(Frame::Proposal(p))
        }
        MsgType::Vote => {
            let v =
                Vote::from_ssz_bytes(payload).map_err(|e| anyhow!("Vote SSZ decode: {:?}", e))?;
            Ok(Frame::Vote(v))
        }
        MsgType::Tx => {
            if payload.len() > TRANSPORT_MAX_TX_BYTES {
                return Err(anyhow!(
                    "Tx payload too large: {} > {}",
                    payload.len(),
                    TRANSPORT_MAX_TX_BYTES
                ));
            }
            let t = Tx::from_ssz_bytes(payload).map_err(|e| anyhow!("Tx SSZ decode: {:?}", e))?;
            Ok(Frame::Tx(t))
        }
        MsgType::BlockRequest => {
            if payload.len() != 8 {
                return Err(anyhow!("BlockRequest payload must be 8 bytes"));
            }
            let height = u64::from_be_bytes(payload.try_into().unwrap());
            Ok(Frame::BlockRequest { height })
        }
        MsgType::BlockResponse => {
            let b =
                Block::from_ssz_bytes(payload).map_err(|e| anyhow!("Block SSZ decode: {:?}", e))?;
            Ok(Frame::BlockResponse(b))
        }
        MsgType::StateBlobRequest => {
            if payload.len() != 32 {
                return Err(anyhow!("StateBlobRequest payload must be 32 bytes"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(payload);
            Ok(Frame::StateBlobRequest { hash: Hash32(arr) })
        }
        MsgType::StateBlobResponse => Ok(Frame::StateBlobResponse(payload.to_vec())),
        MsgType::StateSnapshotRequest => {
            if payload.len() != 8 {
                return Err(anyhow!("StateSnapshotRequest payload must be 8 bytes"));
            }
            Ok(Frame::StateSnapshotRequest {
                min_height: u64::from_be_bytes(payload.try_into().unwrap()),
            })
        }
        MsgType::StateSnapshotResponse => {
            if payload.len() < 4 + 32 + 32 {
                return Err(anyhow!("StateSnapshotResponse payload too short"));
            }
            let block_len = u32::from_be_bytes(payload[..4].try_into().unwrap()) as usize;
            let need = 4usize
                .checked_add(block_len)
                .and_then(|n| n.checked_add(64))
                .ok_or_else(|| anyhow!("StateSnapshotResponse length overflow"))?;
            if payload.len() < need {
                return Err(anyhow!("StateSnapshotResponse truncated"));
            }
            let block = Block::from_ssz_bytes(&payload[4..4 + block_len])
                .map_err(|e| anyhow!("StateSnapshotResponse block SSZ decode: {:?}", e))?;
            let mut state_root = [0u8; 32];
            state_root.copy_from_slice(&payload[4 + block_len..4 + block_len + 32]);
            let mut blob_hash = [0u8; 32];
            blob_hash.copy_from_slice(&payload[4 + block_len + 32..need]);
            Ok(Frame::StateSnapshotResponse {
                block,
                state_root: Hash32(state_root),
                blob_hash: Hash32(blob_hash),
                blob: payload[need..].to_vec(),
            })
        }
        MsgType::Ping => Ok(Frame::Ping),
        MsgType::Pong => Ok(Frame::Pong),
    }
}

// ---------------------------------------------------------------------------
// PeerPool — persistent connection pool with exponential-backoff reconnect
// ---------------------------------------------------------------------------

/// A single entry in the peer pool.
struct PeerState {
    #[allow(dead_code)]
    addr: String,
    /// Channel for sending encoded wire frames to the background writer task.
    tx: mpsc::Sender<Vec<u8>>,
}

/// Persistent connection pool: maintains one TCP connection per peer with
/// exponential-backoff reconnect (initial 1s, max 30s).
///
/// Provides a broadcast helper for sending to all connected peers and a
/// per-peer send queue per the spec §10.1 requirement.
pub struct PeerPool {
    peers: Arc<Mutex<BTreeMap<String, PeerState>>>,
    /// Sender for inbound frames received from peers.
    inbound_tx: mpsc::Sender<(String, Frame)>,
}

impl PeerPool {
    /// Create a new pool and start outbound connector tasks.
    ///
    /// `peer_addrs`: list of `host:port` strings to maintain connections to.
    /// `inbound_tx`: channel where decoded inbound frames are forwarded.
    pub fn new(peer_addrs: Vec<String>, inbound_tx: mpsc::Sender<(String, Frame)>) -> Arc<Self> {
        let pool = Arc::new(PeerPool {
            peers: Arc::new(Mutex::new(BTreeMap::new())),
            inbound_tx,
        });

        for addr in peer_addrs {
            let pool_clone = Arc::clone(&pool);
            tokio::spawn(async move {
                pool_clone.maintain_peer(addr).await;
            });
        }

        pool
    }

    /// Background task: keep one TCP connection to `addr` alive, reconnecting
    /// with exponential backoff (1s → 2s → 4s → … → 30s).
    async fn maintain_peer(self: &Arc<Self>, addr: String) {
        let initial_backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(30);
        let mut backoff = initial_backoff;

        loop {
            debug!(peer = %addr, "peer_pool.connecting");
            match TcpStream::connect(&addr).await {
                Ok(stream) => {
                    info!(peer = %addr, "peer_pool.connected");
                    backoff = initial_backoff; // reset on success

                    // Create a per-peer send queue.
                    let (send_tx, mut send_rx) = mpsc::channel::<Vec<u8>>(256);
                    {
                        let mut peers = self.peers.lock();
                        peers.insert(
                            addr.clone(),
                            PeerState {
                                addr: addr.clone(),
                                tx: send_tx,
                            },
                        );
                    }

                    // Split: one task writes, this task reads.
                    let inbound_tx = self.inbound_tx.clone();
                    let addr_clone = addr.clone();

                    // Writer half
                    let (mut read_half, mut write_half) = stream.into_split();

                    let write_task = tokio::spawn(async move {
                        while let Some(data) = send_rx.recv().await {
                            if write_half.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                    });

                    loop {
                        let Some((mt, payload)) =
                            (match read_wire_frame(&mut read_half, FRAME_READ_TIMEOUT).await {
                                Ok(frame) => frame,
                                Err(e) => {
                                    warn!(peer = %addr_clone, err = %e, "frame read failed");
                                    break;
                                }
                            })
                        else {
                            debug!(peer = %addr_clone, "connection closed");
                            break;
                        };
                        match decode_payload(mt, &payload) {
                            Ok(frame) => {
                                let _ = inbound_tx.send((addr_clone.clone(), frame)).await;
                            }
                            Err(e) => {
                                warn!(peer = %addr_clone, err = %e, "SSZ decode failed");
                            }
                        }
                    }

                    write_task.abort();
                    {
                        let mut peers = self.peers.lock();
                        peers.remove(&addr);
                    }
                    info!(peer = %addr, "peer_pool.disconnected");
                }
                Err(e) => {
                    debug!(peer = %addr, err = %e, "peer_pool.connect_failed");
                }
            }

            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(max_backoff);
        }
    }

    /// Broadcast a frame to all currently connected peers.
    pub async fn broadcast(&self, frame: &Frame) -> Result<()> {
        let (msg_type, payload) = encode_frame_payload(frame)?;
        let wire = encode_wire_frame(msg_type, &payload)?;

        let senders: Vec<mpsc::Sender<Vec<u8>>> = {
            let peers = self.peers.lock();
            peers.values().map(|p| p.tx.clone()).collect()
        };

        for tx in senders {
            if tx.try_send(wire.clone()).is_err() {
                // Queue full or peer gone — best-effort
            }
        }
        Ok(())
    }

    /// Send a frame to a specific peer by address.
    pub async fn send_to(&self, peer_addr: &str, frame: &Frame) -> Result<()> {
        let (msg_type, payload) = encode_frame_payload(frame)?;
        let wire = encode_wire_frame(msg_type, &payload)?;

        let tx = {
            let peers = self.peers.lock();
            peers.get(peer_addr).map(|p| p.tx.clone())
        };

        if let Some(tx) = tx {
            let _ = tx.try_send(wire);
        }
        Ok(())
    }
}

/// Accept inbound TCP connections from peers and forward frames to the pool's
/// inbound queue.
///
/// Accepted sockets are also registered in [`PeerPool`] under their remote
/// socket address. Without this, request/response frames arriving over inbound
/// connections were read-only: the node saw `BlockRequest { height }`, then
/// `send_to(peer_addr, BlockResponse)` silently found no writer for that
/// ephemeral address. Catch-up and restart recovery depend on this path.
pub async fn accept_loop(listener: TcpListener, peer_pool: Arc<PeerPool>) {
    accept_loop_with_limits(
        listener,
        peer_pool,
        TRANSPORT_MAX_INBOUND_CONNECTIONS,
        FRAME_READ_TIMEOUT,
    )
    .await
}

async fn accept_loop_with_limits(
    listener: TcpListener,
    peer_pool: Arc<PeerPool>,
    max_inbound_connections: usize,
    read_timeout: Duration,
) {
    let permits = Arc::new(Semaphore::new(max_inbound_connections.max(1)));
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    warn!(peer = %peer_addr, "transport.inbound_rejected: limit reached");
                    drop(stream);
                    continue;
                };
                let addr_str = peer_addr.to_string();
                let inbound_tx = peer_pool.inbound_tx.clone();
                let peers = Arc::clone(&peer_pool.peers);
                tokio::spawn(async move {
                    let _permit = permit;
                    let (mut read_half, mut write_half) = stream.into_split();
                    let (send_tx, mut send_rx) = mpsc::channel::<Vec<u8>>(256);
                    {
                        let mut peers_guard = peers.lock();
                        peers_guard.insert(
                            addr_str.clone(),
                            PeerState {
                                addr: addr_str.clone(),
                                tx: send_tx,
                            },
                        );
                    }

                    let write_task = tokio::spawn(async move {
                        while let Some(data) = send_rx.recv().await {
                            if write_half.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                    });

                    loop {
                        let Some((mt, payload)) =
                            (match read_wire_frame(&mut read_half, read_timeout).await {
                                Ok(frame) => frame,
                                Err(e) => {
                                    warn!(peer = %addr_str, err = %e, "frame read failed");
                                    break;
                                }
                            })
                        else {
                            debug!(peer = %addr_str, "connection closed");
                            break;
                        };
                        match decode_payload(mt, &payload) {
                            Ok(frame) => {
                                let _ = inbound_tx.send((addr_str.clone(), frame)).await;
                            }
                            Err(e) => {
                                warn!(peer = %addr_str, err = %e, "SSZ decode failed");
                            }
                        }
                    }

                    write_task.abort();
                    {
                        let mut peers_guard = peers.lock();
                        peers_guard.remove(&addr_str);
                    }
                });
            }
            Err(e) => {
                error!(err = %e, "accept_loop error");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_chain_types::{
        tx::TxKind,
        types::{Address, PubKeyBytes, SigBytes},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn test_pool() -> Arc<PeerPool> {
        let (inbound_tx, _inbound_rx) = mpsc::channel(8);
        PeerPool::new(Vec::new(), inbound_tx)
    }

    #[tokio::test]
    async fn inbound_slowloris_connection_is_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let pool = test_pool().await;
        let task = tokio::spawn(accept_loop_with_limits(
            listener,
            pool,
            4,
            Duration::from_millis(50),
        ));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&33u32.to_be_bytes()).await.unwrap();

        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf))
            .await
            .expect("server should close slow body reads")
            .unwrap();
        assert_eq!(n, 0);
        task.abort();
    }

    #[tokio::test]
    async fn excess_inbound_connections_are_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let pool = test_pool().await;
        let task = tokio::spawn(accept_loop_with_limits(
            listener,
            pool,
            1,
            Duration::from_secs(5),
        ));

        let _held = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut rejected = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(1), rejected.read(&mut buf))
            .await
            .expect("excess inbound connection should be closed")
            .unwrap();
        assert_eq!(n, 0);
        task.abort();
    }

    #[test]
    fn tx_frames_are_capped_before_ssz_decode() {
        let payload = vec![0u8; TRANSPORT_MAX_TX_BYTES + 1];

        let err = decode_payload(MsgType::Tx, &payload).unwrap_err();

        assert!(err.to_string().contains("Tx payload too large"));
    }

    #[test]
    fn outgoing_tx_frames_are_capped() {
        let tx = Tx {
            chain_id: "bloomchain.test".to_string(),
            sender: Address([1; 32]),
            nonce: 1,
            max_fuel: 1,
            fee_per_unit: 1,
            kind: TxKind::DeployPetal {
                wasm_bytes: vec![0u8; TRANSPORT_MAX_TX_BYTES + 1],
            },
            pubkey: PubKeyBytes(vec![1; 32]),
            sig: SigBytes(vec![1; 64]),
        };

        let err = encode_frame_payload(&Frame::Tx(tx)).unwrap_err();

        assert!(err.to_string().contains("Tx payload too large"));
    }
}
