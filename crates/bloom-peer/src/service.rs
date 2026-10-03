use std::{collections::BTreeSet, future::Future, pin::Pin, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use iroh::{Endpoint, EndpointAddr, EndpointId, endpoint::presets};
use tokio::{
    sync::{Semaphore, watch},
    task::JoinHandle,
    time::timeout,
};

use crate::{
    Envelope, PeerIdentity, ReplayStore, ReviewDecision, ReviewRequest, now_ms, payload_digest,
};

pub const BLOOM_PEER_ALPN: &[u8] = b"bloom/peer-review/1";

pub type HandlerFuture = Pin<Box<dyn Future<Output = Result<ReviewDecision>> + Send>>;

pub trait InboundReviewHandler: Send + Sync + 'static {
    fn review(&self, peer: EndpointId, request: ReviewRequest) -> HandlerFuture;
}

impl<F, Fut> InboundReviewHandler for F
where
    F: Fn(EndpointId, ReviewRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<ReviewDecision>> + Send + 'static,
{
    fn review(&self, peer: EndpointId, request: ReviewRequest) -> HandlerFuture {
        Box::pin(self(peer, request))
    }
}

#[derive(Clone, Debug)]
pub struct PeerNodeConfig {
    pub max_envelope_bytes: usize,
    pub max_future_skew: Duration,
    pub io_timeout: Duration,
    pub max_concurrent_connections: usize,
    pub max_message_ttl: Duration,
}

impl Default for PeerNodeConfig {
    fn default() -> Self {
        Self {
            max_envelope_bytes: 64 * 1024,
            max_future_skew: Duration::from_secs(5),
            io_timeout: Duration::from_secs(5),
            max_concurrent_connections: 32,
            max_message_ttl: Duration::from_secs(60),
        }
    }
}

pub struct PeerNodeBuilder {
    identity: PeerIdentity,
    config: PeerNodeConfig,
    allowed_peers: BTreeSet<EndpointId>,
    replay: ReplayStore,
    n0: bool,
}

impl PeerNodeBuilder {
    pub fn new(identity: PeerIdentity, replay: ReplayStore) -> Self {
        Self {
            identity,
            config: PeerNodeConfig::default(),
            allowed_peers: BTreeSet::new(),
            replay,
            n0: false,
        }
    }

    pub fn allow_peer(mut self, peer: EndpointId) -> Self {
        self.allowed_peers.insert(peer);
        self
    }

    pub fn config(mut self, config: PeerNodeConfig) -> Self {
        self.config = config;
        self
    }

    pub fn use_n0(mut self, enabled: bool) -> Self {
        self.n0 = enabled;
        self
    }

    pub async fn bind(self) -> Result<PeerNode> {
        let endpoint = if self.n0 {
            Endpoint::builder(presets::N0)
                .secret_key(self.identity.secret_key().clone())
                .alpns(vec![BLOOM_PEER_ALPN.to_vec()])
                .bind()
                .await?
        } else {
            Endpoint::builder(presets::Minimal)
                .secret_key(self.identity.secret_key().clone())
                .alpns(vec![BLOOM_PEER_ALPN.to_vec()])
                .bind()
                .await?
        };
        Ok(PeerNode {
            endpoint,
            identity: self.identity,
            config: self.config,
            allowed_peers: Arc::new(self.allowed_peers),
            replay: self.replay,
        })
    }
}

#[derive(Clone)]
pub struct PeerNode {
    endpoint: Endpoint,
    identity: PeerIdentity,
    config: PeerNodeConfig,
    allowed_peers: Arc<BTreeSet<EndpointId>>,
    replay: ReplayStore,
}

impl PeerNode {
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }
    pub fn endpoint_addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }
    pub async fn online(&self) {
        self.endpoint.online().await;
    }
    pub async fn close(&self) {
        self.endpoint.close().await;
    }

    pub fn serve(&self, handler: Arc<dyn InboundReviewHandler>) -> PeerServer {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let node = self.clone();
        let permits = Arc::new(Semaphore::new(
            self.config.max_concurrent_connections.max(1),
        ));
        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() { break; }
                    }
                    incoming = node.endpoint.accept() => {
                        let Some(incoming) = incoming else { break; };
                        let permit = match permits.clone().acquire_owned().await {
                            Ok(permit) => permit,
                            Err(_) => break,
                        };
                        let node = node.clone();
                        let handler = handler.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(error) = node.handle_connection(incoming, handler).await {
                                tracing::warn!(%error, "rejected Bloom peer connection");
                            }
                        });
                    }
                }
            }
        });
        PeerServer {
            shutdown_tx,
            join,
            endpoint: self.endpoint.clone(),
        }
    }

    async fn handle_connection(
        &self,
        incoming: iroh::endpoint::Incoming,
        handler: Arc<dyn InboundReviewHandler>,
    ) -> Result<()> {
        let accepting = incoming.accept()?;
        let connection = timeout(self.config.io_timeout, accepting)
            .await
            .context("Iroh handshake timeout")??;
        let peer = connection.remote_id();
        if !self.allowed_peers.contains(&peer) {
            bail!("peer {peer} is not allowlisted");
        }
        let (mut send, mut recv) = timeout(self.config.io_timeout, connection.accept_bi())
            .await
            .context("accept stream timeout")??;
        let envelope: Envelope = timeout(
            self.config.io_timeout,
            crate::codec::recv_json(&mut recv, self.config.max_envelope_bytes),
        )
        .await
        .context("read request timeout")??;
        if envelope.expires_at_ms.saturating_sub(envelope.issued_at_ms)
            > self.config.max_message_ttl.as_millis() as u64
        {
            bail!("message TTL exceeds local policy");
        }
        self.replay.purge_expired(now_ms())?;
        let request: ReviewRequest = envelope.verify(
            peer,
            now_ms(),
            self.config.max_future_skew.as_millis() as u64,
        )?;
        if request.expires_at_ms != envelope.expires_at_ms {
            bail!("request expiration does not match its signed envelope");
        }
        if !self.replay.reserve(
            &envelope.sender_endpoint,
            envelope.nonce,
            envelope.message_id,
            envelope.expires_at_ms,
        )? {
            bail!("replayed message");
        }
        self.replay
            .record_envelope(&envelope, &peer.to_string(), "inbound", "accepted")?;
        let request_id = request.request_id;
        let request_digest = envelope.payload_digest.clone();
        let evaluator_alias = request.evaluator_alias.clone();
        let output_schema = request.requested_output_schema.clone();
        let decision = handler.review(peer, request).await?;
        let current = now_ms();
        if !decision.advisory_only
            || decision.request_id != request_id
            || decision.request_digest != request_digest
            || decision.evaluator_alias != evaluator_alias
            || decision.schema != output_schema
            || decision.valid_until_ms <= current
            || decision.valid_until_ms > envelope.expires_at_ms
        {
            bail!("review handler returned an invalid decision binding");
        }
        let response = Envelope::sign(
            &self.identity,
            &decision,
            Some(envelope.message_id),
            current,
            decision.valid_until_ms,
        )?;
        self.replay
            .record_envelope(&response, &peer.to_string(), "outbound", "decision")?;
        timeout(
            self.config.io_timeout,
            crate::codec::send_json(&mut send, &response, self.config.max_envelope_bytes),
        )
        .await
        .context("write decision timeout")??;
        timeout(self.config.io_timeout, send.stopped())
            .await
            .context("decision acknowledgement timeout")??;
        Ok(())
    }

    pub async fn request_review(
        &self,
        peer: EndpointAddr,
        request: &ReviewRequest,
    ) -> Result<ReviewDecision> {
        if !self.allowed_peers.contains(&peer.id) {
            bail!("peer {} is not allowlisted", peer.id);
        }
        let now = now_ms();
        if request.expires_at_ms <= now
            || request.expires_at_ms.saturating_sub(now)
                > self.config.max_message_ttl.as_millis() as u64
        {
            bail!("review request TTL exceeds local policy or is expired");
        }
        let envelope = Envelope::sign(&self.identity, request, None, now, request.expires_at_ms)?;
        self.replay
            .record_envelope(&envelope, &peer.id.to_string(), "outbound", "sending")?;
        let connection = timeout(
            self.config.io_timeout,
            self.endpoint.connect(peer.clone(), BLOOM_PEER_ALPN),
        )
        .await
        .context("connect timeout")??;
        let (mut send, mut recv) = timeout(self.config.io_timeout, connection.open_bi())
            .await
            .context("open stream timeout")??;
        timeout(
            self.config.io_timeout,
            crate::codec::send_json(&mut send, &envelope, self.config.max_envelope_bytes),
        )
        .await
        .context("write request timeout")??;
        let response: Envelope = timeout(
            self.config.io_timeout,
            crate::codec::recv_json(&mut recv, self.config.max_envelope_bytes),
        )
        .await
        .context("read decision timeout")??;
        if response.correlation_id != Some(envelope.message_id) {
            bail!("decision correlation id does not match request");
        }
        let decision = response.verify::<ReviewDecision>(
            peer.id,
            now_ms(),
            self.config.max_future_skew.as_millis() as u64,
        )?;
        self.replay
            .record_envelope(&response, &peer.id.to_string(), "inbound", "decision")?;
        if decision.request_id != request.request_id
            || decision.request_digest != payload_digest(request)?
            || decision.evaluator_alias != request.evaluator_alias
            || decision.schema != request.requested_output_schema
            || decision.valid_until_ms != response.expires_at_ms
            || decision.valid_until_ms > request.expires_at_ms
            || !decision.advisory_only
        {
            bail!("invalid decision binding");
        }
        connection.close(0_u8.into(), b"review complete");
        Ok(decision)
    }
}

pub struct PeerServer {
    shutdown_tx: watch::Sender<bool>,
    join: JoinHandle<()>,
    endpoint: Endpoint,
}

impl PeerServer {
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        self.endpoint.close().await;
        let _ = self.join.await;
    }
}
