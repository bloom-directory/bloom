//! Private, authenticated peer review transport for Bloom.
//!
//! This crate deliberately has no dependency on Bloom's wallet, broker, signer,
//! transaction, VFS, or Petal crates. It transports advisory review requests
//! and decisions; callers decide how a validated request is evaluated.

mod codec;
mod identity;
mod invite;
mod protocol;
mod service;
mod store;

pub use identity::PeerIdentity;
pub use invite::{EnrolledPeer, PeerInvite, PeerRegistry};
pub use protocol::{
    DecisionVerdict, Envelope, MessageKind, ReviewDecision, ReviewRequest, SignedMessage,
    TradeIntent, WireError, now_ms, payload_digest,
};
pub use service::{
    BLOOM_PEER_ALPN, HandlerFuture, InboundReviewHandler, PeerNode, PeerNodeBuilder, PeerNodeConfig,
};
pub use store::ReplayStore;
