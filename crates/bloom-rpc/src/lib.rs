//! Layered RPC engine for `bloom-evm`.
//!
//! This crate owns the alloy transport stack (retry → optional
//! throttle → HTTP) under a `FallbackLayer` for multi-endpoint
//! failover. The public surface is intentionally narrow — `bloom-evm`
//! constructs an `RpcEngine` once per `ChainSpec` and exposes the
//! resulting `RootProvider` to the rest of the workspace through
//! `ChainClient::provider()`. Direct use of this crate from
//! application code should be rare; the engine is plumbed through the
//! existing `ChainClient` API.
//!
//! Phasing (see `docs/specs/rpc-robustness.md`):
//!
//! - WP-2 (this commit): retry policy, fallback wiring, HTTP
//!   transports, public types.
//! - WP-3: real `EndpointHealth` probe loop and snapshots.
//! - WP-4: WS subscription transport hand-off.
//! - WP-5: `Session` for block-pinned reads.

#![forbid(unsafe_code)]

pub mod endpoint;
pub mod error;
pub mod health;
pub mod policy;
pub mod session;
pub mod transport;

pub use endpoint::{EndpointScheme, is_subscription_capable};
pub use error::BloomRpcError;
pub use health::EndpointHealthSnapshot;
pub use policy::BloomRetryPolicy;
pub use session::Session;
pub use transport::RpcEngine;
