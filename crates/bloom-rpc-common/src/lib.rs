//! Chain-neutral RPC transport machinery shared by `bloom-rpc` (EVM) and
//! `bloom-solana`.
//!
//! This crate is deliberately free of any `alloy`/Ethereum dependency: it
//! holds the pieces of the layered transport stack that are identical across
//! chain families. The Ethereum-typed layers (`RootProvider<Ethereum>`,
//! `BloomRetryPolicy` over `alloy::transports::TransportError`) stay in
//! `bloom-rpc`; the endpoint-health registry and cooldown state machine live
//! here so a Solana read client can reuse them without pulling `alloy` into
//! its dependency tree.
#![forbid(unsafe_code)]

pub mod health;
pub mod retry;

pub use health::{CooldownDecision, EndpointHealth, EndpointHealthSnapshot, HealthRegistry};
pub use retry::{RetrySignal, should_retry};
