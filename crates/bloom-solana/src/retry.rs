//! Retry classification for the Solana transport.
//!
//! Delegates entirely to [`bloom_rpc_common::retry`], the chain-neutral
//! rule table shared with `bloom-rpc`'s EVM transport, so the two
//! transports cannot drift apart (Fix H, PLAN-SOLANA-PR-FIXES.md — this
//! module used to hand-duplicate `bloom-rpc`'s rules, and the two lists had
//! already started diverging).

pub use bloom_rpc_common::retry::{RetrySignal, should_retry};
