//! `bloom-chain-node` — bloom-chain v0 node implementation.
//!
//! Wires together consensus, state, petal-execution, TCP transport, and RPC.
//!
//! # Architecture
//!
//! ```text
//!   bloom chain run-validator
//!           │
//!           ▼
//!         Node::run()
//!           ├── TCP transport (PeerPool, accept_loop)
//!           ├── ConsensusDriver (ConsensusEngine<XdsaVerifier>)
//!           ├── RpcServer (UDS JSON-RPC)
//!           └── 1s block-tick scheduler
//! ```
//!
//! # Re-exports
//!
//! The public API surface required by `bloom chain ...` CLI subcommands:
//! - [`Node`] / [`NodeRunConfig`]
//! - [`Genesis`] / [`ValidatorConfig`] / [`NodeConfig`]
//! - [`RpcServer`] / [`RpcClient`]

#![forbid(unsafe_code)]

pub mod block_store;
pub mod chain_petal_runner;
pub mod coin_select;
pub mod consensus_driver;
pub mod error;
pub mod genesis;
pub mod mempool_persist;
pub mod node;
pub mod petal_executor;
pub mod ptb_chain_iface;
pub mod receipt_store;
pub mod rpc;
pub mod sig_verifier;
pub mod state_blob;
pub mod state_index;
pub mod transport;

// Public re-exports
pub use error::NodeError;
pub use genesis::{Genesis, GenesisFile, NodeConfig, ValidatorConfig};
pub use node::{Node, NodeRunConfig};
pub use rpc::{RpcClient, RpcServer};
