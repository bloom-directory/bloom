//! Prelude. `use bloom_contract::prelude::*;` brings every framework primitive
//! into scope.

pub use crate::abi::{
    ABI_SCHEMA_VERSION, AbiDecode, AbiEncode, AbiEncodeError, AbiError, AbiType, Buf, BytesN,
    Encoder, StringN, TypeSchema,
};
pub use crate::context::Context;
pub use crate::error::{ContractError, Error, Result};
pub use crate::interface::{ContractInterface, ContractRef};
pub use crate::storage::{Map, Slot, StorageValue, VecStore};
pub use crate::types::{Address, Hash32, U256};

// Attribute macros — re-exported from the proc-macro crate for ergonomic use.
// `storage`, `event`, `error`, etc. live in the macro namespace; the
// homonymous *modules* (`storage`, `error`) stay accessible via their full
// paths.
pub use bloom_contract_macros::{
    AbiDecode, AbiEncode, AbiType, contract, error, event, init, interface, storage,
};
