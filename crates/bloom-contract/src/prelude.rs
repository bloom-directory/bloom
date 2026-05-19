//! Prelude. `use bloom_contract::prelude::*;` brings every framework primitive
//! into scope.

pub use crate::abi::{AbiDecode, AbiEncode, AbiType, AbiEncodeError, AbiError, Buf, Encoder, TypeSchema};
pub use crate::context::Context;
pub use crate::error::{ContractError, Error, Result};
pub use crate::interface::{ContractInterface, ContractRef};
pub use crate::storage::{Map, Slot, StorageValue, VecStore};
pub use crate::types::{Address, Hash32, U256};

// Attribute macros — re-exported from the proc-macro crate for ergonomic use.
pub use bloom_contract_macros::{
    contract, error as error_macro, event, init, interface as interface_macro, storage as storage_attr,
};
