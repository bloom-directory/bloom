//! ENS error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnsError {
    #[error("ens name not found: {0}")]
    NotFound(String),
    #[error("provider: {0}")]
    Provider(#[from] bloom_chain::ChainError),
    #[error("invalid name: {0}")]
    InvalidName(String),
    #[error("decode: {0}")]
    Decode(String),
}

pub type Result<T> = std::result::Result<T, EnsError>;
