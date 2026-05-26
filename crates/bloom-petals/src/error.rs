//! Error type for the petals subsystem.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PetalError {
    #[error("petal not found: {0}")]
    NotFound(String),
    #[error("invalid hash: {0}")]
    InvalidHash(String),
    #[error("invalid name: {0}")]
    InvalidName(String),
    #[error("invalid wasm: {0}")]
    InvalidWasm(String),
    #[error("capability denied: {petal} requires {cap}")]
    CapabilityDenied { petal: String, cap: String },
    #[error("vm: {0}")]
    Vm(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde: {0}")]
    Serde(String),
    #[error("mode/cap mismatch: mode={mode} disallows cap={cap}")]
    ModeCapMismatch {
        mode: crate::meta::PetalMode,
        cap: String,
    },
    #[error("cap mismatch: petal already installed with different capabilities")]
    CapMismatch,
    #[error("mode conflict: petal already installed as {existing}; uninstall first")]
    ModeConflict { existing: crate::meta::PetalMode },
    #[error("operation not supported in this petal mode: {0}")]
    ModeUnsupported(String),
    #[error("chain call error: {0}")]
    ChainCall(String),
    #[error("chain call trapped after {fuel_used} fuel: {detail}")]
    ChainCallTrap { detail: String, fuel_used: u64 },
}

impl PetalError {
    pub fn vm(s: impl Into<String>) -> Self {
        PetalError::Vm(s.into())
    }
}

impl From<serde_json::Error> for PetalError {
    fn from(e: serde_json::Error) -> Self {
        PetalError::Serde(e.to_string())
    }
}

impl From<toml::de::Error> for PetalError {
    fn from(e: toml::de::Error) -> Self {
        PetalError::Serde(e.to_string())
    }
}

impl From<toml::ser::Error> for PetalError {
    fn from(e: toml::ser::Error) -> Self {
        PetalError::Serde(e.to_string())
    }
}
