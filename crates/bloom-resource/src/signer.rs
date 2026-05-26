//! `Signer` — typed wrapper around a signer-table index (spec §6).
//!
//! The PTB's `signers` field is a vector of post-quantum public keys.
//! When a function declares an arg of type `&Signer`, the PTB encoding
//! says "the i-th signer signed this PTB and must authorize this
//! command"; the chain verifies one xDSA signature per distinct signer.
//! This wrapper just carries the index and looks up the address via
//! `host::signer_address` on demand.

use crate::error::PetalError;
use crate::host;

/// Reference to one of the PTB's signers.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub struct Signer {
    idx: u16,
}

impl Signer {
    /// Build a `Signer` from a known signer-vector index.
    pub const fn from_index(idx: u16) -> Self {
        Self { idx }
    }

    /// Index into the PTB's `signers` vector.
    pub const fn index(&self) -> u16 {
        self.idx
    }

    /// 32-byte post-quantum address corresponding to this signer.
    pub fn address(&self) -> Result<[u8; 32], PetalError> {
        host::signer_address(self.idx)
    }

    /// Look up the primary signer index for the current command.
    /// `None` if no signer was declared by the command.
    pub fn primary() -> Option<Self> {
        host::signer_index().map(Self::from_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{HostResponse, test_hooks};

    #[test]
    fn index_round_trip() {
        let s = Signer::from_index(3);
        assert_eq!(s.index(), 3);
    }

    #[test]
    fn address_routes_through_host() {
        test_hooks::clear();
        let addr = [0x99; 32];
        test_hooks::set_responder(move |_| HostResponse::Address(addr));
        let s = Signer::from_index(0);
        assert_eq!(s.address().unwrap(), addr);
    }

    #[test]
    fn primary_signer_present() {
        test_hooks::clear();
        test_hooks::set_responder(|_| HostResponse::IntReturn(2));
        let s = Signer::primary().unwrap();
        assert_eq!(s.index(), 2);
    }

    #[test]
    fn primary_signer_absent() {
        test_hooks::clear();
        test_hooks::set_responder(|_| HostResponse::IntReturn(-1));
        assert!(Signer::primary().is_none());
    }

    #[test]
    fn address_propagates_error() {
        test_hooks::clear();
        test_hooks::set_responder(|_| HostResponse::Err(PetalError::HostImportFailed));
        let s = Signer::from_index(0);
        assert_eq!(s.address().unwrap_err(), PetalError::HostImportFailed);
    }
}
