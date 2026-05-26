// `#[capability]` end-to-end fixture.

use bloom_resource::{Capability, Signer, UID};
use bloom_resource_macros as bloom;

#[bloom::petal(path = "/test/cap")]
pub mod cap {
    use super::*;

    #[bloom::capability]
    pub struct AdminCap {
        id: UID,
    }

    pub fn admin_op(_signer: &Signer, _cap: &Capability<AdminCap>, _amount: u128) {}
}

