// `#[invariant]` end-to-end fixture.

use bloom_resource::UID;
use bloom_resource_macros as bloom;

#[bloom::petal(path = "/test/inv")]
pub mod inv_test {
    use super::*;

    #[bloom::object(abilities = "key, store")]
    pub struct Counter {
        id: UID,
        value: u128,
        floor: u128,
    }

    #[bloom::invariant(name = "value_ge_floor", target = "Counter",
                       pred = |c: &Counter| c.value >= c.floor)]
    pub fn bump(_amount: u128) {}
}

