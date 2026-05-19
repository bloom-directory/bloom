// Reserved-tag-prefix rejection: explicit `@ "__macro.X"` overrides are not
// allowed (the `__macro.` namespace is reserved for macro-managed slots).

use bloom_chain_abi::contract;

contract! {
    contract Demo {
        storage {
            field: u64 @ "__macro.foo";
        }
    }
}

fn main() {}
