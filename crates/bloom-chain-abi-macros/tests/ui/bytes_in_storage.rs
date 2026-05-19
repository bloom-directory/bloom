// `bytes` storage fields are deferred to v1; the macro rejects them.

use bloom_chain_abi::contract;

contract! {
    contract Demo {
        storage {
            blob: bytes;
        }
    }
}

fn main() {}
