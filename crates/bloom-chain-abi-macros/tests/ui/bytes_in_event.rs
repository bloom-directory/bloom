// `bytes` event fields are deferred to v1; the macro rejects them.

use bloom_chain_abi::contract;

contract! {
    contract Demo {
        event Blob(payload: bytes);
    }
}

fn main() {}
