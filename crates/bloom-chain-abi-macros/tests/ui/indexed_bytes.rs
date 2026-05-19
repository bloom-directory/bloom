// `#[indexed] bytes` cannot exist — indexed fields must have a fixed
// 32-byte encoding.

use bloom_chain_abi::contract;

contract! {
    contract Demo {
        event Blob(#[indexed] payload: bytes);
    }
}

fn main() {}
