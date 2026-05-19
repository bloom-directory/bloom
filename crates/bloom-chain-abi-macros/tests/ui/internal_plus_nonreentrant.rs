// `#[internal]` and `#[nonreentrant]` cannot be combined on the same fn.

use bloom_chain_abi::contract;

contract! {
    contract Demo {
        #[internal]
        #[nonreentrant]
        fn bad();
    }
}

fn main() {}
