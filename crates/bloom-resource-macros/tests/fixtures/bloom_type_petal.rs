use bloom_objects::ObjectId;
use bloom_resource::{BloomType, Bytes};
use bloom_resource_macros as bloom;

#[bloom::petal(path = "/test/bloom-type", version = "0.1.0")]
pub mod bloom_type_fixture {
    use super::*;

    #[derive(Debug, PartialEq, Eq, bloom::BloomType)]
    pub struct Quote {
        pub amount: u128,
        pub label: String,
        pub tags: Vec<String>,
        pub raw: Vec<u8>,
        pub blob: Bytes,
    }

    #[derive(Debug, PartialEq, Eq, bloom::BloomType)]
    pub enum Status {
        Empty,
        Filled(u64, String),
        Named { ok: bool, id: ObjectId },
    }

    #[derive(Debug, PartialEq, Eq, bloom::BloomType)]
    pub struct LocalData {
        value: Quote,
        status: Status,
    }

    #[derive(Debug, PartialEq, Eq, bloom::BloomType)]
    pub enum LocalEnum {
        A,
        B { quote: Quote },
    }

    pub fn read_quote(q: Quote) -> Quote {
        q
    }
}
