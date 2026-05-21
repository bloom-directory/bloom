//! Category: macro-DSL
//!
//! Integration tests for the `contract!` proc-macro.
//!
//! Each test declares a small contract DSL, then exercises the emitted
//! selectors, client call-builders, and dispatcher to verify the round-trip
//! is correct and strict-decoding is enforced.

use bloom_chain_abi::{AbiError, DispatchError, U256, contract};

contract! {
    contract Demo {
        init(creator: Address, salt: u64);

        fn ping() -> u64;
        fn echo_addr(a: Address) -> Address;
        fn sum_u256(a: U256, b: U256) -> U256;
        fn flag(b: bool);
        fn path(p: Vec<Address>) -> u64;
        fn forward(target: Address, inner: bytes) -> u64;

        #[internal]
        fn _bump(by: u64) -> u64;
    }
}

// ----- Stub Handler --------------------------------------------------------

struct Stub {
    bumped: u64,
    reentrancy: [u8; 32],
}

impl Stub {
    fn new() -> Self {
        Stub {
            bumped: 0,
            reentrancy: [0xAA; 32],
        }
    }
}

impl demo::Handler for Stub {
    fn ping(&mut self) -> Result<u64, &'static str> {
        Ok(0xDEAD_BEEF)
    }
    fn echo_addr(&mut self, a: [u8; 32]) -> Result<[u8; 32], &'static str> {
        Ok(a)
    }
    fn sum_u256(&mut self, a: U256, b: U256) -> Result<U256, &'static str> {
        a.checked_add(b).ok_or("overflow")
    }
    fn flag(&mut self, _b: bool) -> Result<(), &'static str> {
        Ok(())
    }
    fn path(&mut self, p: Vec<[u8; 32]>) -> Result<u64, &'static str> {
        Ok(p.len() as u64)
    }
    fn forward(&mut self, _target: [u8; 32], inner: Vec<u8>) -> Result<u64, &'static str> {
        Ok(inner.len() as u64)
    }
    fn _bump(&mut self, by: u64) -> Result<u64, &'static str> {
        self.bumped += by;
        Ok(self.bumped)
    }
    fn reentrancy_addr(&self) -> [u8; 32] {
        self.reentrancy
    }
}

// ----- Selector tests ------------------------------------------------------

#[test]
fn selectors_match_blake3_of_signature() {
    // The macro emits SIG_ and SEL_ constants per method. Confirm SEL_ is the
    // first 4 bytes of blake3(SIG_).
    let full = blake3::hash(demo::SIG_PING.as_bytes());
    assert_eq!(&demo::SEL_PING[..], &full.as_bytes()[..4]);

    let full = blake3::hash(demo::SIG_ECHO_ADDR.as_bytes());
    assert_eq!(&demo::SEL_ECHO_ADDR[..], &full.as_bytes()[..4]);
}

#[test]
fn sig_strings_follow_domain_dot_method_convention() {
    assert_eq!(demo::SIG_PING, "demo.ping()");
    assert_eq!(demo::SIG_ECHO_ADDR, "demo.echo_addr(address)");
    assert_eq!(demo::SIG_SUM_U256, "demo.sum_u256(u256,u256)");
    assert_eq!(demo::SIG_FLAG, "demo.flag(bool)");
    assert_eq!(demo::SIG_PATH, "demo.path(Vec<Address>)");
    assert_eq!(demo::SIG__BUMP, "demo._bump(u64)");
}

// ----- Round-trip via dispatcher ------------------------------------------

#[test]
fn ping_roundtrip() {
    let calldata = demo::calls::ping();
    assert_eq!(&calldata[..4], &demo::SEL_PING);
    let mut stub = Stub::new();
    let caller = [0u8; 32];
    let ret = demo::dispatch(&mut stub, &caller, &calldata).unwrap();
    // u64 return = 8 bytes big-endian
    assert_eq!(ret.len(), 8);
    assert_eq!(u64::from_be_bytes(ret.try_into().unwrap()), 0xDEAD_BEEF);
}

#[test]
fn echo_addr_roundtrip() {
    let a = [0x42u8; 32];
    let calldata = demo::calls::echo_addr(&a);
    let mut stub = Stub::new();
    let caller = [0u8; 32];
    let ret = demo::dispatch(&mut stub, &caller, &calldata).unwrap();
    assert_eq!(ret.len(), 32);
    assert_eq!(&ret[..], &a[..]);
}

#[test]
fn sum_u256_roundtrip() {
    let a = U256::from_u64(7);
    let b = U256::from_u64(35);
    let calldata = demo::calls::sum_u256(a, b);
    let mut stub = Stub::new();
    let caller = [0u8; 32];
    let ret = demo::dispatch(&mut stub, &caller, &calldata).unwrap();
    assert_eq!(ret.len(), 32);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&ret);
    assert_eq!(U256(bytes), U256::from_u64(42));
}

#[test]
fn flag_void_return_is_empty_bytes() {
    let calldata = demo::calls::flag(true);
    let mut stub = Stub::new();
    let caller = [0u8; 32];
    let ret = demo::dispatch(&mut stub, &caller, &calldata).unwrap();
    assert_eq!(ret.len(), 0);
}

#[test]
fn forward_bytes_tail_roundtrip() {
    let target = [0x9u8; 32];
    let payload = vec![0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE];
    let calldata = demo::calls::forward(&target, &payload);
    // 4 (selector) + 32 (address) + 5 (raw bytes, no length prefix)
    assert_eq!(calldata.len(), 4 + 32 + 5);
    assert_eq!(&calldata[36..], &payload[..]);
    let mut stub = Stub::new();
    let caller = [0u8; 32];
    let ret = demo::dispatch(&mut stub, &caller, &calldata).unwrap();
    assert_eq!(u64::from_be_bytes(ret.try_into().unwrap()), 5);
}

#[test]
fn forward_bytes_tail_accepts_empty_payload() {
    let target = [0x1u8; 32];
    let calldata = demo::calls::forward(&target, &[]);
    let mut stub = Stub::new();
    let caller = [0u8; 32];
    let ret = demo::dispatch(&mut stub, &caller, &calldata).unwrap();
    assert_eq!(u64::from_be_bytes(ret.try_into().unwrap()), 0);
}

#[test]
fn path_address_vec_roundtrip() {
    let p: Vec<[u8; 32]> = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    let calldata = demo::calls::path(&p);
    let mut stub = Stub::new();
    let caller = [0u8; 32];
    let ret = demo::dispatch(&mut stub, &caller, &calldata).unwrap();
    assert_eq!(u64::from_be_bytes(ret.try_into().unwrap()), 3);
}

// ----- Adversarial: strict decoding ----------------------------------------

#[test]
fn trailing_bytes_rejected_by_dispatcher() {
    let mut calldata = demo::calls::echo_addr(&[0u8; 32]);
    calldata.push(0xFF); // append one extra byte
    let mut stub = Stub::new();
    let caller = [0u8; 32];
    let err = demo::dispatch(&mut stub, &caller, &calldata).unwrap_err();
    assert!(
        matches!(
            err,
            DispatchError::Decode(AbiError::TrailingBytes { remaining: 1 })
        ),
        "expected TrailingBytes, got {err:?}",
    );
}

#[test]
fn short_calldata_rejected() {
    let mut stub = Stub::new();
    let caller = [0u8; 32];
    let err = demo::dispatch(&mut stub, &caller, &[0x01, 0x02]).unwrap_err();
    assert!(matches!(err, DispatchError::ShortCalldata));
}

#[test]
fn unknown_selector_rejected() {
    let calldata = [0x00, 0x00, 0x00, 0x00 /* no args */];
    let mut stub = Stub::new();
    let caller = [0u8; 32];
    let err = demo::dispatch(&mut stub, &caller, &calldata).unwrap_err();
    match err {
        DispatchError::UnknownSelector(s) => assert_eq!(s, [0, 0, 0, 0]),
        other => panic!("expected UnknownSelector, got {other:?}"),
    }
}

// ----- Adversarial: internal-selector auth ---------------------------------

#[test]
fn internal_selector_rejects_non_reentrancy_caller() {
    let calldata = demo::calls::_bump(5);
    let mut stub = Stub::new();
    let caller = [0u8; 32]; // not the configured reentrancy_addr (0xAA..)
    let err = demo::dispatch(&mut stub, &caller, &calldata).unwrap_err();
    assert!(matches!(err, DispatchError::Unauthorized));
    // The handler's state must NOT have been touched.
    assert_eq!(stub.bumped, 0);
}

#[test]
fn internal_selector_accepts_reentrancy_caller() {
    let calldata = demo::calls::_bump(5);
    let mut stub = Stub::new();
    let caller = [0xAAu8; 32]; // matches stub.reentrancy
    let ret = demo::dispatch(&mut stub, &caller, &calldata).unwrap();
    assert_eq!(u64::from_be_bytes(ret.try_into().unwrap()), 5);
    assert_eq!(stub.bumped, 5);
}

// ----- Init calldata round-trip --------------------------------------------

#[test]
fn init_calldata_roundtrip() {
    let creator = [0x11u8; 32];
    let salt: u64 = 0xCAFE_BABE;
    let payload = demo::init_calldata(&creator, salt);
    // exactly 32 + 8 bytes — no selector
    assert_eq!(payload.len(), 32 + 8);

    let parsed = demo::parse_init(&payload).unwrap();
    assert_eq!(parsed.creator, creator);
    assert_eq!(parsed.salt, salt);
}

#[test]
fn init_calldata_rejects_trailing_bytes() {
    let creator = [0x11u8; 32];
    let salt: u64 = 0xCAFE_BABE;
    let mut payload = demo::init_calldata(&creator, salt);
    payload.push(0xFF);
    let err = demo::parse_init(&payload).unwrap_err();
    assert!(matches!(err, AbiError::TrailingBytes { remaining: 1 }));
}

#[test]
fn init_calldata_rejects_short_payload() {
    let payload = [0u8; 20]; // need 40 bytes
    let err = demo::parse_init(&payload).unwrap_err();
    assert!(matches!(err, AbiError::UnexpectedEof { .. }));
}
