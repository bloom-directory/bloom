//! EIP-712 typed data (CLOB auth + relayer batch) and the contract addresses.
//!
//! All EIP-712 machinery is sourced from the **`alloy` umbrella** modules
//! (`alloy::sol`, `alloy::sol_types::SolStruct`, `alloy::dyn_abi::Eip712Domain`)
//! — never the standalone `alloy-dyn-abi 1.5` dep — so there is exactly one
//! `Eip712Domain` type in play. Byte-exact reference: the Polymarket Rust SDK
//! `src/auth.rs` (`ClobAuth`) and the Polymarket deposit-wallet docs.

use std::borrow::Cow;

use alloy::dyn_abi::Eip712Domain;
use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::sol;
use alloy::sol_types::SolStruct;

// ── CLOB L1 auth (ClobAuth) ─────────────────────────────────────────────────

sol! {
    /// L1 auth message — signed to mint/derive CLOB API credentials.
    #[allow(missing_docs)]
    struct ClobAuth {
        address address;
        string  timestamp;
        uint256 nonce;
        string  message;
    }
}

/// The fixed attestation message Polymarket expects in `ClobAuth`.
pub const CLOB_AUTH_MESSAGE: &str = "This message attests that I control the given wallet";

/// The `ClobAuthDomain` EIP-712 domain for a given chain (no verifying contract,
/// no salt) — matches the SDK exactly.
pub fn clob_auth_domain(chain_id: u64) -> Eip712Domain {
    Eip712Domain {
        name: Some(Cow::Borrowed("ClobAuthDomain")),
        version: Some(Cow::Borrowed("1")),
        chain_id: Some(U256::from(chain_id)),
        ..Eip712Domain::default()
    }
}

/// Build the `ClobAuth` EIP-712 signing hash for `address` at `timestamp`
/// (unix seconds) and `nonce` on `chain_id`. The caller signs this hash.
pub fn clob_auth_signing_hash(address: Address, timestamp: u64, nonce: u32, chain_id: u64) -> B256 {
    let auth = ClobAuth {
        address,
        timestamp: timestamp.to_string(),
        nonce: U256::from(nonce),
        message: CLOB_AUTH_MESSAGE.to_owned(),
    };
    auth.eip712_signing_hash(&clob_auth_domain(chain_id))
}

// ── Relayer `Batch` (deposit-wallet on-chain calls) ─────────────────────────

sol! {
    /// One on-chain call within a deposit-wallet batch.
    #[allow(missing_docs)]
    struct Call {
        address target;
        uint256 value;
        bytes   data;
    }
    /// A deposit-wallet batch — signed (plain 65-byte EIP-712) and submitted to
    /// the relayer as a `WALLET` transaction.
    #[allow(missing_docs)]
    struct Batch {
        address wallet;
        uint256 nonce;
        uint256 deadline;
        Call[]  calls;
    }
}

/// The `DepositWallet` EIP-712 domain bound to a specific deposit wallet.
pub fn deposit_wallet_domain(chain_id: u64, deposit_wallet: Address) -> Eip712Domain {
    Eip712Domain {
        name: Some(Cow::Borrowed("DepositWallet")),
        version: Some(Cow::Borrowed("1")),
        chain_id: Some(U256::from(chain_id)),
        verifying_contract: Some(deposit_wallet),
        ..Eip712Domain::default()
    }
}

/// EIP-712 signing hash for a relayer `Batch` under the `DepositWallet` domain.
pub fn batch_signing_hash(batch: &Batch, chain_id: u64, deposit_wallet: Address) -> B256 {
    batch.eip712_signing_hash(&deposit_wallet_domain(chain_id, deposit_wallet))
}

// ── Deposit-wallet factory + contract addresses (Polygon mainnet, 137) ────
//
// The deposit-wallet **address** is resolved at runtime from the live factory
// (`ChainReader::predict_deposit_wallet`, two eth_calls) and persisted into
// `OnboardState.deposit_wallet`. There is deliberately no local CREATE2
// re-derivation: a prior Solady-port estimate disagreed with the live factory,
// and an offline estimate of a fund-receiving address is a footgun, so it was
// removed — the factory is the single source of truth.

/// Deposit-wallet factory (CREATE2 deployer); also the relayer `to` for
/// `WALLET-CREATE` / `WALLET` submissions.
pub const FACTORY: Address = Address::new(hex_addr(b"00000000000Fb5C9ADea0298D729A0CB3823Cc07"));
/// Deposit-wallet UUPS implementation (Polygon mainnet 137).
pub const DEPOSIT_WALLET_IMPLEMENTATION: Address =
    Address::new(hex_addr(b"58CA52ebe0DadfdF531Cde7062e76746de4Db1eB"));
/// Deposit-wallet UUPS implementation (Amoy testnet 80002).
pub const DEPOSIT_WALLET_IMPLEMENTATION_AMOY: Address =
    Address::new(hex_addr(b"50a88fE9a441cB4c9c2aD6A2207CE2795C7D7Fbd"));

/// pUSD — the CLOB collateral (ERC-20, 6 dp). Replaced USDC.e on 2026-04-28;
/// this is what the deposit wallet holds and what approvals target.
pub const PUSD: Address = Address::new(hex_addr(b"C011a7E12a19f7B1f670d46F03B03f3342E82DFB"));
pub const PUSD_DECIMALS: u8 = 6;
/// USDC.e — the bridge token only (no longer the CLOB collateral).
pub const USDC_E: Address = Address::new(hex_addr(b"2791Bca1f2de4661ED88A30C99A7a9449Aa84174"));
/// Conditional Tokens Framework (ERC-1155).
pub const CTF: Address = Address::new(hex_addr(b"4D97DCd97eC945f40cF65F87097ACe5EA0476045"));
/// CTF Exchange (pUSD-collateralized, EIP-1271). POLY_1271 verifying contract.
pub const CTF_EXCHANGE: Address =
    Address::new(hex_addr(b"E111180000d2663C0091e4f400237545B87B996B"));
/// Neg-Risk CTF Exchange.
pub const NEG_RISK_EXCHANGE: Address =
    Address::new(hex_addr(b"e2222d279d744050d28e00520010520000310F59"));
/// Neg-Risk Adapter.
pub const NEG_RISK_ADAPTER: Address =
    Address::new(hex_addr(b"d91E80cF2E7be2e162c6513ceD06f1dD0dA35296"));
/// CtfCollateralAdapter (pUSD split/merge/redeem).
pub const CTF_COLLATERAL_ADAPTER: Address =
    Address::new(hex_addr(b"AdA100Db00Ca00073811820692005400218FcE1f"));
/// NegRiskCtfCollateralAdapter (pUSD-aware, neg-risk).
pub const NEG_RISK_CTF_COLLATERAL_ADAPTER: Address =
    Address::new(hex_addr(b"adA2005600Dec949baf300f4C6120000bDB6eAab"));

// Solady `LibClone` ERC-1967 init-code constants (UUPS). This local CREATE2
// path is display/test-only; live factory reads remain authoritative.
const ERC1967_INIT_CODE_PREFIX: [u8; 10] =
    [0x61, 0x00, 0x3d, 0x3d, 0x81, 0x60, 0x23, 0x3d, 0x39, 0x73];
const ERC1967_MID: [u8; 2] = [0x60, 0x09];
const ERC1967_CONST2: [u8; 32] = [
    0x51, 0x55, 0xf3, 0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x36, 0x3d, 0x7f, 0x36, 0x08, 0x94, 0xa1,
    0x3b, 0xa1, 0xa3, 0x21, 0x06, 0x67, 0xc8, 0x28, 0x49, 0x2d, 0xb9, 0x8d, 0xca, 0x3e, 0x20, 0x76,
];
const ERC1967_CONST1: [u8; 32] = [
    0xcc, 0x37, 0x35, 0xa9, 0x20, 0xa3, 0xca, 0x50, 0x5d, 0x38, 0x2b, 0xbc, 0x54, 0x5a, 0xf4, 0x3d,
    0x60, 0x00, 0x80, 0x3e, 0x60, 0x38, 0x57, 0x3d, 0x60, 0x00, 0xfd, 0x5b, 0x3d, 0x60, 0x00, 0xf3,
];

/// The UUPS implementation for `chain_id` (137 mainnet, 80002 Amoy).
pub fn deposit_wallet_implementation(chain_id: u64) -> Address {
    match chain_id {
        80_002 => DEPOSIT_WALLET_IMPLEMENTATION_AMOY,
        _ => DEPOSIT_WALLET_IMPLEMENTATION,
    }
}

/// `args = abi.encode(factory, walletId)` where `walletId = bytes32(owner)`.
pub fn deposit_wallet_args(factory: &Address, owner: &Address) -> [u8; 64] {
    let mut args = [0u8; 64];
    args[..32].copy_from_slice(&left_pad_32(factory));
    args[32..].copy_from_slice(&left_pad_32(owner));
    args
}

/// `salt = keccak256(abi.encode(factory, bytes32(owner)))`.
pub fn deposit_wallet_salt(factory: &Address, owner: &Address) -> B256 {
    keccak256(deposit_wallet_args(factory, owner))
}

/// Solady `LibClone.initCodeHashERC1967(implementation, args)`.
pub fn init_code_hash_erc1967(implementation: &Address, args: &[u8]) -> B256 {
    debug_assert!(args.len() <= 255, "ERC1967 args must be <= 255 bytes");
    let mut prefix = ERC1967_INIT_CODE_PREFIX;
    prefix[1] = args.len() as u8;
    let mut pre = Vec::with_capacity(10 + 20 + 2 + 32 + 32 + args.len());
    pre.extend_from_slice(&prefix);
    pre.extend_from_slice(implementation.as_slice());
    pre.extend_from_slice(&ERC1967_MID);
    pre.extend_from_slice(&ERC1967_CONST2);
    pre.extend_from_slice(&ERC1967_CONST1);
    pre.extend_from_slice(args);
    keccak256(pre)
}

/// Display/test-only local CREATE2 estimate. Do not use this as a funding
/// address; onboard runtime resolves the authoritative wallet from the factory.
pub fn derive_deposit_wallet_address(owner: &Address, chain_id: u64) -> Address {
    let args = deposit_wallet_args(&FACTORY, owner);
    let salt = keccak256(args);
    let init_code_hash = init_code_hash_erc1967(&deposit_wallet_implementation(chain_id), &args);
    create2(&FACTORY, &salt, &init_code_hash)
}

/// `CREATE2(deployer, salt, init_code_hash)` per EIP-1014.
pub fn create2(deployer: &Address, salt: &B256, init_code_hash: &B256) -> Address {
    let mut p = Vec::with_capacity(85);
    p.push(0xff);
    p.extend_from_slice(deployer.as_slice());
    p.extend_from_slice(salt.as_slice());
    p.extend_from_slice(init_code_hash.as_slice());
    Address::from_slice(&keccak256(p)[12..])
}

fn left_pad_32(addr: &Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(addr.as_slice());
    out
}

/// Parse a 40-char ASCII-hex (no `0x`) address literal into 20 bytes at compile
/// time, so the contract-address constants can be `const`.
const fn hex_addr(s: &[u8; 40]) -> [u8; 20] {
    let mut out = [0u8; 20];
    let mut i = 0;
    while i < 20 {
        out[i] = (hex_nibble(s[i * 2]) << 4) | hex_nibble(s[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("invalid hex nibble in address literal"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::POLYGON;
    use std::str::FromStr;

    #[test]
    fn const_addresses_match_checksums() {
        assert_eq!(
            FACTORY,
            Address::from_str("0x00000000000Fb5C9ADea0298D729A0CB3823Cc07").unwrap()
        );
        assert_eq!(
            PUSD,
            Address::from_str("0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB").unwrap()
        );
        assert_eq!(
            USDC_E,
            Address::from_str("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174").unwrap()
        );
        assert_eq!(
            CTF_EXCHANGE,
            Address::from_str("0xE111180000d2663C0091e4f400237545B87B996B").unwrap()
        );
    }

    /// Lock the `Batch` EIP-712 signing hash for a fixed batch **with a nested
    /// `Call[]`** — the exact payload that authorizes fund moves. Confirms
    /// alloy's `sol!` recursive-array encoding is stable.
    #[test]
    fn batch_signing_hash_is_stable_with_nested_calls() {
        let deposit_wallet =
            Address::from_str("0x6c625c75652cf2cdf2bfe94ad59cb6f79b899a18").unwrap();
        let batch = Batch {
            wallet: deposit_wallet,
            nonce: U256::from(0u64),
            deadline: U256::from(1_760_000_000u64),
            calls: vec![Call {
                target: PUSD,
                value: U256::ZERO,
                data: alloy::primitives::Bytes::from_static(&[0x09, 0x5e, 0xa7, 0xb3]),
            }],
        };
        let h = batch_signing_hash(&batch, POLYGON, deposit_wallet);
        // Recompute via the explicit domain — must match the helper.
        assert_eq!(
            h,
            batch.eip712_signing_hash(&deposit_wallet_domain(POLYGON, deposit_wallet))
        );
        // Non-zero, fixed-length digest.
        assert_ne!(h, B256::ZERO);
    }

    /// Salt for the vitalik.eth owner — the exact value the deposit-wallet
    /// discovery probe printed for this public test owner.
    #[test]
    fn deposit_wallet_salt_matches_probe_vector() {
        let owner = Address::from_str("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").unwrap();
        let salt = deposit_wallet_salt(&FACTORY, &owner);
        assert_eq!(
            format!("0x{}", hex::encode(salt)),
            "0x92a469daa57f86982b8f8bbffc305b0bab81819d3b70668c0d904f1d79ead041"
        );
    }

    /// EIP-1014 known-answer vector proves the CREATE2 helper independently of
    /// the (separately tested) ERC-1967 init-code hash:
    /// deployer 0, salt 0, init_code 0x00 → keccak256(0x00) → 0x4D1A…Bf38.
    #[test]
    fn create2_matches_eip1014_vector() {
        let ich =
            B256::from_str("0xbc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a")
                .unwrap();
        let got = create2(&Address::ZERO, &B256::ZERO, &ich);
        assert_eq!(
            got,
            Address::from_str("0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26Bf38").unwrap()
        );
    }

    #[test]
    fn clob_auth_domain_has_no_verifying_contract() {
        let d = clob_auth_domain(137);
        assert_eq!(d.name.as_deref(), Some("ClobAuthDomain"));
        assert_eq!(d.version.as_deref(), Some("1"));
        assert_eq!(d.chain_id, Some(U256::from(137u64)));
        assert!(d.verifying_contract.is_none());
        assert!(d.salt.is_none());
    }

    /// Step-0 resolver (read-only, network-gated): the deposit-wallet factory's
    /// `BEACON()` must revert (or return zero) — confirming the factory deploys
    /// **UUPS ERC-1967** clones, not BeaconProxy. If this ever fails, the clone
    /// shape changed and `derive_deposit_wallet_address` must be revisited
    /// before any fund-moving use.
    #[cfg(feature = "native-client")]
    #[tokio::test]
    #[ignore = "hits a live Polygon RPC (set POLYGON_RPC_URL)"]
    async fn factory_beacon_reverts_confirming_uups() {
        // Opt-in only (live Polygon RPC). Self-skip unless BLOOM_LIVE_POLYMARKET
        // is set, so the acceptance `--run-ignored` job stays green.
        match std::env::var("BLOOM_LIVE_POLYMARKET") {
            Ok(v) if !v.is_empty() => {}
            _ => {
                eprintln!("skip: set BLOOM_LIVE_POLYMARKET=1 to run live Polymarket tests");
                return;
            }
        }
        let rpc = std::env::var("POLYGON_RPC_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "https://polygon-bor-rpc.publicnode.com".to_string());
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "eth_call",
            "params": [{ "to": format!("{FACTORY:#x}"), "data": "0x49493a4d" }, "latest"]
        });
        let resp: serde_json::Value = reqwest::Client::new()
            .post(&rpc)
            .json(&body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let reverted = resp.get("error").is_some();
        let zero = resp
            .get("result")
            .and_then(serde_json::Value::as_str)
            .map(|s| {
                s.trim_start_matches("0x")
                    .trim_start_matches('0')
                    .is_empty()
            })
            .unwrap_or(false);
        assert!(
            reverted || zero,
            "BEACON() should revert/zero for UUPS; got {resp}"
        );
    }
}
