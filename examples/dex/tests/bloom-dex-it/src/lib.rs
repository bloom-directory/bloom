//! Shared helpers for the DEX v0 integration tests.
//!
//! Both the in-process e2e (`tests/chain_dex_demo.rs`) and the docker-compose
//! multi-user e2e (`tests/docker_dex_multi_user.rs`) drive `bloom-dex` and
//! query the same v0 storage layout (`pair.reserve0/1`, `erc20.balance:<addr>`,
//! account-level loom). This module centralises:
//!
//!   * Binary + wasm location (`bloom_dex_bin`, `locate_wasm_dir`)
//!   * Wallet/pair address derivation (`wallet_addr_for_home`, `derive_pair_addr`)
//!   * CLI invocation (`run_bloom_dex`)
//!   * JSON-output scraping (`last_json_object`, `json_hex`)
//!   * RPC queries (`current_height`, `wait_for_height`, `query_nonce`,
//!     `query_account_loom`, `query_pair_reserves`, `query_erc20_balance`,
//!     `query_storage_u128`)
//!   * Uniswap-v2 math (`mul_u256`, `uniswap_get_amount_out`, `pro_rata`,
//!     `reserves_by_token`)
//!
//! Test-binary-specific scaffolding (the chain_harness multi-validator
//! provisioner used in-process, the docker `User`/`compose_tmpdir` glue) stays
//! in the corresponding `tests/*.rs` file.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use tokio::time::sleep;

use bloom_chain_node::rpc::RpcClient;

// ---------------------------------------------------------------------------
// Binary + wasm location
// ---------------------------------------------------------------------------

/// The six DEX wasm artifacts produced by `cargo build --target wasm32-unknown-unknown -p bloom-dex-*`.
pub const DEX_WASMS: &[&str] = &[
    "bloom_dex_reentrancy.wasm",
    "bloom_dex_wloom.wasm",
    "bloom_dex_pair.wasm",
    "bloom_dex_factory.wasm",
    "bloom_dex_router.wasm",
    "bloom_dex_erc20.wasm",
];

/// Resolve the `bloom-dex` binary path. Honors `$BLOOM_DEX_BIN`; otherwise
/// derives it from the same target dir as `chain_harness::bloom_bin()` so the
/// flavor (debug/release) matches `bloom`.
pub fn bloom_dex_bin() -> PathBuf {
    if let Ok(p) = std::env::var("BLOOM_DEX_BIN") {
        return PathBuf::from(p);
    }
    let bloom = bloom_it::chain_harness::bloom_bin();
    let dir = bloom.parent().expect("bloom_bin must have a parent");
    dir.join("bloom-dex")
}

/// Locate the directory containing the 6 DEX wasm artifacts (relative to
/// `bloom-dex-it`'s manifest dir, i.e. `<workspace>/target/wasm32-unknown-unknown/release`).
pub fn locate_wasm_dir() -> Result<PathBuf> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let candidate = PathBuf::from(manifest_dir)
        .join("../../../../target/wasm32-unknown-unknown/release");
    let canon = candidate.canonicalize().with_context(|| {
        format!(
            "wasm dir {} not found — build DEX petals first",
            candidate.display()
        )
    })?;
    for name in DEX_WASMS {
        if !canon.join(name).exists() {
            bail!("missing {} in {}", name, canon.display());
        }
    }
    Ok(canon)
}

// ---------------------------------------------------------------------------
// Address derivation
// ---------------------------------------------------------------------------

/// Derive the validator/user's xDSA address from the keystore at
/// `<home>/chain/keystore/validator.xdsa`.
pub fn wallet_addr_for_home(home: &Path) -> Result<[u8; 32]> {
    let key_path = home.join("chain/keystore/validator.xdsa");
    let bytes = std::fs::read(&key_path)
        .with_context(|| format!("read {}", key_path.display()))?;
    let sk = bloom_keystore::xdsa::XdsaSecretKey::from_bytes(&bytes)
        .map_err(|e| anyhow!("decode xdsa key: {e}"))?;
    let pk = sk.public_key();
    Ok(bloom_keystore::xdsa::derive_address(&pk))
}

/// Derive a pair instance address using the same formula as `factory.createPair`:
///   pair_salt    = blake3("dex.pair.salt:" || sorted(t0, t1))
///   pair_address = blake3("bloom-chain.v0.addr:deploy:" || factory || ":" || pair_salt || ":" || pair_petal_hash)
pub fn derive_pair_addr(
    factory: &[u8; 32],
    t_a: &[u8; 32],
    t_b: &[u8; 32],
    pair_petal_hash: &[u8; 32],
) -> [u8; 32] {
    let (lo, hi) = if t_a <= t_b { (t_a, t_b) } else { (t_b, t_a) };
    let salt = {
        let mut h = blake3::Hasher::new();
        h.update(b"dex.pair.salt:");
        h.update(lo);
        h.update(hi);
        *h.finalize().as_bytes()
    };
    let mut h = blake3::Hasher::new();
    h.update(b"bloom-chain.v0.addr:deploy:");
    h.update(factory);
    h.update(b":");
    h.update(&salt);
    h.update(b":");
    h.update(pair_petal_hash);
    *h.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// CLI invocation
// ---------------------------------------------------------------------------

/// Shell out to `bloom-dex --home <home> <args>`. If `rpc_tcp` is `Some(addr)`,
/// sets `BLOOM_RPC_TCP=addr` so the CLI dials TCP rather than the default UDS
/// at `<home>/chain/rpc.sock`.
pub fn run_bloom_dex(home: &Path, args: &[&str], rpc_tcp: Option<&str>) -> Result<String> {
    let bin = bloom_dex_bin();
    let mut cmd = Command::new(&bin);
    if let Some(addr) = rpc_tcp {
        cmd.env("BLOOM_RPC_TCP", addr);
    }
    cmd.arg("--home").arg(home);
    for a in args {
        cmd.arg(a);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let out = cmd
        .output()
        .with_context(|| format!("invoke {} {:?}", bin.display(), args))?;
    if !out.status.success() {
        bail!(
            "bloom-dex {:?} failed: stdout={} stderr={}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

// ---------------------------------------------------------------------------
// JSON output scraping
// ---------------------------------------------------------------------------

/// Parse the last well-formed JSON object from CLI stdout. DEX subcommands
/// emit one JSON object per tx submission plus a final summary; this returns
/// the trailing one.
pub fn last_json_object(text: &str) -> Result<Value> {
    let mut depth = 0i32;
    let mut last_start: Option<usize> = None;
    let mut last_complete: Option<(usize, usize)> = None;
    for (i, c) in text.char_indices() {
        if c == '{' {
            if depth == 0 {
                last_start = Some(i);
            }
            depth += 1;
        } else if c == '}' {
            depth -= 1;
            if depth == 0 {
                if let Some(s) = last_start {
                    last_complete = Some((s, i + 1));
                }
                last_start = None;
            }
        }
    }
    let (s, e) = last_complete.ok_or_else(|| anyhow!("no JSON object in output: {text}"))?;
    serde_json::from_str(&text[s..e]).with_context(|| format!("parse JSON: {}", &text[s..e]))
}

/// Extract a 32-byte hex-encoded field from a JSON object.
pub fn json_hex(v: &Value, field: &str) -> Result<[u8; 32]> {
    let s = v
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("field `{field}` missing in {v:?}"))?;
    let bytes = hex::decode(s).with_context(|| format!("hex decode {field}"))?;
    if bytes.len() != 32 {
        bail!("field `{field}` not 32 bytes: {} bytes", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Chain query helpers
// ---------------------------------------------------------------------------

/// Latest committed height per `chain_tip`.
pub async fn current_height(client: &RpcClient) -> Result<u64> {
    let v = client.call("chain_tip", json!({})).await?;
    Ok(v.get("height").and_then(Value::as_u64).unwrap_or(0))
}

/// Block until `chain_query_block(target)` returns a non-null block.
pub async fn wait_for_height(client: &RpcClient, target: u64) -> Result<()> {
    loop {
        match client
            .call("chain_query_block", json!({ "height": target }))
            .await
        {
            Ok(v) if !v.is_null() => return Ok(()),
            _ => sleep(Duration::from_millis(250)).await,
        }
    }
}

pub async fn query_nonce(client: &RpcClient, addr: &[u8; 32]) -> Result<u64> {
    let v = client
        .call(
            "chain_query_account",
            json!({ "address": hex::encode(addr) }),
        )
        .await?;
    if v.is_null() {
        return Ok(0);
    }
    Ok(v.get("nonce").and_then(Value::as_u64).unwrap_or(0))
}

pub async fn query_account_loom(client: &RpcClient, addr: &[u8; 32]) -> Result<u128> {
    let v = client
        .call(
            "chain_query_account",
            json!({ "address": hex::encode(addr) }),
        )
        .await?;
    if v.is_null() {
        return Ok(0);
    }
    let s = v
        .get("loom")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing loom in account"))?;
    Ok(s.parse::<u128>().context("parse loom u128")?)
}

pub async fn query_pair_reserves(
    client: &RpcClient,
    pair: &[u8; 32],
) -> Result<(u128, u128)> {
    let r0 =
        query_storage_u128(client, pair, blake3::hash(b"pair.reserve0").as_bytes()).await?;
    let r1 =
        query_storage_u128(client, pair, blake3::hash(b"pair.reserve1").as_bytes()).await?;
    Ok((r0, r1))
}

pub async fn query_erc20_balance(
    client: &RpcClient,
    token: &[u8; 32],
    holder: &[u8; 32],
) -> Result<u128> {
    let mut tag = Vec::with_capacity(14 + 32);
    tag.extend_from_slice(b"erc20.balance:");
    tag.extend_from_slice(holder);
    let key = blake3::hash(&tag);
    query_storage_u128(client, token, key.as_bytes()).await
}

pub async fn query_storage_u128(
    client: &RpcClient,
    addr: &[u8; 32],
    key: &[u8; 32],
) -> Result<u128> {
    let v = client
        .call(
            "chain_query_state",
            json!({
                "address": hex::encode(addr),
                "key": hex::encode(key),
            }),
        )
        .await?;
    let hex_s = v
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing storage value"))?;
    let bytes = hex::decode(hex_s).context("decode storage value")?;
    if bytes.len() != 32 {
        bail!("storage value not 32 bytes: {}", bytes.len());
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[16..32]);
    Ok(u128::from_be_bytes(buf))
}

// ---------------------------------------------------------------------------
// Uniswap-v2 math
// ---------------------------------------------------------------------------

/// Multiply two u128s and return the 256-bit product as `(hi, lo)` where
/// `result == hi * 2^128 + lo`. Used for the x*y=k invariant check, since
/// realistic Uniswap reserves can exceed `u128::MAX` when multiplied.
pub fn mul_u256(a: u128, b: u128) -> (u128, u128) {
    const MASK: u128 = u64::MAX as u128;
    let a_lo = a & MASK;
    let a_hi = a >> 64;
    let b_lo = b & MASK;
    let b_hi = b >> 64;

    let p00 = a_lo * b_lo;
    let p01 = a_lo * b_hi;
    let p10 = a_hi * b_lo;
    let p11 = a_hi * b_hi;

    let c0 = p00 & MASK;
    let r0 = p00 >> 64;

    let s1 = r0 + (p01 & MASK) + (p10 & MASK);
    let c1 = s1 & MASK;
    let r1 = s1 >> 64;

    let s2 = r1 + (p01 >> 64) + (p10 >> 64) + (p11 & MASK);
    let c2 = s2 & MASK;
    let r2 = s2 >> 64;

    let c3 = r2 + (p11 >> 64);

    let lo = (c1 << 64) | c0;
    let hi = (c3 << 64) | c2;
    (hi, lo)
}

/// Resolve `(tka_reserve, tkb_reserve)` from on-chain `(reserve0, reserve1)`,
/// using the Uniswap-v2 token-sort convention (`token0 = min(addr_a, addr_b)`).
pub fn reserves_by_token(
    tka: &[u8; 32],
    tkb: &[u8; 32],
    reserve0: u128,
    reserve1: u128,
) -> (u128, u128) {
    if tka.as_slice() < tkb.as_slice() {
        (reserve0, reserve1)
    } else {
        (reserve1, reserve0)
    }
}

/// `floor(numerator * reserve / total_lp)` in U256 — the LP-burn pro-rata
/// payout formula.
pub fn pro_rata(numerator: u128, reserve: u128, total_lp: u128) -> u128 {
    use primitive_types::U256;
    let n = U256::from(numerator) * U256::from(reserve);
    let d = U256::from(total_lp.max(1));
    (n / d).as_u128()
}

/// Uniswap-v2 `getAmountOut` with 0.3% fee. Uses U256 internally so the
/// intermediate `amount_in_with_fee * reserve_out` doesn't overflow at
/// production-scale reserves.
pub fn uniswap_get_amount_out(amount_in: u128, reserve_in: u128, reserve_out: u128) -> u128 {
    use primitive_types::U256;
    let amount_in_u = U256::from(amount_in);
    let reserve_in_u = U256::from(reserve_in);
    let reserve_out_u = U256::from(reserve_out);
    let amount_in_with_fee = amount_in_u * U256::from(997u64);
    let numerator = amount_in_with_fee * reserve_out_u;
    let denominator = reserve_in_u * U256::from(1000u64) + amount_in_with_fee;
    let out = numerator / denominator;
    out.as_u128()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_u256_known_vectors() {
        assert_eq!(mul_u256(0, 0), (0, 0));
        assert_eq!(mul_u256(1, 1), (0, 1));
        assert_eq!(mul_u256(1u128 << 64, 1u128 << 64), (1, 0));
        assert_eq!(mul_u256(u128::MAX, 2), (1, u128::MAX - 1));
        let r = 100_000u128 * 10u128.pow(18);
        let (h, _l) = mul_u256(r, r);
        assert!(h > 0, "expected high half nonzero for 10^46 product");
    }

    #[test]
    fn reserves_by_token_sorts() {
        let lo = [0u8; 32];
        let mut hi = [0u8; 32];
        hi[0] = 1;
        assert_eq!(reserves_by_token(&lo, &hi, 7, 9), (7, 9));
        assert_eq!(reserves_by_token(&hi, &lo, 7, 9), (9, 7));
    }
}
