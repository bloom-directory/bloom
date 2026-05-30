use anyhow::{Context, Result};
use bloom_objects::ObjectId;
use bloom_script::{CORE_FUNGIBLE_PATH, loom_coin_type_tag};
use serde_json::json;

use crate::rpc::RpcClient;

pub async fn select_loom_gas_payer_rpc(
    client: &RpcClient,
    signer: [u8; 32],
    min_amount: u128,
) -> Result<ObjectId> {
    let fungible = client
        .call("chain_resolve_path", json!({ "path": CORE_FUNGIBLE_PATH }))
        .await
        .context("rpc chain_resolve_path for Coin<LOOM>")?;
    let hash_hex = fungible
        .get("hash")
        .and_then(|v| v.as_str())
        .context("missing Coin<LOOM> petal binding")?;
    let hash_bytes = hex::decode(hash_hex).context("decode Coin<LOOM> petal hash")?;
    let hash_arr: [u8; 32] = hash_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Coin<LOOM> petal hash must be 32 bytes"))?;
    let coin_type = loom_coin_type_tag(bloom_chain_types::Hash32(hash_arr));

    let objects = client
        .call(
            "chain_ls_objects",
            json!({ "owner_addr": hex::encode(signer) }),
        )
        .await
        .context("rpc chain_ls_objects for gas payer")?;
    let mut best: Option<(u128, ObjectId)> = None;
    for value in objects
        .as_array()
        .context("chain_ls_objects returned non-array")?
    {
        let Some(bytes_hex) = value.get("bytes").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(bytes) = hex::decode(bytes_hex) else {
            continue;
        };
        let Ok(obj) = bloom_objects::Object::decode_canonical(&bytes) else {
            continue;
        };
        if obj.type_tag != coin_type {
            continue;
        }
        let Some(amount) = decode_coin_value(&obj.payload) else {
            continue;
        };
        if amount < min_amount {
            continue;
        }
        match best {
            Some((prev, _)) if prev >= amount => {}
            _ => best = Some((amount, obj.id)),
        }
    }
    best.map(|(_, id)| id).ok_or_else(|| {
        anyhow::anyhow!("no signer-owned Coin<LOOM> gas payer covers budget {min_amount}")
    })
}

pub fn decode_coin_value(bytes: &[u8]) -> Option<u128> {
    if bytes.len() < 48 {
        return None;
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[32..48]);
    Some(u128::from_be_bytes(buf))
}
