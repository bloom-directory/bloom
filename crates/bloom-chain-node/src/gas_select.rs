use anyhow::{Context, Result};
use bloom_objects::{Object, ObjectId, TypeTag};
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
    select_loom_gas_payer_from_object_json(
        objects
            .as_array()
            .context("chain_ls_objects returned non-array")?,
        &coin_type,
        min_amount,
    )
}

pub fn select_loom_gas_payer_from_object_json(
    objects: &[serde_json::Value],
    coin_type: &TypeTag,
    min_amount: u128,
) -> Result<ObjectId> {
    let mut best: Option<(u128, ObjectId)> = None;
    for value in objects {
        let Some(bytes_hex) = value.get("bytes").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(bytes) = hex::decode(bytes_hex) else {
            continue;
        };
        let Ok(obj) = Object::decode_canonical(&bytes) else {
            continue;
        };
        if obj.type_tag != *coin_type {
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

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_objects::{Object, Owner};
    use bloom_script::{DEFAULT_FUNGIBLE_PETAL_HASH, loom_coin_type_tag};

    fn coin_object(id_byte: u8, amount: u128) -> Object {
        let mut payload = vec![0u8; 32];
        payload.extend_from_slice(&amount.to_be_bytes());
        Object {
            id: ObjectId([id_byte; 32]),
            type_tag: loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH),
            owner: Owner::Address([0xAA; 32]),
            version: 0,
            payload,
        }
    }

    #[test]
    fn selects_largest_covering_loom_coin() {
        let coin_type = loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH);
        let objects = vec![
            serde_json::json!({ "bytes": hex::encode(coin_object(1, 50).encode_canonical().unwrap()) }),
            serde_json::json!({ "bytes": hex::encode(coin_object(2, 500).encode_canonical().unwrap()) }),
            serde_json::json!({ "bytes": hex::encode(coin_object(3, 300).encode_canonical().unwrap()) }),
        ];
        let selected = select_loom_gas_payer_from_object_json(&objects, &coin_type, 100).unwrap();
        assert_eq!(selected, ObjectId([2; 32]));
    }

    #[test]
    fn errors_when_no_loom_coin_covers_budget() {
        let coin_type = loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH);
        let objects = vec![
            serde_json::json!({ "bytes": hex::encode(coin_object(1, 50).encode_canonical().unwrap()) }),
        ];
        let err = select_loom_gas_payer_from_object_json(&objects, &coin_type, 100).unwrap_err();
        assert!(
            err.to_string()
                .contains("no signer-owned Coin<LOOM> gas payer covers budget 100"),
            "unexpected error: {err:#}"
        );
    }
}
