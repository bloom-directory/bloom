use anyhow::{Context, Result};
use bloom_objects::{Object, ObjectId, TypeTag};
use bloom_script::{CORE_FUNGIBLE_PATH, loom_coin_type_tag};
use serde_json::json;

use crate::rpc::RpcClient;

const GAS_OBJECT_SCAN_PAGE_LIMIT: usize = 1_024;

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

    let signer_hex = hex::encode(signer);
    let mut offset = 0usize;
    let mut best: Option<(u128, ObjectId)> = None;
    loop {
        let objects = client
            .call(
                "chain_ls_objects",
                json!({
                    "owner_addr": signer_hex,
                    "limit": GAS_OBJECT_SCAN_PAGE_LIMIT,
                    "offset": offset,
                }),
            )
            .await
            .context("rpc chain_ls_objects for gas payer")?;
        let page = objects
            .as_array()
            .context("chain_ls_objects returned non-array")?;
        best =
            select_best_loom_gas_payer_from_object_json(page, &coin_type, signer, min_amount, best);
        if page.len() < GAS_OBJECT_SCAN_PAGE_LIMIT {
            break;
        }
        offset = offset.saturating_add(GAS_OBJECT_SCAN_PAGE_LIMIT);
    }
    best.map(|(_, id)| id).ok_or_else(|| {
        anyhow::anyhow!("no signer-owned Coin<LOOM> gas payer covers budget {min_amount}")
    })
}

pub fn select_loom_gas_payer_from_object_json(
    objects: &[serde_json::Value],
    coin_type: &TypeTag,
    signer: [u8; 32],
    min_amount: u128,
) -> Result<ObjectId> {
    let mut best: Option<(u128, ObjectId)> = None;
    best =
        select_best_loom_gas_payer_from_object_json(objects, coin_type, signer, min_amount, best);
    best.map(|(_, id)| id).ok_or_else(|| {
        anyhow::anyhow!("no signer-owned Coin<LOOM> gas payer covers budget {min_amount}")
    })
}

fn select_best_loom_gas_payer_from_object_json(
    objects: &[serde_json::Value],
    coin_type: &TypeTag,
    signer: [u8; 32],
    min_amount: u128,
    mut best: Option<(u128, ObjectId)>,
) -> Option<(u128, ObjectId)> {
    let signer_hex = hex::encode(signer);
    for value in objects {
        if value.get("owner_kind").and_then(|v| v.as_str()) != Some("address")
            || value.get("owner_addr").and_then(|v| v.as_str()) != Some(signer_hex.as_str())
        {
            continue;
        }
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
        if obj.owner != bloom_objects::Owner::Address(signer) {
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
    best
}

pub fn decode_coin_value(bytes: &[u8]) -> Option<u128> {
    if bytes.len() != 16 {
        return None;
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(bytes);
    Some(u128::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_objects::{Object, Owner};
    use bloom_petal_fungible::ops::coin_payload;
    use bloom_script::{DEFAULT_FUNGIBLE_PETAL_HASH, loom_coin_type_tag};

    fn coin_object(id_byte: u8, owner: Owner, amount: u128) -> Object {
        Object {
            id: ObjectId([id_byte; 32]),
            type_tag: loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH),
            owner,
            version: 0,
            payload: coin_payload(amount),
        }
    }

    fn object_json(obj: Object) -> serde_json::Value {
        let (owner_kind, owner_addr) = match &obj.owner {
            Owner::Address(addr) => ("address", Some(hex::encode(addr))),
            Owner::Object(id) => ("object", Some(hex::encode(id.0))),
            Owner::Shared => ("shared", None),
            Owner::Immutable => ("immutable", None),
        };
        serde_json::json!({
            "owner_kind": owner_kind,
            "owner_addr": owner_addr,
            "bytes": hex::encode(obj.encode_canonical().unwrap()),
        })
    }

    #[test]
    fn selects_largest_covering_loom_coin() {
        let coin_type = loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH);
        let signer = [0xAA; 32];
        let objects = vec![
            object_json(coin_object(1, Owner::Address(signer), 50)),
            object_json(coin_object(2, Owner::Address(signer), 500)),
            object_json(coin_object(3, Owner::Address(signer), 300)),
        ];
        let selected =
            select_loom_gas_payer_from_object_json(&objects, &coin_type, signer, 100).unwrap();
        assert_eq!(selected, ObjectId([2; 32]));
    }

    #[test]
    fn ignores_object_owned_coin_even_when_owner_id_matches_signer() {
        let coin_type = loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH);
        let signer = [0xAA; 32];
        let objects = vec![
            object_json(coin_object(1, Owner::Object(ObjectId(signer)), 1_000)),
            object_json(coin_object(2, Owner::Address(signer), 200)),
        ];

        let selected =
            select_loom_gas_payer_from_object_json(&objects, &coin_type, signer, 100).unwrap();
        assert_eq!(selected, ObjectId([2; 32]));
    }

    #[test]
    fn errors_when_no_loom_coin_covers_budget() {
        let coin_type = loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH);
        let signer = [0xAA; 32];
        let objects = vec![object_json(coin_object(1, Owner::Address(signer), 50))];
        let err =
            select_loom_gas_payer_from_object_json(&objects, &coin_type, signer, 100).unwrap_err();
        assert!(
            err.to_string()
                .contains("no signer-owned Coin<LOOM> gas payer covers budget 100"),
            "unexpected error: {err:#}"
        );
    }
}
