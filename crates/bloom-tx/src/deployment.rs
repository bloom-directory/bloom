//! Strict, normalized developer-tool transaction input. No signing credentials.
use alloy::primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentTransaction {
    pub chain_id: u64,
    pub from: Address,
    pub to: Option<Address>,
    pub data: String,
    pub value: U256,
    pub nonce: Option<u64>,
    pub gas: Option<u64>,
    pub gas_price: Option<u128>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
}

fn quantity(value: &Value) -> Result<U256, String> {
    let s = value.as_str().ok_or("quantities must be hex strings")?;
    let h = s.strip_prefix("0x").ok_or("quantity requires 0x prefix")?;
    if h.is_empty()
        || (h.len() > 1 && h.starts_with('0'))
        || !h.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("quantity must be canonical unsigned hex".into());
    }
    U256::from_str_radix(h, 16).map_err(|_| "quantity exceeds 256 bits".into())
}

impl DeploymentTransaction {
    pub fn parse(
        value: &Value,
        sender: Address,
        chain_id: u64,
        legacy: bool,
    ) -> Result<Self, String> {
        let o = value.as_object().ok_or("transaction must be an object")?;
        for key in o.keys() {
            if ![
                "from",
                "to",
                "data",
                "input",
                "value",
                "nonce",
                "gas",
                "gasPrice",
                "maxFeePerGas",
                "maxPriorityFeePerGas",
                "chainId",
                "type",
                "accessList",
            ]
            .contains(&key.as_str())
            {
                return Err(format!("unsupported transaction field: {key}"));
            }
        }
        let q = |key: &str| o.get(key).map(quantity).transpose();
        let u64q = |key: &str| -> Result<Option<u64>, String> {
            q(key)?
                .map(|n| n.try_into().map_err(|_| format!("{key} exceeds u64")))
                .transpose()
        };
        let u128q = |key: &str| -> Result<Option<u128>, String> {
            q(key)?
                .map(|n| n.try_into().map_err(|_| format!("{key} exceeds u128")))
                .transpose()
        };
        let addr = |key: &str| -> Result<Address, String> {
            o.get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{key} must be an address"))?
                .parse()
                .map_err(|_| format!("invalid {key} address"))
        };
        let from = addr("from")?;
        if from != sender {
            return Err("from does not match the selected Bloom wallet".into());
        }
        if u64q("chainId")?.is_some_and(|id| id != chain_id) {
            return Err("chainId does not match the selected Bloom chain".into());
        }
        if o.get("accessList")
            .is_some_and(|v| v.as_array().is_none_or(|a| !a.is_empty()))
        {
            return Err("nonempty access lists are not supported".into());
        }
        let data_field = |key: &str| -> Result<Option<String>, String> {
            o.get(key)
                .map(|v| {
                    let s = v.as_str().ok_or("data must be hex bytes")?;
                    let h = s.strip_prefix("0x").ok_or("data requires 0x prefix")?;
                    hex::decode(h)
                        .map(|b| format!("0x{}", hex::encode(b)))
                        .map_err(|_| "invalid data hex".into())
                })
                .transpose()
        };
        let data = data_field("data")?;
        let input = data_field("input")?;
        if data
            .as_ref()
            .zip(input.as_ref())
            .is_some_and(|(a, b)| a != b)
        {
            return Err("conflicting data and input".into());
        }
        let data = data.or(input).unwrap_or_else(|| "0x".into());
        let to = if o.get("to").is_none_or(Value::is_null) {
            None
        } else {
            Some(addr("to")?)
        };
        if to.is_none() && data == "0x" {
            return Err("creation requires nonempty initcode".into());
        }
        let gas_price = u128q("gasPrice")?;
        let max_fee_per_gas = u128q("maxFeePerGas")?;
        let max_priority_fee_per_gas = u128q("maxPriorityFeePerGas")?;
        let kind = u64q("type")?.unwrap_or(if gas_price.is_some() || legacy { 0 } else { 2 });
        if ![0, 2].contains(&kind) {
            return Err("only legacy (0x0) and EIP-1559 (0x2) transactions are supported".into());
        }
        if (kind == 2 && (legacy || gas_price.is_some()))
            || (kind == 0 && (max_fee_per_gas.is_some() || max_priority_fee_per_gas.is_some()))
        {
            return Err("transaction type and fee fields conflict".into());
        }
        if max_fee_per_gas.is_some() != max_priority_fee_per_gas.is_some() {
            return Err("supply both EIP-1559 fee fields".into());
        }
        if max_fee_per_gas
            .zip(max_priority_fee_per_gas)
            .is_some_and(|(max, tip)| tip > max)
        {
            return Err("priority fee exceeds maximum fee".into());
        }
        // An explicit legacy request without gasPrice cannot be represented by the
        // normalized fee shape; require it rather than silently selecting type 2.
        if kind == 0 && !legacy && gas_price.is_none() {
            return Err("legacy requests require gasPrice on an EIP-1559 chain".into());
        }
        if !o.contains_key("nonce") {
            return Err("deployment RPC requires an explicit nonce for safe retries; use Foundry or an ethers NonceManager".into());
        }
        let gas = u64q("gas")?;
        if gas == Some(0) {
            return Err("gas must be positive".into());
        }
        Ok(Self {
            chain_id,
            from,
            to,
            data,
            value: q("value")?.unwrap_or_default(),
            nonce: u64q("nonce")?,
            gas,
            gas_price,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        })
    }

    pub fn id(&self, wallet: &str, chain: &str) -> String {
        let bytes = serde_json::to_vec(&(wallet, chain, self)).expect("serializable transaction");
        format!("deploy-{}", blake3::hash(&bytes).to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn parse(v: Value) -> Result<DeploymentTransaction, String> {
        DeploymentTransaction::parse(&v, Address::ZERO, 31337, false)
    }
    #[test]
    fn strict_fields_and_semantic_identity() {
        let base = json!({"from":Address::ZERO,"data":"0x6000","nonce":"0x0","value":"0x7b","gas":"0x186a0"});
        let tx = parse(base.clone()).unwrap();
        assert!(tx.to.is_none());
        assert_eq!(tx.value, U256::from(123));
        assert_eq!(tx.gas, Some(100000));
        let mut alias = base.clone();
        alias.as_object_mut().unwrap().remove("data");
        alias["input"] = json!("0x6000");
        alias["to"] = Value::Null;
        assert_eq!(
            tx.id("alice", "anvil"),
            parse(alias).unwrap().id("alice", "anvil")
        );
        for (field, value) in [
            ("from", json!("0x1111111111111111111111111111111111111111")),
            ("chainId", json!("0x1")),
            ("nonce", json!("0x00")),
            ("nonce", json!(-1)),
            ("gas", json!("0x0")),
            ("value", json!("-1")),
            ("input", json!("0x00")),
            ("accessList", json!([{}])),
            ("authorizationList", json!([])),
            ("blobVersionedHashes", json!([])),
            ("type", json!("0x1")),
            ("maxFeePerGas", json!("0x1")),
            ("unknown", json!(true)),
        ] {
            let mut invalid = base.clone();
            invalid[field] = value;
            assert!(parse(invalid).is_err(), "accepted {field}");
        }
        let mut no_nonce = base.clone();
        no_nonce.as_object_mut().unwrap().remove("nonce");
        assert!(parse(no_nonce).is_err());
        let mut call = base;
        call["to"] = json!(Address::ZERO);
        assert!(parse(call).unwrap().to.is_some());
    }
}
