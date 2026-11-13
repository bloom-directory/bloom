//! Built gasless component through the existing disposable real-triad fixture.
use super::*;

pub(super) const USDC: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";

pub(super) fn quote_response(request: &HttpRequest, serial: u64) -> Vec<u8> {
    let serial = serial
        + if std::env::var("BLOOM_PM80_BUY_PHASE").as_deref() == Ok("restart") {
            1000
        } else {
            0
        };
    let input: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(input["originChainId"], 8453);
    assert_eq!(input["originCurrency"], USDC);
    let owner = input["user"].as_str().unwrap();
    let amount = input["amount"].as_str().unwrap().parse::<u64>().unwrap();
    let mut quote: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/gasless-relay-quote.json"
    ))
    .unwrap();
    let old_owner = quote["details"]["sender"].as_str().unwrap().to_owned();
    fn replace(value: &mut serde_json::Value, replacements: &[(&str, String)]) {
        match value {
            serde_json::Value::String(text) => {
                if let Some((_, replacement)) =
                    replacements.iter().find(|(old, _)| text.as_str() == *old)
                {
                    *text = replacement.clone();
                }
            }
            serde_json::Value::Object(map) => {
                map.values_mut().for_each(|v| replace(v, replacements))
            }
            serde_json::Value::Array(values) => {
                values.iter_mut().for_each(|v| replace(v, replacements))
            }
            _ => {}
        }
    }
    replace(
        &mut quote,
        &[
            (&old_owner, owner.into()),
            ("100000000", amount.to_string()),
            ("98000000", (amount * 98 / 100).to_string()),
            ("97500000", (amount * 975 / 1000).to_string()),
            (
                &format!("0x{}", "aa".repeat(32)),
                format!("0x{:064x}", serial + 1),
            ),
            (
                &format!("0x{}", "bb".repeat(32)),
                format!("0x{:064x}", serial + 101),
            ),
        ],
    );
    let request_id = quote["steps"][0]["requestId"].as_str().unwrap().to_owned();
    quote["steps"][0]["items"][0]["check"]["endpoint"] =
        serde_json::json!(format!("/intents/status/v3?requestId={request_id}"));
    quote["steps"][0]["items"][0]["data"]["sign"]["value"]["validBefore"] = serde_json::json!(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300
    );
    serde_json::to_vec(&quote).unwrap()
}

#[test]
fn mock_quote_keeps_the_status_endpoint_bound_to_the_distinct_request() {
    let request = HttpRequest {
        method: "POST".into(),
        url: "https://api.relay.link/quote/v2".into(),
        headers: vec![],
        body: serde_json::to_vec(&serde_json::json!({
            "originChainId":8453, "originCurrency":USDC, "amount":"1000000",
            "user":"0x1111111111111111111111111111111111111111"
        }))
        .unwrap(),
    };
    let first: serde_json::Value = serde_json::from_slice(&quote_response(&request, 0)).unwrap();
    let second: serde_json::Value = serde_json::from_slice(&quote_response(&request, 1)).unwrap();
    assert_ne!(
        first["steps"][0]["requestId"],
        second["steps"][0]["requestId"]
    );
    assert_ne!(
        first["steps"][0]["items"][0]["data"]["sign"]["value"]["nonce"],
        second["steps"][0]["items"][0]["data"]["sign"]["value"]["nonce"]
    );
    for quote in [first, second] {
        let id = quote["steps"][0]["requestId"].as_str().unwrap();
        let item = &quote["steps"][0]["items"][0];
        assert_eq!(item["data"]["post"]["body"]["requestId"], id);
        assert_eq!(
            item["check"]["endpoint"],
            format!("/intents/status/v3?requestId={id}")
        );
        assert_eq!(item["data"]["sign"]["value"]["value"], "1000000");
    }
}

pub(super) fn body(amount: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "origin":{"chain":"base","chain_id":8453,"currency":USDC,"decimals":6,
            "permit_domain":{"name":"USD Coin","version":"2"}},
        "destination":{"chain":"optimism","chain_id":10,
            "currency":"0x0b2c639c533813f4aa9d7837caf62653d097ff85","decimals":6},
        "amount":amount,"minimum_output":"0.9"
    }))
    .unwrap()
}
