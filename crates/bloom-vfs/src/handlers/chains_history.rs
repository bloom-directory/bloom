//! Backend-neutral history helpers for the `chains/` subtree.
//!
//! Split out of `chains.rs` to keep the main handler readable. All
//! functions return JSON byte payloads ready to be served by the VFS;
//! lookups for these paths are performed by `chains.rs` directly.
//!
//! Helpers take trait objects ([`AddressHistorySource`] /
//! [`ContractMetadataSource`]) so a future local indexer can drop in
//! without touching this module.

use std::sync::Arc;

use bloom_etherscan::{AddressHistorySource, ContractMetadataSource, DataSourceError, Sort};
use bloom_proto::prelude::Address;

use crate::handler::HandlerError;

/// Default page size — 50 records is a reasonable shell-friendly size
/// and keeps free-tier Etherscan callers well below the 10k row cap.
pub const DEFAULT_PAGE_SIZE: u32 = 50;

pub(crate) fn map_err(e: DataSourceError) -> HandlerError {
    match e {
        DataSourceError::Unsupported(s) => HandlerError::Unsupported(s),
        DataSourceError::RateLimit => HandlerError::backend("etherscan rate limited"),
        DataSourceError::NotFound(s) => HandlerError::not_found(s),
        DataSourceError::Backend(s) => HandlerError::backend(s),
        DataSourceError::Transport(s) => HandlerError::backend(s),
    }
}

fn json_bytes<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, HandlerError> {
    let mut bytes =
        serde_json::to_vec_pretty(v).map_err(|e| HandlerError::backend(e.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub async fn read_txs(
    src: &Arc<dyn AddressHistorySource>,
    chain_id: u64,
    addr: Address,
) -> Result<Vec<u8>, HandlerError> {
    let txs = src
        .get_tx_list(
            chain_id,
            addr,
            0,
            99_999_999,
            1,
            DEFAULT_PAGE_SIZE,
            Sort::Desc,
        )
        .await
        .map_err(map_err)?;
    json_bytes(&txs)
}

pub async fn read_internal_txs(
    src: &Arc<dyn AddressHistorySource>,
    chain_id: u64,
    addr: Address,
) -> Result<Vec<u8>, HandlerError> {
    let txs = src
        .get_internal_tx_list(
            chain_id,
            addr,
            0,
            99_999_999,
            1,
            DEFAULT_PAGE_SIZE,
            Sort::Desc,
        )
        .await
        .map_err(map_err)?;
    json_bytes(&txs)
}

pub async fn read_erc20_txs(
    src: &Arc<dyn AddressHistorySource>,
    chain_id: u64,
    addr: Address,
) -> Result<Vec<u8>, HandlerError> {
    let txs = src
        .get_token_tx(
            chain_id,
            addr,
            None,
            0,
            99_999_999,
            1,
            DEFAULT_PAGE_SIZE,
            Sort::Desc,
        )
        .await
        .map_err(map_err)?;
    json_bytes(&txs)
}

pub async fn read_erc721_txs(
    src: &Arc<dyn AddressHistorySource>,
    chain_id: u64,
    addr: Address,
) -> Result<Vec<u8>, HandlerError> {
    let txs = src
        .get_nft_tx(
            chain_id,
            addr,
            None,
            0,
            99_999_999,
            1,
            DEFAULT_PAGE_SIZE,
            Sort::Desc,
        )
        .await
        .map_err(map_err)?;
    json_bytes(&txs)
}

pub async fn read_contract_source(
    src: &Arc<dyn ContractMetadataSource>,
    chain_id: u64,
    addr: Address,
) -> Result<Vec<u8>, HandlerError> {
    let s = src.get_source_code(chain_id, addr).await.map_err(map_err)?;
    json_bytes(&s)
}

/// Read the raw ABI without proxy resolution.
///
/// Currently unused at the router level — the contracts surface uses
/// [`super::chains_contracts::fetch_abi_proxy_aware`] so EIP-1967
/// proxies surface the implementation ABI rather than the proxy/admin
/// one. Kept around (and tested) because future callers wanting the
/// raw proxy-side ABI for inspection can reach for it directly.
#[allow(dead_code)]
pub async fn read_contract_abi(
    src: &Arc<dyn ContractMetadataSource>,
    chain_id: u64,
    addr: Address,
) -> Result<Vec<u8>, HandlerError> {
    let abi = src.get_abi(chain_id, addr).await.map_err(map_err)?;
    json_bytes(&abi)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_etherscan::{EtherscanClient, EtherscanError};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use url::Url;

    /// Single-shot canned-response HTTP server: accepts one connection,
    /// returns `body`, then exits. Etherscan helpers issue exactly one
    /// HTTP call per public function, so this is sufficient.
    async fn spawn_canned(body: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        addr
    }

    fn history_for(addr: SocketAddr) -> Arc<dyn AddressHistorySource> {
        let url = Url::parse(&format!("http://{addr}/api")).unwrap();
        Arc::new(EtherscanClient::with_base_url("test_key".into(), url))
    }

    fn metadata_for(addr: SocketAddr) -> Arc<dyn ContractMetadataSource> {
        let url = Url::parse(&format!("http://{addr}/api")).unwrap();
        Arc::new(EtherscanClient::with_base_url("test_key".into(), url))
    }

    fn fixed_addr() -> Address {
        "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap()
    }

    // --- map_err -----------------------------------------------------------

    #[test]
    fn map_err_disabled_to_unsupported() {
        match map_err(DataSourceError::from(EtherscanError::Disabled)) {
            HandlerError::Unsupported(s) => assert!(s.contains("not supported")),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn map_err_rate_limit_to_backend() {
        match map_err(DataSourceError::from(EtherscanError::RateLimit)) {
            HandlerError::Backend(s) => assert!(s.contains("rate limited")),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn map_err_api_not_found_phrases() {
        for msg in ["Contract source code not Verified", "Address NOT FOUND"] {
            let e = map_err(DataSourceError::from(EtherscanError::Api {
                status: "0".into(),
                message: msg.into(),
            }));
            match e {
                HandlerError::NotFound(s) => assert!(s.to_ascii_lowercase().contains("not")),
                other => panic!("expected NotFound for {msg:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn map_err_api_other_to_backend() {
        let e = map_err(DataSourceError::from(EtherscanError::Api {
            status: "0".into(),
            message: "Invalid API Key".into(),
        }));
        match e {
            HandlerError::Backend(s) => {
                assert!(s.contains("Invalid API Key"));
                assert!(s.contains("etherscan"));
            }
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn map_err_invalid_response_to_backend() {
        let e = map_err(DataSourceError::from(EtherscanError::InvalidResponse(
            "garbage".into(),
        )));
        assert!(matches!(e, HandlerError::Backend(_)));
    }

    // --- read_txs ----------------------------------------------------------

    #[tokio::test]
    async fn read_txs_success_emits_pretty_json_array() {
        let body = r#"{"status":"1","message":"OK","result":[{
            "blockNumber":"19000000",
            "timeStamp":"1700000000",
            "hash":"0xabc",
            "from":"0x1111111111111111111111111111111111111111",
            "to":"0x2222222222222222222222222222222222222222",
            "value":"100",
            "gas":"21000",
            "gasPrice":"1000000000",
            "isError":"0",
            "txreceipt_status":"1",
            "input":"0x",
            "contractAddress":"",
            "cumulativeGasUsed":"21000",
            "gasUsed":"21000",
            "confirmations":"100",
            "methodId":"0x",
            "functionName":""
        }]}"#;
        let addr = spawn_canned(body).await;
        let client = history_for(addr);
        let bytes = read_txs(&client, 1, fixed_addr()).await.unwrap();

        // payload must be valid JSON, terminated with a newline.
        assert_eq!(bytes.last().copied(), Some(b'\n'));
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed.is_array());
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["hash"], "0xabc");
        assert_eq!(arr[0]["blockNumber"], "19000000");
    }

    #[tokio::test]
    async fn read_txs_empty_result_yields_empty_array() {
        // Etherscan returns status=0 with this message; the underlying
        // client converts it into a successful empty array.
        let body = r#"{"status":"0","message":"No transactions found","result":[]}"#;
        let addr = spawn_canned(body).await;
        let client = history_for(addr);
        let bytes = read_txs(&client, 1, fixed_addr()).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.as_array().map(|a| a.len()), Some(0));
    }

    #[tokio::test]
    async fn read_txs_rate_limit_maps_to_backend() {
        let body = r#"{"status":"0","message":"NOTOK","result":"Max rate limit reached"}"#;
        let addr = spawn_canned(body).await;
        let client = history_for(addr);
        let err = read_txs(&client, 1, fixed_addr()).await.unwrap_err();
        match err {
            HandlerError::Backend(s) => assert!(s.contains("rate limited")),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_txs_api_error_maps_to_backend() {
        let body = r#"{"status":"0","message":"NOTOK","result":"Invalid API Key"}"#;
        let addr = spawn_canned(body).await;
        let client = history_for(addr);
        let err = read_txs(&client, 1, fixed_addr()).await.unwrap_err();
        match err {
            HandlerError::Backend(s) => assert!(s.contains("Invalid API Key")),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    // --- read_internal_txs / read_erc20_txs / read_erc721_txs --------------

    #[tokio::test]
    async fn read_internal_txs_decodes_array() {
        let body = r#"{"status":"1","message":"OK","result":[{
            "blockNumber":"1",
            "timeStamp":"1",
            "hash":"0xinternal",
            "from":"0x1111111111111111111111111111111111111111",
            "to":"0x2222222222222222222222222222222222222222",
            "value":"0",
            "gas":"0",
            "gasPrice":"0",
            "isError":"0",
            "txreceipt_status":"",
            "input":"0x",
            "contractAddress":"",
            "cumulativeGasUsed":"",
            "gasUsed":"0",
            "confirmations":"",
            "methodId":"",
            "functionName":""
        }]}"#;
        let addr = spawn_canned(body).await;
        let client = history_for(addr);
        let bytes = read_internal_txs(&client, 1, fixed_addr()).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed[0]["hash"], "0xinternal");
    }

    #[tokio::test]
    async fn read_erc20_txs_decodes_array() {
        let body = r#"{"status":"1","message":"OK","result":[{
            "blockNumber":"1",
            "timeStamp":"1",
            "hash":"0xerc20",
            "from":"0x1111111111111111111111111111111111111111",
            "contractAddress":"0x3333333333333333333333333333333333333333",
            "to":"0x2222222222222222222222222222222222222222",
            "value":"0",
            "tokenName":"Mock",
            "tokenSymbol":"MCK",
            "tokenDecimal":"18",
            "transactionIndex":"0",
            "gas":"0",
            "gasPrice":"0",
            "gasUsed":"0",
            "cumulativeGasUsed":"0",
            "input":"0x"
        }]}"#;
        let addr = spawn_canned(body).await;
        let client = history_for(addr);
        let bytes = read_erc20_txs(&client, 1, fixed_addr()).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed[0]["tokenSymbol"], "MCK");
    }

    #[tokio::test]
    async fn read_erc721_txs_decodes_array() {
        let body = r#"{"status":"1","message":"OK","result":[{
            "blockNumber":"1",
            "timeStamp":"1",
            "hash":"0xnft",
            "from":"0x1111111111111111111111111111111111111111",
            "contractAddress":"0x3333333333333333333333333333333333333333",
            "to":"0x2222222222222222222222222222222222222222",
            "value":"0",
            "tokenName":"NFT",
            "tokenSymbol":"NFT",
            "tokenDecimal":"0",
            "transactionIndex":"0",
            "gas":"0",
            "gasPrice":"0",
            "gasUsed":"0",
            "cumulativeGasUsed":"0",
            "input":"0x"
        }]}"#;
        let addr = spawn_canned(body).await;
        let client = history_for(addr);
        let bytes = read_erc721_txs(&client, 1, fixed_addr()).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed[0]["hash"], "0xnft");
    }

    // --- read_contract_source / read_contract_abi --------------------------

    #[tokio::test]
    async fn read_contract_source_emits_serialized_record() {
        let body = r#"{"status":"1","message":"OK","result":[{
            "SourceCode":"contract X {}",
            "ABI":"[]",
            "ContractName":"X",
            "CompilerVersion":"v0.8.20",
            "OptimizationUsed":"1",
            "Runs":"200",
            "ConstructorArguments":"",
            "EVMVersion":"london",
            "Library":"",
            "LicenseType":"MIT",
            "Proxy":"0",
            "Implementation":"",
            "SwarmSource":""
        }]}"#;
        let addr = spawn_canned(body).await;
        let client = metadata_for(addr);
        let bytes = read_contract_source(&client, 1, fixed_addr())
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // ContractSource serializes with PascalCase field names.
        assert_eq!(parsed["ContractName"], "X");
        assert_eq!(parsed["Proxy"], "0");
    }

    #[tokio::test]
    async fn read_contract_source_unverified_maps_to_not_found() {
        let body =
            r#"{"status":"0","message":"NOTOK","result":"Contract source code not verified"}"#;
        let addr = spawn_canned(body).await;
        let client = metadata_for(addr);
        let err = read_contract_source(&client, 1, fixed_addr())
            .await
            .unwrap_err();
        match err {
            HandlerError::NotFound(s) => {
                assert!(s.to_ascii_lowercase().contains("not verified"))
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_contract_abi_emits_array_payload() {
        let body = r#"{"status":"1","message":"OK","result":"[{\"type\":\"function\",\"name\":\"foo\"}]"}"#;
        let addr = spawn_canned(body).await;
        let client = metadata_for(addr);
        let bytes = read_contract_abi(&client, 1, fixed_addr()).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed[0]["name"], "foo");
        assert_eq!(bytes.last().copied(), Some(b'\n'));
    }

    #[tokio::test]
    async fn read_contract_abi_unverified_maps_to_not_found() {
        // get_abi raises Api{status:"0", message:"Contract source code not verified"}
        // when the result is the literal sentinel. map_err should surface NotFound.
        let body = r#"{"status":"1","message":"OK","result":"Contract source code not verified"}"#;
        let addr = spawn_canned(body).await;
        let client = metadata_for(addr);
        let err = read_contract_abi(&client, 1, fixed_addr())
            .await
            .unwrap_err();
        match err {
            HandlerError::NotFound(_) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    // --- payload conventions -----------------------------------------------

    #[test]
    fn json_bytes_is_pretty_and_newline_terminated() {
        let value = serde_json::json!({"a": 1, "b": [2, 3]});
        let bytes = json_bytes(&value).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        // serde_json::to_vec_pretty inserts a newline between fields.
        assert!(s.contains('\n'));
        assert!(s.ends_with('\n'));
    }

    #[test]
    fn default_page_size_is_50() {
        assert_eq!(DEFAULT_PAGE_SIZE, 50);
    }
}
