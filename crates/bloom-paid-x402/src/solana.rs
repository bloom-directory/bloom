//! V2 exact SPL-USDC payments. Machine constructs only a checked transfer,
//! bounded compute budget and uniqueness memo; Broker/Signer signs its bytes.
//! No merchant-supplied transaction or wallet key is accepted here.
use super::{B64, X402PaymentCredential, X402SignContext, persist_draft_atomically};
use base64::Engine;
use bloom_solana::SolanaRpcClient;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use solana_instruction::{AccountMeta, Instruction};
use solana_message::{VersionedMessage, v0};
use solana_pubkey::Pubkey;
use std::str::FromStr;

const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const MEMO: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const COMPUTE: &str = "ComputeBudget111111111111111111111111111111";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Draft {
    owner: String,
    accepted: Value,
    resource: Value,
    blockhash: String,
    last_valid_block_height: u64,
    nonce: String,
}

fn pubkey(s: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(s).map_err(|e| format!("invalid Solana public key: {e}"))
}

fn associated_account(owner: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[
            owner.as_ref(),
            pubkey(TOKEN).unwrap().as_ref(),
            pubkey(USDC).unwrap().as_ref(),
        ],
        &pubkey(ATA).unwrap(),
    )
    .0
}

fn transfer_message(draft: &Draft) -> Result<Vec<u8>, String> {
    if B64
        .decode(&draft.nonce)
        .map_err(|_| "invalid payment nonce")?
        .len()
        != 32
    {
        return Err("invalid payment nonce length".into());
    }
    let owner = pubkey(&draft.owner)?;
    let recipient = pubkey(draft.accepted["payTo"].as_str().ok_or("missing payTo")?)?;
    let payer = pubkey(
        draft.accepted["extra"]["feePayer"]
            .as_str()
            .ok_or("missing facilitator feePayer")?,
    )?;
    if payer == owner {
        return Err("facilitator fee payer must differ from buyer".into());
    }
    if draft.accepted["scheme"] != "exact" || draft.accepted["asset"] != USDC {
        return Err("Solana x402 currently supports exact SPL USDC only".into());
    }
    let amount: u64 = draft.accepted["amount"]
        .as_str()
        .ok_or("missing integer amount")?
        .parse()
        .map_err(|_| "invalid Solana payment amount")?;
    if amount == 0 {
        return Err("zero Solana payment amount".into());
    }
    let mut data = vec![12]; // SPL Token TransferChecked, six decimals.
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(6);
    let transfer = Instruction {
        program_id: pubkey(TOKEN)?,
        accounts: vec![
            AccountMeta::new(associated_account(&owner), false),
            AccountMeta::new_readonly(pubkey(USDC)?, false),
            AccountMeta::new(associated_account(&recipient), false),
            AccountMeta::new_readonly(owner, true),
        ],
        data,
    };
    let mut limit = vec![2];
    limit.extend_from_slice(&100_000u32.to_le_bytes());
    let mut price = vec![3];
    price.extend_from_slice(&1u64.to_le_bytes());
    let instructions = [
        Instruction::new_with_bytes(pubkey(COMPUTE)?, &limit, vec![]),
        Instruction::new_with_bytes(pubkey(COMPUTE)?, &price, vec![]),
        transfer,
        Instruction::new_with_bytes(pubkey(MEMO)?, draft.nonce.as_bytes(), vec![]),
    ];
    let blockhash = draft
        .blockhash
        .parse()
        .map_err(|_| "invalid recent blockhash")?;
    let message = v0::Message::try_compile(&payer, &instructions, &[], blockhash)
        .map_err(|e| e.to_string())?;
    if message.header.num_required_signatures != 2 || message.account_keys[..2] != [payer, owner] {
        return Err("unexpected Solana payment signer layout".into());
    }
    Ok(VersionedMessage::V0(message).serialize())
}

fn transaction(message: &[u8], signature: &[u8; 64]) -> String {
    // Wire format: short-vec signature count, fee-payer placeholder, buyer
    // signature, then the versioned message. The facilitator signs slot zero.
    let mut bytes = vec![2];
    bytes.extend_from_slice(&[0; 64]);
    bytes.extend_from_slice(signature);
    bytes.extend_from_slice(message);
    B64.encode(bytes)
}

async fn rpc(client: &SolanaRpcClient, method: &str, params: Value) -> Result<Value, String> {
    client
        .call_raw(method, &params)
        .await
        .map_err(|e| e.to_string())
}

pub(super) async fn sign(ctx: &X402SignContext<'_>) -> Result<X402PaymentCredential, String> {
    let owner = ctx
        .solana_address
        .ok_or("Solana payment account is not selected")?;
    let network = ctx
        .requirement
        .network
        .as_deref()
        .ok_or("missing Solana network")?;
    let spec = ctx
        .rpc_resolver
        .solana_spec(network)
        .ok_or("no unambiguous genesis-pinned Solana RPC for this payment network")?;
    let genesis = spec
        .expected_genesis_base58
        .as_deref()
        .ok_or("Solana RPC requires a genesis pin")?;
    if network != format!("solana:{}", genesis.get(..32).ok_or("invalid genesis pin")?) {
        return Err("Solana network differs from configured genesis".into());
    }
    let client = SolanaRpcClient::build(&spec).map_err(|e| e.to_string())?;
    client
        .verify_all_genesis(genesis)
        .await
        .map_err(|e| e.to_string())?;
    let required = super::parse_payment_required(ctx.challenge)?;
    let required = match required {
        x402_types::proto::PaymentRequired::V2(required) => {
            serde_json::to_value(required).map_err(|e| e.to_string())?
        }
        _ => return Err("Solana x402 currently supports version 2 only".into()),
    };
    let accepted = ctx.requirement.raw.clone();
    if !required["accepts"]
        .as_array()
        .is_some_and(|a| a.contains(&accepted))
        || accepted["network"] != network
    {
        return Err("selected Solana requirement is absent from the challenge".into());
    }
    let resource = required["resource"].clone();
    if resource["url"].as_str() != Some(ctx.request.url.as_str()) {
        return Err("Solana challenge resource differs from the requested URL".into());
    }
    let draft: Draft = match std::fs::read_to_string(ctx.draft_path) {
        Ok(bytes) => serde_json::from_str(&bytes)
            .map_err(|e| format!("invalid persisted Solana draft: {e}"))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let latest = rpc(
                &client,
                "getLatestBlockhash",
                json!([{"commitment":"confirmed"}]),
            )
            .await?;
            let draft = Draft {
                owner: owner.into(),
                accepted: accepted.clone(),
                resource: resource.clone(),
                blockhash: latest["value"]["blockhash"]
                    .as_str()
                    .ok_or("RPC omitted blockhash")?
                    .into(),
                last_valid_block_height: latest["value"]["lastValidBlockHeight"]
                    .as_u64()
                    .ok_or("RPC omitted lastValidBlockHeight")?,
                nonce: B64.encode(rand::random::<[u8; 32]>()),
            };
            transfer_message(&draft)?;
            persist_draft_atomically(
                ctx.draft_path,
                &serde_json::to_string(&draft).map_err(|e| e.to_string())?,
            )?;
            draft
        }
        Err(e) => return Err(format!("read Solana draft: {e}")),
    };
    if draft.owner != owner || draft.accepted != accepted || draft.resource != resource {
        return Err("Solana payment retry differs from its frozen account or challenge".into());
    }
    let message = transfer_message(&draft)?;
    let height = rpc(
        &client,
        "getBlockHeight",
        json!([{"commitment":"confirmed"}]),
    )
    .await?
    .as_u64()
    .ok_or("invalid block height")?;
    let valid = rpc(
        &client,
        "isBlockhashValid",
        json!([draft.blockhash, {"commitment":"confirmed"}]),
    )
    .await?;
    if height > draft.last_valid_block_height || valid["value"] != true {
        return Err(
            "Solana payment blockhash expired; cancel this unpaid request and create a fresh one"
                .into(),
        );
    }
    let simulation = rpc(
        &client,
        "simulateTransaction",
        json!([transaction(&message, &[0; 64]),
        {"encoding":"base64","sigVerify":false,"commitment":"confirmed"}]),
    )
    .await?;
    if !simulation["value"]["err"].is_null() || !simulation["value"].is_object() {
        return Err(format!(
            "Solana payment simulation failed: {}",
            simulation["value"]["err"]
        ));
    }
    let signature = ctx
        .host_signer
        .sign_paid_http_solana_message(&message, ctx.facts)
        .await?;
    VerifyingKey::from_bytes(&pubkey(owner)?.to_bytes())
        .map_err(|e| e.to_string())?
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| "Signer returned an invalid Solana payment signature")?;
    // Recheck expiry and cluster after an approval/signing round trip.
    client
        .verify_all_genesis(genesis)
        .await
        .map_err(|e| e.to_string())?;
    let valid = rpc(
        &client,
        "isBlockhashValid",
        json!([draft.blockhash, {"commitment":"confirmed"}]),
    )
    .await?;
    if valid["value"] != true {
        return Err("Solana payment blockhash expired before transmission".into());
    }
    let mut header = json!({"x402Version":2,"accepted":accepted,"resource":resource,
        "payload":{"transaction":transaction(&message, &signature)}});
    if let Some(extensions) = required.get("extensions") {
        header["extensions"] = extensions.clone();
    }
    Ok(X402PaymentCredential {
        header_name: "Payment-Signature",
        header_value: B64.encode(serde_json::to_vec(&header).map_err(|e| e.to_string())?),
        public_metadata: json!({"signer_backend":"solana/host-signing","wallet":ctx.wallet,"address":owner,
            "network":network,"asset":USDC,"amount":accepted["amount"],"pay_to":accepted["payTo"],"signature":"redacted"}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_paid_http::{
        PaidHttpChainRpcResolver, PaidHttpHostSigner, PaidHttpSigningFacts, normalize_challenge,
        parse_request,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const GENESIS: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
    const NETWORK: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
    struct Host {
        messages: Mutex<Vec<Vec<u8>>>,
    }
    #[async_trait::async_trait]
    impl PaidHttpHostSigner for Host {
        async fn sign_paid_http_solana_message(
            &self,
            message: &[u8],
            _: &PaidHttpSigningFacts,
        ) -> Result<[u8; 64], String> {
            self.messages.lock().unwrap().push(message.to_vec());
            Ok(SigningKey::from_bytes(&[7; 32]).sign(message).to_bytes())
        }
        async fn sign_paid_http_payload(
            &self,
            _: &str,
            _: &str,
            _: &[u8],
            _: [u8; 32],
            _: &PaidHttpSigningFacts,
        ) -> Result<[u8; 65], String> {
            panic!("Solana must not use an EVM signer")
        }
        async fn sign_paid_http_hash(
            &self,
            _: &str,
            _: [u8; 32],
            _: &PaidHttpSigningFacts,
        ) -> Result<[u8; 65], String> {
            panic!("Solana must not use hash-only signing")
        }
    }
    struct Resolver(bloom_solana::SolanaSpec);
    impl PaidHttpChainRpcResolver for Resolver {
        fn http_rpc_urls_for_chain_id(&self, _: u64) -> Vec<String> {
            vec![]
        }
        fn solana_spec(&self, network: &str) -> Option<bloom_solana::SolanaSpec> {
            (network == NETWORK).then(|| self.0.clone())
        }
    }

    async fn fixture(mode: &'static str) -> (Resolver, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut data = vec![];
                    let (header_len, content_len) = loop {
                        let mut buf = [0; 4096];
                        let n = stream.read(&mut buf).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        data.extend_from_slice(&buf[..n]);
                        if let Some(pos) = data.windows(4).position(|s| s == b"\r\n\r\n") {
                            let headers = String::from_utf8_lossy(&data[..pos]);
                            let len = headers
                                .lines()
                                .find_map(|line| {
                                    line.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .map(|s| s.trim().parse::<usize>().unwrap())
                                })
                                .unwrap();
                            break (pos + 4, len);
                        }
                    };
                    while data.len() < header_len + content_len {
                        let mut buf = [0; 4096];
                        let n = stream.read(&mut buf).await.unwrap();
                        data.extend_from_slice(&buf[..n]);
                    }
                    let request: Value =
                        serde_json::from_slice(&data[header_len..header_len + content_len])
                            .unwrap();
                    let result = match request["method"].as_str().unwrap() {
                        "getGenesisHash" => json!(if mode == "wrong-cluster" {
                            "wrong"
                        } else {
                            GENESIS
                        }),
                        "getLatestBlockhash" => {
                            json!({"value":{"blockhash":Pubkey::new_from_array([9;32]).to_string(),"lastValidBlockHeight":100}})
                        }
                        "getBlockHeight" => json!(1),
                        "isBlockhashValid" => json!({"value":mode!="expired"}),
                        "simulateTransaction" => {
                            json!({"value":{"err":if mode=="simulation-failed" {json!("InsufficientFunds")} else {Value::Null}}})
                        }
                        other => panic!("unexpected RPC {other}"),
                    };
                    let body = serde_json::to_vec(
                        &json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
                    )
                    .unwrap();
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(headers.as_bytes()).await.unwrap();
                    stream.write_all(&body).await.unwrap();
                });
            }
        });
        (
            Resolver(bloom_solana::SolanaSpec {
                name: "fixture".into(),
                expected_genesis_base58: Some(GENESIS.into()),
                endpoints: vec![bloom_solana::EndpointSpec {
                    url: endpoint,
                    weight: 100,
                    cu_per_sec: None,
                    max_rps: None,
                    http_only: true,
                }],
            }),
            task,
        )
    }

    async fn exercise(mode: &'static str) {
        let (resolver, task) = fixture(mode).await;
        let owner =
            Pubkey::new_from_array(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes())
                .to_string();
        let request =
            parse_request("GET https://merchant.test/flights wallet=alice max_amount_usd=0.10")
                .unwrap();
        let required = json!({"x402Version":2,"resource":{"url":request.url},"accepts":[{"scheme":"exact","network":NETWORK,"asset":USDC,"amount":"100000","payTo":Pubkey::new_from_array([5;32]).to_string(),"maxTimeoutSeconds":60,"extra":{"feePayer":Pubkey::new_from_array([4;32]).to_string()}}]});
        let challenge = normalize_challenge(
            &reqwest::header::HeaderMap::new(),
            &serde_json::to_vec(&required).unwrap(),
            &request.url,
        );
        let host = Arc::new(Host {
            messages: Mutex::new(vec![]),
        });
        let host_trait: Arc<dyn PaidHttpHostSigner> = host.clone();
        let facts = PaidHttpSigningFacts::default();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("draft");
        let ctx = X402SignContext {
            wallet: "alice",
            request_id: "req-1",
            request: &request,
            challenge: &challenge,
            requirement: &challenge.accepts[0],
            rpc_resolver: &resolver,
            wallet_address: alloy::primitives::Address::ZERO,
            solana_address: Some(&owner),
            host_signer: &host_trait,
            facts: &facts,
            draft_path: &path,
        };
        let result = sign(&ctx).await;
        if mode == "ok" {
            let first = result.unwrap();
            let second = sign(&ctx).await.unwrap();
            assert_eq!(first.header_value, second.header_value);
            let header: Value =
                serde_json::from_slice(&B64.decode(first.header_value).unwrap()).unwrap();
            assert_eq!(header["accepted"], required["accepts"][0]);
            let tx = B64
                .decode(header["payload"]["transaction"].as_str().unwrap())
                .unwrap();
            assert_eq!(tx[0], 2);
            assert_eq!(&tx[1..65], &[0; 64]);
            let message: VersionedMessage = wincode::deserialize(&tx[129..]).unwrap();
            assert_eq!(message.header().num_required_signatures, 2);
            let keys = message.static_account_keys();
            assert_eq!(keys[1].to_string(), owner);
            let transfer = &message.instructions()[2];
            assert_eq!(
                keys[transfer.program_id_index as usize],
                pubkey(TOKEN).unwrap()
            );
            assert_eq!(
                transfer.data,
                [vec![12], 100000u64.to_le_bytes().to_vec(), vec![6]].concat()
            );
            let mut stored: Draft =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            stored.accepted["amount"] = json!("200000");
            std::fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
            assert!(sign(&ctx).await.err().unwrap().contains("frozen"));
            assert_eq!(host.messages.lock().unwrap().len(), 2);
        } else {
            assert!(result.is_err());
            assert!(host.messages.lock().unwrap().is_empty());
        }
        task.abort();
    }
    #[tokio::test]
    async fn exact_solana_wire_and_retry_binding() {
        exercise("ok").await;
    }
    #[tokio::test]
    async fn expired_draft_never_signs() {
        exercise("expired").await;
    }
    #[tokio::test]
    async fn wrong_cluster_never_signs() {
        exercise("wrong-cluster").await;
    }
    #[tokio::test]
    async fn failed_simulation_never_signs() {
        exercise("simulation-failed").await;
    }
}
