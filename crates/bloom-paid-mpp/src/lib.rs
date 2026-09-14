//! Tempo MPP protocol adapter for Bloom paid HTTP requests.

use alloy::consensus::SignableTransaction;
use alloy::eips::{Decodable2718, Encodable2718};
use alloy::primitives::{Address, B256, Signature};
use alloy::providers::ProviderBuilder;
use alloy::signers::{Error as SignerError, Result as SignerResult, Signer};
use alloy::sol_types::{SolStruct, eip712_domain};
use async_trait::async_trait;
use bloom_paid_http::{
    EmptyPaidHttpChainRpcResolver, NormalizedChallenge, PaidHttpChainRpcResolver,
    PaidHttpHostSigner, PaidHttpSigningFacts, ParsedRequest, usd_to_atomic_units,
};
use bloom_proto::Policy;
use mpp::client::tempo::charge::{SignOptions, TempoCharge};
use mpp::client::tempo::session::channel_ops::{
    OpenPayloadOptions, build_credential, create_open_payload, create_voucher_payload,
    resolve_chain_id, resolve_escrow, try_recover_channel,
};
use mpp::client::tempo::signing::TempoSigningMode;
use mpp::protocol::intents::SessionRequest;
use mpp::protocol::methods::tempo::fee_payer_envelope::FeePayerEnvelope78;
use mpp::protocol::methods::tempo::session::SessionCredentialPayload;
use mpp::protocol::methods::tempo::session::TempoSessionExt;
use serde_json::json;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempo_alloy::TempoNetwork;
use tempo_alloy::primitives::transaction::{AASigned, PrimitiveSignature, TempoSignature};

/// The `sign-hash` intent string every Tempo MPP host signature is authorized under.
pub const MPP_SIGN_INTENT: &str = "paid-http.mpp.sign";

#[async_trait]
pub trait PaymentBackend: Send + Sync {
    fn name(&self) -> &'static str;
    async fn prepare(
        &self,
        challenge: &NormalizedChallenge,
        request: &ParsedRequest,
        wallet: &str,
        policy: &Policy,
        request_id: &str,
    ) -> Result<PaymentExecution, String>;
}

pub struct RealMppBackend {
    pub client: reqwest::Client,
    pub rpc_resolver: Arc<dyn PaidHttpChainRpcResolver>,
    pub wallet_address: Address,
    pub host_signer: Arc<dyn PaidHttpHostSigner>,
    pub facts: PaidHttpSigningFacts,
    pub draft_path: Option<PathBuf>,
}

impl RealMppBackend {
    pub fn new(
        client: reqwest::Client,
        rpc_resolver: Arc<dyn PaidHttpChainRpcResolver>,
        wallet_address: Address,
        host_signer: Arc<dyn PaidHttpHostSigner>,
        facts: PaidHttpSigningFacts,
    ) -> Self {
        Self {
            client,
            rpc_resolver,
            wallet_address,
            host_signer,
            facts,
            draft_path: None,
        }
    }

    pub fn without_rpc_resolver(
        client: reqwest::Client,
        wallet_address: Address,
        host_signer: Arc<dyn PaidHttpHostSigner>,
        facts: PaidHttpSigningFacts,
    ) -> Self {
        Self::new(
            client,
            Arc::new(EmptyPaidHttpChainRpcResolver),
            wallet_address,
            host_signer,
            facts,
        )
    }
}

/// Adapter that satisfies the upstream Alloy signer contract by routing every
/// digest through Bloom's paid-HTTP host signing seam.
#[derive(Clone)]
struct DraftMppSigner {
    address: Address,
    chain_id: Option<u64>,
}

impl DraftMppSigner {
    fn new(address: Address, chain_id: Option<u64>) -> Self {
        Self { address, chain_id }
    }
}

#[async_trait]
impl Signer for DraftMppSigner {
    async fn sign_hash(&self, _hash: &B256) -> SignerResult<Signature> {
        Signature::from_raw(&[1_u8; 65]).map_err(SignerError::other)
    }

    fn address(&self) -> Address {
        self.address
    }

    fn chain_id(&self) -> Option<u64> {
        self.chain_id
    }

    fn set_chain_id(&mut self, chain_id: Option<u64>) {
        self.chain_id = chain_id;
    }
}

pub struct PaymentExecution {
    pub credential_metadata: serde_json::Value,
    pub header_name: &'static str,
    pub header_value: String,
}

fn persist_draft_atomically(path: &Path, authorization: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "MPP draft path has no parent directory".to_string())?;
    std::fs::create_dir_all(parent).map_err(|e| format!("create MPP draft directory: {e}"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("create temporary MPP draft: {e}"))?;
    temporary
        .write_all(authorization.as_bytes())
        .map_err(|e| format!("write temporary MPP draft: {e}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|e| format!("sync temporary MPP draft: {e}"))?;
    temporary
        .persist(path)
        .map_err(|e| format!("persist MPP unsigned draft: {}", e.error))?;
    Ok(())
}

fn draft_binding(
    authorization: &str,
    challenge: &mpp::PaymentChallenge,
    chain_id: u64,
    wallet_address: Address,
) -> Result<serde_json::Value, String> {
    let echo = serde_json::to_vec(&challenge.to_echo())
        .map_err(|error| format!("serialize MPP challenge binding: {error}"))?;
    Ok(json!({
        "schema": "bloom.machine_mpp_unsigned_draft.v1",
        "authorization_sha256": bloom_tools::sha256_hex(authorization.as_bytes()),
        "challenge_echo_sha256": bloom_tools::sha256_hex(&echo),
        "source": mpp::PaymentCredential::evm_did(chain_id, &wallet_address.to_string()),
    }))
}

fn persist_draft_binding_atomically(
    path: &Path,
    authorization: &str,
    challenge: &mpp::PaymentChallenge,
    chain_id: u64,
    wallet_address: Address,
) -> Result<(), String> {
    let envelope = json!({
        "schema": "bloom.machine_mpp_unsigned_draft_envelope.v1",
        "authorization": authorization,
        "binding": draft_binding(authorization, challenge, chain_id, wallet_address)?,
    });
    let encoded = serde_json::to_string(&envelope)
        .map_err(|error| format!("serialize MPP draft envelope: {error}"))?;
    persist_draft_atomically(path, &encoded)
}

fn validate_persisted_draft_binding(
    path: &Path,
    challenge: &mpp::PaymentChallenge,
    chain_id: u64,
    wallet_address: Address,
) -> Result<String, String> {
    let envelope: serde_json::Value = serde_json::from_slice(
        &std::fs::read(path).map_err(|error| format!("read MPP draft envelope: {error}"))?,
    )
    .map_err(|error| format!("parse MPP draft envelope: {error}"))?;
    if envelope["schema"] != "bloom.machine_mpp_unsigned_draft_envelope.v1" {
        return Err("MPP unsigned draft envelope schema is unsupported".into());
    }
    let authorization = envelope["authorization"]
        .as_str()
        .ok_or_else(|| "MPP unsigned draft envelope has no authorization".to_string())?;
    let expected = draft_binding(authorization, challenge, chain_id, wallet_address)?;
    if envelope["binding"] != expected {
        return Err("MPP unsigned draft binding differs from its canonical identity".into());
    }
    Ok(authorization.to_owned())
}

alloy::sol! {
    struct BloomMppVoucher {
        bytes32 channelId;
        uint128 cumulativeAmount;
    }
}

async fn exactize_credential(
    mut credential: mpp::PaymentCredential,
    challenge: &mpp::PaymentChallenge,
    chain_id: u64,
    host: &dyn PaidHttpHostSigner,
    facts: &PaidHttpSigningFacts,
) -> Result<mpp::PaymentCredential, String> {
    if challenge.intent.as_str() == "charge" {
        let mut payload = credential
            .charge_payload()
            .map_err(|error| format!("parse MPP charge draft: {error}"))?;
        let signed = payload
            .signed_tx()
            .ok_or_else(|| "MPP charge draft is not a transaction".to_string())?;
        payload = mpp::PaymentPayload::transaction(
            exactize_tempo_transaction(signed, "charge-transaction", host, facts).await?,
        );
        credential.payload = serde_json::to_value(payload).map_err(|error| error.to_string())?;
        return Ok(credential);
    }

    let payload: SessionCredentialPayload = credential
        .payload_as()
        .map_err(|error| format!("parse MPP session draft: {error}"))?;
    let escrow = resolve_escrow(challenge, chain_id, None)
        .map_err(|error| format!("resolve MPP session escrow: {error}"))?;
    let payload = match payload {
        SessionCredentialPayload::Open {
            payload_type,
            channel_id,
            transaction,
            authorized_signer,
            cumulative_amount,
            signature: _,
        } => {
            let transaction =
                exactize_tempo_transaction(&transaction, "session-open-transaction", host, facts)
                    .await?;
            let signature = exactize_voucher(
                &channel_id,
                &cumulative_amount,
                escrow,
                chain_id,
                "session-open-voucher",
                host,
                facts,
            )
            .await?;
            SessionCredentialPayload::Open {
                payload_type,
                channel_id,
                transaction,
                authorized_signer,
                cumulative_amount,
                signature,
            }
        }
        SessionCredentialPayload::TopUp {
            payload_type,
            channel_id,
            transaction,
            additional_deposit,
        } => SessionCredentialPayload::TopUp {
            payload_type,
            channel_id,
            transaction: exactize_tempo_transaction(
                &transaction,
                "session-topup-transaction",
                host,
                facts,
            )
            .await?,
            additional_deposit,
        },
        SessionCredentialPayload::Voucher {
            channel_id,
            cumulative_amount,
            signature: _,
        } => SessionCredentialPayload::Voucher {
            signature: exactize_voucher(
                &channel_id,
                &cumulative_amount,
                escrow,
                chain_id,
                "session-voucher",
                host,
                facts,
            )
            .await?,
            channel_id,
            cumulative_amount,
        },
        SessionCredentialPayload::Close {
            channel_id,
            cumulative_amount,
            signature: _,
        } => SessionCredentialPayload::Close {
            signature: exactize_voucher(
                &channel_id,
                &cumulative_amount,
                escrow,
                chain_id,
                "session-close-voucher",
                host,
                facts,
            )
            .await?,
            channel_id,
            cumulative_amount,
        },
    };
    credential.payload = serde_json::to_value(payload).map_err(|error| error.to_string())?;
    Ok(credential)
}

fn validate_credential_binding(
    credential: &mpp::PaymentCredential,
    challenge: &mpp::PaymentChallenge,
    chain_id: u64,
    wallet_address: Address,
) -> Result<(), String> {
    let actual_echo = serde_json::to_value(&credential.challenge)
        .map_err(|error| format!("serialize MPP draft challenge echo: {error}"))?;
    let expected_echo = serde_json::to_value(challenge.to_echo())
        .map_err(|error| format!("serialize MPP expected challenge echo: {error}"))?;
    if actual_echo != expected_echo {
        return Err("MPP unsigned draft challenge echo differs from the sealed challenge".into());
    }
    let expected_source = mpp::PaymentCredential::evm_did(chain_id, &wallet_address.to_string());
    if credential.source.as_deref() != Some(expected_source.as_str()) {
        return Err("MPP unsigned draft payer differs from the selected wallet".into());
    }
    Ok(())
}

async fn exactize_tempo_transaction(
    encoded: &str,
    signing_slot: &str,
    host: &dyn PaidHttpHostSigner,
    facts: &PaidHttpSigningFacts,
) -> Result<String, String> {
    let bytes = alloy::hex::decode(encoded).map_err(|error| format!("decode Tempo tx: {error}"))?;
    if bytes.first() == Some(&0x78) {
        let mut envelope = FeePayerEnvelope78::decode_envelope(&bytes)
            .map_err(|error| format!("decode Tempo fee-payer envelope: {error}"))?;
        let recoverable = envelope.to_recoverable_signed();
        let preimage = recoverable.tx().encoded_for_signing();
        let hash: [u8; 32] = alloy::primitives::keccak256(&preimage).into();
        let raw = host
            .sign_paid_http_payload(MPP_SIGN_INTENT, signing_slot, &preimage, hash, facts)
            .await?;
        let signature = Signature::from_raw(&raw).map_err(|error| error.to_string())?;
        envelope.signature = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature));
        return Ok(alloy::hex::encode_prefixed(envelope.encoded_envelope()));
    }
    let signed = AASigned::decode_2718(&mut bytes.as_slice())
        .map_err(|error| format!("decode signed Tempo transaction: {error}"))?;
    let tx = signed.strip_signature();
    let preimage = tx.encoded_for_signing();
    let hash: [u8; 32] = alloy::primitives::keccak256(&preimage).into();
    let raw = host
        .sign_paid_http_payload(MPP_SIGN_INTENT, signing_slot, &preimage, hash, facts)
        .await?;
    let signature = Signature::from_raw(&raw).map_err(|error| error.to_string())?;
    let signed = tx.into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
        signature,
    )));
    Ok(alloy::hex::encode_prefixed(signed.encoded_2718()))
}

async fn exactize_voucher(
    channel_id: &str,
    cumulative_amount: &str,
    escrow: Address,
    chain_id: u64,
    signing_slot: &str,
    host: &dyn PaidHttpHostSigner,
    facts: &PaidHttpSigningFacts,
) -> Result<String, String> {
    let domain = eip712_domain! {
        name: mpp::protocol::methods::tempo::voucher::DOMAIN_NAME,
        version: mpp::protocol::methods::tempo::voucher::DOMAIN_VERSION,
        chain_id: chain_id,
        verifying_contract: escrow,
    };
    let voucher = BloomMppVoucher {
        channelId: channel_id
            .parse::<B256>()
            .map_err(|error| format!("parse MPP channel id: {error}"))?,
        cumulativeAmount: cumulative_amount
            .parse::<u128>()
            .map_err(|error| format!("parse MPP cumulative amount: {error}"))?,
    };
    let mut preimage = Vec::with_capacity(66);
    preimage.extend_from_slice(&[0x19, 0x01]);
    preimage.extend_from_slice(domain.separator().as_slice());
    preimage.extend_from_slice(voucher.eip712_hash_struct().as_slice());
    let hash: [u8; 32] = alloy::primitives::keccak256(&preimage).into();
    let raw = host
        .sign_paid_http_payload(MPP_SIGN_INTENT, signing_slot, &preimage, hash, facts)
        .await?;
    Ok(alloy::hex::encode_prefixed(raw))
}

#[async_trait]
impl PaymentBackend for RealMppBackend {
    fn name(&self) -> &'static str {
        "mpp_tempo"
    }

    async fn prepare(
        &self,
        challenge: &NormalizedChallenge,
        request: &ParsedRequest,
        _wallet: &str,
        policy: &Policy,
        _request_id: &str,
    ) -> Result<PaymentExecution, String> {
        let _ = request;
        if challenge.protocol != "mpp" || challenge.network.as_deref() != Some("tempo") {
            return Err(
                "only Tempo MPP challenges can be confirmed by the real MPP backend".to_string(),
            );
        }
        let chain_id = challenge
            .chain_id
            .ok_or_else(|| "Tempo MPP challenge missing chainId".to_string())?;
        let rpc_url = self
            .rpc_resolver
            .http_rpc_url_for_chain_id(chain_id)
            .ok_or_else(|| {
                format!("no configured HTTP RPC URL for Tempo MPP chain_id {chain_id}")
            })?;
        let payment_challenge = parse_stored_mpp_challenge(challenge)?;
        let signer = DraftMppSigner::new(self.wallet_address, Some(chain_id));
        let draft_exists = match self.draft_path.as_ref() {
            Some(path) => path
                .try_exists()
                .map_err(|error| format!("inspect MPP draft envelope: {error}"))?,
            None => false,
        };
        let (draft_authorization, generated_draft) = match self.draft_path.as_ref() {
            Some(path) if draft_exists => (
                validate_persisted_draft_binding(
                    path,
                    &payment_challenge,
                    chain_id,
                    self.wallet_address,
                )?,
                false,
            ),
            Some(_) | None => {
                let credential = match challenge.intent.as_str() {
                    "charge" => {
                        prepare_charge_credential(&payment_challenge, &signer, &rpc_url).await
                    }
                    "session" => {
                        prepare_session_credential(
                            &payment_challenge,
                            &signer,
                            &rpc_url,
                            policy.payments.sessions.max_deposit_usd.and_then(|usd| {
                                usd_to_atomic_units(challenge.asset.as_deref(), usd)
                            }),
                        )
                        .await
                    }
                    other => {
                        return Err(format!("unsupported MPP intent '{other}'"));
                    }
                }
                .map_err(|e| format!("Tempo MPP credential: {e}"))?;
                let authorization = mpp::format_authorization(&credential)
                    .map_err(|e| format!("format MPP unsigned authorization: {e}"))?;
                (authorization, true)
            }
        };
        let credential = mpp::parse_authorization(&draft_authorization)
            .map_err(|e| format!("parse MPP unsigned draft: {e}"))?;
        validate_credential_binding(
            &credential,
            &payment_challenge,
            chain_id,
            self.wallet_address,
        )?;
        let exactized = exactize_credential(
            credential,
            &payment_challenge,
            chain_id,
            self.host_signer.as_ref(),
            &self.facts,
        )
        .await;
        // The production host persists the immutable semantic-slot signing
        // identity before returning either a ceremony or a signature. Persist
        // the retry draft only after that point, eliminating a crash window in
        // which an unbound draft could become the first signed payload.
        if generated_draft && let Some(path) = &self.draft_path {
            persist_draft_binding_atomically(
                path,
                &draft_authorization,
                &payment_challenge,
                chain_id,
                self.wallet_address,
            )?;
        }
        let credential = exactized?;
        let authorization = mpp::format_authorization(&credential)
            .map_err(|e| format!("format MPP Authorization: {e}"))?;
        let authorization_sha256 = bloom_tools::sha256_hex(authorization.as_bytes());
        let credential_value = serde_json::to_value(&credential)
            .map_err(|e| format!("serialize MPP credential metadata: {e}"))?;
        Ok(PaymentExecution {
            credential_metadata: json!({
                "redacted": true,
                "protocol": challenge.protocol,
                "intent": challenge.intent,
                "backend": self.name(),
                "authorization_sha256": authorization_sha256,
                "source": credential_value.get("source").cloned(),
                "payload_type": credential_value.get("payload").and_then(|p| p.get("type")).cloned(),
                "charge_id": challenge.charge_id,
                "session_id": challenge.session_id,
                "channel_id": challenge.channel_id,
                "secret_material_in_vfs": false,
                "raw_authorization_stored": false,
                "raw_signed_payload_stored": false,
                "chain_id": chain_id,
                "rpc_url_configured": true
            }),
            header_name: "Authorization",
            header_value: authorization,
        })
    }
}

async fn prepare_charge_credential(
    challenge: &mpp::PaymentChallenge,
    signer: &DraftMppSigner,
    rpc_url: &str,
) -> Result<mpp::PaymentCredential, mpp::MppError> {
    let mut charge = TempoCharge::from_challenge(challenge)?;
    if charge.memo().is_none() {
        let memo = mpp::tempo::attribution::encode(&challenge.id, &challenge.realm, None);
        charge = charge.with_memo(memo);
    }
    let signed = charge
        .sign_with_options(
            signer,
            SignOptions {
                rpc_url: Some(rpc_url.to_string()),
                signing_mode: Some(TempoSigningMode::Direct),
                ..Default::default()
            },
        )
        .await?;
    Ok(signed.into_credential())
}

async fn prepare_session_credential(
    challenge: &mpp::PaymentChallenge,
    signer: &DraftMppSigner,
    rpc_url: &str,
    max_deposit: Option<u128>,
) -> Result<mpp::PaymentCredential, mpp::MppError> {
    challenge.validate_for_session(mpp::protocol::methods::tempo::METHOD_NAME)?;
    let chain_id = resolve_chain_id(challenge);
    let escrow_contract = resolve_escrow(challenge, chain_id, None)?;
    let session_req: SessionRequest = challenge.request.decode()?;
    let payee: Address = session_req
        .recipient
        .as_deref()
        .ok_or_else(|| {
            mpp::MppError::InvalidConfig("session challenge missing recipient".to_string())
        })?
        .parse()
        .map_err(|_| mpp::MppError::InvalidConfig("invalid recipient address".to_string()))?;
    let currency: Address = session_req
        .currency
        .parse()
        .map_err(|_| mpp::MppError::InvalidConfig("invalid currency address".to_string()))?;
    let amount = session_req.parse_amount()?;
    let payer = signer.address();
    let rpc_url = rpc_url
        .parse()
        .map_err(|_| mpp::MppError::InvalidConfig("invalid RPC URL".to_string()))?;
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc_url);

    if let Some(cid_str) = session_req.channel_id()
        && let Ok(channel_id) = cid_str.parse::<B256>()
        && let Some(mut recovered) = try_recover_channel(
            &provider,
            escrow_contract,
            channel_id,
            chain_id,
            payer,
            payee,
            currency,
            payer,
        )
        .await
    {
        recovered.cumulative_amount += amount;
        let payload = create_voucher_payload(
            signer,
            recovered.channel_id,
            recovered.cumulative_amount,
            escrow_contract,
            chain_id,
        )
        .await?;
        return Ok(build_credential(challenge, payload, chain_id, payer));
    }

    let deposit = resolve_session_deposit(session_req.suggested_deposit.as_deref(), max_deposit)?;
    let (_entry, payload) = create_open_payload(
        &provider,
        signer,
        Some(&TempoSigningMode::Direct),
        payer,
        OpenPayloadOptions {
            authorized_signer: None,
            escrow_contract,
            payee,
            currency,
            deposit,
            initial_amount: amount,
            chain_id,
            fee_payer: session_req.fee_payer(),
        },
    )
    .await?;
    Ok(build_credential(challenge, payload, chain_id, payer))
}

fn resolve_session_deposit(
    suggested_deposit: Option<&str>,
    max_deposit: Option<u128>,
) -> Result<u128, mpp::MppError> {
    let suggested = suggested_deposit.and_then(|s| s.parse::<u128>().ok());
    match (suggested, max_deposit) {
        (Some(suggested), Some(max)) => Ok(suggested.min(max)),
        (Some(suggested), None) => Ok(suggested),
        (None, Some(max)) => Ok(max),
        (None, None) => Err(mpp::MppError::InvalidConfig(
            "No deposit amount available. Set `max_deposit_usd` or ensure the server challenge includes `suggestedDeposit`.".to_string(),
        )),
    }
}

fn parse_stored_mpp_challenge(
    challenge: &NormalizedChallenge,
) -> Result<mpp::PaymentChallenge, String> {
    challenge
        .headers
        .get("www-authenticate")
        .and_then(|h| {
            mpp::parse_www_authenticate_all([h.as_str()])
                .into_iter()
                .filter_map(Result::ok)
                .find(|c| c.method.as_str() == "tempo" && c.intent.as_str() == challenge.intent)
        })
        .ok_or_else(|| {
            "stored challenge is missing a parseable Tempo MPP WWW-Authenticate header".to_string()
        })
}

#[cfg(test)]
mod tests {
    use super::{
        DraftMppSigner, MPP_SIGN_INTENT, exactize_tempo_transaction,
        persist_draft_binding_atomically, validate_persisted_draft_binding,
    };
    use alloy::primitives::{Address, Bytes, TxKind, U256};
    use async_trait::async_trait;
    use bloom_paid_http::{PaidHttpHostSigner, PaidHttpSigningFacts};
    use mpp::client::tempo::charge::tx_builder::{TempoTxOptions, build_tempo_tx};
    use mpp::client::tempo::signing::{TempoSigningMode, sign_and_encode_async};
    use std::sync::Mutex;
    use tempo_alloy::primitives::transaction::Call;

    #[derive(Default)]
    struct ExactHost(Mutex<Vec<Vec<u8>>>);

    #[async_trait]
    impl PaidHttpHostSigner for ExactHost {
        async fn sign_paid_http_payload(
            &self,
            intent: &str,
            _signing_slot: &str,
            preimage: &[u8],
            signing_hash: [u8; 32],
            _facts: &PaidHttpSigningFacts,
        ) -> Result<[u8; 65], String> {
            assert_eq!(intent, MPP_SIGN_INTENT);
            assert_eq!(
                alloy::primitives::keccak256(preimage).as_slice(),
                signing_hash
            );
            self.0.lock().unwrap().push(preimage.to_vec());
            let mut signature = [2_u8; 65];
            signature[64] = 1;
            Ok(signature)
        }

        async fn sign_paid_http_hash(
            &self,
            _intent: &str,
            _signing_hash: [u8; 32],
            _facts: &PaidHttpSigningFacts,
        ) -> Result<[u8; 65], String> {
            panic!("hash-only MPP signing must not be used")
        }
    }

    #[tokio::test]
    async fn tempo_transaction_is_resigned_from_exact_encoded_preimage() {
        let tx = build_tempo_tx(TempoTxOptions {
            calls: vec![Call {
                to: TxKind::Call(Address::repeat_byte(0x22)),
                value: U256::ZERO,
                input: Bytes::from_static(b"payment"),
            }],
            chain_id: 42431,
            fee_token: Address::repeat_byte(0x33),
            nonce: 7,
            nonce_key: U256::ZERO,
            gas_limit: 500_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            fee_payer: false,
            valid_before: None,
            key_authorization: None,
        });
        let signer = DraftMppSigner::new(Address::repeat_byte(0x11), Some(42431));
        let draft = sign_and_encode_async(tx, &signer, &TempoSigningMode::Direct)
            .await
            .unwrap();
        let host = ExactHost::default();
        let signed = exactize_tempo_transaction(
            &alloy::hex::encode_prefixed(&draft),
            "charge-transaction",
            &host,
            &PaidHttpSigningFacts::default(),
        )
        .await
        .unwrap();
        assert_ne!(signed, alloy::hex::encode_prefixed(draft));
        let preimages = host.0.lock().unwrap();
        assert_eq!(preimages.len(), 1);
        assert!(!preimages[0].is_empty());
    }

    #[tokio::test]
    async fn altered_persisted_transaction_is_rejected_by_canonical_binding() {
        let challenge = mpp::PaymentChallenge::new(
            "charge-binding",
            "merchant.test",
            "tempo",
            "charge",
            mpp::Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1",
                "currency": format!("{:#x}", Address::repeat_byte(0x33)),
                "recipient": format!("{:#x}", Address::repeat_byte(0x22)),
                "methodDetails": { "chainId": 42431 }
            }))
            .unwrap(),
        );
        let wallet = Address::repeat_byte(0x11);
        let original = mpp::PaymentCredential::with_source(
            challenge.to_echo(),
            mpp::PaymentCredential::evm_did(42431, &wallet.to_string()),
            mpp::PaymentPayload::transaction("0x7601"),
        );
        let original = mpp::format_authorization(&original).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mpp-unsigned-draft");
        persist_draft_binding_atomically(&path, &original, &challenge, 42431, wallet).unwrap();

        let altered = mpp::PaymentCredential::with_source(
            challenge.to_echo(),
            mpp::PaymentCredential::evm_did(42431, &wallet.to_string()),
            mpp::PaymentPayload::transaction("0x76ffff"),
        );
        let altered = mpp::format_authorization(&altered).unwrap();
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        envelope["authorization"] = altered.into();
        std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let error = validate_persisted_draft_binding(&path, &challenge, 42431, wallet).unwrap_err();
        assert!(error.contains("canonical identity"));
    }
}
