//! Tempo MPP protocol adapter for Bloom paid HTTP requests.

use alloy::primitives::{Address, B256, Signature};
use alloy::providers::ProviderBuilder;
use alloy::signers::{Error as SignerError, Result as SignerResult, Signer};
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
use mpp::protocol::methods::tempo::session::TempoSessionExt;
use serde_json::json;
use std::sync::Arc;
use tempo_alloy::TempoNetwork;

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
struct HostMppSigner {
    host: Arc<dyn PaidHttpHostSigner>,
    address: Address,
    facts: Arc<PaidHttpSigningFacts>,
    chain_id: Option<u64>,
}

impl HostMppSigner {
    fn new(
        host: Arc<dyn PaidHttpHostSigner>,
        address: Address,
        facts: PaidHttpSigningFacts,
        chain_id: Option<u64>,
    ) -> Self {
        Self {
            host,
            address,
            facts: Arc::new(facts),
            chain_id,
        }
    }
}

#[async_trait]
impl Signer for HostMppSigner {
    async fn sign_hash(&self, hash: &B256) -> SignerResult<Signature> {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(hash.as_slice());
        let raw = self
            .host
            .sign_paid_http_hash(MPP_SIGN_INTENT, digest, &self.facts)
            .await
            .map_err(SignerError::other)?;
        Signature::from_raw(&raw).map_err(SignerError::other)
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
        let signer = HostMppSigner::new(
            Arc::clone(&self.host_signer),
            self.wallet_address,
            self.facts.clone(),
            Some(chain_id),
        );
        let credential = match challenge.intent.as_str() {
            "charge" => prepare_charge_credential(&payment_challenge, &signer, &rpc_url).await,
            "session" => {
                prepare_session_credential(
                    &payment_challenge,
                    &signer,
                    &rpc_url,
                    policy
                        .payments
                        .sessions
                        .max_deposit_usd
                        .and_then(|usd| usd_to_atomic_units(challenge.asset.as_deref(), usd)),
                )
                .await
            }
            other => {
                return Err(format!("unsupported MPP intent '{other}'"));
            }
        }
        .map_err(|e| format!("Tempo MPP credential: {e}"))?;
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
    signer: &HostMppSigner,
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
    signer: &HostMppSigner,
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
