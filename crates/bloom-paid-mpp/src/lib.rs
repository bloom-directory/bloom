//! Tempo MPP protocol adapter for Bloom paid HTTP requests.

use alloy::consensus::SignableTransaction;
use alloy::eips::{Decodable2718, Encodable2718};
use alloy::primitives::{Address, B256, Signature};
use alloy::providers::ProviderBuilder;
use alloy::signers::{Error as SignerError, Result as SignerResult, Signer};
use alloy::sol_types::{SolCall, SolStruct, eip712_domain};
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
use mpp::protocol::methods::tempo::voucher::{Voucher, compute_channel_id};
use serde_json::json;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempo_alloy::TempoNetwork;
use tempo_alloy::primitives::transaction::{AASigned, Call, PrimitiveSignature, TempoSignature};

/// The `sign-hash` intent string every Tempo MPP host signature is authorized under.
pub const MPP_SIGN_INTENT: &str = "paid-http.mpp.sign";

/// Schema of every envelope Broker decodes to show the owner what is signed.
const REVIEW_SCHEMA: &str = "bloom.message.review.v1";
const CHANNEL_RECORD_SCHEMA: &str = "bloom.machine_mpp_channel.v1";

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
    /// Machine-private directory of opened channels' parameters, keyed by
    /// channel ID, so later vouchers show the owner who the channel pays.
    pub channel_dir: Option<PathBuf>,
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
            channel_dir: None,
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

fn persist_atomically(path: &Path, value: &str, what: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{what} path has no parent directory"))?;
    std::fs::create_dir_all(parent).map_err(|e| format!("create {what} directory: {e}"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("create temporary {what}: {e}"))?;
    temporary
        .write_all(value.as_bytes())
        .map_err(|e| format!("write temporary {what}: {e}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|e| format!("sync temporary {what}: {e}"))?;
    temporary
        .persist(path)
        .map_err(|e| format!("persist {what}: {}", e.error))?;
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
    persist_atomically(path, &encoded, "MPP unsigned draft")
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
    interface ITempoEscrow {
        function open(
            address payee,
            address token,
            uint128 deposit,
            bytes32 salt,
            address authorizedSigner
        ) external;
    }
}

/// The parameters that, with the payer, escrow and chain, hash to a channel
/// ID. Broker recomputes that hash before it tells the owner who a voucher pays.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TempoChannel {
    payee: Address,
    token: Address,
    salt: B256,
    authorized_signer: Address,
}

impl TempoChannel {
    fn id(&self, payer: Address, escrow: Address, chain_id: u64) -> B256 {
        compute_channel_id(
            payer,
            self.payee,
            self.token,
            self.salt,
            self.authorized_signer,
            escrow,
            chain_id,
        )
    }
}

/// Where Machine and the channel's identity meet: the signer, chain, escrow,
/// and the directory of recorded channels.
struct ChannelContext<'a> {
    payer: Address,
    chain_id: u64,
    escrow: Address,
    dir: Option<&'a Path>,
}

impl ChannelContext<'_> {
    fn record_path(&self, channel_id: B256) -> Option<PathBuf> {
        self.dir
            .map(|dir| dir.join(format!("{channel_id:#x}.json")))
    }

    fn save(&self, channel_id: B256, channel: &TempoChannel) -> Result<(), String> {
        let Some(path) = self.record_path(channel_id) else {
            return Ok(());
        };
        let record = json!({
            "schema": CHANNEL_RECORD_SCHEMA,
            "chain_id": self.chain_id,
            "escrow": format!("{:#x}", self.escrow),
            "payer": format!("{:#x}", self.payer),
            "payee": format!("{:#x}", channel.payee),
            "token": format!("{:#x}", channel.token),
            "salt": format!("{:#x}", channel.salt),
            "authorized_signer": format!("{:#x}", channel.authorized_signer),
        });
        persist_atomically(&path, &record.to_string(), "MPP channel record")
    }

    /// The recorded channel, if Machine opened it after it began recording.
    /// A record that no longer hashes to its channel ID is refused.
    fn load(&self, channel_id: B256) -> Result<Option<TempoChannel>, String> {
        let Some(path) = self.record_path(channel_id) else {
            return Ok(None);
        };
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("read MPP channel record: {error}")),
        };
        let record: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse MPP channel record: {error}"))?;
        let field = |name: &str| {
            record[name]
                .as_str()
                .ok_or_else(|| format!("MPP channel record has no {name}"))
        };
        let address = |name: &str| {
            field(name)?
                .parse::<Address>()
                .map_err(|error| format!("MPP channel record {name}: {error}"))
        };
        if record["schema"] != CHANNEL_RECORD_SCHEMA {
            return Err("MPP channel record schema is unsupported".into());
        }
        let channel = TempoChannel {
            payee: address("payee")?,
            token: address("token")?,
            salt: field("salt")?
                .parse()
                .map_err(|error| format!("MPP channel record salt: {error}"))?,
            authorized_signer: address("authorized_signer")?,
        };
        if channel.id(self.payer, self.escrow, self.chain_id) != channel_id {
            return Err(format!(
                "MPP channel record {channel_id:#x} does not match this wallet, escrow and chain"
            ));
        }
        Ok(Some(channel))
    }
}

/// The calls of an unsigned draft Tempo transaction, in either encoding.
fn draft_calls(bytes: &[u8]) -> Result<Vec<Call>, String> {
    if bytes.first() == Some(&0x78) {
        return FeePayerEnvelope78::decode_envelope(bytes)
            .map(|envelope| envelope.calls)
            .map_err(|error| format!("decode Tempo fee-payer envelope: {error}"));
    }
    AASigned::decode_2718(&mut &bytes[..])
        .map(|signed| signed.strip_signature().calls)
        .map_err(|error| format!("decode signed Tempo transaction: {error}"))
}

/// Read the channel a session-open draft opens from its own `open` call.
/// Drafts are reused on retry, so this never trusts state from when the
/// draft was built.
fn opened_channel(encoded: &str, escrow: Address) -> Result<TempoChannel, String> {
    let bytes = alloy::hex::decode(encoded).map_err(|error| format!("decode Tempo tx: {error}"))?;
    let mut opens = draft_calls(&bytes)?.into_iter().filter(|call| {
        call.input
            .starts_with(ITempoEscrow::openCall::SELECTOR.as_slice())
    });
    let (Some(open), None) = (opens.next(), opens.next()) else {
        return Err("MPP session open draft must contain exactly one escrow open call".into());
    };
    if open.to.to() != Some(&escrow) {
        return Err("MPP session open draft opens a channel on a different escrow".into());
    }
    let call = ITempoEscrow::openCall::abi_decode(&open.input)
        .map_err(|error| format!("decode MPP escrow open call: {error}"))?;
    Ok(TempoChannel {
        payee: call.payee,
        token: call.token,
        salt: call.salt,
        authorized_signer: call.authorizedSigner,
    })
}

async fn exactize_credential(
    mut credential: mpp::PaymentCredential,
    challenge: &mpp::PaymentChallenge,
    chain_id: u64,
    wallet_address: Address,
    channel_dir: Option<&Path>,
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
    let channels = ChannelContext {
        payer: wallet_address,
        chain_id,
        escrow,
        dir: channel_dir,
    };
    let payload = match payload {
        SessionCredentialPayload::Open {
            payload_type,
            channel_id,
            transaction,
            authorized_signer,
            cumulative_amount,
            signature: _,
        } => {
            let channel = opened_channel(&transaction, escrow)?;
            let id = parse_channel_id(&channel_id)?;
            if channel.id(wallet_address, escrow, chain_id) != id {
                return Err("MPP session open draft opens a different channel than it pays".into());
            }
            // Record before either signature, so a voucher signed after a
            // crash here still shows who the channel pays.
            channels.save(id, &channel)?;
            let transaction =
                exactize_tempo_transaction(&transaction, "session-open-transaction", host, facts)
                    .await?;
            let signature = exactize_voucher(
                &channel_id,
                &cumulative_amount,
                &channels,
                Some(&channel),
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
        // mpp 0.10.4 has no client topUp builder, so a topUp draft did not
        // come from Bloom.
        SessionCredentialPayload::TopUp { .. } => {
            return Err(
                "MPP session topUp is not supported: Bloom never builds a topUp payment".into(),
            );
        }
        SessionCredentialPayload::Voucher {
            channel_id,
            cumulative_amount,
            signature: _,
        } => SessionCredentialPayload::Voucher {
            signature: exactize_voucher(
                &channel_id,
                &cumulative_amount,
                &channels,
                channels.load(parse_channel_id(&channel_id)?)?.as_ref(),
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
                &channels,
                channels.load(parse_channel_id(&channel_id)?)?.as_ref(),
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
        let review = transaction_review(&preimage);
        let raw = host
            .sign_paid_http_payload(
                MPP_SIGN_INTENT,
                signing_slot,
                &preimage,
                hash,
                facts,
                Some(&review),
            )
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
    let review = transaction_review(&preimage);
    let raw = host
        .sign_paid_http_payload(
            MPP_SIGN_INTENT,
            signing_slot,
            &preimage,
            hash,
            facts,
            Some(&review),
        )
        .await?;
    let signature = Signature::from_raw(&raw).map_err(|error| error.to_string())?;
    let signed = tx.into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
        signature,
    )));
    Ok(alloy::hex::encode_prefixed(signed.encoded_2718()))
}

/// Broker decodes the exact signing preimage itself.
fn transaction_review(preimage: &[u8]) -> Vec<u8> {
    json!({
        "schema": REVIEW_SCHEMA,
        "kind": "tempo_transaction",
        "transaction": alloy::hex::encode_prefixed(preimage),
    })
    .to_string()
    .into_bytes()
}

/// Broker rebuilds the voucher preimage from these fields. `channel` is
/// absent for a channel opened before Machine recorded its parameters.
fn voucher_review(
    channels: &ChannelContext<'_>,
    voucher: &Voucher,
    channel: Option<&TempoChannel>,
) -> Vec<u8> {
    let mut review = json!({
        "schema": REVIEW_SCHEMA,
        "kind": "tempo_voucher",
        "chain_id": channels.chain_id,
        "escrow": format!("{:#x}", channels.escrow),
        "channel_id": format!("{:#x}", voucher.channelId),
        "cumulative_amount": voucher.cumulativeAmount.to_string(),
    });
    if let Some(channel) = channel {
        review["channel"] = json!({
            "payee": format!("{:#x}", channel.payee),
            "token": format!("{:#x}", channel.token),
            "salt": format!("{:#x}", channel.salt),
            "authorized_signer": format!("{:#x}", channel.authorized_signer),
        });
    }
    review.to_string().into_bytes()
}

fn parse_channel_id(channel_id: &str) -> Result<B256, String> {
    channel_id
        .parse::<B256>()
        .map_err(|error| format!("parse MPP channel id: {error}"))
}

async fn exactize_voucher(
    channel_id: &str,
    cumulative_amount: &str,
    channels: &ChannelContext<'_>,
    channel: Option<&TempoChannel>,
    signing_slot: &str,
    host: &dyn PaidHttpHostSigner,
    facts: &PaidHttpSigningFacts,
) -> Result<String, String> {
    let domain = eip712_domain! {
        name: mpp::protocol::methods::tempo::voucher::DOMAIN_NAME,
        version: mpp::protocol::methods::tempo::voucher::DOMAIN_VERSION,
        chain_id: channels.chain_id,
        verifying_contract: channels.escrow,
    };
    // The escrow verifies `Voucher(bytes32 channelId,uint128 cumulativeAmount)`;
    // the struct's name is part of the signed type hash.
    let voucher = Voucher {
        channelId: parse_channel_id(channel_id)?,
        cumulativeAmount: cumulative_amount
            .parse::<u128>()
            .map_err(|error| format!("parse MPP cumulative amount: {error}"))?,
    };
    let mut preimage = Vec::with_capacity(66);
    preimage.extend_from_slice(&[0x19, 0x01]);
    preimage.extend_from_slice(domain.separator().as_slice());
    preimage.extend_from_slice(voucher.eip712_hash_struct().as_slice());
    let hash: [u8; 32] = alloy::primitives::keccak256(&preimage).into();
    let review = voucher_review(channels, &voucher, channel);
    let raw = host
        .sign_paid_http_payload(
            MPP_SIGN_INTENT,
            signing_slot,
            &preimage,
            hash,
            facts,
            Some(&review),
        )
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
            self.wallet_address,
            self.channel_dir.as_deref(),
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
        DraftMppSigner, ITempoEscrow, MPP_SIGN_INTENT, exactize_credential,
        exactize_tempo_transaction, persist_draft_binding_atomically,
        validate_persisted_draft_binding,
    };
    use alloy::primitives::{Address, B256, Bytes, TxKind, U256, keccak256};
    use alloy::sol_types::{SolCall, SolValue};
    use async_trait::async_trait;
    use bloom_paid_http::{PaidHttpHostSigner, PaidHttpSigningFacts};
    use mpp::client::tempo::charge::tx_builder::{TempoTxOptions, build_tempo_tx};
    use mpp::client::tempo::signing::{
        TempoSigningMode, sign_and_encode_async, sign_and_encode_fee_payer_envelope_async,
    };
    use mpp::protocol::methods::tempo::session::SessionCredentialPayload;
    use std::sync::Mutex;
    use tempo_alloy::primitives::TempoTransaction;
    use tempo_alloy::primitives::transaction::Call;

    /// Signed slots: (slot, preimage, review envelope).
    type Signed = (String, Vec<u8>, serde_json::Value);

    #[derive(Default)]
    struct ExactHost(Mutex<Vec<Vec<u8>>>, Mutex<Vec<Signed>>);

    #[async_trait]
    impl PaidHttpHostSigner for ExactHost {
        async fn sign_paid_http_payload(
            &self,
            intent: &str,
            signing_slot: &str,
            preimage: &[u8],
            signing_hash: [u8; 32],
            _facts: &PaidHttpSigningFacts,
            review: Option<&[u8]>,
        ) -> Result<[u8; 65], String> {
            assert_eq!(intent, MPP_SIGN_INTENT);
            assert_eq!(
                alloy::primitives::keccak256(preimage).as_slice(),
                signing_hash
            );
            let review = serde_json::from_slice(review.expect("every MPP slot has a review"))
                .expect("review is JSON");
            self.1
                .lock()
                .unwrap()
                .push((signing_slot.to_owned(), preimage.to_vec(), review));
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

    fn tempo_tx(calls: Vec<Call>, fee_payer: bool) -> TempoTransaction {
        build_tempo_tx(TempoTxOptions {
            calls,
            chain_id: 42431,
            fee_token: Address::repeat_byte(0x33),
            nonce: 7,
            nonce_key: if fee_payer { U256::MAX } else { U256::ZERO },
            gas_limit: 500_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            fee_payer,
            valid_before: fee_payer.then_some(1_900_000_000),
            key_authorization: None,
        })
    }

    #[tokio::test]
    async fn tempo_transaction_review_is_the_exact_signing_preimage() {
        let signer = DraftMppSigner::new(Address::repeat_byte(0x11), Some(42431));
        let call = Call {
            to: TxKind::Call(Address::repeat_byte(0x22)),
            value: U256::ZERO,
            input: Bytes::from_static(b"payment"),
        };
        let direct = sign_and_encode_async(
            tempo_tx(vec![call.clone()], false),
            &signer,
            &TempoSigningMode::Direct,
        )
        .await
        .unwrap();
        let sponsored = sign_and_encode_fee_payer_envelope_async(
            tempo_tx(vec![call], true),
            &signer,
            &TempoSigningMode::Direct,
        )
        .await
        .unwrap();
        assert_eq!((direct[0], sponsored[0]), (0x76, 0x78));
        for draft in [direct, sponsored] {
            let host = ExactHost::default();
            exactize_tempo_transaction(
                &alloy::hex::encode_prefixed(&draft),
                "charge-transaction",
                &host,
                &PaidHttpSigningFacts::default(),
            )
            .await
            .unwrap();
            let signed = host.1.lock().unwrap();
            let (_, preimage, review) = &signed[0];
            assert_eq!(preimage[0], 0x76);
            assert_eq!(
                review,
                &serde_json::json!({
                    "schema": "bloom.message.review.v1",
                    "kind": "tempo_transaction",
                    "transaction": alloy::hex::encode_prefixed(preimage),
                })
            );
        }
    }

    /// The voucher preimage Broker rebuilds from a `tempo_voucher` envelope.
    fn rebuilt_voucher_preimage(review: &serde_json::Value) -> Vec<u8> {
        let domain = alloy::sol_types::Eip712Domain::new(
            Some("Tempo Stream Channel".into()),
            Some("1".into()),
            Some(U256::from(review["chain_id"].as_u64().unwrap())),
            Some(review["escrow"].as_str().unwrap().parse().unwrap()),
            None,
        );
        let channel_id: B256 = review["channel_id"].as_str().unwrap().parse().unwrap();
        let amount: u128 = review["cumulative_amount"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let mut encoded = keccak256("Voucher(bytes32 channelId,uint128 cumulativeAmount)").to_vec();
        encoded.extend_from_slice(channel_id.as_slice());
        encoded.extend_from_slice(&U256::from(amount).to_be_bytes::<32>());
        let mut preimage = vec![0x19, 0x01];
        preimage.extend_from_slice(domain.separator().as_slice());
        preimage.extend_from_slice(keccak256(encoded).as_slice());
        preimage
    }

    #[tokio::test]
    async fn session_vouchers_show_the_channel_recorded_from_its_open_call() {
        let payer = Address::repeat_byte(0x11);
        let payee = Address::repeat_byte(0x22);
        let token = Address::repeat_byte(0x33);
        let salt = B256::repeat_byte(0x44);
        let escrow = mpp::client::tempo::session::channel_ops::resolve_escrow(
            &session_challenge(payee, token),
            42431,
            None,
        )
        .unwrap();
        let channel_id = keccak256(
            (
                payer,
                payee,
                token,
                salt,
                payer,
                escrow,
                U256::from(42431_u64),
            )
                .abi_encode(),
        );
        let open = ITempoEscrow::openCall::new((payee, token, 1_000, salt, payer)).abi_encode();
        let approve = [
            [0x09, 0x5e, 0xa7, 0xb3].as_slice(),
            &(escrow, U256::from(1_000)).abi_encode(),
        ]
        .concat();
        let calls = vec![
            Call {
                to: TxKind::Call(token),
                value: U256::ZERO,
                input: approve.into(),
            },
            Call {
                to: TxKind::Call(escrow),
                value: U256::ZERO,
                input: open.into(),
            },
        ];
        let signer = DraftMppSigner::new(payer, Some(42431));
        let transaction = alloy::hex::encode_prefixed(
            sign_and_encode_async(tempo_tx(calls, false), &signer, &TempoSigningMode::Direct)
                .await
                .unwrap(),
        );
        let directory = tempfile::tempdir().unwrap();
        let host = ExactHost::default();
        let run = |payload: SessionCredentialPayload| {
            let challenge = session_challenge(payee, token);
            let mut credential = mpp::PaymentCredential::with_source(
                challenge.to_echo(),
                mpp::PaymentCredential::evm_did(42431, &payer.to_string()),
                mpp::PaymentPayload::transaction("0x"),
            );
            credential.payload = serde_json::to_value(payload).unwrap();
            let host = &host;
            let dir = directory.path().to_owned();
            async move {
                exactize_credential(
                    credential,
                    &challenge,
                    42431,
                    payer,
                    Some(&dir),
                    host,
                    &PaidHttpSigningFacts::default(),
                )
                .await
            }
        };
        let channel = serde_json::json!({
            "payee": format!("{payee:#x}"),
            "token": format!("{token:#x}"),
            "salt": format!("{salt:#x}"),
            "authorized_signer": format!("{payer:#x}"),
        });

        // A draft whose open call does not hash to its channel ID is refused.
        let open_payload = |channel_id: B256| SessionCredentialPayload::Open {
            payload_type: "transaction".into(),
            channel_id: format!("{channel_id:#x}"),
            transaction: transaction.clone(),
            authorized_signer: Some(payer.to_string()),
            cumulative_amount: "10".into(),
            signature: "0x".into(),
        };
        let error = run(open_payload(B256::repeat_byte(0x55)))
            .await
            .unwrap_err();
        assert!(error.contains("different channel"), "{error}");
        assert!(host.1.lock().unwrap().is_empty());

        run(open_payload(channel_id)).await.unwrap();
        let voucher = |cumulative: &str, close: bool| {
            let (channel_id, cumulative_amount, signature) = (
                format!("{channel_id:#x}"),
                cumulative.to_owned(),
                "0x".into(),
            );
            if close {
                SessionCredentialPayload::Close {
                    channel_id,
                    cumulative_amount,
                    signature,
                }
            } else {
                SessionCredentialPayload::Voucher {
                    channel_id,
                    cumulative_amount,
                    signature,
                }
            }
        };
        run(voucher("20", false)).await.unwrap();
        run(voucher("30", true)).await.unwrap();
        {
            let signed = host.1.lock().unwrap();
            let slots: Vec<_> = signed.iter().map(|(slot, ..)| slot.as_str()).collect();
            assert_eq!(
                slots,
                [
                    "session-open-transaction",
                    "session-open-voucher",
                    "session-voucher",
                    "session-close-voucher"
                ]
            );
            assert_eq!(signed[0].2["kind"], "tempo_transaction");
            for ((_, preimage, review), cumulative) in signed[1..].iter().zip(["10", "20", "30"]) {
                assert_eq!(review["kind"], "tempo_voucher");
                assert_eq!(review["chain_id"], 42431);
                assert_eq!(review["escrow"], format!("{escrow:#x}"));
                assert_eq!(review["channel_id"], format!("{channel_id:#x}"));
                assert_eq!(review["cumulative_amount"], cumulative);
                assert_eq!(review["channel"], channel);
                assert_eq!(&rebuilt_voucher_preimage(review), preimage);
            }
        }

        // What Machine persisted hashes to the channel ID.
        let record_path = directory.path().join(format!("{channel_id:#x}.json"));
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
        let address = |name: &str| record[name].as_str().unwrap().parse::<Address>().unwrap();
        let persisted_salt: B256 = record["salt"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            keccak256(
                (
                    address("payer"),
                    address("payee"),
                    address("token"),
                    persisted_salt,
                    address("authorized_signer"),
                    address("escrow"),
                    U256::from(record["chain_id"].as_u64().unwrap()),
                )
                    .abi_encode()
            ),
            channel_id
        );

        // A channel Machine never recorded still gets a voucher envelope.
        let unknown = B256::repeat_byte(0x66);
        run(SessionCredentialPayload::Voucher {
            channel_id: format!("{unknown:#x}"),
            cumulative_amount: "5".into(),
            signature: "0x".into(),
        })
        .await
        .unwrap();
        {
            let signed = host.1.lock().unwrap();
            let (_, preimage, review) = signed.last().unwrap();
            assert!(review.get("channel").is_none());
            assert_eq!(&rebuilt_voucher_preimage(review), preimage);
        }

        // A record that no longer hashes to its channel ID is refused.
        let mut tampered = record.clone();
        tampered["payee"] = format!("{:#x}", Address::repeat_byte(0x77)).into();
        std::fs::write(&record_path, tampered.to_string()).unwrap();
        let error = run(voucher("40", false)).await.unwrap_err();
        assert!(error.contains("does not match"), "{error}");

        let error = run(SessionCredentialPayload::TopUp {
            payload_type: "transaction".into(),
            channel_id: format!("{channel_id:#x}"),
            transaction,
            additional_deposit: "1".into(),
        })
        .await
        .unwrap_err();
        assert!(error.contains("topUp is not supported"), "{error}");
    }

    fn session_challenge(payee: Address, token: Address) -> mpp::PaymentChallenge {
        mpp::PaymentChallenge::new(
            "session-1",
            "merchant.test",
            "tempo",
            "session",
            mpp::Base64UrlJson::from_value(&serde_json::json!({
                "amount": "10",
                "unitType": "request",
                "currency": format!("{token:#x}"),
                "recipient": format!("{payee:#x}"),
                "methodDetails": { "chainId": 42431 }
            }))
            .unwrap(),
        )
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
