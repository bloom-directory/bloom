//! Solana signing via the Machine→Broker→Signer triad, mirroring EVM's
//! `TriadSigningService` pattern (`bloom-tx`'s `triad_sign_evm_payload`) but
//! for `Ed25519Message` over the raw legacy transfer message.
//!
//! The signer binds an `ExactPayloadSignRequest` to the installer-provenance
//! record for `solana.transfer.confirm`, asks Broker to sign the raw message
//! bytes with the wallet's derived Solana child (BIP-44 `m/44'/501'/…'`), and
//! verifies the returned signature over exactly those bytes before returning
//! it — the honest-runtime proof that the signer cannot be handed different
//! bytes than the ones the verifier later sees.

use bloom_broker_api::{
    AssetId, ClaimAssurance, CryptoSuite, DecimalU64, DecimalU256, DeclaredDebit,
    DeclaredDestination, DeclaredFee, Digest32, ExactMessageNormalization, KeyRef, OperationId,
    ProvenanceCatalog, ProvenanceSubject, RequestNonce,
    SOLANA_SYSTEM_TRANSFER_VERIFIER_DIGEST_BYTES, SOLANA_SYSTEM_TRANSFER_VERIFIER_ID,
    SystemChainContext, SystemUseClaim, Token, ValueLimit, solana_native_transfer_approval_digest,
};
use bloom_machine_client::{ExactPayloadSignOutcome, ExactPayloadSignRequest, MachineBrokerClient};
use sha2::{Digest as _, Sha256};

use crate::message::verify_signature;

/// The action class this signer is bound to.
pub const SOLANA_CONFIRM_ACTION_CLASS: &str = "solana.transfer.confirm";
const SOLANA_APPROVAL_OPERATION_DOMAIN: &[u8] = b"bloom-solana-approval-operation/v1";
const SOLANA_SIGNING_OPERATION_DOMAIN: &[u8] = b"bloom-solana-signing-operation/v1";
const SOLANA_REQUEST_NONCE_DOMAIN: &[u8] = b"bloom-solana-request-nonce/v1";
/// Identity domains for a blockhash-normalized approval.
///
/// A v1 identity hashes the message, whose blockhash is about to become
/// replaceable — two attempts on one transfer would otherwise hash to
/// different identities and the ceremony could never be resumed. A v2 identity
/// hashes the outbox intent id, the approval attempt and the normalized
/// digest, none of which move when the blockhash does.
const SOLANA_APPROVAL_OPERATION_DOMAIN_V2: &[u8] = b"bloom-solana-approval-operation/v2";
const SOLANA_SIGNING_OPERATION_DOMAIN_V2: &[u8] = b"bloom-solana-signing-operation/v2";
const SOLANA_REQUEST_NONCE_DOMAIN_V2: &[u8] = b"bloom-solana-request-nonce/v2";
/// Prefix the outbox gives every Solana entry id.
const SOLANA_OUTBOX_ID_PREFIX: &str = "sol-";

/// Outcome of one sign attempt.
#[derive(Debug, Clone)]
pub enum SolanaSignOutcome {
    /// A 64-byte Ed25519 signature, already verified over the raw message.
    Signed { signature: [u8; 64] },
    /// Owner approval is required before signing; the caller must re-invoke
    /// with the returned `approval_id` after the ceremony completes.
    ApprovalRequired {
        approval_id: Digest32,
        ceremony_url: String,
        ceremony_expires_at_ms: u64,
    },
}

/// Why one sign attempt failed, and what that means for the approval the
/// attempt was carrying.
///
/// The distinction is the Broker's own error contract, not a local guess. An
/// error whose contract says the request can never be retried and left no
/// durable effect means no signature exists and never will under this
/// approval: the caller may safely retire it and start a new attempt. Anything
/// else — a possible provider effect, an unknown outcome, a transient fault,
/// or a prior operation that still stands — must keep the approval, because
/// abandoning it could authorize a second signature for one intent.
#[derive(Debug, Clone)]
pub struct SolanaSignError {
    message: String,
    approval_is_dead: bool,
}

impl SolanaSignError {
    fn from_broker(error: &bloom_broker_api::ProtocolError) -> Self {
        let contract = error.code.contract();
        Self {
            message: format!("{}: {}", error.code.as_str(), error.message),
            approval_is_dead: contract.retry == bloom_broker_api::RetryClass::Never
                && contract.durable_effect == bloom_broker_api::DurableEffect::None,
        }
    }

    fn local(message: impl Into<String>) -> Self {
        // A fault on this side of the wire never reached a decision, so the
        // approval it was carrying is still whatever it was.
        Self {
            message: message.into(),
            approval_is_dead: false,
        }
    }

    /// True when the approval this attempt used can never produce a signature
    /// and the caller should begin a new approval attempt.
    pub fn approval_is_dead(&self) -> bool {
        self.approval_is_dead
    }
}

impl From<String> for SolanaSignError {
    /// Every string error raised inside this module is a local encoding or
    /// validation fault, not a Broker decision, so it leaves the approval
    /// intact.
    fn from(message: String) -> Self {
        Self::local(message)
    }
}

impl std::fmt::Display for SolanaSignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SolanaSignError {}

/// The full set of inputs to [`SolanaTransferSigner::sign_transfer`].
///
/// Grouped into one request so the signing call cannot silently transpose the
/// account, amount, fee, and blockhash fields — a real hazard when they were a
/// dozen same-typed positional arguments.
pub struct SignTransferRequest<'a> {
    /// The wallet whose derived child signs.
    pub wallet_id: &'a str,
    /// The 32-byte Ed25519 public key that must be both fee payer and signer.
    pub fee_payer: &'a [u8; 32],
    /// The exact child to sign with. Required whenever the wallet holds more
    /// than one active Solana child; see the method docs for why.
    pub account_key_ref: Option<KeyRef>,
    /// The canonical legacy transfer message bytes to be signed.
    pub message_bytes: &'a [u8],
    /// Base58 destination address.
    pub destination: &'a str,
    /// Transfer amount, in lamports.
    pub lamports: u64,
    /// Network fee, in lamports.
    pub fee_lamports: u64,
    /// Genesis hash binding the target chain identity.
    pub genesis_hash: &'a str,
    /// The recent blockhash embedded in `message_bytes`.
    pub recent_blockhash: &'a str,
    /// The last block height at which `recent_blockhash` is valid.
    pub last_valid_block_height: u64,
    /// `None` on the first attempt (prepares the ceremony) and the id returned
    /// by [`SolanaSignOutcome::ApprovalRequired`] on retry.
    pub approval_id: Option<Digest32>,
    /// Approval issuance timestamp, in ms.
    pub issued_at_ms: u64,
    /// Approval expiry timestamp, in ms.
    pub expires_at_ms: u64,
    /// Which approval attempt this is for the same transfer. Folded into the
    /// approval intent so a retired approval's successor gets a distinct
    /// operation id instead of colliding with the dead one.
    pub approval_attempt: u32,
    /// The outbox entry id, 32 hex characters of the random 16-byte intent.
    /// This is the intent identity a normalized approval hashes, in place of
    /// the message whose blockhash it allows to move.
    pub outbox_id: &'a str,
    /// The entry's persisted matching mode. `None` keeps every v1 identity and
    /// raw Exact terms.
    pub message_normalization: Option<ExactMessageNormalization>,
    /// Digest of the canonical staged-transfer plan facts.
    pub canonical_plan_facts_digest: Digest32,
}

/// Signs Solana transfers through the exact Broker signing seam.
pub struct SolanaTransferSigner {
    broker: MachineBrokerClient,
    subject: ProvenanceSubject,
    provenance_digest: Digest32,
}

impl SolanaTransferSigner {
    /// Build the signer from the installer provenance catalog, selecting the
    /// record that authorizes [`SOLANA_CONFIRM_ACTION_CLASS`].
    pub fn from_catalog(
        broker: MachineBrokerClient,
        catalog: &ProvenanceCatalog,
    ) -> Result<Self, String> {
        let record = catalog
            .records
            .iter()
            .find(|record| {
                matches!(
                    &record.subject,
                    ProvenanceSubject::System { operation_class, .. }
                        if operation_class.as_str() == SOLANA_CONFIRM_ACTION_CLASS
                )
            })
            .ok_or_else(|| {
                format!("installer provenance does not authorize {SOLANA_CONFIRM_ACTION_CLASS}")
            })?;
        let provenance_digest = record.digest().map_err(|e| e.to_string())?;
        Ok(Self {
            broker,
            subject: record.subject.clone(),
            provenance_digest,
        })
    }

    /// Sign the exact raw message bytes with the wallet's derived Solana
    /// child. `fee_payer` is the derived child's Ed25519 public key; the
    /// returned signature is verified over `message_bytes` before returning.
    ///
    /// `account_key_ref` names that exact child. It is required whenever the
    /// wallet holds more than one active Solana child, because `fee_payer`
    /// alone is a public key the Broker would still have to resolve back to a
    /// key, and resolving it by list order is what this selection exists to
    /// prevent. It is bound into the sealed approval terms, so an approval
    /// issued for one account can never authorise a signature from another.
    ///
    /// `approval_id` is `None` on first attempt (prepares the ceremony) and
    /// the id returned by [`SolanaSignOutcome::ApprovalRequired`] on retry.
    fn exact_request(
        &self,
        request: SignTransferRequest<'_>,
    ) -> Result<ExactPayloadSignRequest, SolanaSignError> {
        let SignTransferRequest {
            wallet_id,
            fee_payer: _,
            account_key_ref,
            message_bytes,
            destination,
            lamports,
            fee_lamports,
            genesis_hash,
            recent_blockhash,
            last_valid_block_height,
            approval_id,
            issued_at_ms,
            expires_at_ms,
            approval_attempt,
            outbox_id,
            message_normalization,
            canonical_plan_facts_digest,
        } = request;
        let preimage = message_bytes.to_vec();
        let claimed_hash = Digest32::from_bytes(Sha256::digest(&preimage).into());
        let maximum_native_debit = lamports
            .checked_add(fee_lamports)
            .ok_or_else(|| "Solana transfer value plus fee exceeds u64".to_owned())?;
        // These authority identities must survive the owner-ceremony retry
        // and an unknown-result process restart.
        //
        // Raw entries keep the v1 construction: the immutable message makes
        // this an Exact approval, and the attempt suffix only stops a new
        // ceremony reusing a definitively dead approval's identity.
        //
        // A normalized entry cannot hash the message, because the whole point
        // is that its blockhash may be replaced before signing — the identity
        // would move with it and the standing ceremony would be unreachable.
        // It hashes the intent instead: the outbox id, the attempt counter and
        // the normalized digest, none of which a refresh disturbs.
        let identity = match message_normalization {
            Some(ExactMessageNormalization::SolanaNativeTransferBlockhashV1) => {
                SigningIdentity::normalized(
                    outbox_id,
                    approval_attempt,
                    &solana_native_transfer_approval_digest(message_bytes)
                        .map_err(|error| SolanaSignError::local(error.to_string()))?,
                    &claimed_hash,
                )?
            }
            None => SigningIdentity::raw(message_bytes, approval_attempt),
        };
        let request_nonce = identity.request_nonce.clone();
        let system_use_claim = SystemUseClaim {
            component_id: Token::new("bloom-machine").map_err(|e| e.to_string())?,
            action_class: Token::new(SOLANA_CONFIRM_ACTION_CLASS).map_err(|e| e.to_string())?,
            operation_class: Token::new("solana.native-transfer").map_err(|e| e.to_string())?,
            crypto_suite: CryptoSuite::Ed25519Message,
            payload_digest: claimed_hash.clone(),
            ordered_hashes: vec![claimed_hash.clone()],
            declared_debits: vec![DeclaredDebit {
                asset: AssetId {
                    chain: Token::new("solana").map_err(|e| e.to_string())?,
                    asset: "native".into(),
                },
                amount: DecimalU256::parse(lamports.to_string()).map_err(|e| e.to_string())?,
            }],
            declared_destinations: vec![DeclaredDestination {
                chain: Token::new("solana").map_err(|e| e.to_string())?,
                destination: destination.to_owned(),
            }],
            declared_fee: DeclaredFee::Fee {
                chain: Token::new("solana").map_err(|e| e.to_string())?,
                asset: "native".into(),
                amount: DecimalU256::parse(fee_lamports.to_string()).map_err(|e| e.to_string())?,
            },
            nonce: request_nonce.clone(),
            chain_context: SystemChainContext {
                chain_family: Token::new("solana").map_err(|e| e.to_string())?,
                genesis_hash: genesis_hash.to_owned(),
                recent_blockhash: recent_blockhash.to_owned(),
                last_valid_block_height: DecimalU64::new(last_valid_block_height),
            },
            claim_assurance: ClaimAssurance::ProofVerified {
                verifier_id: Token::new(SOLANA_SYSTEM_TRANSFER_VERIFIER_ID)
                    .map_err(|e| e.to_string())?,
                verifier_digest: Digest32::from_bytes(SOLANA_SYSTEM_TRANSFER_VERIFIER_DIGEST_BYTES),
                proof_digest: claimed_hash.clone(),
            },
        };
        let request = ExactPayloadSignRequest {
            wallet_id: Token::new(wallet_id).map_err(|e| e.to_string())?,
            preimage,
            claimed_hash,
            crypto_suite: CryptoSuite::Ed25519Message,
            provenance: self.subject.clone(),
            provenance_digest: self.provenance_digest.clone(),
            activation_mode: None,
            approval_operation_id: identity.approval_operation_id,
            signing_operation_id: identity.signing_operation_id,
            request_nonce,
            issued_at_ms: DecimalU64::new(issued_at_ms),
            expires_at_ms: DecimalU64::new(expires_at_ms),
            canonical_plan_facts_digest,
            approval_id,
            petal_use_claim: None,
            system_use_claim: Some(system_use_claim),
            claim_assurance_evidence: Some(message_bytes.to_vec()),
            account_key_ref,
            message_normalization,
            approval_value_limits: vec![ValueLimit {
                asset: AssetId {
                    chain: Token::new("solana").map_err(|e| e.to_string())?,
                    asset: "native".into(),
                },
                lifetime: DecimalU256::parse(maximum_native_debit.to_string())
                    .map_err(|e| e.to_string())?,
                rolling_windows: Vec::new(),
            }],
        };
        Ok(request)
    }

    pub async fn sign_transfer(
        &self,
        request: SignTransferRequest<'_>,
    ) -> Result<SolanaSignOutcome, SolanaSignError> {
        let fee_payer = *request.fee_payer;
        let message_bytes = request.message_bytes.to_vec();
        let request = self.exact_request(request)?;
        match self
            .broker
            .sign_exact_payload(request)
            .await
            .map_err(|error| SolanaSignError::from_broker(&error))?
        {
            ExactPayloadSignOutcome::ApprovalRequired(prepared) => {
                Ok(SolanaSignOutcome::ApprovalRequired {
                    approval_id: prepared.approval_id,
                    ceremony_url: prepared.ceremony_url,
                    ceremony_expires_at_ms: prepared.ceremony_expires_at_ms.get(),
                })
            }
            ExactPayloadSignOutcome::Signed(signing) => {
                let signature = normalized_ed25519_signature(&signing)?;
                if !verify_signature(&fee_payer, &message_bytes, &signature) {
                    return Err(SolanaSignError::local(
                        "Broker returned a signature that does not verify over the raw message",
                    ));
                }
                Ok(SolanaSignOutcome::Signed { signature })
            }
        }
    }
}

/// What one normalized confirm resolves to before anything is dispatched.
pub enum SolanaSignPlan {
    /// The ceremony the owner still has to complete.
    ApprovalRequired {
        approval_id: Digest32,
        ceremony_url: String,
        ceremony_expires_at_ms: u64,
    },
    /// The approval exists: this is the exact request to persist and send.
    Dispatch(Box<bloom_broker_api::MachineSignRequest>),
}

impl SolanaTransferSigner {
    /// Read-through to the Broker's approval status.
    ///
    /// Holding an approval id is not permission to sign. The engine checks the
    /// approval is actually ACTIVE before it finalizes anything, because a
    /// prepared-but-unapproved ceremony and a revoked one both still have ids.
    pub async fn approval_status(
        &self,
        approval_id: Digest32,
    ) -> Result<bloom_broker_api::ApprovalPublicStatus, SolanaSignError> {
        self.broker
            .approval_status(approval_id)
            .await
            .map_err(|error| SolanaSignError::from_broker(&error))
    }

    /// Read-through to the Broker's operation status, for resolving a request
    /// that was dispatched but whose response was lost.
    pub async fn operation_status(
        &self,
        operation_id: OperationId,
    ) -> Result<bloom_broker_api::OperationPublicStatus, SolanaSignError> {
        self.broker
            .operation_status(operation_id)
            .await
            .map_err(|error| SolanaSignError::from_broker(&error))
    }

    /// Resolve a transfer into either its outstanding ceremony or the concrete
    /// request to send, without sending anything.
    ///
    /// The caller persists that request before dispatching it, so a lost
    /// response replays these exact bytes instead of rebuilding them against
    /// whatever the world looks like later.
    pub async fn plan_transfer(
        &self,
        request: SignTransferRequest<'_>,
    ) -> Result<SolanaSignPlan, SolanaSignError> {
        let exact = self.exact_request(request)?;
        match self
            .broker
            .plan_exact_payload(exact)
            .await
            .map_err(|error| SolanaSignError::from_broker(&error))?
        {
            bloom_machine_client::ExactPayloadPlan::Sign(request) => {
                Ok(SolanaSignPlan::Dispatch(request))
            }
            bloom_machine_client::ExactPayloadPlan::Prepare(prepare) => {
                let prepared = self
                    .broker
                    .prepare_approval(*prepare)
                    .await
                    .map_err(|error| SolanaSignError::from_broker(&error))?;
                Ok(SolanaSignPlan::ApprovalRequired {
                    approval_id: prepared.approval_id,
                    ceremony_url: prepared.ceremony_url,
                    ceremony_expires_at_ms: prepared.ceremony_expires_at_ms.get(),
                })
            }
        }
    }

    /// Send a previously persisted request and verify the signature it returns
    /// against the exact bytes that request carries.
    pub async fn dispatch(
        &self,
        request: bloom_broker_api::MachineSignRequest,
        fee_payer: &[u8; 32],
        message_bytes: &[u8],
    ) -> Result<[u8; 64], SolanaSignError> {
        let signing = self
            .broker
            .sign(request)
            .await
            .map_err(|error| SolanaSignError::from_broker(&error))?;
        let signature = normalized_ed25519_signature(&signing)?;
        if !verify_signature(fee_payer, message_bytes, &signature) {
            return Err(SolanaSignError::local(
                "Broker returned a signature that does not verify over the raw message",
            ));
        }
        Ok(signature)
    }
}

/// Normalize a Broker signing result and check it over exactly `message`.
pub(crate) fn verified_ed25519_signature(
    signing: &bloom_broker_api::SigningResult,
    fee_payer: &[u8; 32],
    message: &[u8],
) -> Result<[u8; 64], SolanaSignError> {
    let signature = normalized_ed25519_signature(signing)?;
    if !verify_signature(fee_payer, message, &signature) {
        return Err(SolanaSignError::local(
            "recovered signature does not verify over the persisted message",
        ));
    }
    Ok(signature)
}

fn normalized_ed25519_signature(
    signing: &bloom_broker_api::SigningResult,
) -> Result<[u8; 64], String> {
    let [signature] = signing.signatures.as_slice() else {
        return Err("Broker returned an invalid signature count".into());
    };
    if signature.crypto_suite != CryptoSuite::Ed25519Message {
        return Err(format!(
            "Broker returned {:?}, expected Ed25519Message",
            signature.crypto_suite
        ));
    }
    let bytes = signature.bytes.decode();
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| format!("Broker returned a {len} byte signature, expected 64"))
}

fn deterministic_operation_id(domain: &[u8], message: &[u8]) -> OperationId {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(message);
    OperationId::from_bytes(hasher.finalize().into())
}

fn deterministic_request_nonce(message: &[u8]) -> RequestNonce {
    let mut hasher = Sha256::new();
    hasher.update(SOLANA_REQUEST_NONCE_DOMAIN);
    hasher.update(message);
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    RequestNonce::from_bytes(bytes)
}

/// The three authority identities one sign attempt presents to the Broker.
///
/// They are grouped so the raw and normalized constructions cannot be mixed by
/// accident: an attempt either derives all three from the message, or all three
/// from the intent.
struct SigningIdentity {
    approval_operation_id: OperationId,
    signing_operation_id: OperationId,
    request_nonce: RequestNonce,
}

impl SigningIdentity {
    /// The pre-existing construction, hashing the immutable message.
    fn raw(message_bytes: &[u8], approval_attempt: u32) -> Self {
        let mut material = Vec::with_capacity(message_bytes.len() + 12);
        material.extend_from_slice(&(message_bytes.len() as u64).to_be_bytes());
        material.extend_from_slice(message_bytes);
        material.extend_from_slice(&approval_attempt.to_be_bytes());
        Self {
            approval_operation_id: deterministic_operation_id(
                SOLANA_APPROVAL_OPERATION_DOMAIN,
                &material,
            ),
            signing_operation_id: deterministic_operation_id(
                SOLANA_SIGNING_OPERATION_DOMAIN,
                message_bytes,
            ),
            request_nonce: deterministic_request_nonce(&material),
        }
    }

    /// The intent-bound construction for a blockhash-normalized approval:
    ///
    /// ```text
    /// I        = the outbox id's 16 raw bytes
    /// A        = the approval attempt counter, u32 big endian
    /// N        = the normalized message digest
    /// material = I || A || N
    /// ```
    ///
    /// Fixed-width throughout, so no two different intents can produce the same
    /// material. The approval identity stops at `material`, which a blockhash
    /// refresh leaves untouched; the signing identity additionally binds the
    /// raw digest, so each distinct message signs under its own operation and
    /// a replayed request is recognisably the same one.
    fn normalized(
        outbox_id: &str,
        approval_attempt: u32,
        normalized_digest: &Digest32,
        raw_digest: &Digest32,
    ) -> Result<Self, SolanaSignError> {
        let intent = decode_intent_id(outbox_id)?;
        let mut material = Vec::with_capacity(16 + 4 + 32);
        material.extend_from_slice(&intent);
        material.extend_from_slice(&approval_attempt.to_be_bytes());
        material.extend_from_slice(&normalized_digest.to_bytes());
        let mut signing_material = material.clone();
        signing_material.extend_from_slice(&raw_digest.to_bytes());
        let mut hasher = Sha256::new();
        hasher.update(SOLANA_REQUEST_NONCE_DOMAIN_V2);
        hasher.update(&material);
        let digest = hasher.finalize();
        let mut nonce = [0_u8; 16];
        nonce.copy_from_slice(&digest[..16]);
        Ok(Self {
            approval_operation_id: deterministic_operation_id(
                SOLANA_APPROVAL_OPERATION_DOMAIN_V2,
                &material,
            ),
            signing_operation_id: deterministic_operation_id(
                SOLANA_SIGNING_OPERATION_DOMAIN_V2,
                &signing_material,
            ),
            request_nonce: RequestNonce::from_bytes(nonce),
        })
    }
}

/// The outbox id is `sol-` followed by 16 random bytes as 32 hex characters.
///
/// Decoded strictly. A shortened, differently prefixed or non-hex id would
/// otherwise hash to a different intent than the entry it names, and the
/// approval identity would stop matching the entry it belongs to.
fn decode_intent_id(outbox_id: &str) -> Result<[u8; 16], SolanaSignError> {
    let hex_part = outbox_id
        .strip_prefix(SOLANA_OUTBOX_ID_PREFIX)
        .ok_or_else(|| {
            SolanaSignError::local(format!(
                "outbox id {outbox_id} does not start with {SOLANA_OUTBOX_ID_PREFIX}"
            ))
        })?;
    let raw = hex::decode(hex_part).map_err(|error| {
        SolanaSignError::local(format!("outbox id {outbox_id} is not hex: {error}"))
    })?;
    raw.try_into().map_err(|_| {
        SolanaSignError::local(format!(
            "outbox id {outbox_id} is not the expected 16 intent bytes"
        ))
    })
}
