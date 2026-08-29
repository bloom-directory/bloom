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
    DeclaredDestination, DeclaredFee, Digest32, KeyRef, OperationId, ProvenanceCatalog,
    ProvenanceSubject, RequestNonce, SOLANA_SYSTEM_TRANSFER_VERIFIER_DIGEST_BYTES,
    SOLANA_SYSTEM_TRANSFER_VERIFIER_ID, SystemChainContext, SystemUseClaim, Token, ValueLimit,
};
use bloom_machine_client::{ExactPayloadSignOutcome, ExactPayloadSignRequest, MachineBrokerClient};
use sha2::{Digest as _, Sha256};

use crate::message::verify_signature;

/// The action class this signer is bound to.
pub const SOLANA_CONFIRM_ACTION_CLASS: &str = "solana.transfer.confirm";
const SOLANA_APPROVAL_OPERATION_DOMAIN: &[u8] = b"bloom-solana-approval-operation/v1";
const SOLANA_SIGNING_OPERATION_DOMAIN: &[u8] = b"bloom-solana-signing-operation/v1";
const SOLANA_REQUEST_NONCE_DOMAIN: &[u8] = b"bloom-solana-request-nonce/v1";

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
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_transfer(
        &self,
        wallet_id: &str,
        fee_payer: &[u8; 32],
        account_key_ref: Option<KeyRef>,
        message_bytes: &[u8],
        destination: &str,
        lamports: u64,
        fee_lamports: u64,
        genesis_hash: &str,
        recent_blockhash: &str,
        last_valid_block_height: u64,
        approval_id: Option<Digest32>,
        issued_at_ms: u64,
        expires_at_ms: u64,
        canonical_plan_facts_digest: Digest32,
    ) -> Result<SolanaSignOutcome, String> {
        let preimage = message_bytes.to_vec();
        let claimed_hash = Digest32::from_bytes(Sha256::digest(&preimage).into());
        let maximum_native_debit = lamports
            .checked_add(fee_lamports)
            .ok_or_else(|| "Solana transfer value plus fee exceeds u64".to_owned())?;
        // These authority identities must survive the owner-ceremony retry
        // and an unknown-result process restart. The immutable Solana message
        // includes its recent blockhash, so domain-separated hashes are both
        // collision resistant and unique to this staged transfer.
        let request_nonce = deterministic_request_nonce(message_bytes);
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
            approval_operation_id: deterministic_operation_id(
                SOLANA_APPROVAL_OPERATION_DOMAIN,
                message_bytes,
            ),
            signing_operation_id: deterministic_operation_id(
                SOLANA_SIGNING_OPERATION_DOMAIN,
                message_bytes,
            ),
            request_nonce,
            issued_at_ms: DecimalU64::new(issued_at_ms),
            expires_at_ms: DecimalU64::new(expires_at_ms),
            canonical_plan_facts_digest,
            approval_id,
            petal_use_claim: None,
            system_use_claim: Some(system_use_claim),
            claim_assurance_evidence: Some(message_bytes.to_vec()),
            account_key_ref,
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
        match self
            .broker
            .sign_exact_payload(request)
            .await
            .map_err(|e| e.to_string())?
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
                if !verify_signature(fee_payer, message_bytes, &signature) {
                    return Err(
                        "Broker returned a signature that does not verify over the raw message"
                            .into(),
                    );
                }
                Ok(SolanaSignOutcome::Signed { signature })
            }
        }
    }
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
