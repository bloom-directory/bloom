//! The Solana transfer engine: stage → confirm/sign → verified simulation → broadcast,
//! mirroring `bloom-tx`'s `TxEngine` shape for the native-transfer MVP.
//!
//! The engine owns the orchestration: it fetches the recent blockhash, builds
//! the canonical legacy message, stages it in the durable outbox, signs it
//! through the Broker/Signer triad (the [`crate::signing::SolanaTransferSigner`]),
//! records the signature, assembles the signed transaction, and broadcasts it
//! via the read client's gated `sendTransaction`. Reconciliation is separate
//! (see [`crate::reconcile`]).

use base64::Engine as _;
use bloom_broker_api::{Digest32, KeyRef};
use bloom_solana::{SolanaClient, SolanaRpcError};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::outbox::{OutboxError, SolanaOutbox, SolanaOutboxEntry, SolanaOutboxState};
use crate::signing::{SolanaSignOutcome, SolanaTransferSigner};
use crate::types::{SolanaTxStatus, StagedSolanaTransfer};
use crate::{assemble_transaction, build_transfer_message, verify_signature};

const SIMULATION_SCHEMA: &str = "bloom.solana-simulation/1";

#[derive(serde::Serialize)]
struct SimulationArtifact<'a> {
    schema: &'static str,
    block_height: u64,
    last_valid_block_height: u64,
    success: bool,
    error: &'a Option<serde_json::Value>,
    units_consumed: Option<u64>,
    logs: &'a Option<Vec<String>>,
}

/// Default approval/signing TTL for a staged transfer (ms).
const SIGN_TTL_MS: u64 = 60_000;

/// Conservative estimate of Solana's per-slot duration, used only to turn a
/// block-height-denominated blockhash validity window into a wall-clock
/// expiry. Solana's target slot time; real slot times are frequently at or
/// above this under load, so converting at this rate slightly
/// *underestimates* how long the blockhash actually stays valid — erring
/// toward reaping a stage a little early rather than letting one that has
/// truly gone stale linger, which was the actual bug (Fix D,
/// PLAN-SOLANA-PR-FIXES.md).
const APPROX_SLOT_MS: u128 = 400;

/// A native SOL transfer intent as supplied by the write surface
/// (`wallets/<wallet>/chains/<chain>/outbox/new.tx`).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolanaTransferIntent {
    /// Destination public key, base58.
    pub destination: String,
    /// Native SOL debit in lamports.
    pub lamports: u64,
    /// Which derived Solana child to spend from, named by its public-key
    /// fingerprint (hex) or a unique prefix of one.
    ///
    /// Required once the wallet has more than one active Solana child.
    /// Omitting it stays valid for a single-child wallet, which is
    /// unambiguous; it is never a request to pick whichever child is listed
    /// first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_fingerprint: Option<String>,
}

impl SolanaTransferIntent {
    /// The destination as its raw 32-byte public key.
    pub fn destination_bytes(&self) -> Result<[u8; 32], String> {
        let bytes = bs58::decode(&self.destination)
            .into_vec()
            .map_err(|e| e.to_string())?;
        bytes
            .try_into()
            .map_err(|_| "destination must be a 32-byte base58 public key".to_string())
    }
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("outbox: {0}")]
    Outbox(#[from] OutboxError),
    #[error("chain: {0}")]
    Chain(#[from] SolanaRpcError),
    #[error("signing: {0}")]
    Signer(String),
    #[error("invalid transfer: {0}")]
    Invalid(String),
    #[error("broadcasting is disabled for chain '{0}' (operator release posture)")]
    BroadcastDisabled(String),
}

/// Orchestrates the native SOL transfer lifecycle.
pub struct SolanaTransferEngine {
    outbox: SolanaOutbox,
    client: SolanaClient,
    signer: SolanaTransferSigner,
    chain: String,
}

impl SolanaTransferEngine {
    pub fn new(
        outbox: SolanaOutbox,
        client: SolanaClient,
        signer: SolanaTransferSigner,
        chain: impl Into<String>,
    ) -> Self {
        Self {
            outbox,
            client,
            signer,
            chain: chain.into(),
        }
    }

    pub fn outbox(&self) -> &SolanaOutbox {
        &self.outbox
    }

    pub fn chain(&self) -> &str {
        &self.chain
    }

    async fn require_fresh_blockhash(
        &self,
        last_valid_block_height: u64,
    ) -> Result<u64, EngineError> {
        let current = self.client.get_block_height().await?;
        if current > last_valid_block_height {
            return Err(EngineError::Invalid(format!(
                "staged blockhash expired at block height {last_valid_block_height}; current block height is {current}; restage the transfer"
            )));
        }
        Ok(current)
    }

    /// Turn a fetched blockhash's `last_valid_block_height` into a
    /// wall-clock expiry, so a staged-but-abandoned transfer is eventually
    /// reaped by the sweep guard instead of lingering forever
    /// (`stage()` previously hardcoded `expires_ms: 0`, which the sweep's
    /// `!= 0` guard treats as "never expires").
    ///
    /// Fetching the current height is part of staging's fail-closed freshness
    /// check; Bloom never persists an RPC's already-expired "latest" hash.
    async fn blockhash_expiry_ms(
        &self,
        last_valid_block_height: u64,
        now_ms: u128,
    ) -> Result<u128, EngineError> {
        let current_height = self
            .require_fresh_blockhash(last_valid_block_height)
            .await?;
        Ok(now_ms
            + u128::from(last_valid_block_height.saturating_sub(current_height)) * APPROX_SLOT_MS)
    }

    /// Stage a native transfer: fetch a recent blockhash, build the canonical
    /// legacy message, and persist the write-once intent in `pending/<id>/`.
    pub async fn stage(
        &self,
        wallet: &str,
        fee_payer: &[u8; 32],
        account_fingerprint: Option<String>,
        account_derivation_path: Option<String>,
        destination: &[u8; 32],
        lamports: u64,
        now_ms: u128,
    ) -> Result<StagedSolanaTransfer, EngineError> {
        // Establish cluster identity before fetching the blockhash. Keeping
        // both observations on the same client makes endpoint failover safe:
        // every endpoint must identify as the configured cluster.
        let genesis_hash = self.client.verify_genesis().await?;
        let blockhash = self.client.get_latest_blockhash().await?;
        let blockhash_bytes: [u8; 32] = bs58::decode(&blockhash.blockhash)
            .into_vec()
            .map_err(|e| EngineError::Invalid(format!("blockhash base58: {e}")))?
            .try_into()
            .map_err(|_| EngineError::Invalid("blockhash must be 32 bytes".into()))?;
        let message = build_transfer_message(fee_payer, destination, lamports, &blockhash_bytes)
            .map_err(|e| EngineError::Invalid(e.to_string()))?;
        let message_b64 = base64::engine::general_purpose::STANDARD.encode(&message);
        let fee_lamports = self
            .client
            .get_fee_for_message(&message_b64)
            .await?
            .ok_or_else(|| {
                EngineError::Invalid("RPC could not quote the exact message fee".into())
            })?;
        let payload_digest_hex = hex::encode(Sha256::digest(&message));
        let id = self.outbox.allocate_id();
        let expires_ms = self
            .blockhash_expiry_ms(blockhash.last_valid_block_height, now_ms)
            .await?;
        let staged = StagedSolanaTransfer {
            id,
            wallet: wallet.to_string(),
            chain: self.chain.clone(),
            fee_payer: bs58::encode(fee_payer).into_string(),
            account_fingerprint,
            account_derivation_path,
            destination: bs58::encode(destination).into_string(),
            lamports,
            fee_lamports,
            genesis_hash,
            blockhash: blockhash.blockhash,
            last_valid_block_height: blockhash.last_valid_block_height,
            message_b64,
            payload_digest_hex,
            signature: None,
            created_ms: now_ms,
            expires_ms,
            status: SolanaTxStatus::Pending,
            action_id: None,
        };
        self.outbox.write_pending(
            &staged,
            &format!(
                "Solana native transfer: {} → {} ({lamports} lamports)\nblockhash {} valid through block {}\n",
                staged.fee_payer,
                staged.destination,
                staged.blockhash,
                staged.last_valid_block_height,
            ),
        )?;
        Ok(staged)
    }

    /// Replace an expired pending transfer with the same economic intent and
    /// a fresh blockhash/fee quote. This is deliberately explicit: the old
    /// message cannot be mutated after approval, and its approval/signature
    /// are never reused for the replacement.
    pub async fn restage_expired(
        &self,
        wallet: &str,
        id: &str,
        fee_payer: &[u8; 32],
        now_ms: u128,
    ) -> Result<StagedSolanaTransfer, EngineError> {
        let (entry, found_in) = self.outbox.read_restageable(wallet, &self.chain, id)?;
        // A swept entry is only recoverable if it went stale. Anything else in
        // `failed` — a policy refusal, say — is a decision, not an accident,
        // and must not be revived by restaging it.
        if found_in == SolanaOutboxState::Failed && entry.staged.status != SolanaTxStatus::Expired {
            return Err(EngineError::Invalid(
                "only an expired failed transfer can be restaged".into(),
            ));
        }
        let current = self.client.get_block_height().await?;
        if current <= entry.staged.last_valid_block_height {
            return Err(EngineError::Invalid(format!(
                "staged blockhash remains valid through block {}; current block height is {current}",
                entry.staged.last_valid_block_height
            )));
        }
        let stored_fee_payer: [u8; 32] = bs58::decode(&entry.staged.fee_payer)
            .into_vec()
            .map_err(|error| EngineError::Invalid(format!("fee payer base58: {error}")))?
            .try_into()
            .map_err(|_| EngineError::Invalid("fee payer must be 32 bytes".into()))?;
        if stored_fee_payer != *fee_payer {
            return Err(EngineError::Invalid(
                "resolved signing key differs from the staged fee payer".into(),
            ));
        }
        let destination: [u8; 32] = bs58::decode(&entry.staged.destination)
            .into_vec()
            .map_err(|error| EngineError::Invalid(format!("destination base58: {error}")))?
            .try_into()
            .map_err(|_| EngineError::Invalid("destination must be 32 bytes".into()))?;
        let replacement = self
            .stage(
                wallet,
                fee_payer,
                // The replacement is the same transfer from the same account,
                // so it carries the original pin forward rather than being
                // re-resolved.
                entry.staged.account_fingerprint.clone(),
                entry.staged.account_derivation_path.clone(),
                &destination,
                entry.staged.lamports,
                now_ms,
            )
            .await?;

        let mut expired = entry;
        expired.staged.status = SolanaTxStatus::Expired;
        if expired.state == SolanaOutboxState::Pending {
            let old_dir = self
                .outbox
                .transition(&expired, SolanaOutboxState::Failed)?;
            expired.state = SolanaOutboxState::Failed;
            expired.dir = old_dir;
        }
        self.outbox.rewrite_intent(&expired)?;
        self.outbox
            .write_restage_advice(&expired, &replacement.id)?;
        Ok(replacement)
    }

    /// Confirm and sign a staged transfer. On `Signed` the signature is
    /// recorded in the outbox, but the entry **stays `pending`** — it only
    /// moves to `sent` once [`Self::broadcast`] actually succeeds. A signed
    /// message with no broadcast attempt yet is still exactly as
    /// retryable/cancellable as an unsigned one (mirrors `bloom-tx`'s EVM
    /// `confirm` path, which gates its `Sent` transition on the broadcast
    /// RPC call itself succeeding, never on signing alone). On
    /// `ApprovalRequired` the ceremony details are returned and the entry
    /// stays pending for a retry with the returned `approval_id`.
    pub async fn sign(
        &self,
        wallet: &str,
        id: &str,
        fee_payer: &[u8; 32],
        account_key_ref: Option<KeyRef>,
        approval_id: Option<Digest32>,
        now_ms: u128,
    ) -> Result<SolanaSignOutcome, EngineError> {
        let entry =
            self.outbox
                .read_in_state(wallet, &self.chain, id, SolanaOutboxState::Pending)?;
        self.require_fresh_blockhash(entry.staged.last_valid_block_height)
            .await?;
        let message = base64::engine::general_purpose::STANDARD
            .decode(&entry.staged.message_b64)
            .map_err(|e| EngineError::Invalid(format!("message base64: {e}")))?;
        validate_staged_message(&entry.staged, fee_payer, &message)?;
        validate_staged_account(&entry.staged, account_key_ref.as_ref())?;
        let canonical_plan_facts = serde_jcs::to_vec(&entry.staged)
            .map_err(|e| EngineError::Invalid(format!("canonical plan facts: {e}")))?;
        let plan_facts_digest = Digest32::from_bytes(Sha256::digest(&canonical_plan_facts).into());

        let outcome = self
            .signer
            .sign_transfer(
                wallet,
                fee_payer,
                account_key_ref,
                &message,
                &entry.staged.destination,
                entry.staged.lamports,
                entry.staged.fee_lamports,
                &entry.staged.genesis_hash,
                &entry.staged.blockhash,
                entry.staged.last_valid_block_height,
                approval_id,
                now_ms.min(u128::from(u64::MAX)) as u64,
                (now_ms + u128::from(SIGN_TTL_MS)).min(u128::from(u64::MAX)) as u64,
                plan_facts_digest,
            )
            .await
            .map_err(EngineError::Signer)?;

        if let SolanaSignOutcome::Signed { signature } = &outcome {
            let signature_b58 = bs58::encode(signature).into_string();
            self.outbox
                .record_signature(wallet, &self.chain, id, &signature_b58)?;
        }
        Ok(outcome)
    }

    /// Broadcast a signed transfer: assemble the transaction from the
    /// recorded signature + message and submit it. The entry transitions
    /// `pending` → `sent` only *after* the broadcast RPC call actually
    /// succeeds — if `send_transaction` fails (RPC timeout, node error, a
    /// normal and expected failure mode), the entry is left exactly where
    /// it was, still `pending` and so still retryable (call `sign`+
    /// `broadcast` again — signing is idempotent, it just re-records the
    /// same signature) or cancellable, never permanently stranded in a
    /// `sent` state that reflects a broadcast that never happened.
    /// Returns the transaction signature.
    /// The fourth and last mainnet-beta gate: the per-value caps.
    ///
    /// The three preceding gates only decide whether mainnet-beta may be
    /// reached at all. This one decides whether *this exact transfer* is the
    /// one the operator authorized — same wallet, same key fingerprint, same
    /// source, same destination, same amount, a fee inside the ceiling, and a
    /// funded balance inside the stated total loss budget.
    ///
    /// Returns the authorization so the caller can spend its single use
    /// immediately before sending. On any non-mainnet cluster this is `None`
    /// and nothing changes.
    async fn authorized_mainnet_canary(
        &self,
        entry: &SolanaOutboxEntry,
        observed_genesis: &str,
        now_ms: u128,
    ) -> Result<Option<bloom_solana::canary::LoadedAuthorization>, EngineError> {
        if observed_genesis != bloom_solana::MAINNET_BETA_GENESIS_HASH {
            return Ok(None);
        }
        let loaded =
            bloom_solana::canary::authorization_for(&self.chain, now_ms).ok_or_else(|| {
                EngineError::Invalid(
                    "mainnet-beta broadcast requires a valid canary authorization".into(),
                )
            })?;
        let fingerprint = entry.staged.account_fingerprint.as_deref().ok_or_else(|| {
            EngineError::Invalid(
                "mainnet canary requires a transfer pinned to an exact key fingerprint".into(),
            )
        })?;
        loaded
            .authorization
            .authorizes_transfer(
                &entry.staged.wallet,
                fingerprint,
                &entry.staged.fee_payer,
                &entry.staged.destination,
                entry.staged.lamports,
                entry.staged.fee_lamports,
            )
            .map_err(|error| EngineError::Invalid(error.to_string()))?;
        // The balance is read live rather than trusted from staging time: the
        // loss budget the operator agreed to is a statement about the funded
        // account right now, not about what it held when the transfer was
        // built.
        let balance = self.client.get_balance(&entry.staged.fee_payer).await?;
        loaded
            .authorization
            .authorizes_balance(balance)
            .map_err(|error| EngineError::Invalid(error.to_string()))?;
        Ok(Some(loaded))
    }

    pub async fn broadcast(
        &self,
        wallet: &str,
        id: &str,
        now_ms: u128,
    ) -> Result<String, EngineError> {
        if !self.client.allow_broadcast() {
            return Err(EngineError::BroadcastDisabled(self.chain.clone()));
        }
        let entry =
            self.outbox
                .read_in_state(wallet, &self.chain, id, SolanaOutboxState::Pending)?;
        let observed_genesis = self.client.verify_genesis().await?;
        if observed_genesis != entry.staged.genesis_hash {
            return Err(EngineError::Invalid(format!(
                "live cluster genesis {} differs from staged genesis {}",
                observed_genesis, entry.staged.genesis_hash
            )));
        }
        let canary = self
            .authorized_mainnet_canary(&entry, &observed_genesis, now_ms)
            .await?;
        let signature_b58 = self
            .outbox
            .recorded_signature(&entry)?
            .ok_or_else(|| EngineError::Invalid("entry has no recorded signature".into()))?;
        let signature: [u8; 64] = bs58::decode(&signature_b58)
            .into_vec()
            .map_err(|e| EngineError::Invalid(format!("signature base58: {e}")))?
            .try_into()
            .map_err(|_| EngineError::Invalid("signature must be 64 bytes".into()))?;
        let message = base64::engine::general_purpose::STANDARD
            .decode(&entry.staged.message_b64)
            .map_err(|e| EngineError::Invalid(format!("message base64: {e}")))?;
        let fee_payer: [u8; 32] = bs58::decode(&entry.staged.fee_payer)
            .into_vec()
            .map_err(|e| EngineError::Invalid(format!("fee payer base58: {e}")))?
            .try_into()
            .map_err(|_| EngineError::Invalid("fee payer must be 32 bytes".into()))?;
        validate_staged_message(&entry.staged, &fee_payer, &message)?;
        if !verify_signature(&fee_payer, &message, &signature) {
            return Err(EngineError::Invalid(
                "recorded signature does not verify over the staged message".into(),
            ));
        }
        let block_height = self
            .require_fresh_blockhash(entry.staged.last_valid_block_height)
            .await?;
        let tx_bytes = assemble_transaction(&message, &signature)
            .map_err(|e| EngineError::Invalid(e.to_string()))?;
        let tx_b64 = base64::engine::general_purpose::STANDARD.encode(&tx_bytes);

        // Run an explicit signature-verifying preflight over the exact bytes
        // that will be submitted and persist only its public diagnostics.
        let simulation = self.client.simulate_transaction(&tx_b64).await?;
        let artifact = SimulationArtifact {
            schema: SIMULATION_SCHEMA,
            block_height,
            last_valid_block_height: entry.staged.last_valid_block_height,
            success: simulation.err.is_none(),
            error: &simulation.err,
            units_consumed: simulation.units_consumed,
            logs: &simulation.logs,
        };
        let artifact_bytes = serde_json::to_vec_pretty(&artifact)
            .map_err(|error| EngineError::Invalid(format!("simulation artifact: {error}")))?;
        self.outbox.write_simulation(&entry, &artifact_bytes)?;
        if let Some(error) = simulation.err {
            return Err(EngineError::Invalid(format!(
                "signed transaction simulation failed: {error}"
            )));
        }

        // Spend the canary's single use *before* the send, not after. A crash
        // or a lost response between here and the node must leave the canary
        // spent: an ambiguous outcome is exactly the case where an automatic
        // retry could double-send real funds, so the authorization has to be
        // gone even though we may never learn what happened. Reconciliation by
        // the deterministic signature is how the outcome is recovered.
        if let Some(loaded) = &canary {
            loaded
                .claim_single_use(&format!("{} {} {}", entry.staged.wallet, id, signature_b58))
                .map_err(|error| EngineError::Invalid(error.to_string()))?;
            tracing::warn!(
                chain = %self.chain,
                signature = %signature_b58,
                "solana.mainnet_canary_single_use_claimed"
            );
        }

        // Broadcast first, while the entry is still `pending`: on failure
        // it must stay exactly there, never move to `sent` for a broadcast
        // that never actually happened.
        let submitted = self.client.send_transaction(&tx_b64).await?;
        if submitted != signature_b58 {
            return Err(EngineError::Invalid(format!(
                "RPC returned transaction signature {submitted}, but Bloom submitted {signature_b58}"
            )));
        }

        // Only a confirmed-successful broadcast earns the `sent` transition.
        // `staged.status` and the on-disk directory must agree, so derive
        // the target state from the status via `from_status` rather than
        // hardcoding a state literal that could drift from it.
        let mut staged = entry.staged.clone();
        staged.status = SolanaTxStatus::Sent;
        let target_state = SolanaOutboxState::from_status(&staged.status);
        let sent_dir = self.outbox.transition(&entry, target_state)?;
        let sent_entry = SolanaOutboxEntry {
            state: target_state,
            staged,
            dir: sent_dir,
        };
        self.outbox.rewrite_intent(&sent_entry)?;
        self.outbox
            .write_broadcast_attempt(&sent_entry, &submitted, &tx_bytes, now_ms)?;
        Ok(submitted)
    }
}

/// The signing key must be the exact derived child the transfer was staged
/// for.
///
/// The staged message bytes commit to one fee payer, and the sealed approval
/// commits to one `KeyRef`. Re-resolving the wallet's children at signing time
/// could pick a different active child, which would then be asked to sign a
/// message it was never staged for, so the pinned fingerprint is checked
/// rather than trusted.
///
/// An entry staged before account selection existed carries no fingerprint. It
/// is accepted, because it cannot have been staged against a second child, and
/// `validate_staged_message` has already tied the key to the staged fee payer.
fn validate_staged_account(
    staged: &StagedSolanaTransfer,
    account_key_ref: Option<&bloom_broker_api::KeyRef>,
) -> Result<(), EngineError> {
    let Some(pinned) = staged.account_fingerprint.as_deref() else {
        return Ok(());
    };
    let Some(selected) = account_key_ref else {
        return Err(EngineError::Invalid(
            "staged transfer pins a derived Solana account but none was selected for signing"
                .into(),
        ));
    };
    if selected.public_key_fingerprint.as_str() != pinned {
        return Err(EngineError::Invalid(
            "selected Solana account differs from the account this transfer was staged for".into(),
        ));
    }
    if let Some(expected_path) = staged.account_derivation_path.as_deref() {
        let selected_path = match selected.derivation.as_ref() {
            Some(bloom_broker_api::DerivationRef::Bip39Multicurve {
                profile: bloom_broker_api::DerivationProfile::Bip44SolanaSlip10Ed25519V1,
                path,
                ..
            }) => path.as_str(),
            _ => {
                return Err(EngineError::Invalid(
                    "selected Solana account has no canonical BIP-39 derivation path".into(),
                ));
            }
        };
        if selected_path != expected_path {
            return Err(EngineError::Invalid(
                "selected Solana account derivation path differs from the staged transfer".into(),
            ));
        }
    }
    Ok(())
}

fn validate_staged_message(
    staged: &StagedSolanaTransfer,
    expected_fee_payer: &[u8; 32],
    message: &[u8],
) -> Result<(), EngineError> {
    let stored_fee_payer: [u8; 32] = bs58::decode(&staged.fee_payer)
        .into_vec()
        .map_err(|e| EngineError::Invalid(format!("fee payer base58: {e}")))?
        .try_into()
        .map_err(|_| EngineError::Invalid("fee payer must be 32 bytes".into()))?;
    if &stored_fee_payer != expected_fee_payer {
        return Err(EngineError::Invalid(
            "resolved signing key differs from the staged fee payer".into(),
        ));
    }
    let destination: [u8; 32] = bs58::decode(&staged.destination)
        .into_vec()
        .map_err(|e| EngineError::Invalid(format!("destination base58: {e}")))?
        .try_into()
        .map_err(|_| EngineError::Invalid("destination must be 32 bytes".into()))?;
    let blockhash: [u8; 32] = bs58::decode(&staged.blockhash)
        .into_vec()
        .map_err(|e| EngineError::Invalid(format!("blockhash base58: {e}")))?
        .try_into()
        .map_err(|_| EngineError::Invalid("blockhash must be 32 bytes".into()))?;
    let expected =
        build_transfer_message(&stored_fee_payer, &destination, staged.lamports, &blockhash)
            .map_err(|e| EngineError::Invalid(e.to_string()))?;
    if expected != message {
        return Err(EngineError::Invalid(
            "serialized message differs from immutable staged transfer facts".into(),
        ));
    }
    let digest = hex::encode(Sha256::digest(message));
    if digest != staged.payload_digest_hex {
        return Err(EngineError::Invalid(
            "serialized message digest differs from staged payload digest".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_ref_with(fingerprint: &str) -> KeyRef {
        KeyRef {
            backend: bloom_broker_api::Token::new("local").unwrap(),
            backend_instance: bloom_broker_api::Token::new("primary").unwrap(),
            locator: "wallet/derived/0".into(),
            key_spec: bloom_broker_api::KeySpec::Ed25519,
            public_key_fingerprint: Digest32::new(fingerprint.to_owned()).unwrap(),
            derivation: Some(bloom_broker_api::DerivationRef::Bip39Multicurve {
                wallet_seed_ref: bloom_broker_api::Token::new("wallet-seed").unwrap(),
                profile: bloom_broker_api::DerivationProfile::Bip44SolanaSlip10Ed25519V1,
                path: "m/44'/501'/0'/0'".into(),
            }),
        }
    }

    #[test]
    fn a_pinned_account_must_be_reselected_exactly_to_sign() {
        let (mut staged, _, _) = staged_fixture();
        let pinned = "aa".repeat(32);
        staged.account_fingerprint = Some(pinned.clone());

        // The account the transfer was staged for.
        validate_staged_account(&staged, Some(&key_ref_with(&pinned)))
            .expect("the pinned account signs its own staged transfer");

        // A different active child must not be able to sign a message that
        // was built for, and approved against, another account.
        let other = "bb".repeat(32);
        let error = validate_staged_account(&staged, Some(&key_ref_with(&other)))
            .expect_err("a substituted account must fail closed");
        assert!(
            matches!(&error, EngineError::Invalid(message) if message.contains("differs from the account")),
            "{error:?}"
        );

        // Dropping the selector entirely must not silently fall back to
        // resolving the wallet's children by order.
        let error = validate_staged_account(&staged, None)
            .expect_err("a pinned transfer must not sign without its account");
        assert!(
            matches!(&error, EngineError::Invalid(message) if message.contains("none was selected")),
            "{error:?}"
        );

        staged.account_derivation_path = Some("m/44'/501'/0'/0'".into());
        validate_staged_account(&staged, Some(&key_ref_with(&pinned)))
            .expect("the canonical staged path matches the selected account");
        let mut wrong_path = key_ref_with(&pinned);
        let Some(bloom_broker_api::DerivationRef::Bip39Multicurve { path, .. }) =
            wrong_path.derivation.as_mut()
        else {
            unreachable!()
        };
        *path = "m/44'/501'/1'/0'".into();
        let error = validate_staged_account(&staged, Some(&wrong_path))
            .expect_err("a substituted derivation path must fail closed");
        assert!(
            matches!(&error, EngineError::Invalid(message) if message.contains("derivation path differs")),
            "{error:?}"
        );
    }

    #[test]
    fn an_entry_staged_before_selection_existed_still_signs() {
        let (staged, _, _) = staged_fixture();
        assert!(staged.account_fingerprint.is_none());
        // No pin to enforce, and such an entry cannot have been staged against
        // a second child. `validate_staged_message` still ties the key to the
        // staged fee payer.
        validate_staged_account(&staged, None).expect("legacy entries keep working");
        validate_staged_account(&staged, Some(&key_ref_with(&"cc".repeat(32))))
            .expect("legacy entries do not constrain the selector");
    }

    fn staged_fixture() -> (StagedSolanaTransfer, [u8; 32], Vec<u8>) {
        let payer = [0x11; 32];
        let destination = [0x22; 32];
        let blockhash = [0x42; 32];
        let message = build_transfer_message(&payer, &destination, 1_000_000, &blockhash).unwrap();
        let staged = StagedSolanaTransfer {
            id: "0001-test".into(),
            wallet: "wallet".into(),
            chain: "solana-devnet".into(),
            fee_payer: bs58::encode(payer).into_string(),
            account_fingerprint: None,
            account_derivation_path: None,
            destination: bs58::encode(destination).into_string(),
            lamports: 1_000_000,
            fee_lamports: 5_000,
            genesis_hash: "test-genesis".into(),
            blockhash: bs58::encode(blockhash).into_string(),
            last_valid_block_height: 100,
            message_b64: base64::engine::general_purpose::STANDARD.encode(&message),
            payload_digest_hex: hex::encode(Sha256::digest(&message)),
            signature: None,
            created_ms: 1,
            expires_ms: 2,
            status: SolanaTxStatus::Pending,
            action_id: None,
        };
        (staged, payer, message)
    }

    #[test]
    fn staged_message_validation_binds_economic_and_freshness_facts() {
        let (staged, payer, message) = staged_fixture();
        validate_staged_message(&staged, &payer, &message).unwrap();

        let mut changed_amount = staged.clone();
        changed_amount.lamports += 1;
        assert!(validate_staged_message(&changed_amount, &payer, &message).is_err());

        let mut changed_blockhash = staged.clone();
        changed_blockhash.blockhash = bs58::encode([0x43; 32]).into_string();
        assert!(validate_staged_message(&changed_blockhash, &payer, &message).is_err());

        let mut changed_digest = staged;
        changed_digest.payload_digest_hex = "00".repeat(32);
        assert!(validate_staged_message(&changed_digest, &payer, &message).is_err());
    }
}
