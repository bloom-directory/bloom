//! Hash-chained append-only audit log.
//!
//! Every entry references the prior entry's blake3 digest. Tampering
//! with any line breaks the chain.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_PENDING_MACHINE_EFFECTS: usize = 64;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("audit chain broken at line {line}: prev hash mismatch")]
    Broken { line: usize },
    #[error("audit journal is degraded: {0}")]
    Degraded(String),
    #[error("audit signature invalid at line {line}")]
    Signature { line: usize },
    #[error("audit identity mismatch at line {line}")]
    Identity { line: usize },
    #[error("audit sequence invalid at line {line}")]
    Sequence { line: usize },
}

/// One audit record. Always serialized as a single JSON line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unix epoch milliseconds.
    pub ts_ms: u64,
    /// What happened. e.g. "wallet.create", "tx.stage", "tx.broadcast".
    pub kind: String,
    /// Optional wallet name (when relevant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet: Option<String>,
    /// Optional chain name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
    /// Free-form details.
    #[serde(default)]
    pub data: serde_json::Value,
    /// Hex of the blake3 digest of the previous record's full line. Empty
    /// for the first record.
    pub prev: String,
    /// Hex of the blake3 digest of *this* record minus the `digest` field
    /// itself — i.e. the digest binds the (timestamp, kind, … prev) tuple.
    pub digest: String,
}

#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<Mutex<AuditInner>>,
}

struct AuditInner {
    path: PathBuf,
    last_digest: String,
    sequence: u64,
    identity: Option<AuditIdentity>,
    degraded: Option<String>,
    #[cfg(any(test, feature = "audit-test-seam"))]
    fail_next_write: bool,
    #[cfg(any(test, feature = "audit-test-seam"))]
    fail_after_writes: Option<usize>,
}

/// The Machine service identity used to sign its local audit journal. This is
/// the already-pinned application identity, never a wallet or custody key.
#[derive(Clone)]
pub struct AuditIdentity {
    service_id: String,
    key_id: String,
    signing_key: Arc<SigningKey>,
}

/// Packaging-pinned historical application key and the exact archived segment
/// it is allowed to authenticate during audit-key rotation verification.
#[derive(Clone)]
pub struct AuditTrustedPredecessor {
    service_id: String,
    key_id: String,
    public_key: [u8; 32],
    archive_path: PathBuf,
}

impl AuditTrustedPredecessor {
    pub fn new(
        service_id: impl Into<String>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
        archive_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            service_id: service_id.into(),
            key_id: key_id.into(),
            public_key,
            archive_path: archive_path.into(),
        }
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
    pub fn archive_path(&self) -> &Path {
        &self.archive_path
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedHistoryDocument {
    schema: String,
    predecessors: Vec<TrustedHistoryEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedHistoryEntry {
    service_id: String,
    key_id: String,
    public_key_hex: String,
    archive_path: PathBuf,
}

#[derive(Clone)]
struct AuditVerifierIdentity {
    service_id: String,
    key_id: String,
    public_key: [u8; 32],
}

impl AuditIdentity {
    fn verifier(&self) -> AuditVerifierIdentity {
        AuditVerifierIdentity {
            service_id: self.service_id.clone(),
            key_id: self.key_id.clone(),
            public_key: self.signing_key.verifying_key().to_bytes(),
        }
    }
}

impl AuditIdentity {
    pub fn new(
        service_id: impl Into<String>,
        key_id: impl Into<String>,
        signing_key: Arc<SigningKey>,
    ) -> Self {
        Self {
            service_id: service_id.into(),
            key_id: key_id.into(),
            signing_key,
        }
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedAuditLine {
    #[serde(flatten)]
    record: AuditRecord,
    sequence: u64,
    service_id: String,
    key_id: String,
    public_key_hex: String,
    signature_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationMarker {
    schema: String,
    service_id: String,
    old_key_id: String,
    new_key_id: String,
    archive_name: String,
    next_name: String,
    proof_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationProof {
    #[serde(flatten)]
    payload: RotationProofPayload,
    old_signature_hex: String,
    new_signature_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationProofPayload {
    schema: String,
    service_id: String,
    old_key_id: String,
    old_public_key_hex: String,
    old_sequence: u64,
    final_old_head: String,
    new_key_id: String,
    new_public_key_hex: String,
    new_sequence: u64,
    first_new_head: String,
    archive_name: String,
}

#[derive(Clone)]
struct VerifiedTail {
    sequence: u64,
    pending_effects: std::collections::BTreeSet<String>,
}

impl AuditLog {
    /// Rotate the service audit key while both application identities are
    /// available. The old key signs a final authorization for the new key;
    /// the new key's genesis binds that signed old head. Both journal segments
    /// remain owner-readable and independently verifiable.
    pub fn rotate_identity(
        path: impl AsRef<Path>,
        old_identity: AuditIdentity,
        new_identity: AuditIdentity,
    ) -> Result<PathBuf, AuditError> {
        Self::rotate_identity_with_history(path, old_identity, new_identity, &[])
    }

    pub fn rotate_identity_with_history(
        path: impl AsRef<Path>,
        old_identity: AuditIdentity,
        new_identity: AuditIdentity,
        trusted_history: &[AuditTrustedPredecessor],
    ) -> Result<PathBuf, AuditError> {
        let path = path.as_ref();
        if old_identity.service_id != new_identity.service_id
            || old_identity.key_id == new_identity.key_id
        {
            return Err(AuditError::Degraded(
                "audit rotation requires one service and distinct key IDs".to_owned(),
            ));
        }
        let marker_path = path.with_extension("rotation.json");
        if marker_path.exists() {
            return Self::resume_identity_rotation_with_history(
                path,
                old_identity,
                new_identity,
                trusted_history,
            );
        }
        let old = Self::open_signed_with_history(path, old_identity.clone(), trusted_history)?;
        if let Some(reason) = old.mutation_degradation() {
            return Err(AuditError::Degraded(reason));
        }
        let archive = Self::rotation_archive_path(path, &old_identity.key_id);
        let archive_name = archive
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| AuditError::Degraded("audit archive name is not UTF-8".to_owned()))?
            .to_owned();
        let next = path.with_extension("rotation-next.jsonl");
        let proof_path = Self::rotation_proof_path(path, &old_identity.key_id);
        for (kind, candidate) in [
            ("archive", archive.as_path()),
            ("next segment", next.as_path()),
            ("rotation proof", proof_path.as_path()),
            ("rotation marker", marker_path.as_path()),
        ] {
            if candidate.exists() {
                return Err(AuditError::Degraded(format!(
                    "audit rotation {kind} already exists at {}",
                    candidate.display()
                )));
            }
        }
        let next_name = next
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| AuditError::Degraded("audit next name is not UTF-8".to_owned()))?
            .to_owned();
        let proof_name = proof_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| AuditError::Degraded("audit proof name is not UTF-8".to_owned()))?
            .to_owned();
        let marker = RotationMarker {
            schema: "bloom.machine-audit-rotation.v1".to_owned(),
            service_id: old_identity.service_id.clone(),
            old_key_id: old_identity.key_id.clone(),
            new_key_id: new_identity.key_id.clone(),
            archive_name: archive_name.clone(),
            next_name,
            proof_name: proof_name.clone(),
        };
        // This durable marker is the point of no return. It precedes the first
        // journal mutation, so any interruption makes both the old and new
        // identity startup paths latch until packaging completes recovery.
        write_new_synced(&marker_path, &serde_json::to_vec(&marker)?)?;
        sync_parent(path)?;
        finish_rotation_from_marker(path, old_identity, new_identity, trusted_history, &marker)
    }

    /// Idempotently continue a durable rotation transaction using both the
    /// old and new application identities. This is the packaging recovery
    /// entry point after a crash at any phase.
    pub fn resume_identity_rotation_with_history(
        path: impl AsRef<Path>,
        old_identity: AuditIdentity,
        new_identity: AuditIdentity,
        trusted_history: &[AuditTrustedPredecessor],
    ) -> Result<PathBuf, AuditError> {
        let path = path.as_ref();
        let marker_path = path.with_extension("rotation.json");
        let marker: RotationMarker = serde_json::from_slice(&std::fs::read(&marker_path)?)?;
        if marker.schema != "bloom.machine-audit-rotation.v1"
            || marker.service_id != old_identity.service_id
            || marker.service_id != new_identity.service_id
            || marker.old_key_id != old_identity.key_id
            || marker.new_key_id != new_identity.key_id
        {
            return Err(AuditError::Degraded(
                "audit rotation marker conflicts with supplied identities".to_owned(),
            ));
        }
        finish_rotation_from_marker(path, old_identity, new_identity, trusted_history, &marker)
    }

    pub fn rotation_archive_path(path: &Path, old_key_id: &str) -> PathBuf {
        let archive_tag = &blake3::hash(old_key_id.as_bytes()).to_hex().to_string()[..16];
        path.with_extension(format!("key-{archive_tag}.jsonl"))
    }

    pub fn rotation_proof_path(path: &Path, old_key_id: &str) -> PathBuf {
        let archive_tag = &blake3::hash(old_key_id.as_bytes()).to_hex().to_string()[..16];
        path.with_extension(format!("key-{archive_tag}.rotation-proof.json"))
    }

    pub fn load_root_trusted_history(
        path: &Path,
    ) -> Result<Vec<AuditTrustedPredecessor>, AuditError> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        require_root_public_metadata(path)?;
        let document: TrustedHistoryDocument = serde_json::from_slice(&std::fs::read(path)?)?;
        if document.schema != "bloom.machine-audit-trust.v1" {
            return Err(AuditError::Degraded(
                "Machine audit history has an unsupported schema".to_owned(),
            ));
        }
        document
            .predecessors
            .into_iter()
            .map(|entry| {
                if entry.service_id != "bloom-machine" || !entry.archive_path.is_absolute() {
                    return Err(AuditError::Degraded(
                        "Machine audit predecessor has invalid service or relative archive path"
                            .to_owned(),
                    ));
                }
                let public_key: [u8; 32] = hex::decode(entry.public_key_hex)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| {
                        AuditError::Degraded(
                            "Machine audit predecessor public key is invalid".to_owned(),
                        )
                    })?;
                Ok(AuditTrustedPredecessor::new(
                    entry.service_id,
                    entry.key_id,
                    public_key,
                    entry.archive_path,
                ))
            })
            .collect()
    }

    /// Installer-only writer for the root-owned trust history. The history is
    /// public metadata, but must not be writable by the Machine principal.
    pub fn write_root_trusted_history(
        path: &Path,
        predecessors: &[AuditTrustedPredecessor],
    ) -> Result<(), AuditError> {
        if path.exists() {
            require_root_public_metadata(path)?;
        }
        let parent = path.parent().ok_or_else(|| {
            AuditError::Degraded("Machine audit history path has no parent".to_owned())
        })?;
        std::fs::create_dir_all(parent)?;
        let document = TrustedHistoryDocument {
            schema: "bloom.machine-audit-trust.v1".to_owned(),
            predecessors: predecessors
                .iter()
                .map(|entry| TrustedHistoryEntry {
                    service_id: entry.service_id.clone(),
                    key_id: entry.key_id.clone(),
                    public_key_hex: hex::encode(entry.public_key),
                    archive_path: entry.archive_path.clone(),
                })
                .collect(),
        };
        let temporary = path.with_extension("json.tmp");
        if temporary.exists() {
            return Err(AuditError::Degraded(format!(
                "stale Machine audit history temporary exists at {}",
                temporary.display()
            )));
        }
        write_new_synced(&temporary, &serde_json::to_vec_pretty(&document)?)?;
        require_root_public_metadata(&temporary)?;
        std::fs::rename(&temporary, path)?;
        sync_parent(path)
    }

    /// Open a service-signed production journal. Integrity failures are
    /// latched rather than preventing startup, so read/status surfaces remain
    /// available while every subsequent mutation fails closed.
    pub fn open_signed(
        path: impl Into<PathBuf>,
        identity: AuditIdentity,
    ) -> Result<Self, AuditError> {
        Self::open_signed_with_history(path, identity, &[])
    }

    pub fn open_signed_with_history(
        path: impl Into<PathBuf>,
        identity: AuditIdentity,
        trusted_history: &[AuditTrustedPredecessor],
    ) -> Result<Self, AuditError> {
        Self::open_inner(path.into(), Some(identity), trusted_history, true)
    }

    /// Explicit unsigned compatibility seam for unit tests and retired
    /// components. Production Machine construction must use `open_signed`.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AuditError> {
        Self::open_inner(path.into(), None, &[], true)
    }

    fn open_inner(
        path: PathBuf,
        identity: Option<AuditIdentity>,
        trusted_history: &[AuditTrustedPredecessor],
        recover_rotation_marker: bool,
    ) -> Result<Self, AuditError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if identity.is_none() && path.exists() && first_nonempty_line_is_signed(&path)? {
            return Err(AuditError::Degraded(
                "refusing to reopen a signed audit journal without its application identity"
                    .to_owned(),
            ));
        }
        let rotation_recovery_error = recover_rotation_marker
            .then(|| {
                identity.as_ref().and_then(|current| {
                    recover_rotation(&path, &current.verifier(), trusted_history).err()
                })
            })
            .flatten()
            .map(|error| error.to_string());
        let (legacy_binding, legacy_error) = if identity.is_some() {
            match prepare_legacy_migration(&path) {
                Ok(binding) => (binding, None),
                Err(error) => (None, Some(error.to_string())),
            }
        } else {
            (None, None)
        };
        let verifier = identity.as_ref().map(AuditIdentity::verifier);
        let inspected = inspect(&path, verifier.as_ref());
        let (last_digest, sequence, degraded) = if path.exists() {
            match inspected {
                Ok((digest, tail)) => {
                    let degraded = pending_effect_degradation(&tail.pending_effects);
                    (digest, tail.sequence, degraded)
                }
                Err(error) if identity.is_some() => (String::new(), 0, Some(error.to_string())),
                Err(error) => return Err(error),
            }
        } else {
            (String::new(), 0, None)
        };
        let history_error = identity
            .as_ref()
            .and_then(|current| {
                verify_rotation_history(&path, &current.verifier(), trusted_history).err()
            })
            .map(|error| error.to_string());
        let log = Self {
            inner: Arc::new(Mutex::new(AuditInner {
                path,
                last_digest,
                sequence,
                identity,
                degraded: legacy_error
                    .or(degraded)
                    .or(rotation_recovery_error)
                    .or(history_error),
                #[cfg(any(test, feature = "audit-test-seam"))]
                fail_next_write: false,
                #[cfg(any(test, feature = "audit-test-seam"))]
                fail_after_writes: None,
            })),
        };
        if let Some(binding) = legacy_binding {
            log.append(AuditRecord {
                ts_ms: 0,
                kind: "machine.audit.legacy_genesis".to_owned(),
                wallet: None,
                chain: None,
                data: serde_json::json!({
                    "legacy_schema": "bloom-unsigned-audit/v0",
                    "legacy_head": binding.head,
                    "legacy_count": binding.count,
                    "legacy_source_blake3": binding.source_blake3,
                    "preserved_as": binding.preserved_name,
                }),
                prev: String::new(),
                digest: String::new(),
            })?;
        }
        Ok(log)
    }

    pub fn append(&self, record: AuditRecord) -> Result<AuditRecord, AuditError> {
        let mut g = self.inner.lock();
        Self::append_locked(&mut g, record, false)
    }

    fn append_locked(
        g: &mut AuditInner,
        mut record: AuditRecord,
        allow_degraded_reconciliation: bool,
    ) -> Result<AuditRecord, AuditError> {
        if !allow_degraded_reconciliation && let Some(reason) = &g.degraded {
            return Err(AuditError::Degraded(reason.clone()));
        }
        // Re-read and authenticate the complete journal before every security
        // mutation. Comparing the observed tail also detects replacement or
        // truncation after startup.
        let verifier = g.identity.as_ref().map(AuditIdentity::verifier);
        match inspect(&g.path, verifier.as_ref()) {
            Ok((digest, tail))
                if digest == g.last_digest
                    && (tail.sequence == g.sequence
                        || (!g.path.exists()
                            && digest.is_empty()
                            && g.last_digest.is_empty()
                            && tail.sequence == 0
                            && g.sequence > 0))
                    && prospective_effect_transition_is_valid(&tail.pending_effects, &record) => {}
            Ok(_) => {
                let reason = "journal changed since its last verified mutation".to_owned();
                g.degraded = Some(reason.clone());
                return Err(AuditError::Degraded(reason));
            }
            Err(error) => {
                let reason = error.to_string();
                g.degraded = Some(reason.clone());
                return Err(AuditError::Degraded(reason));
            }
        }
        record.prev = g.last_digest.clone();
        record.ts_ms = now_ms();
        record.digest = String::new();
        let body = serde_json::to_string(&record)?;
        let digest = blake3::hash(body.as_bytes()).to_hex().to_string();
        record.digest = digest.clone();
        let line = if let Some(identity) = &g.identity {
            let public_key_hex = hex::encode(identity.signing_key.verifying_key().to_bytes());
            let sequence = g
                .sequence
                .checked_add(1)
                .ok_or_else(|| AuditError::Degraded("audit sequence exhausted".to_owned()))?;
            let signature = identity.signing_key.sign(&audit_signature_bytes(
                sequence,
                &identity.service_id,
                &identity.key_id,
                &public_key_hex,
                &record,
            )?);
            serde_json::to_string(&SignedAuditLine {
                record: record.clone(),
                sequence,
                service_id: identity.service_id.clone(),
                key_id: identity.key_id.clone(),
                public_key_hex,
                signature_hex: hex::encode(signature.to_bytes()),
            })?
        } else {
            serde_json::to_string(&record)?
        };
        #[cfg(any(test, feature = "audit-test-seam"))]
        if g.fail_next_write {
            g.fail_next_write = false;
            let reason = "injected audit write failure".to_owned();
            g.degraded = Some(reason.clone());
            return Err(AuditError::Degraded(reason));
        }
        #[cfg(any(test, feature = "audit-test-seam"))]
        if let Some(remaining) = g.fail_after_writes.as_mut() {
            if *remaining == 0 {
                g.fail_after_writes = None;
                let reason = "injected delayed audit write failure".to_owned();
                g.degraded = Some(reason.clone());
                return Err(AuditError::Degraded(reason));
            }
            *remaining -= 1;
        }
        let file_existed = g.path.exists();
        let write_result = (|| -> Result<(), std::io::Error> {
            let mut options = OpenOptions::new();
            options.create(true).append(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut f = options.open(&g.path)?;
            f.write_all(line.as_bytes())?;
            f.write_all(b"\n")?;
            f.sync_data()
        })();
        if let Err(error) = write_result {
            let reason = error.to_string();
            g.degraded = Some(reason);
            return Err(AuditError::Io(error));
        }
        if !file_existed && let Err(error) = sync_parent(&g.path) {
            let reason = error.to_string();
            g.degraded = Some(reason);
            return Err(error);
        }
        g.last_digest = digest;
        if g.identity.is_some() {
            g.sequence += 1;
        }
        Ok(record)
    }

    pub fn mutation_degradation(&self) -> Option<String> {
        self.inner.lock().degraded.clone()
    }

    /// Latch all future mutations while preserving authenticated read/status
    /// access. Used when packaging-owned trust metadata is malformed or
    /// unavailable; the evidence itself is never rewritten by Machine.
    pub fn latch_mutations(&self, reason: impl Into<String>) {
        let mut g = self.inner.lock();
        let reason = reason.into();
        match &mut g.degraded {
            Some(existing) if !existing.contains(&reason) => {
                existing.push_str("; ");
                existing.push_str(&reason);
            }
            Some(_) => {}
            None => g.degraded = Some(reason),
        }
    }

    pub fn sequence(&self) -> u64 {
        self.inner.lock().sequence
    }

    /// Return the exact unresolved external-effect correlation, if any. This
    /// is a read/status operation and remains available while mutations are
    /// latched.
    pub fn pending_effect_correlation(&self) -> Result<Option<String>, AuditError> {
        Ok(self.pending_effect_correlations()?.into_iter().next())
    }

    pub fn pending_effect_correlations(&self) -> Result<Vec<String>, AuditError> {
        let g = self.inner.lock();
        let verifier = g.identity.as_ref().map(AuditIdentity::verifier);
        let (_, tail) = inspect(&g.path, verifier.as_ref())?;
        Ok(tail.pending_effects.into_iter().collect())
    }

    /// Explicit operator recovery for an effect whose intent was durable but
    /// whose result was not. This only closes the journal record; it never
    /// invokes or redispatches the underlying handler.
    pub fn reconcile_pending_effect(
        &self,
        correlation_id: &str,
        outcome: &str,
        confirmation: &str,
    ) -> Result<AuditRecord, AuditError> {
        if !matches!(outcome, "committed" | "aborted") {
            return Err(AuditError::Degraded(
                "reconciliation outcome must be committed or aborted".to_owned(),
            ));
        }
        let expected_confirmation = format!(
            "RECONCILE MACHINE AUDIT {correlation_id} AS {}",
            outcome.to_ascii_uppercase()
        );
        if confirmation != expected_confirmation {
            return Err(AuditError::Degraded(format!(
                "confirmation must exactly equal {expected_confirmation:?}"
            )));
        }
        let mut g = self.inner.lock();
        if g.identity.is_none() {
            return Err(AuditError::Degraded(
                "unsigned test journals cannot use production reconciliation".to_owned(),
            ));
        }
        let verifier = g.identity.as_ref().map(AuditIdentity::verifier);
        let (digest, tail) = inspect(&g.path, verifier.as_ref())?;
        if !tail.pending_effects.contains(correlation_id) {
            return Err(AuditError::Degraded(
                "requested correlation is not the journal's unresolved effect".to_owned(),
            ));
        }
        let pending_degradation = pending_effect_degradation(&tail.pending_effects);
        if g.degraded != pending_degradation {
            return Err(AuditError::Degraded(g.degraded.clone().unwrap_or_else(|| {
                "audit reconciliation refused because the active degradation is not solely an unresolved effect"
                    .to_owned()
            })));
        }
        g.last_digest = digest;
        g.sequence = tail.sequence;
        let result = Self::append_locked(
            &mut g,
            AuditRecord {
                ts_ms: 0,
                kind: "machine.effect.result".to_owned(),
                wallet: None,
                chain: None,
                data: serde_json::json!({
                    "operation": "operator.reconcile",
                    "correlation_id": correlation_id,
                    "outcome": outcome,
                    "result": {
                        "source": "explicit_local_operator_reconciliation",
                        "redispatched": false,
                    },
                }),
                prev: String::new(),
                digest: String::new(),
            },
            true,
        )?;
        let verifier = g.identity.as_ref().map(AuditIdentity::verifier);
        let (_, tail) = inspect(&g.path, verifier.as_ref())?;
        g.degraded = pending_effect_degradation(&tail.pending_effects);
        Ok(result)
    }

    #[cfg(any(test, feature = "audit-test-seam"))]
    pub fn fail_next_write_for_test(&self) {
        self.inner.lock().fail_next_write = true;
    }

    #[cfg(any(test, feature = "audit-test-seam"))]
    pub fn fail_after_writes_for_test(&self, successful_writes: usize) {
        self.inner.lock().fail_after_writes = Some(successful_writes);
    }

    /// Hex of the most recently appended record's digest (empty if log is empty).
    pub fn head_hash(&self) -> String {
        self.inner.lock().last_digest.clone()
    }

    /// On-disk path of the audit log file.
    pub fn path(&self) -> PathBuf {
        self.inner.lock().path.clone()
    }

    /// Total number of entries currently persisted on disk. Lines that
    /// fail to parse are skipped (consistent with `verify`'s tolerance of
    /// blank lines). Returns 0 if the file does not exist.
    pub fn count(&self) -> Result<usize, AuditError> {
        let g = self.inner.lock();
        if !g.path.exists() {
            return Ok(0);
        }
        let f = std::fs::File::open(&g.path)?;
        let mut n = 0usize;
        for line in BufReader::new(f).lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            n += 1;
        }
        Ok(n)
    }

    /// Read up to the last `n` records from the log, oldest-first. Empty
    /// vec if the log is missing.
    pub fn tail(&self, n: usize) -> Result<Vec<AuditRecord>, AuditError> {
        let g = self.inner.lock();
        if !g.path.exists() || n == 0 {
            return Ok(Vec::new());
        }
        let f = std::fs::File::open(&g.path)?;
        let mut buf: std::collections::VecDeque<AuditRecord> =
            std::collections::VecDeque::with_capacity(n);
        for (line_no, line) in BufReader::new(f).lines().enumerate() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            let rec: AuditRecord = match decode_record(&line) {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(line = line_no + 1, error = %e, "audit.tail.skip_unparsable");
                    continue;
                }
            };
            if buf.len() == n {
                buf.pop_front();
            }
            buf.push_back(rec);
        }
        Ok(buf.into_iter().collect())
    }

    /// Walk the log and return Ok(()) iff the hash chain is intact.
    pub fn verify(path: &Path) -> Result<(), AuditError> {
        inspect(path, None)?;
        Ok(())
    }

    pub fn verify_signed(path: &Path, identity: &AuditIdentity) -> Result<(), AuditError> {
        let verifier = identity.verifier();
        inspect(path, Some(&verifier))?;
        Ok(())
    }
}

struct LegacyBinding {
    head: String,
    count: usize,
    source_blake3: String,
    preserved_name: String,
}

/// Move a fully verified unsigned predecessor aside and return the values to
/// bind into the first signed record. Malformed legacy input is never renamed
/// or trusted. The fixed preservation name also makes a crash between rename
/// and signed-genesis creation safely resumable.
fn prepare_legacy_migration(path: &Path) -> Result<Option<LegacyBinding>, AuditError> {
    let preserved = path.with_extension("legacy-unsigned-v0.jsonl");
    let source = if path.exists() && !first_nonempty_line_is_signed(path)? {
        if preserved.exists() {
            return Err(AuditError::Degraded(format!(
                "both unsigned journal {} and preserved predecessor {} exist",
                path.display(),
                preserved.display()
            )));
        }
        // Full legacy verification is mandatory before moving evidence.
        inspect(path, None)?;
        std::fs::rename(path, &preserved)?;
        sync_parent(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&preserved, std::fs::Permissions::from_mode(0o600))?;
        }
        preserved.as_path()
    } else if !path.exists() && preserved.exists() {
        // Resume an interrupted migration. Re-verify rather than trusting the
        // mere presence of the preservation file.
        inspect(&preserved, None)?;
        preserved.as_path()
    } else {
        return Ok(None);
    };
    let bytes = std::fs::read(source)?;
    let (head, tail) = inspect(source, None)?;
    let count = std::str::from_utf8(&bytes)
        .map_err(|_| AuditError::Degraded("legacy audit is not UTF-8".to_owned()))?
        .lines()
        .filter(|line| !line.is_empty())
        .count();
    if tail.sequence != 0 || !tail.pending_effects.is_empty() {
        return Err(AuditError::Degraded(
            "legacy predecessor is not an unsigned v0 journal".to_owned(),
        ));
    }
    Ok(Some(LegacyBinding {
        head,
        count,
        source_blake3: blake3::hash(&bytes).to_hex().to_string(),
        preserved_name: preserved
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("audit.legacy-unsigned-v0.jsonl")
            .to_owned(),
    }))
}

fn first_nonempty_line_is_signed(path: &Path) -> Result<bool, AuditError> {
    let file = std::fs::File::open(path)?;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if !line.is_empty() {
            let value: serde_json::Value = serde_json::from_str(&line)?;
            return Ok(value.get("sequence").is_some());
        }
    }
    Ok(false)
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), AuditError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn require_root_public_metadata(path: &Path) -> Result<(), AuditError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(AuditError::Degraded(format!(
            "Machine audit trust file {} is not a regular non-symlink file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            return Err(AuditError::Degraded(format!(
                "Machine audit trust file {} must be root-owned and not group/world writable",
                path.display()
            )));
        }
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), AuditError> {
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn finish_rotation_from_marker(
    path: &Path,
    old_identity: AuditIdentity,
    new_identity: AuditIdentity,
    trusted_history: &[AuditTrustedPredecessor],
    marker: &RotationMarker,
) -> Result<PathBuf, AuditError> {
    let parent = path
        .parent()
        .ok_or_else(|| AuditError::Degraded("audit path has no parent".to_owned()))?;
    let archive = parent.join(&marker.archive_name);
    let next = parent.join(&marker.next_name);
    let proof_path = parent.join(&marker.proof_name);
    if archive.parent() != Some(parent)
        || next.parent() != Some(parent)
        || proof_path.parent() != Some(parent)
        || marker.archive_name.contains('/')
        || marker.next_name.contains('/')
        || marker.proof_name.contains('/')
    {
        return Err(AuditError::Degraded(
            "audit rotation marker contains a non-local segment path".to_owned(),
        ));
    }
    let trusted = AuditTrustedPredecessor::new(
        old_identity.service_id.clone(),
        old_identity.key_id.clone(),
        old_identity.signing_key.verifying_key().to_bytes(),
        archive.clone(),
    );
    let mut complete_history = trusted_history.to_vec();
    if !complete_history.iter().any(|entry| {
        entry.service_id == trusted.service_id
            && entry.key_id == trusted.key_id
            && entry.archive_path == trusted.archive_path
    }) {
        complete_history.push(trusted);
    }

    // Once the predecessor has been renamed, verifier-only forward recovery
    // is sufficient and remains idempotent.
    if archive.exists() || !path.exists() {
        recover_rotation(path, &new_identity.verifier(), &complete_history)?;
        return Ok(archive);
    }

    let old = AuditLog::open_inner(
        path.to_owned(),
        Some(old_identity.clone()),
        trusted_history,
        false,
    )?;
    if let Some(reason) = old.mutation_degradation() {
        return Err(AuditError::Degraded(reason));
    }
    let old_lines = read_signed_lines(path)?;
    let final_record = match old_lines.last() {
        Some(line) if line.record.kind == "machine.audit.key_rotation.final" => {
            if line.record.data["next_key_id"].as_str() != Some(new_identity.key_id.as_str())
                || line.record.data["next_public_key_hex"].as_str()
                    != Some(new_identity.public_key_hex().as_str())
                || line.record.data["predecessor_archive"].as_str()
                    != Some(marker.archive_name.as_str())
            {
                return Err(AuditError::Degraded(
                    "durable audit rotation final conflicts with marker".to_owned(),
                ));
            }
            line.record.clone()
        }
        _ => old.append(AuditRecord {
            ts_ms: 0,
            kind: "machine.audit.key_rotation.final".to_owned(),
            wallet: None,
            chain: None,
            data: serde_json::json!({
                "next_key_id": new_identity.key_id,
                "next_public_key_hex": new_identity.public_key_hex(),
                "predecessor_archive": marker.archive_name,
            }),
            prev: String::new(),
            digest: String::new(),
        })?,
    };
    let old_sequence = old.sequence();
    let authorization_message = serde_json::json!({
        "domain": "bloom-audit-key-rotation/v1",
        "service_id": old_identity.service_id,
        "old_key_id": old_identity.key_id,
        "old_sequence": old_sequence,
        "old_head": final_record.digest,
        "new_key_id": new_identity.key_id,
        "new_public_key_hex": new_identity.public_key_hex(),
        "predecessor_archive": marker.archive_name,
    });
    let authorization_bytes = serde_json::to_vec(&authorization_message)?;
    let old_authorization_hex = hex::encode(
        old_identity
            .signing_key
            .sign(&authorization_bytes)
            .to_bytes(),
    );

    let genesis_record = if next.exists() {
        let (_, tail) = inspect(&next, Some(&new_identity.verifier()))?;
        let lines = read_signed_lines(&next)?;
        let first = lines.first().ok_or_else(|| {
            AuditError::Degraded("audit rotation next segment is empty".to_owned())
        })?;
        if lines.len() != 1
            || first.record.kind != "machine.audit.key_rotation.genesis"
            || first.record.data["authorization"] != authorization_message
            || tail.sequence != old_sequence.checked_add(1).unwrap_or(0)
        {
            return Err(AuditError::Degraded(
                "audit rotation next segment conflicts with durable marker".to_owned(),
            ));
        }
        first.record.clone()
    } else {
        if proof_path.exists() {
            return Err(AuditError::Degraded(
                "audit rotation proof exists without its next segment".to_owned(),
            ));
        }
        let new_log = AuditLog::open_inner(next.clone(), Some(new_identity.clone()), &[], false)?;
        new_log.inner.lock().sequence = old_sequence;
        new_log.append(AuditRecord {
            ts_ms: 0,
            kind: "machine.audit.key_rotation.genesis".to_owned(),
            wallet: None,
            chain: None,
            data: serde_json::json!({
                "authorization": authorization_message,
                "old_public_key_hex": old_identity.public_key_hex(),
                "old_authorization_hex": old_authorization_hex,
                "predecessor_archive": marker.archive_name,
                "rotation_proof": marker.proof_name,
            }),
            prev: String::new(),
            digest: String::new(),
        })?
    };
    let new_sequence = old_sequence
        .checked_add(1)
        .ok_or_else(|| AuditError::Degraded("audit sequence exhausted".to_owned()))?;
    let proof_payload = RotationProofPayload {
        schema: "bloom.machine-audit-rotation-proof.v1".to_owned(),
        service_id: old_identity.service_id.clone(),
        old_key_id: old_identity.key_id.clone(),
        old_public_key_hex: old_identity.public_key_hex(),
        old_sequence,
        final_old_head: final_record.digest,
        new_key_id: new_identity.key_id.clone(),
        new_public_key_hex: new_identity.public_key_hex(),
        new_sequence,
        first_new_head: genesis_record.digest,
        archive_name: marker.archive_name.clone(),
    };
    if proof_path.exists() {
        let existing: RotationProof = serde_json::from_slice(&std::fs::read(&proof_path)?)?;
        if serde_json::to_value(&existing.payload)? != serde_json::to_value(&proof_payload)? {
            return Err(AuditError::Degraded(
                "audit rotation proof conflicts with resumed transaction".to_owned(),
            ));
        }
    } else {
        let proof_bytes = serde_json::to_vec(&proof_payload)?;
        let proof = RotationProof {
            old_signature_hex: hex::encode(old_identity.signing_key.sign(&proof_bytes).to_bytes()),
            new_signature_hex: hex::encode(new_identity.signing_key.sign(&proof_bytes).to_bytes()),
            payload: proof_payload,
        };
        write_new_synced(&proof_path, &serde_json::to_vec(&proof)?)?;
    }
    std::fs::rename(path, &archive)?;
    sync_parent(path)?;
    std::fs::rename(&next, path)?;
    sync_parent(path)?;
    verify_rotation_history(path, &new_identity.verifier(), &complete_history)?;
    std::fs::remove_file(path.with_extension("rotation.json"))?;
    sync_parent(path)?;
    Ok(archive)
}

fn recover_rotation(
    path: &Path,
    current: &AuditVerifierIdentity,
    trusted_history: &[AuditTrustedPredecessor],
) -> Result<(), AuditError> {
    let marker_path = path.with_extension("rotation.json");
    if !marker_path.exists() {
        return Ok(());
    }
    let marker: RotationMarker = serde_json::from_slice(&std::fs::read(&marker_path)?)?;
    if marker.schema != "bloom.machine-audit-rotation.v1"
        || marker.service_id != current.service_id
        || marker.new_key_id != current.key_id
    {
        return Err(AuditError::Degraded(
            "audit rotation marker conflicts with the pinned current identity".to_owned(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| AuditError::Degraded("audit path has no parent".to_owned()))?;
    let archive = parent.join(&marker.archive_name);
    let next = parent.join(&marker.next_name);
    let proof = parent.join(&marker.proof_name);
    if archive.parent() != Some(parent)
        || next.parent() != Some(parent)
        || proof.parent() != Some(parent)
        || marker.archive_name.contains('/')
        || marker.next_name.contains('/')
        || marker.proof_name.contains('/')
    {
        return Err(AuditError::Degraded(
            "audit rotation marker contains a non-local segment path".to_owned(),
        ));
    }
    let predecessor = trusted_history
        .iter()
        .find(|entry| {
            entry.service_id == marker.service_id
                && entry.key_id == marker.old_key_id
                && entry.archive_path == archive
        })
        .ok_or_else(|| {
            AuditError::Degraded(
                "audit rotation recovery lacks the packaging-pinned predecessor".to_owned(),
            )
        })?;
    let old_verifier = AuditVerifierIdentity {
        service_id: predecessor.service_id.clone(),
        key_id: predecessor.key_id.clone(),
        public_key: predecessor.public_key,
    };
    match (path.exists(), archive.exists(), next.exists()) {
        (true, false, true) => {
            inspect(path, Some(&old_verifier))?;
            inspect(&next, Some(current))?;
            std::fs::rename(path, &archive)?;
            sync_parent(path)?;
            std::fs::rename(&next, path)?;
            sync_parent(path)?;
        }
        (false, true, true) => {
            inspect(&archive, Some(&old_verifier))?;
            inspect(&next, Some(current))?;
            std::fs::rename(&next, path)?;
            sync_parent(path)?;
        }
        (true, true, false) => {
            inspect(&archive, Some(&old_verifier))?;
            inspect(path, Some(current))?;
        }
        state => {
            return Err(AuditError::Degraded(format!(
                "conflicting audit rotation files (current, archive, next) = {state:?}"
            )));
        }
    }
    verify_rotation_history(path, current, trusted_history)?;
    std::fs::remove_file(&marker_path)?;
    sync_parent(path)
}

fn verify_rotation_history(
    path: &Path,
    current: &AuditVerifierIdentity,
    trusted_history: &[AuditTrustedPredecessor],
) -> Result<(), AuditError> {
    let mut consumed = std::collections::BTreeSet::new();
    verify_rotation_segment(path, current, trusted_history, &mut consumed)?;
    if consumed.len() != trusted_history.len() {
        return Err(AuditError::Degraded(
            "packaging supplied extra or conflicting audit predecessor history".to_owned(),
        ));
    }
    Ok(())
}

fn verify_rotation_segment(
    path: &Path,
    current: &AuditVerifierIdentity,
    trusted_history: &[AuditTrustedPredecessor],
    consumed: &mut std::collections::BTreeSet<usize>,
) -> Result<(), AuditError> {
    inspect(path, Some(current))?;
    let lines = read_signed_lines(path)?;
    let Some(first) = lines.first() else {
        if trusted_history.is_empty() {
            return Ok(());
        }
        return Err(AuditError::Degraded(
            "empty current audit segment conflicts with predecessor history".to_owned(),
        ));
    };
    if first.record.kind != "machine.audit.key_rotation.genesis" {
        return Ok(());
    }
    let authorization = &first.record.data["authorization"];
    let old_key_id = authorization["old_key_id"]
        .as_str()
        .ok_or(AuditError::Signature { line: 1 })?;
    let old_head = authorization["old_head"]
        .as_str()
        .ok_or(AuditError::Signature { line: 1 })?;
    let old_sequence = authorization["old_sequence"]
        .as_u64()
        .ok_or(AuditError::Signature { line: 1 })?;
    let archive_name = first.record.data["predecessor_archive"]
        .as_str()
        .ok_or(AuditError::Signature { line: 1 })?;
    let old_public: [u8; 32] = hex::decode(
        first.record.data["old_public_key_hex"]
            .as_str()
            .ok_or(AuditError::Signature { line: 1 })?,
    )
    .ok()
    .and_then(|bytes| bytes.try_into().ok())
    .ok_or(AuditError::Signature { line: 1 })?;
    let matches = trusted_history
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            entry.service_id == current.service_id
                && entry.key_id == old_key_id
                && entry.public_key == old_public
                && entry
                    .archive_path
                    .file_name()
                    .and_then(|value| value.to_str())
                    == Some(archive_name)
        })
        .collect::<Vec<_>>();
    let [(index, predecessor)] = matches.as_slice() else {
        return Err(AuditError::Degraded(
            "rotated audit genesis has no unique packaging-pinned predecessor".to_owned(),
        ));
    };
    if !consumed.insert(*index) {
        return Err(AuditError::Degraded(
            "audit predecessor history contains a cycle".to_owned(),
        ));
    }
    let old_verifier = AuditVerifierIdentity {
        service_id: predecessor.service_id.clone(),
        key_id: predecessor.key_id.clone(),
        public_key: predecessor.public_key,
    };
    let (archive_head, archive_tail) = inspect(&predecessor.archive_path, Some(&old_verifier))?;
    if archive_head != old_head || archive_tail.sequence != old_sequence {
        return Err(AuditError::Degraded(
            "rotated audit authorization does not bind the archived predecessor tail".to_owned(),
        ));
    }
    let old_lines = read_signed_lines(&predecessor.archive_path)?;
    let final_old = old_lines
        .last()
        .ok_or_else(|| AuditError::Degraded("rotated audit predecessor is empty".to_owned()))?;
    let expected_current_public = hex::encode(current.public_key);
    if final_old.record.kind != "machine.audit.key_rotation.final"
        || final_old.record.data["next_key_id"].as_str() != Some(current.key_id.as_str())
        || final_old.record.data["next_public_key_hex"].as_str()
            != Some(expected_current_public.as_str())
        || final_old.record.data["predecessor_archive"].as_str() != Some(archive_name)
    {
        return Err(AuditError::Degraded(
            "archived audit final record does not authorize the current segment".to_owned(),
        ));
    }
    let proof_name = first.record.data["rotation_proof"]
        .as_str()
        .ok_or(AuditError::Signature { line: 1 })?;
    let parent = path
        .parent()
        .ok_or_else(|| AuditError::Degraded("audit path has no parent".to_owned()))?;
    let proof_path = parent.join(proof_name);
    if proof_path.parent() != Some(parent) || proof_name.contains('/') {
        return Err(AuditError::Degraded(
            "audit rotation proof has a non-local path".to_owned(),
        ));
    }
    verify_rotation_proof(
        &proof_path,
        &old_verifier,
        current,
        &predecessor.archive_path,
        archive_head,
        archive_tail.sequence,
        path,
        &lines,
    )?;
    verify_rotation_segment(
        &predecessor.archive_path,
        &old_verifier,
        trusted_history,
        consumed,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_rotation_proof(
    proof_path: &Path,
    old: &AuditVerifierIdentity,
    new: &AuditVerifierIdentity,
    archive_path: &Path,
    old_head: String,
    old_sequence: u64,
    _new_segment_path: &Path,
    new_lines: &[SignedAuditLine],
) -> Result<(), AuditError> {
    let proof: RotationProof = serde_json::from_slice(&std::fs::read(proof_path)?)?;
    let first_new = new_lines
        .first()
        .ok_or_else(|| AuditError::Degraded("audit rotation new segment is empty".to_owned()))?;
    let archive_name = archive_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| AuditError::Degraded("audit archive name is not UTF-8".to_owned()))?;
    let payload = &proof.payload;
    if payload.schema != "bloom.machine-audit-rotation-proof.v1"
        || payload.service_id != old.service_id
        || payload.service_id != new.service_id
        || payload.old_key_id != old.key_id
        || payload.old_public_key_hex != hex::encode(old.public_key)
        || payload.old_sequence != old_sequence
        || payload.final_old_head != old_head
        || payload.new_key_id != new.key_id
        || payload.new_public_key_hex != hex::encode(new.public_key)
        || payload.new_sequence != first_new.sequence
        || first_new.sequence != old_sequence.checked_add(1).unwrap_or(0)
        || payload.first_new_head != first_new.record.digest
        || payload.archive_name != archive_name
    {
        return Err(AuditError::Degraded(
            "audit rotation proof does not bind the exact segment boundary".to_owned(),
        ));
    }
    let bytes = serde_json::to_vec(payload)?;
    verify_detached_signature(old, &bytes, &proof.old_signature_hex)?;
    verify_detached_signature(new, &bytes, &proof.new_signature_hex)?;
    Ok(())
}

fn verify_detached_signature(
    identity: &AuditVerifierIdentity,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), AuditError> {
    let signature: [u8; 64] = hex::decode(signature_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(AuditError::Signature { line: 0 })?;
    VerifyingKey::from_bytes(&identity.public_key)
        .map_err(|_| AuditError::Signature { line: 0 })?
        .verify(message, &Signature::from_bytes(&signature))
        .map_err(|_| AuditError::Signature { line: 0 })
}

fn read_signed_lines(path: &Path) -> Result<Vec<SignedAuditLine>, AuditError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(path)?;
    BufReader::new(file)
        .lines()
        .filter_map(|line| match line {
            Ok(line) if line.is_empty() => None,
            other => Some(other),
        })
        .map(|line| Ok(serde_json::from_str(&line?)?))
        .collect()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn decode_record(line: &str) -> Result<AuditRecord, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_str(line)?;
    if value.get("sequence").is_some() {
        serde_json::from_str::<SignedAuditLine>(line).map(|line| line.record)
    } else {
        serde_json::from_str(line)
    }
}

fn audit_signature_bytes(
    sequence: u64,
    service_id: &str,
    key_id: &str,
    public_key_hex: &str,
    record: &AuditRecord,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = b"bloom-service-audit/v1\0".to_vec();
    bytes.extend_from_slice(sequence.to_string().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(service_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(key_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(public_key_hex.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&serde_json::to_vec(record)?);
    Ok(bytes)
}

fn inspect(
    path: &Path,
    expected_identity: Option<&AuditVerifierIdentity>,
) -> Result<(String, VerifiedTail), AuditError> {
    if !path.exists() {
        return Ok((
            String::new(),
            VerifiedTail {
                sequence: 0,
                pending_effects: std::collections::BTreeSet::new(),
            },
        ));
    }
    let f = std::fs::File::open(path)?;
    let mut prev = String::new();
    let mut sequence = 0_u64;
    let mut pending_effects = std::collections::BTreeSet::new();
    let mut inferred_identity: Option<(String, String, [u8; 32])> = None;
    for (i, raw) in BufReader::new(f).lines().enumerate() {
        let raw = raw?;
        if raw.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(&raw)?;
        let signed = value.get("sequence").is_some();
        if expected_identity.is_some() && !signed {
            return Err(AuditError::Signature { line: i + 1 });
        }
        let mut record = if signed {
            let line: SignedAuditLine = serde_json::from_str(&raw)?;
            let expected_sequence =
                if sequence == 0 && line.record.kind == "machine.audit.key_rotation.genesis" {
                    line.record.data["authorization"]["old_sequence"]
                        .as_u64()
                        .and_then(|value| value.checked_add(1))
                        .ok_or(AuditError::Sequence { line: i + 1 })?
                } else {
                    sequence
                        .checked_add(1)
                        .ok_or(AuditError::Sequence { line: i + 1 })?
                };
            if line.sequence != expected_sequence {
                return Err(AuditError::Sequence { line: i + 1 });
            }
            let key_bytes: [u8; 32] = hex::decode(&line.public_key_hex)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(AuditError::Signature { line: i + 1 })?;
            if let Some(identity) = expected_identity
                && (line.service_id != identity.service_id
                    || line.key_id != identity.key_id
                    || key_bytes != identity.public_key)
            {
                return Err(AuditError::Identity { line: i + 1 });
            }
            match &inferred_identity {
                Some((service, key, public))
                    if service != &line.service_id
                        || key != &line.key_id
                        || public != &key_bytes =>
                {
                    return Err(AuditError::Identity { line: i + 1 });
                }
                None => {
                    inferred_identity =
                        Some((line.service_id.clone(), line.key_id.clone(), key_bytes));
                }
                _ => {}
            }
            let signature_bytes: [u8; 64] = hex::decode(&line.signature_hex)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(AuditError::Signature { line: i + 1 })?;
            let public = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|_| AuditError::Signature { line: i + 1 })?;
            public
                .verify(
                    &audit_signature_bytes(
                        line.sequence,
                        &line.service_id,
                        &line.key_id,
                        &line.public_key_hex,
                        &line.record,
                    )?,
                    &Signature::from_bytes(&signature_bytes),
                )
                .map_err(|_| AuditError::Signature { line: i + 1 })?;
            if line.record.kind == "machine.audit.key_rotation.genesis" {
                verify_rotation_genesis(&line, i + 1)?;
            }
            sequence = line.sequence;
            line.record
        } else {
            serde_json::from_str(&raw)?
        };
        if record.prev != prev {
            return Err(AuditError::Broken { line: i + 1 });
        }
        let saved = std::mem::take(&mut record.digest);
        let body = serde_json::to_string(&record)?;
        let digest = blake3::hash(body.as_bytes()).to_hex().to_string();
        if digest != saved {
            return Err(AuditError::Broken { line: i + 1 });
        }
        prev = saved;
        if record.kind == "machine.effect.intent" {
            let correlation =
                effect_correlation(&record).ok_or(AuditError::Broken { line: i + 1 })?;
            if pending_effects.len() >= MAX_PENDING_MACHINE_EFFECTS
                || !pending_effects.insert(correlation.to_owned())
            {
                return Err(AuditError::Broken { line: i + 1 });
            }
        } else if record.kind == "machine.effect.result" {
            let correlation =
                effect_correlation(&record).ok_or(AuditError::Broken { line: i + 1 })?;
            if !pending_effects.remove(correlation) {
                return Err(AuditError::Broken { line: i + 1 });
            }
        }
    }
    Ok((
        prev,
        VerifiedTail {
            sequence,
            pending_effects,
        },
    ))
}

fn effect_correlation(record: &AuditRecord) -> Option<&str> {
    record
        .data
        .get("correlation_id")
        .or_else(|| record.data.get("details")?.get("correlation_id"))
        .and_then(serde_json::Value::as_str)
}

fn prospective_effect_transition_is_valid(
    pending: &std::collections::BTreeSet<String>,
    record: &AuditRecord,
) -> bool {
    match record.kind.as_str() {
        "machine.effect.intent" => effect_correlation(record).is_some_and(|correlation| {
            pending.len() < MAX_PENDING_MACHINE_EFFECTS && !pending.contains(correlation)
        }),
        "machine.effect.result" => {
            effect_correlation(record).is_some_and(|correlation| pending.contains(correlation))
        }
        _ => true,
    }
}

fn pending_effect_degradation(pending: &std::collections::BTreeSet<String>) -> Option<String> {
    (!pending.is_empty()).then(|| {
        format!(
            "external effects {pending:?} have durable intents but no results; explicit reconciliation is required"
        )
    })
}

fn verify_rotation_genesis(line: &SignedAuditLine, line_number: usize) -> Result<(), AuditError> {
    let authorization = line
        .record
        .data
        .get("authorization")
        .ok_or(AuditError::Signature { line: line_number })?;
    if authorization
        .get("domain")
        .and_then(serde_json::Value::as_str)
        != Some("bloom-audit-key-rotation/v1")
        || authorization
            .get("service_id")
            .and_then(serde_json::Value::as_str)
            != Some(line.service_id.as_str())
        || authorization
            .get("new_key_id")
            .and_then(serde_json::Value::as_str)
            != Some(line.key_id.as_str())
        || authorization
            .get("new_public_key_hex")
            .and_then(serde_json::Value::as_str)
            != Some(line.public_key_hex.as_str())
    {
        return Err(AuditError::Identity { line: line_number });
    }
    let old_public_bytes: [u8; 32] = line
        .record
        .data
        .get("old_public_key_hex")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| hex::decode(value).ok())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(AuditError::Signature { line: line_number })?;
    let old_signature_bytes: [u8; 64] = line
        .record
        .data
        .get("old_authorization_hex")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| hex::decode(value).ok())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(AuditError::Signature { line: line_number })?;
    VerifyingKey::from_bytes(&old_public_bytes)
        .map_err(|_| AuditError::Signature { line: line_number })?
        .verify(
            &serde_json::to_vec(authorization)?,
            &Signature::from_bytes(&old_signature_bytes),
        )
        .map_err(|_| AuditError::Signature { line: line_number })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(byte: u8, key_id: &str) -> AuditIdentity {
        AuditIdentity::new(
            "bloom-machine",
            key_id,
            Arc::new(SigningKey::from_bytes(&[byte; 32])),
        )
    }

    fn record(kind: &str, value: usize) -> AuditRecord {
        AuditRecord {
            ts_ms: 0,
            kind: kind.into(),
            wallet: None,
            chain: None,
            data: serde_json::json!({"value": value}),
            prev: String::new(),
            digest: String::new(),
        }
    }

    fn write_rotation_marker_fixture(
        path: &Path,
        old: &AuditIdentity,
        new: &AuditIdentity,
    ) -> RotationMarker {
        let archive = AuditLog::rotation_archive_path(path, old.key_id());
        let next = path.with_extension("rotation-next.jsonl");
        let proof = AuditLog::rotation_proof_path(path, old.key_id());
        let marker = RotationMarker {
            schema: "bloom.machine-audit-rotation.v1".into(),
            service_id: old.service_id().into(),
            old_key_id: old.key_id().into(),
            new_key_id: new.key_id().into(),
            archive_name: archive.file_name().unwrap().to_str().unwrap().into(),
            next_name: next.file_name().unwrap().to_str().unwrap().into(),
            proof_name: proof.file_name().unwrap().to_str().unwrap().into(),
        };
        write_new_synced(
            &path.with_extension("rotation.json"),
            &serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();
        marker
    }

    fn signed_fixture(count: usize) -> (tempfile::TempDir, PathBuf, AuditIdentity) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let identity = identity(7, "machine-audit-1");
        let log = AuditLog::open_signed(&path, identity.clone()).unwrap();
        for value in 0..count {
            log.append(record("test", value)).unwrap();
        }
        (dir, path, identity)
    }

    #[test]
    fn round_trip_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&p).unwrap();
        for i in 0..5 {
            log.append(AuditRecord {
                ts_ms: 0,
                kind: "test".into(),
                wallet: None,
                chain: None,
                data: serde_json::json!({"i": i}),
                prev: String::new(),
                digest: String::new(),
            })
            .unwrap();
        }
        AuditLog::verify(&p).unwrap();
    }

    #[test]
    fn detects_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&p).unwrap();
        log.append(AuditRecord {
            ts_ms: 0,
            kind: "a".into(),
            wallet: None,
            chain: None,
            data: serde_json::json!({}),
            prev: String::new(),
            digest: String::new(),
        })
        .unwrap();
        log.append(AuditRecord {
            ts_ms: 0,
            kind: "b".into(),
            wallet: None,
            chain: None,
            data: serde_json::json!({}),
            prev: String::new(),
            digest: String::new(),
        })
        .unwrap();
        // Corrupt the first line.
        let s = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<&str> = s.lines().collect();
        let mut tampered: AuditRecord = serde_json::from_str(lines[0]).unwrap();
        tampered.kind = "evil".into();
        let new_first = serde_json::to_string(&tampered).unwrap();
        lines[0] = &new_first;
        let body = lines.join("\n") + "\n";
        std::fs::write(&p, body).unwrap();
        assert!(AuditLog::verify(&p).is_err());
    }

    #[test]
    fn signed_journal_rejects_payload_digest_signature_and_key_id_tamper() {
        for field in ["payload", "digest", "signature_hex", "key_id"] {
            let (_dir, path, identity) = signed_fixture(2);
            let source = std::fs::read_to_string(&path).unwrap();
            let mut lines: Vec<serde_json::Value> = source
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            match field {
                "payload" => lines[0]["data"]["value"] = serde_json::json!(99),
                "digest" => lines[0]["digest"] = serde_json::json!("00"),
                "signature_hex" => lines[0]["signature_hex"] = serde_json::json!("00"),
                "key_id" => lines[0]["key_id"] = serde_json::json!("attacker"),
                _ => unreachable!(),
            }
            let body = lines
                .iter()
                .map(serde_json::to_string)
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .join("\n")
                + "\n";
            std::fs::write(&path, body).unwrap();
            assert!(
                AuditLog::verify_signed(&path, &identity).is_err(),
                "{field} tamper must fail"
            );
        }
    }

    #[test]
    fn signed_journal_rejects_non_tail_deletion_and_reorder() {
        for reorder in [false, true] {
            let (_dir, path, identity) = signed_fixture(4);
            let source = std::fs::read_to_string(&path).unwrap();
            let mut lines: Vec<&str> = source.lines().collect();
            if reorder {
                lines.swap(1, 2);
            } else {
                lines.remove(1);
            }
            std::fs::write(&path, lines.join("\n") + "\n").unwrap();
            assert!(AuditLog::verify_signed(&path, &identity).is_err());
        }
    }

    #[test]
    fn startup_and_runtime_tamper_latch_mutations_but_reads_remain() {
        let (_dir, path, identity) = signed_fixture(2);
        let running = AuditLog::open_signed(&path, identity.clone()).unwrap();
        let mut source = std::fs::read_to_string(&path).unwrap();
        source = source.replacen("\"value\":0", "\"value\":9", 1);
        std::fs::write(&path, &source).unwrap();
        assert!(matches!(
            running.append(record("blocked", 3)),
            Err(AuditError::Degraded(_))
        ));
        assert!(running.mutation_degradation().is_some());
        assert_eq!(running.count().unwrap(), 2, "read/status remains available");

        let restarted = AuditLog::open_signed(&path, identity).unwrap();
        assert!(restarted.mutation_degradation().is_some());
        assert!(restarted.append(record("blocked", 4)).is_err());
        assert_eq!(restarted.tail(10).unwrap().len(), 2);
    }

    #[test]
    fn malformed_signed_or_legacy_evidence_starts_readable_and_mutation_latched() {
        for source in [
            r#"{"sequence":1}"#,
            r#"{"ts_ms":0,"kind":"legacy","data":{},"prev":"","digest":"bad"}"#,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("audit.jsonl");
            std::fs::write(&path, source.as_bytes()).unwrap();
            let before = std::fs::read(&path).unwrap();
            let log = AuditLog::open_signed(&path, identity(19, "machine-audit-malformed"))
                .expect("malformed evidence must not prevent read/status startup");
            assert!(log.mutation_degradation().is_some());
            assert_eq!(log.count().unwrap(), 1);
            assert!(log.tail(10).unwrap().len() <= 1);
            assert!(log.append(record("must-not-migrate", 1)).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert!(!path.with_extension("legacy-unsigned-v0.jsonl").exists());
        }
    }

    #[test]
    fn malformed_root_history_can_be_latched_without_losing_journal_status() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        let history = directory.path().join("machine-audit-history.json");
        std::fs::write(&history, b"not-json").unwrap();
        let history_error = match AuditLog::load_root_trusted_history(&history) {
            Err(error) => error,
            Ok(_) => panic!("malformed history unexpectedly loaded"),
        };
        let log = AuditLog::open_signed(&path, identity(20, "machine-audit-history-bad"))
            .expect("journal must remain status-capable");
        log.latch_mutations(format!("invalid packaging history: {history_error}"));
        assert!(log.mutation_degradation().is_some());
        assert_eq!(log.count().unwrap(), 0);
        assert!(log.tail(1).unwrap().is_empty());
        assert!(log.append(record("blocked", 1)).is_err());
        assert_eq!(std::fs::read(&history).unwrap(), b"not-json");
    }

    #[test]
    fn forced_write_failure_latches_without_publishing_a_record() {
        let (_dir, path, identity) = signed_fixture(1);
        let log = AuditLog::open_signed(&path, identity).unwrap();
        log.fail_next_write_for_test();
        assert!(log.append(record("not-written", 2)).is_err());
        assert!(log.mutation_degradation().is_some());
        assert_eq!(log.count().unwrap(), 1);
        assert!(log.append(record("still-blocked", 3)).is_err());
    }

    #[test]
    fn verified_unsigned_upgrade_is_preserved_and_bound_by_signed_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let legacy = AuditLog::open(&path).unwrap();
        legacy.append(record("legacy", 1)).unwrap();
        legacy.append(record("legacy", 2)).unwrap();
        let legacy_head = legacy.head_hash();
        drop(legacy);

        let identity = identity(8, "machine-audit-upgrade");
        let signed = AuditLog::open_signed(&path, identity.clone()).unwrap();
        assert!(signed.mutation_degradation().is_none());
        let genesis = signed.tail(1).unwrap().pop().unwrap();
        assert_eq!(genesis.kind, "machine.audit.legacy_genesis");
        assert_eq!(genesis.data["legacy_head"], legacy_head);
        assert_eq!(genesis.data["legacy_count"], 2);
        assert!(path.with_extension("legacy-unsigned-v0.jsonl").is_file());
        AuditLog::verify_signed(&path, &identity).unwrap();
    }

    #[test]
    fn signed_journal_cannot_be_reopened_or_extended_as_unsigned() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let signed = AuditLog::open_signed(&path, identity(81, "machine-audit-signed")).unwrap();
        signed.append(record("signed", 1)).unwrap();
        let original = std::fs::read(&path).unwrap();
        drop(signed);

        let error = match AuditLog::open(&path) {
            Ok(_) => panic!("signed journal reopened without its identity"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("without its application identity")
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn unmatched_intent_requires_exact_non_redispatch_reconciliation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let identity = identity(9, "machine-audit-reconcile");
        let log = AuditLog::open_signed(&path, identity.clone()).unwrap();
        log.append(AuditRecord {
            ts_ms: 0,
            kind: "machine.effect.intent".into(),
            wallet: None,
            chain: None,
            data: serde_json::json!({"correlation_id":"op:1"}),
            prev: String::new(),
            digest: String::new(),
        })
        .unwrap();
        drop(log);
        let restarted = AuditLog::open_signed(&path, identity).unwrap();
        assert_eq!(
            restarted.pending_effect_correlation().unwrap().as_deref(),
            Some("op:1")
        );
        assert!(restarted.append(record("must-not-dispatch", 1)).is_err());
        assert!(
            restarted
                .reconcile_pending_effect("op:1", "aborted", "wrong")
                .is_err()
        );
        let result = restarted
            .reconcile_pending_effect("op:1", "aborted", "RECONCILE MACHINE AUDIT op:1 AS ABORTED")
            .unwrap();
        assert_eq!(result.data["result"]["redispatched"], false);
        assert!(restarted.mutation_degradation().is_none());
        restarted.append(record("allowed", 2)).unwrap();
    }

    #[test]
    fn reconciling_one_of_multiple_intents_keeps_mutations_latched_until_all_close() {
        let (_dir, path, identity) = signed_fixture(0);
        let log = AuditLog::open_signed(&path, identity.clone()).unwrap();
        for correlation in ["op:a", "op:b"] {
            log.append(AuditRecord {
                ts_ms: 0,
                kind: "machine.effect.intent".into(),
                wallet: None,
                chain: None,
                data: serde_json::json!({"correlation_id": correlation}),
                prev: String::new(),
                digest: String::new(),
            })
            .unwrap();
        }
        drop(log);
        let restarted = AuditLog::open_signed(&path, identity).unwrap();
        assert!(restarted.mutation_degradation().is_some());
        restarted
            .reconcile_pending_effect("op:a", "aborted", "RECONCILE MACHINE AUDIT op:a AS ABORTED")
            .unwrap();
        assert!(restarted.mutation_degradation().is_some());
        assert_eq!(
            restarted.pending_effect_correlations().unwrap(),
            vec!["op:b".to_owned()]
        );
        assert!(restarted.append(record("still-latched", 1)).is_err());
        restarted
            .reconcile_pending_effect(
                "op:b",
                "committed",
                "RECONCILE MACHINE AUDIT op:b AS COMMITTED",
            )
            .unwrap();
        assert!(restarted.mutation_degradation().is_none());
        restarted.append(record("unlatched", 2)).unwrap();
    }

    #[test]
    fn reconciliation_and_remaining_latch_are_atomic_against_concurrent_mutations() {
        let (_dir, path, identity) = signed_fixture(0);
        let log = AuditLog::open_signed(&path, identity.clone()).unwrap();
        for correlation in ["race:a", "race:b"] {
            log.append(AuditRecord {
                ts_ms: 0,
                kind: "machine.effect.intent".into(),
                wallet: None,
                chain: None,
                data: serde_json::json!({"correlation_id": correlation}),
                prev: String::new(),
                digest: String::new(),
            })
            .unwrap();
        }
        drop(log);
        let restarted = Arc::new(AuditLog::open_signed(&path, identity).unwrap());
        let barrier = Arc::new(std::sync::Barrier::new(33));
        let mut racers = Vec::new();
        for value in 0..32 {
            let audit = restarted.clone();
            let barrier = barrier.clone();
            racers.push(std::thread::spawn(move || {
                barrier.wait();
                audit.append(record("concurrent-mutation-must-fail", value))
            }));
        }
        barrier.wait();
        restarted
            .reconcile_pending_effect(
                "race:a",
                "aborted",
                "RECONCILE MACHINE AUDIT race:a AS ABORTED",
            )
            .unwrap();
        for racer in racers {
            assert!(racer.join().unwrap().is_err());
        }
        assert_eq!(
            restarted.pending_effect_correlations().unwrap(),
            vec!["race:b".to_owned()]
        );
        assert!(
            restarted
                .tail(64)
                .unwrap()
                .iter()
                .all(|record| record.kind != "concurrent-mutation-must-fail")
        );
    }

    #[test]
    fn reconciliation_cannot_clear_an_independent_degradation_latch() {
        let (_dir, path, identity) = signed_fixture(0);
        let log = AuditLog::open_signed(&path, identity.clone()).unwrap();
        log.append(AuditRecord {
            ts_ms: 0,
            kind: "machine.effect.intent".into(),
            wallet: None,
            chain: None,
            data: serde_json::json!({"correlation_id": "independent:a"}),
            prev: String::new(),
            digest: String::new(),
        })
        .unwrap();
        drop(log);
        let restarted = AuditLog::open_signed(&path, identity).unwrap();
        restarted.latch_mutations("packaging trust evidence invalid");
        let error = restarted
            .reconcile_pending_effect(
                "independent:a",
                "aborted",
                "RECONCILE MACHINE AUDIT independent:a AS ABORTED",
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("packaging trust evidence invalid")
        );
        assert_eq!(
            restarted.pending_effect_correlations().unwrap(),
            vec!["independent:a".to_owned()]
        );
        assert!(
            restarted
                .mutation_degradation()
                .unwrap()
                .contains("packaging trust evidence invalid")
        );
    }

    #[test]
    fn application_key_rotation_cross_binds_segments_and_restarts() {
        let (_dir, path, old) = signed_fixture(2);
        let new = identity(10, "machine-audit-2");
        let archive = AuditLog::rotate_identity(&path, old.clone(), new.clone()).unwrap();
        AuditLog::verify_signed(&archive, &old).unwrap();
        AuditLog::verify_signed(&path, &new).unwrap();
        let history = [AuditTrustedPredecessor::new(
            old.service_id(),
            old.key_id(),
            old.signing_key.verifying_key().to_bytes(),
            archive,
        )];
        let restarted = AuditLog::open_signed_with_history(&path, new, &history).unwrap();
        assert!(restarted.mutation_degradation().is_none());
        assert_eq!(restarted.sequence(), 4);
        assert_eq!(
            restarted.tail(1).unwrap()[0].kind,
            "machine.audit.key_rotation.genesis"
        );
        restarted.append(record("post-rotation", 3)).unwrap();
        assert_eq!(restarted.sequence(), 5);
    }

    #[test]
    fn rotation_sequence_is_global_and_proof_binds_the_exact_increment() {
        let (_dir, path, old) = signed_fixture(5);
        let new = identity(17, "machine-audit-global-sequence");
        let archive = AuditLog::rotate_identity(&path, old.clone(), new.clone()).unwrap();
        let old_lines = read_signed_lines(&archive).unwrap();
        let new_lines = read_signed_lines(&path).unwrap();
        assert_eq!(old_lines.last().unwrap().sequence, 6);
        assert_eq!(new_lines.first().unwrap().sequence, 7);
        let proof: RotationProof = serde_json::from_slice(
            &std::fs::read(AuditLog::rotation_proof_path(&path, old.key_id())).unwrap(),
        )
        .unwrap();
        assert_eq!(proof.payload.old_sequence, 6);
        assert_eq!(proof.payload.new_sequence, 7);
        let history = [AuditTrustedPredecessor::new(
            old.service_id(),
            old.key_id(),
            old.signing_key.verifying_key().to_bytes(),
            archive,
        )];
        let restarted = AuditLog::open_signed_with_history(&path, new, &history).unwrap();
        assert!(restarted.mutation_degradation().is_none());
        assert_eq!(restarted.sequence(), 7);
    }

    #[test]
    fn rotation_retry_resumes_marker_only_and_marker_plus_final_without_next() {
        for phase in ["marker_only", "marker_plus_final"] {
            let (_dir, path, old) = signed_fixture(2);
            let new = identity(18, "machine-audit-forward-resume");
            let marker = write_rotation_marker_fixture(&path, &old, &new);
            if phase == "marker_plus_final" {
                let old_log =
                    AuditLog::open_inner(path.clone(), Some(old.clone()), &[], false).unwrap();
                old_log
                    .append(AuditRecord {
                        ts_ms: 0,
                        kind: "machine.audit.key_rotation.final".into(),
                        wallet: None,
                        chain: None,
                        data: serde_json::json!({
                            "next_key_id": new.key_id(),
                            "next_public_key_hex": new.public_key_hex(),
                            "predecessor_archive": marker.archive_name,
                        }),
                        prev: String::new(),
                        digest: String::new(),
                    })
                    .unwrap();
            }
            let archive = AuditLog::rotate_identity(&path, old.clone(), new.clone()).unwrap();
            let history = [AuditTrustedPredecessor::new(
                old.service_id(),
                old.key_id(),
                old.signing_key.verifying_key().to_bytes(),
                archive,
            )];
            let restarted = AuditLog::open_signed_with_history(&path, new, &history).unwrap();
            assert!(restarted.mutation_degradation().is_none(), "phase={phase}");
            assert_eq!(restarted.sequence(), 4, "phase={phase}");
            assert!(!path.with_extension("rotation.json").exists());
        }
    }

    #[test]
    fn rotation_restart_rejects_boundary_head_and_either_cross_signature_tamper() {
        for field in [
            "final_old_head",
            "first_new_head",
            "old_signature_hex",
            "new_signature_hex",
        ] {
            let (_dir, path, old) = signed_fixture(2);
            let new = identity(14, "machine-audit-cross-signatures");
            let archive = AuditLog::rotate_identity(&path, old.clone(), new.clone()).unwrap();
            let proof_path = AuditLog::rotation_proof_path(&path, old.key_id());
            let mut proof: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&proof_path).unwrap()).unwrap();
            if matches!(field, "final_old_head" | "first_new_head") {
                proof["payload"][field] = serde_json::Value::String("00".repeat(32));
            } else {
                proof[field] = serde_json::Value::String("00".repeat(64));
            }
            std::fs::write(&proof_path, serde_json::to_vec(&proof).unwrap()).unwrap();
            let history = [AuditTrustedPredecessor::new(
                old.service_id(),
                old.key_id(),
                old.signing_key.verifying_key().to_bytes(),
                archive,
            )];
            let restarted =
                AuditLog::open_signed_with_history(&path, new.clone(), &history).unwrap();
            assert!(
                restarted.mutation_degradation().is_some(),
                "tampered field {field} must latch mutations"
            );
        }
    }

    #[test]
    fn application_key_rotation_recovers_each_rename_interruption() {
        for phase in ["before_old_rename", "between_renames", "after_both_renames"] {
            let (_dir, path, old) = signed_fixture(2);
            let new = identity(11, "machine-audit-recovery");
            let archive = AuditLog::rotate_identity(&path, old.clone(), new.clone()).unwrap();
            let next = path.with_extension("rotation-next.jsonl");
            let marker_path = path.with_extension("rotation.json");
            let marker = RotationMarker {
                schema: "bloom.machine-audit-rotation.v1".into(),
                service_id: "bloom-machine".into(),
                old_key_id: old.key_id().into(),
                new_key_id: new.key_id().into(),
                archive_name: archive.file_name().unwrap().to_str().unwrap().into(),
                next_name: next.file_name().unwrap().to_str().unwrap().into(),
                proof_name: AuditLog::rotation_proof_path(&path, old.key_id())
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .into(),
            };
            if phase == "before_old_rename" {
                std::fs::rename(&path, &next).unwrap();
                std::fs::rename(&archive, &path).unwrap();
            } else if phase == "between_renames" {
                std::fs::rename(&path, &next).unwrap();
            }
            write_new_synced(&marker_path, &serde_json::to_vec(&marker).unwrap()).unwrap();
            let history = [AuditTrustedPredecessor::new(
                old.service_id(),
                old.key_id(),
                old.signing_key.verifying_key().to_bytes(),
                archive.clone(),
            )];
            let recovered =
                AuditLog::open_signed_with_history(&path, new.clone(), &history).unwrap();
            assert!(recovered.mutation_degradation().is_none(), "phase={phase}");
            assert!(path.is_file());
            assert!(archive.is_file());
            assert!(!next.exists());
            assert!(!marker_path.exists());
        }
    }

    #[test]
    fn durable_rotation_marker_before_first_mutation_latches_old_and_new_startup() {
        let (_dir, path, old) = signed_fixture(2);
        let new = identity(15, "machine-audit-early-marker");
        let archive = AuditLog::rotation_archive_path(&path, old.key_id());
        let next = path.with_extension("rotation-next.jsonl");
        let proof = AuditLog::rotation_proof_path(&path, old.key_id());
        let marker = RotationMarker {
            schema: "bloom.machine-audit-rotation.v1".into(),
            service_id: old.service_id().into(),
            old_key_id: old.key_id().into(),
            new_key_id: new.key_id().into(),
            archive_name: archive.file_name().unwrap().to_str().unwrap().into(),
            next_name: next.file_name().unwrap().to_str().unwrap().into(),
            proof_name: proof.file_name().unwrap().to_str().unwrap().into(),
        };
        write_new_synced(
            &path.with_extension("rotation.json"),
            &serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();

        let old_restart = AuditLog::open_signed(&path, old.clone()).unwrap();
        assert!(old_restart.mutation_degradation().is_some());
        assert!(old_restart.append(record("must-not-continue", 3)).is_err());

        let history = [AuditTrustedPredecessor::new(
            old.service_id(),
            old.key_id(),
            old.signing_key.verifying_key().to_bytes(),
            archive,
        )];
        let new_restart = AuditLog::open_signed_with_history(&path, new, &history).unwrap();
        assert!(new_restart.mutation_degradation().is_some());
    }

    #[test]
    fn rotation_preflights_every_output_before_appending_final_authorization() {
        for conflict in ["archive", "next", "proof", "marker"] {
            let (_dir, path, old) = signed_fixture(2);
            let new = identity(16, "machine-audit-preflight");
            let candidate = match conflict {
                "archive" => AuditLog::rotation_archive_path(&path, old.key_id()),
                "next" => path.with_extension("rotation-next.jsonl"),
                "proof" => AuditLog::rotation_proof_path(&path, old.key_id()),
                "marker" => path.with_extension("rotation.json"),
                _ => unreachable!(),
            };
            std::fs::write(candidate, b"conflict").unwrap();
            assert!(AuditLog::rotate_identity(&path, old.clone(), new).is_err());
            let lines = read_signed_lines(&path).unwrap();
            assert_eq!(lines.len(), 2, "conflict={conflict}");
            assert_ne!(
                lines.last().unwrap().record.kind,
                "machine.audit.key_rotation.final",
                "conflict={conflict}"
            );
        }
    }

    #[test]
    fn rotation_restart_rejects_missing_extra_or_tampered_pinned_history() {
        let (_dir, path, old) = signed_fixture(2);
        let new = identity(12, "machine-audit-history");
        let archive = AuditLog::rotate_identity(&path, old.clone(), new.clone()).unwrap();
        let missing = AuditLog::open_signed(&path, new.clone()).unwrap();
        assert!(missing.mutation_degradation().is_some());

        let mut archive_source = std::fs::read_to_string(&archive).unwrap();
        archive_source = archive_source.replacen("\"value\":0", "\"value\":8", 1);
        std::fs::write(&archive, archive_source).unwrap();
        let history = [AuditTrustedPredecessor::new(
            old.service_id(),
            old.key_id(),
            old.signing_key.verifying_key().to_bytes(),
            archive.clone(),
        )];
        let tampered = AuditLog::open_signed_with_history(&path, new.clone(), &history).unwrap();
        assert!(tampered.mutation_degradation().is_some());

        let extra = [
            history[0].clone(),
            AuditTrustedPredecessor::new(
                "bloom-machine",
                "unrelated",
                [99; 32],
                archive.with_extension("unrelated.jsonl"),
            ),
        ];
        let extra_log = AuditLog::open_signed_with_history(&path, new, &extra).unwrap();
        assert!(extra_log.mutation_degradation().is_some());
    }
}
