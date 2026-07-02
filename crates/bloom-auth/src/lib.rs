//! Concrete Layer B authorization store and verifier.
//!
//! The daemon wires [`AuthStore`] and [`StoreApprovalVerifier`] into the VFS
//! handlers, TX engine, and IPC server at startup. VFS-facing crates depend
//! only on `bloom-auth-api`; this crate stays daemon-side so NFS/petal
//! surfaces never pull in the authorization TCB.

use async_trait::async_trait;
use bloom_auth_api::{
    Approval, ApprovalCredentialRecord, ApprovalSignature, ApprovalSignatureVerifier,
    ApprovalVerifier, AssuranceLevel, AuthApiError, AuthEntryRecord, AuthEntryState, AuthStoreView,
    AuthStoreWriter, CanonicalEnvelope, ChallengeRecord, NonceState, PriceOracle,
    ReservationRecord, ReservationState, ReviewSessionRecord, SealedIntentRecord, SignerKind,
    UnsignedApproval, ValuationPolicy, ValuationQuote,
};
use bloom_prices::{CoinId, PricesClient};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum AuthStoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("auth api: {0}")]
    Api(#[from] AuthApiError),
    #[error("invalid database pragma {name}: expected {expected}, got {actual}")]
    InvalidPragma {
        name: &'static str,
        expected: &'static str,
        actual: String,
    },
    #[error("invalid state value {0}")]
    InvalidState(String),
    #[error("invalid assurance value {0}")]
    InvalidAssurance(String),
    #[error("invalid reservation state value {0}")]
    InvalidReservationState(String),
    #[error("invalid integer value {field}: {value}")]
    InvalidInteger { field: &'static str, value: String },
    #[error("authorization denied: {0}")]
    Denied(String),
}

impl From<AuthStoreError> for AuthApiError {
    fn from(value: AuthStoreError) -> Self {
        AuthApiError::Store(value.to_string())
    }
}

pub struct AuthStore {
    conn: Connection,
}

pub struct StoreApprovalVerifier<S> {
    store: Mutex<AuthStore>,
    signature_verifier: S,
}

/// Fail-closed placeholder for runtime wiring before production approval
/// signature verification is installed.
///
/// This is deliberately not a test signer. If a migrated production path is
/// connected to it, approval verification fails instead of creating a soft
/// authorization bypass while the WebAuthn/CTAP verifier is still being built.
#[derive(Debug, Clone, Copy, Default)]
pub struct RejectingApprovalSignatureVerifier;

#[derive(Debug, Clone)]
pub struct BloomPricesOracle {
    client: PricesClient,
    source: String,
}

impl BloomPricesOracle {
    pub fn new(client: PricesClient) -> Self {
        Self {
            client,
            source: "bloom-prices:defillama".into(),
        }
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = source.into();
        self
    }
}

impl<S> StoreApprovalVerifier<S> {
    pub fn new(store: AuthStore, signature_verifier: S) -> Self {
        Self {
            store: Mutex::new(store),
            signature_verifier,
        }
    }
}

#[async_trait]
impl ApprovalSignatureVerifier for RejectingApprovalSignatureVerifier {
    async fn verify_signature(
        &self,
        _unsigned: &UnsignedApproval,
        _signature: &ApprovalSignature,
        _now_ms: u64,
    ) -> Result<(), AuthApiError> {
        Err(AuthApiError::Denied(
            "production approval signature verifier is not installed".into(),
        ))
    }
}

impl AuthStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuthStoreError> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        Self::configure_connection(&conn)?;
        Self::migrate(&conn)?;
        Ok(Self { conn })
    }

    pub fn open_in_memory_for_tests() -> Result<Self, AuthStoreError> {
        let conn = Connection::open_in_memory()?;
        Self::configure_connection(&conn)?;
        Self::migrate(&conn)?;
        Ok(Self { conn })
    }

    fn configure_connection(conn: &Connection) -> Result<(), AuthStoreError> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        let synchronous: i64 = conn.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
        if synchronous != 2 {
            return Err(AuthStoreError::InvalidPragma {
                name: "synchronous",
                expected: "FULL",
                actual: synchronous.to_string(),
            });
        }
        let foreign_keys: i64 = conn.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
        if foreign_keys != 1 {
            return Err(AuthStoreError::InvalidPragma {
                name: "foreign_keys",
                expected: "ON",
                actual: foreign_keys.to_string(),
            });
        }
        Ok(())
    }

    fn migrate(conn: &Connection) -> Result<(), AuthStoreError> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS sealed_intents (
                intent_hash TEXT PRIMARY KEY NOT NULL,
                envelope_json TEXT NOT NULL,
                sealed_at_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS auth_entries (
                surface TEXT NOT NULL,
                entry_id TEXT NOT NULL,
                state TEXT NOT NULL,
                intent_hash TEXT NOT NULL REFERENCES sealed_intents(intent_hash),
                assurance TEXT NOT NULL,
                nonce TEXT,
                nonce_state TEXT NOT NULL DEFAULT 'unused',
                challenge_expiry_ms INTEGER,
                reservation_id TEXT,
                updated_ms INTEGER NOT NULL,
                PRIMARY KEY(surface, entry_id)
            );

            CREATE TABLE IF NOT EXISTS approvals (
                surface TEXT NOT NULL,
                entry_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                approval_json TEXT NOT NULL,
                signer_kind TEXT NOT NULL,
                assurance TEXT NOT NULL,
                expiry_ms INTEGER NOT NULL,
                consumed_ms INTEGER,
                PRIMARY KEY(surface, entry_id, nonce)
            );

            CREATE TABLE IF NOT EXISTS review_sessions (
                review_session_id TEXT PRIMARY KEY NOT NULL,
                surface TEXT NOT NULL,
                entry_id TEXT NOT NULL,
                intent_hash TEXT NOT NULL REFERENCES sealed_intents(intent_hash),
                assurance TEXT NOT NULL,
                expires_ms INTEGER NOT NULL,
                consumed_ms INTEGER,
                created_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS approval_credentials (
                wallet TEXT NOT NULL,
                credential_id TEXT NOT NULL,
                signer_kind TEXT NOT NULL,
                assurance TEXT NOT NULL,
                public_key_json TEXT NOT NULL,
                registered_ms INTEGER NOT NULL,
                revoked_ms INTEGER,
                PRIMARY KEY(wallet, credential_id)
            );

            CREATE TABLE IF NOT EXISTS reservations (
                reservation_id TEXT PRIMARY KEY NOT NULL,
                wallet TEXT NOT NULL,
                venue TEXT NOT NULL,
                amount_micro_usd TEXT NOT NULL,
                state TEXT NOT NULL,
                created_ms INTEGER NOT NULL,
                updated_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS valuation_snapshots (
                reservation_id TEXT PRIMARY KEY NOT NULL REFERENCES reservations(reservation_id),
                valuation_json TEXT NOT NULL,
                created_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                prev_digest TEXT NOT NULL,
                digest TEXT NOT NULL,
                event TEXT NOT NULL,
                record_json TEXT NOT NULL,
                created_ms INTEGER NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    pub fn insert_sealed_intent(
        &mut self,
        envelope: &CanonicalEnvelope,
        sealed_at_ms: u64,
    ) -> Result<String, AuthStoreError> {
        let intent_hash = envelope.intent_hash().map_err(AuthStoreError::from_api)?;
        let envelope_json = serde_json::to_string(envelope)?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO sealed_intents(intent_hash, envelope_json, sealed_at_ms)
             VALUES (?1, ?2, ?3)",
            params![intent_hash, envelope_json, sealed_at_ms as i64],
        )?;
        tx.commit()?;
        Ok(intent_hash)
    }

    pub fn stage_entry(
        &mut self,
        envelope: &CanonicalEnvelope,
        assurance: AssuranceLevel,
        now_ms: u64,
    ) -> Result<AuthEntryRecord, AuthStoreError> {
        let intent_hash = envelope.intent_hash().map_err(AuthStoreError::from_api)?;
        let envelope_json = serde_json::to_string(envelope)?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO sealed_intents(intent_hash, envelope_json, sealed_at_ms)
             VALUES (?1, ?2, ?3)",
            params![intent_hash, envelope_json, now_ms as i64],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO auth_entries(
                surface, entry_id, state, intent_hash, assurance, nonce, nonce_state,
                reservation_id, updated_ms
             )
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, NULL, ?7)
            ",
            params![
                envelope.header.surface,
                envelope.header.entry_id,
                AuthEntryState::Staged.as_str(),
                intent_hash,
                assurance.as_str(),
                NonceState::Unused.as_str(),
                now_ms as i64,
            ],
        )?;
        tx.commit()?;
        let entry = self
            .auth_entry(&envelope.header.surface, &envelope.header.entry_id)?
            .ok_or_else(|| AuthStoreError::Denied("staged entry was not persisted".into()))?;
        if entry.intent_hash != intent_hash || entry.assurance != assurance {
            return Err(AuthStoreError::Denied(
                "auth entry already exists for different intent or assurance".into(),
            ));
        }
        Ok(entry)
    }

    pub fn issue_challenge(
        &mut self,
        surface: &str,
        entry_id: &str,
        server_nonce: &str,
        expiry_ms: u64,
        now_ms: u64,
    ) -> Result<ChallengeRecord, AuthStoreError> {
        let tx = self.conn.transaction()?;
        let (intent_hash, assurance): (String, String) = tx
            .query_row(
                "SELECT intent_hash, assurance FROM auth_entries
                 WHERE surface = ?1 AND entry_id = ?2 AND nonce_state = 'unused'",
                params![surface, entry_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| AuthStoreError::Denied("entry is not challengeable".into()))?;
        tx.execute(
            "UPDATE auth_entries
             SET state = ?3, nonce = ?4, nonce_state = ?5, challenge_expiry_ms = ?6, updated_ms = ?7
             WHERE surface = ?1 AND entry_id = ?2 AND nonce_state = 'unused'",
            params![
                surface,
                entry_id,
                AuthEntryState::Challenged.as_str(),
                server_nonce,
                NonceState::Unused.as_str(),
                expiry_ms as i64,
                now_ms as i64,
            ],
        )?;
        tx.commit()?;
        Ok(ChallengeRecord {
            surface: surface.to_string(),
            entry_id: entry_id.to_string(),
            intent_hash,
            server_nonce: server_nonce.to_string(),
            assurance: parse_assurance(&assurance)?,
            expiry_ms,
        })
    }

    pub fn issue_review_session(
        &mut self,
        review_session_id: &str,
        surface: &str,
        entry_id: &str,
        expires_ms: u64,
        now_ms: u64,
    ) -> Result<ReviewSessionRecord, AuthStoreError> {
        let tx = self.conn.transaction()?;
        let (intent_hash, assurance): (String, String) = tx
            .query_row(
                "SELECT intent_hash, assurance FROM auth_entries
                 WHERE surface = ?1 AND entry_id = ?2",
                params![surface, entry_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| AuthStoreError::Denied("entry not found".into()))?;
        tx.execute(
            "INSERT INTO review_sessions(
                review_session_id, surface, entry_id, intent_hash, assurance, expires_ms,
                consumed_ms, created_ms
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
            params![
                review_session_id,
                surface,
                entry_id,
                intent_hash,
                assurance,
                expires_ms as i64,
                now_ms as i64,
            ],
        )?;
        tx.commit()?;
        self.review_session(review_session_id)?
            .ok_or_else(|| AuthStoreError::Denied("review session was not persisted".into()))
    }

    pub fn review_session(
        &self,
        review_session_id: &str,
    ) -> Result<Option<ReviewSessionRecord>, AuthStoreError> {
        self.conn
            .query_row(
                "SELECT surface, entry_id, intent_hash, assurance, expires_ms, consumed_ms, created_ms
                 FROM review_sessions WHERE review_session_id = ?1",
                params![review_session_id],
                |row| {
                    let surface: String = row.get(0)?;
                    let entry_id: String = row.get(1)?;
                    let intent_hash: String = row.get(2)?;
                    let assurance: String = row.get(3)?;
                    let expires_ms: i64 = row.get(4)?;
                    let consumed_ms: Option<i64> = row.get(5)?;
                    let created_ms: i64 = row.get(6)?;
                    Ok((
                        surface,
                        entry_id,
                        intent_hash,
                        assurance,
                        expires_ms,
                        consumed_ms,
                        created_ms,
                    ))
                },
            )
            .optional()?
            .map(
                |(surface, entry_id, intent_hash, assurance, expires_ms, consumed_ms, created_ms)| {
                    Ok(ReviewSessionRecord {
                        review_session_id: review_session_id.to_string(),
                        surface,
                        entry_id,
                        intent_hash,
                        assurance: parse_assurance(&assurance)?,
                        expires_ms: expires_ms as u64,
                        consumed_ms: consumed_ms.map(|v| v as u64),
                        created_ms: created_ms as u64,
                    })
                },
            )
            .transpose()
    }

    pub fn register_approval_credential(
        &mut self,
        record: &ApprovalCredentialRecord,
    ) -> Result<(), AuthStoreError> {
        record.validate().map_err(AuthStoreError::from_api)?;
        let public_key_json = serde_json::to_string(&record.public_key_json)?;
        self.conn.execute(
            "INSERT INTO approval_credentials(
                wallet, credential_id, signer_kind, assurance, public_key_json,
                registered_ms, revoked_ms
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.wallet,
                record.credential_id,
                signer_kind_str(record.signer_kind),
                record.assurance.as_str(),
                public_key_json,
                record.registered_ms as i64,
                record.revoked_ms.map(|v| v as i64),
            ],
        )?;
        Ok(())
    }

    pub fn approval_credential(
        &self,
        wallet: &str,
        credential_id: &str,
    ) -> Result<Option<ApprovalCredentialRecord>, AuthStoreError> {
        self.conn
            .query_row(
                "SELECT signer_kind, assurance, public_key_json, registered_ms, revoked_ms
                 FROM approval_credentials WHERE wallet = ?1 AND credential_id = ?2",
                params![wallet, credential_id],
                |row| {
                    let signer_kind: String = row.get(0)?;
                    let assurance: String = row.get(1)?;
                    let public_key_json: String = row.get(2)?;
                    let registered_ms: i64 = row.get(3)?;
                    let revoked_ms: Option<i64> = row.get(4)?;
                    Ok((
                        signer_kind,
                        assurance,
                        public_key_json,
                        registered_ms,
                        revoked_ms,
                    ))
                },
            )
            .optional()?
            .map(
                |(signer_kind, assurance, public_key_json, registered_ms, revoked_ms)| {
                    let record = ApprovalCredentialRecord {
                        wallet: wallet.to_string(),
                        credential_id: credential_id.to_string(),
                        signer_kind: parse_signer_kind(&signer_kind)?,
                        assurance: parse_assurance(&assurance)?,
                        public_key_json: serde_json::from_str(&public_key_json)?,
                        registered_ms: registered_ms as u64,
                        revoked_ms: revoked_ms.map(|v| v as u64),
                    };
                    record.validate().map_err(AuthStoreError::from_api)?;
                    Ok(record)
                },
            )
            .transpose()
    }

    pub fn revoke_approval_credential(
        &mut self,
        wallet: &str,
        credential_id: &str,
        revoked_ms: u64,
    ) -> Result<(), AuthStoreError> {
        let rows = self.conn.execute(
            "UPDATE approval_credentials
             SET revoked_ms = ?3
             WHERE wallet = ?1 AND credential_id = ?2 AND revoked_ms IS NULL",
            params![wallet, credential_id, revoked_ms as i64],
        )?;
        if rows == 0 {
            return Err(AuthStoreError::Denied(
                "approval credential not found or already revoked".into(),
            ));
        }
        Ok(())
    }

    pub fn auth_entry(
        &self,
        surface: &str,
        entry_id: &str,
    ) -> Result<Option<AuthEntryRecord>, AuthStoreError> {
        self.conn
            .query_row(
                "SELECT state, intent_hash, assurance, nonce, nonce_state, reservation_id, updated_ms
                 FROM auth_entries WHERE surface = ?1 AND entry_id = ?2",
                params![surface, entry_id],
                |row| {
                    let state: String = row.get(0)?;
                    let intent_hash: String = row.get(1)?;
                    let assurance: String = row.get(2)?;
                    let nonce: Option<String> = row.get(3)?;
                    let nonce_state: String = row.get(4)?;
                    let reservation_id: Option<String> = row.get(5)?;
                    let updated_ms: i64 = row.get(6)?;
                    Ok((
                        state,
                        intent_hash,
                        assurance,
                        nonce,
                        nonce_state,
                        reservation_id,
                        updated_ms,
                    ))
                },
            )
            .optional()?
            .map(
                |(state, intent_hash, assurance, nonce, nonce_state, reservation_id, updated_ms)| {
                    Ok(AuthEntryRecord {
                        surface: surface.to_string(),
                        entry_id: entry_id.to_string(),
                        state: parse_entry_state(&state)?,
                        intent_hash,
                        assurance: parse_assurance(&assurance)?,
                        nonce,
                        nonce_state: parse_nonce_state(&nonce_state)?,
                        reservation_id,
                        updated_ms: updated_ms as u64,
                    })
                },
            )
            .transpose()
    }

    pub fn consume_verified_approval_transactionally(
        &mut self,
        approval: &Approval,
        now_ms: u64,
    ) -> Result<(), AuthStoreError> {
        let tx = self.conn.transaction()?;
        let (entry_intent_hash, entry_assurance, entry_nonce, nonce_state, challenge_expiry_ms): (
            String,
            String,
            Option<String>,
            String,
            Option<i64>,
        ) = tx
            .query_row(
                "SELECT intent_hash, assurance, nonce, nonce_state, challenge_expiry_ms
                 FROM auth_entries
                 WHERE surface = ?1 AND entry_id = ?2",
                params![approval.surface, approval.entry_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| AuthStoreError::Denied("entry not found".into()))?;
        if entry_intent_hash != approval.intent_hash {
            return Err(AuthStoreError::Denied("entry intent_hash mismatch".into()));
        }
        if parse_assurance(&entry_assurance)? != approval.assurance {
            return Err(AuthStoreError::Denied("entry assurance mismatch".into()));
        }
        if entry_nonce.as_deref() != Some(approval.server_nonce.as_str()) {
            return Err(AuthStoreError::Denied("server_nonce mismatch".into()));
        }
        if parse_nonce_state(&nonce_state)? != NonceState::Unused {
            return Err(AuthStoreError::Denied(
                "server_nonce already consumed".into(),
            ));
        }
        // The TTL is daemon-issued, not client-attested: the approval must carry
        // exactly the expiry that was persisted when the challenge was minted,
        // otherwise a compromised client could inflate the window and bank a
        // signed approval for later execution.
        if challenge_expiry_ms != Some(approval.expiry_ms as i64) {
            return Err(AuthStoreError::Denied(
                "approval expiry does not match issued challenge".into(),
            ));
        }
        let (envelope_json, sealed_at_ms): (String, i64) = tx.query_row(
            "SELECT envelope_json, sealed_at_ms FROM sealed_intents WHERE intent_hash = ?1",
            params![approval.intent_hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let envelope: CanonicalEnvelope = serde_json::from_str(&envelope_json)?;
        approval
            .validate_against_sealed(
                &SealedIntentRecord {
                    intent_hash: approval.intent_hash.clone(),
                    envelope,
                    sealed_at_ms: sealed_at_ms as u64,
                },
                now_ms,
            )
            .map_err(AuthStoreError::from_api)?;
        if approval.assurance == AssuranceLevel::Hardened {
            let review_session_id = approval.review_session_id.as_deref().ok_or_else(|| {
                AuthStoreError::Denied("hardened approval requires a review_session_id".into())
            })?;
            let (
                session_surface,
                session_entry_id,
                session_intent_hash,
                session_assurance,
                session_expires_ms,
                session_consumed_ms,
            ): (String, String, String, String, i64, Option<i64>) = tx
                .query_row(
                    "SELECT surface, entry_id, intent_hash, assurance, expires_ms, consumed_ms
                     FROM review_sessions WHERE review_session_id = ?1",
                    params![review_session_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| AuthStoreError::Denied("review session not found".into()))?;
            if session_surface != approval.surface
                || session_entry_id != approval.entry_id
                || session_intent_hash != approval.intent_hash
                || parse_assurance(&session_assurance)? != approval.assurance
            {
                return Err(AuthStoreError::Denied(
                    "review session does not match approval".into(),
                ));
            }
            if session_consumed_ms.is_some() {
                return Err(AuthStoreError::Denied(
                    "review session already consumed".into(),
                ));
            }
            if now_ms >= session_expires_ms as u64 {
                return Err(AuthStoreError::Denied("review session expired".into()));
            }
            tx.execute(
                "UPDATE review_sessions SET consumed_ms = ?2
                 WHERE review_session_id = ?1 AND consumed_ms IS NULL",
                params![review_session_id, now_ms as i64],
            )?;
            if tx.changes() != 1 {
                return Err(AuthStoreError::Denied(
                    "review session was not consumed".into(),
                ));
            }
        }
        let approval_json = serde_json::to_string(approval)?;
        tx.execute(
            "INSERT INTO approvals(
                surface, entry_id, nonce, approval_json, signer_kind, assurance, expiry_ms,
                consumed_ms
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(surface, entry_id, nonce) DO UPDATE SET
                approval_json = excluded.approval_json,
                signer_kind = excluded.signer_kind,
                assurance = excluded.assurance,
                expiry_ms = excluded.expiry_ms,
                consumed_ms = excluded.consumed_ms",
            params![
                approval.surface,
                approval.entry_id,
                approval.server_nonce,
                approval_json,
                signer_kind_str(approval.signer_kind),
                approval.assurance.as_str(),
                approval.expiry_ms as i64,
                now_ms as i64,
            ],
        )?;
        tx.execute(
            "UPDATE auth_entries
             SET state = ?3, nonce_state = ?4, updated_ms = ?5
             WHERE surface = ?1 AND entry_id = ?2 AND nonce = ?6 AND nonce_state = 'unused'",
            params![
                approval.surface,
                approval.entry_id,
                AuthEntryState::Approved.as_str(),
                NonceState::Consumed.as_str(),
                now_ms as i64,
                approval.server_nonce,
            ],
        )?;
        if tx.changes() != 1 {
            return Err(AuthStoreError::Denied("approval was not consumed".into()));
        }
        let audit_record = serde_json::json!({
            "surface": approval.surface,
            "entry_id": approval.entry_id,
            "intent_hash": approval.intent_hash,
            "nonce": approval.server_nonce,
        })
        .to_string();
        let prev_digest: String = tx
            .query_row(
                "SELECT digest FROM audit ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_else(|| "0".repeat(64));
        let digest = audit_digest(&prev_digest, "approval_consumed", &audit_record, now_ms);
        tx.execute(
            "INSERT INTO audit(prev_digest, digest, event, record_json, created_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                prev_digest,
                digest,
                "approval_consumed",
                audit_record,
                now_ms as i64,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn create_reservation(
        &mut self,
        reservation_id: &str,
        wallet: &str,
        venue: &str,
        amount_micro_usd: i128,
        now_ms: u64,
    ) -> Result<ReservationRecord, AuthStoreError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO reservations(
                reservation_id, wallet, venue, amount_micro_usd, state, created_ms, updated_ms
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                reservation_id,
                wallet,
                venue,
                amount_micro_usd.to_string(),
                ReservationState::Active.as_str(),
                now_ms as i64,
                now_ms as i64,
            ],
        )?;
        tx.commit()?;
        self.reservation(reservation_id)?
            .ok_or_else(|| AuthStoreError::Denied("reservation was not persisted".into()))
    }

    pub fn create_reservation_with_valuation(
        &mut self,
        reservation_id: &str,
        wallet: &str,
        venue: &str,
        valuation: &ValuationQuote,
        policy: &ValuationPolicy,
        now_ms: u64,
    ) -> Result<ReservationRecord, AuthStoreError> {
        valuation.validate_for_authorization(policy, now_ms)?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO reservations(
                reservation_id, wallet, venue, amount_micro_usd, state, created_ms, updated_ms
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                reservation_id,
                wallet,
                venue,
                valuation.usd_micro.to_string(),
                ReservationState::Active.as_str(),
                now_ms as i64,
                now_ms as i64,
            ],
        )?;
        tx.execute(
            "INSERT INTO valuation_snapshots(reservation_id, valuation_json, created_ms)
             VALUES (?1, ?2, ?3)",
            params![
                reservation_id,
                serde_json::to_string(valuation)?,
                now_ms as i64,
            ],
        )?;
        tx.commit()?;
        self.reservation(reservation_id)?
            .ok_or_else(|| AuthStoreError::Denied("reservation was not persisted".into()))
    }

    pub fn transition_reservation(
        &mut self,
        reservation_id: &str,
        from: ReservationState,
        to: ReservationState,
        now_ms: u64,
    ) -> Result<ReservationRecord, AuthStoreError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE reservations SET state = ?2, updated_ms = ?3
             WHERE reservation_id = ?1 AND state = ?4",
            params![reservation_id, to.as_str(), now_ms as i64, from.as_str()],
        )?;
        if tx.changes() != 1 {
            return Err(AuthStoreError::Denied(
                "reservation transition was not applied".into(),
            ));
        }
        tx.commit()?;
        self.reservation(reservation_id)?
            .ok_or_else(|| AuthStoreError::Denied("reservation disappeared".into()))
    }

    pub fn reservation(
        &self,
        reservation_id: &str,
    ) -> Result<Option<ReservationRecord>, AuthStoreError> {
        self.conn
            .query_row(
                "SELECT wallet, venue, amount_micro_usd, state, created_ms, updated_ms
                 FROM reservations WHERE reservation_id = ?1",
                params![reservation_id],
                |row| {
                    let wallet: String = row.get(0)?;
                    let venue: String = row.get(1)?;
                    let amount_micro_usd: String = row.get(2)?;
                    let state: String = row.get(3)?;
                    let created_ms: i64 = row.get(4)?;
                    let updated_ms: i64 = row.get(5)?;
                    Ok((
                        wallet,
                        venue,
                        amount_micro_usd,
                        state,
                        created_ms,
                        updated_ms,
                    ))
                },
            )
            .optional()?
            .map(
                |(wallet, venue, amount_micro_usd, state, created_ms, updated_ms)| {
                    Ok(ReservationRecord {
                        reservation_id: reservation_id.to_string(),
                        wallet,
                        venue,
                        amount_micro_usd: parse_i128("amount_micro_usd", &amount_micro_usd)?,
                        state: parse_reservation_state(&state)?,
                        created_ms: created_ms as u64,
                        updated_ms: updated_ms as u64,
                    })
                },
            )
            .transpose()
    }

    pub fn valuation_snapshot(
        &self,
        reservation_id: &str,
    ) -> Result<Option<ValuationQuote>, AuthStoreError> {
        self.conn
            .query_row(
                "SELECT valuation_json FROM valuation_snapshots WHERE reservation_id = ?1",
                params![reservation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|json| Ok(serde_json::from_str(&json)?))
            .transpose()
    }

    pub fn active_reservation_total(
        &self,
        wallet: &str,
        venue: Option<&str>,
    ) -> Result<i128, AuthStoreError> {
        let mut total = 0i128;
        if let Some(venue) = venue {
            let mut stmt = self.conn.prepare(
                "SELECT amount_micro_usd FROM reservations
                 WHERE wallet = ?1 AND venue = ?2 AND state = 'active'",
            )?;
            let mut rows = stmt.query(params![wallet, venue])?;
            while let Some(row) = rows.next()? {
                let amount: String = row.get(0)?;
                total += parse_i128("amount_micro_usd", &amount)?;
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT amount_micro_usd FROM reservations
                 WHERE wallet = ?1 AND state = 'active'",
            )?;
            let mut rows = stmt.query(params![wallet])?;
            while let Some(row) = rows.next()? {
                let amount: String = row.get(0)?;
                total += parse_i128("amount_micro_usd", &amount)?;
            }
        }
        Ok(total)
    }

    pub fn sealed_intent(
        &self,
        intent_hash: &str,
    ) -> Result<Option<SealedIntentRecord>, AuthStoreError> {
        self.conn
            .query_row(
                "SELECT envelope_json, sealed_at_ms FROM sealed_intents WHERE intent_hash = ?1",
                params![intent_hash],
                |row| {
                    let envelope_json: String = row.get(0)?;
                    let sealed_at_ms: i64 = row.get(1)?;
                    Ok((envelope_json, sealed_at_ms))
                },
            )
            .optional()?
            .map(|(envelope_json, sealed_at_ms)| {
                let envelope: CanonicalEnvelope = serde_json::from_str(&envelope_json)?;
                Ok(SealedIntentRecord {
                    intent_hash: intent_hash.to_string(),
                    envelope,
                    sealed_at_ms: sealed_at_ms as u64,
                })
            })
            .transpose()
    }

    pub fn pragma_string(&self, name: &str) -> Result<String, AuthStoreError> {
        let sql = format!("PRAGMA {name}");
        Ok(self.conn.query_row(&sql, [], |row| row.get(0))?)
    }

    pub fn pragma_i64(&self, name: &str) -> Result<i64, AuthStoreError> {
        let sql = format!("PRAGMA {name}");
        Ok(self.conn.query_row(&sql, [], |row| row.get(0))?)
    }
}

#[async_trait]
impl<S> ApprovalVerifier for StoreApprovalVerifier<S>
where
    S: ApprovalSignatureVerifier + Send + Sync,
{
    async fn verify_and_consume(
        &self,
        approval: Approval,
        now_ms: u64,
    ) -> Result<(), AuthApiError> {
        let unsigned = approval.unsigned_payload();
        self.signature_verifier
            .verify_signature(&unsigned, &approval.signature, now_ms)
            .await?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| AuthApiError::Store("auth store mutex poisoned".into()))?;
        store.consume_verified_approval_transactionally(&approval, now_ms)?;
        Ok(())
    }
}

#[async_trait]
impl<S> AuthStoreView for StoreApprovalVerifier<S>
where
    S: Send + Sync,
{
    async fn sealed_intent(&self, intent_hash: &str) -> Result<SealedIntentRecord, AuthApiError> {
        let store = self
            .store
            .lock()
            .map_err(|_| AuthApiError::Store("auth store mutex poisoned".into()))?;
        store
            .sealed_intent(intent_hash)?
            .ok_or_else(|| AuthApiError::NotFound(format!("sealed intent {intent_hash}")))
    }
}

#[async_trait]
impl<S> AuthStoreWriter for StoreApprovalVerifier<S>
where
    S: Send + Sync,
{
    async fn stage_entry(
        &self,
        envelope: CanonicalEnvelope,
        assurance: AssuranceLevel,
        now_ms: u64,
    ) -> Result<AuthEntryRecord, AuthApiError> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| AuthApiError::Store("auth store mutex poisoned".into()))?;
        Ok(store.stage_entry(&envelope, assurance, now_ms)?)
    }

    async fn issue_challenge(
        &self,
        surface: &str,
        entry_id: &str,
        server_nonce: &str,
        expiry_ms: u64,
        now_ms: u64,
    ) -> Result<ChallengeRecord, AuthApiError> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| AuthApiError::Store("auth store mutex poisoned".into()))?;
        Ok(store.issue_challenge(surface, entry_id, server_nonce, expiry_ms, now_ms)?)
    }

    async fn issue_review_session(
        &self,
        review_session_id: &str,
        surface: &str,
        entry_id: &str,
        expires_ms: u64,
        now_ms: u64,
    ) -> Result<ReviewSessionRecord, AuthApiError> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| AuthApiError::Store("auth store mutex poisoned".into()))?;
        Ok(store.issue_review_session(review_session_id, surface, entry_id, expires_ms, now_ms)?)
    }
}

#[async_trait]
impl PriceOracle for BloomPricesOracle {
    async fn quote_usd(
        &self,
        asset_id: &str,
        amount_base_units: &str,
        now_ms: u64,
    ) -> Result<ValuationQuote, AuthApiError> {
        let coin = parse_coin_id(asset_id)?;
        let quote = self
            .client
            .current(coin)
            .await
            .map_err(|err| AuthApiError::Denied(format!("price oracle unavailable: {err}")))?;
        let decimals = quote
            .decimals
            .ok_or_else(|| AuthApiError::Denied("price quote decimals missing".into()))?;
        if quote.timestamp == 0 {
            return Err(AuthApiError::Denied("price quote timestamp missing".into()));
        }
        let usd_micro = amount_to_usd_micro(amount_base_units, decimals, quote.price)
            .map_err(AuthApiError::Denied)?;
        let confidence_ppm = match quote.confidence {
            Some(confidence) if confidence.is_finite() && confidence >= 0.0 => {
                Some((confidence.min(1.0) * 1_000_000.0).round() as u32)
            }
            Some(_) => {
                return Err(AuthApiError::Denied(
                    "price quote confidence is invalid".into(),
                ));
            }
            None => None,
        };
        Ok(ValuationQuote {
            asset_id: asset_id.to_string(),
            amount_base_units: amount_base_units.to_string(),
            usd_micro,
            source: self.source.clone(),
            quote_timestamp_ms: quote.timestamp.saturating_mul(1_000),
            fetched_at_ms: now_ms,
            max_age_ms: self.client.ttl().as_millis().try_into().unwrap_or(u64::MAX),
            confidence_ppm,
            stablecoin_assumption: false,
        })
    }
}

fn parse_coin_id(asset_id: &str) -> Result<CoinId, AuthApiError> {
    if asset_id.contains(':') {
        CoinId::parse(asset_id)
            .map_err(|err| AuthApiError::Denied(format!("invalid price asset id: {err}")))
    } else {
        Ok(CoinId::Symbol(asset_id.to_string()))
    }
}

fn amount_to_usd_micro(
    amount_base_units: &str,
    decimals: u8,
    price_usd: f64,
) -> Result<i128, String> {
    if !price_usd.is_finite() || price_usd < 0.0 {
        return Err("price quote is invalid".into());
    }
    let amount = amount_base_units
        .parse::<u128>()
        .map_err(|_| "amount_base_units is invalid".to_string())?;
    let scale = 10f64.powi(decimals as i32);
    if !scale.is_finite() || scale <= 0.0 {
        return Err("asset decimals are invalid".into());
    }
    let usd_micro = (amount as f64 / scale) * price_usd * 1_000_000.0;
    if !usd_micro.is_finite() || usd_micro < 0.0 || usd_micro > i128::MAX as f64 {
        return Err("computed USD value is invalid".into());
    }
    Ok(usd_micro.round() as i128)
}

fn parse_entry_state(value: &str) -> Result<AuthEntryState, AuthStoreError> {
    match value {
        "staged" => Ok(AuthEntryState::Staged),
        "challenged" => Ok(AuthEntryState::Challenged),
        "approved" => Ok(AuthEntryState::Approved),
        "submitting" => Ok(AuthEntryState::Submitting),
        "submitted" => Ok(AuthEntryState::Submitted),
        "settled" => Ok(AuthEntryState::Settled),
        "failed" => Ok(AuthEntryState::Failed),
        "unknown" => Ok(AuthEntryState::Unknown),
        other => Err(AuthStoreError::InvalidState(other.to_string())),
    }
}

fn parse_nonce_state(value: &str) -> Result<NonceState, AuthStoreError> {
    match value {
        "unused" => Ok(NonceState::Unused),
        "consumed" => Ok(NonceState::Consumed),
        other => Err(AuthStoreError::InvalidState(other.to_string())),
    }
}

fn parse_assurance(value: &str) -> Result<AssuranceLevel, AuthStoreError> {
    match value {
        "convenience" => Ok(AssuranceLevel::Convenience),
        "hardened" => Ok(AssuranceLevel::Hardened),
        other => Err(AuthStoreError::InvalidAssurance(other.to_string())),
    }
}

fn parse_reservation_state(value: &str) -> Result<ReservationState, AuthStoreError> {
    match value {
        "active" => Ok(ReservationState::Active),
        "committed" => Ok(ReservationState::Committed),
        "released" => Ok(ReservationState::Released),
        "failed" => Ok(ReservationState::Failed),
        "unknown" => Ok(ReservationState::Unknown),
        other => Err(AuthStoreError::InvalidReservationState(other.to_string())),
    }
}

fn parse_i128(field: &'static str, value: &str) -> Result<i128, AuthStoreError> {
    value
        .parse::<i128>()
        .map_err(|_| AuthStoreError::InvalidInteger {
            field,
            value: value.to_string(),
        })
}

fn signer_kind_str(value: bloom_auth_api::SignerKind) -> &'static str {
    match value {
        bloom_auth_api::SignerKind::Password => "password",
        bloom_auth_api::SignerKind::PasskeyBrowser => "passkey_browser",
        bloom_auth_api::SignerKind::PasskeyCtap => "passkey_ctap",
        bloom_auth_api::SignerKind::Test => "test",
    }
}

fn parse_signer_kind(value: &str) -> Result<SignerKind, AuthStoreError> {
    match value {
        "password" => Ok(SignerKind::Password),
        "passkey_browser" => Ok(SignerKind::PasskeyBrowser),
        "passkey_ctap" => Ok(SignerKind::PasskeyCtap),
        "test" => Ok(SignerKind::Test),
        other => Err(AuthStoreError::Denied(format!(
            "invalid signer_kind {other}"
        ))),
    }
}

fn audit_digest(prev_digest: &str, event: &str, record_json: &str, created_ms: u64) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.auth.audit.v1");
    hasher.update(prev_digest.as_bytes());
    hasher.update(event.as_bytes());
    hasher.update(record_json.as_bytes());
    hasher.update(&created_ms.to_be_bytes());
    hasher.finalize().to_hex().to_string()
}

impl AuthStoreError {
    fn from_api(err: AuthApiError) -> Self {
        Self::Api(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_auth_api::{
        APPROVAL_SCHEMA_V1, ApprovalCaps, ApprovalSignature, CanonicalEnvelope,
        CanonicalIntentHeader, SignerKind,
    };

    fn envelope() -> CanonicalEnvelope {
        CanonicalEnvelope::new(
            CanonicalIntentHeader {
                schema: "bloom.intent_header.v1".into(),
                wallet: "my-wallet".into(),
                surface: "requests".into(),
                entry_id: "req_1".into(),
                executor_id: "paid-http".into(),
                network: "base".into(),
                account: "default".into(),
                action_kind: "x402_payment".into(),
                value_movement: true,
                authority_change: false,
            },
            "paid_http",
            "paid_http.v1",
            br#"{"amount":"1.00"}"#.to_vec(),
        )
    }

    fn approval_for(entry: &AuthEntryRecord, sealed: &SealedIntentRecord) -> Approval {
        Approval {
            schema: APPROVAL_SCHEMA_V1.into(),
            wallet: sealed.envelope.header.wallet.clone(),
            surface: entry.surface.clone(),
            entry_id: entry.entry_id.clone(),
            intent_hash: entry.intent_hash.clone(),
            executor_id: sealed.envelope.header.executor_id.clone(),
            network: sealed.envelope.header.network.clone(),
            assurance: entry.assurance,
            server_nonce: entry.nonce.clone().unwrap(),
            caps: ApprovalCaps::default(),
            // Matches the expiry every test issues its challenge with; consume
            // requires equality with the persisted challenge_expiry_ms.
            expiry_ms: 220,
            signer_kind: SignerKind::Password,
            credential_id: None,
            review_session_id: None,
            signature: ApprovalSignature::PasswordMac {
                mac_hex: "test-only".into(),
            },
        }
    }

    #[test]
    fn production_pragmas_are_strict() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuthStore::open(dir.path().join("auth.sqlite")).unwrap();
        assert_eq!(store.pragma_i64("synchronous").unwrap(), 2);
        assert_eq!(store.pragma_i64("foreign_keys").unwrap(), 1);
        assert_eq!(
            store.pragma_string("journal_mode").unwrap().to_lowercase(),
            "wal"
        );
    }

    #[test]
    fn sealed_intent_round_trip_uses_hash_key() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let env = envelope();
        let hash = store.insert_sealed_intent(&env, 123).unwrap();
        assert_eq!(hash.len(), 64);
        let got = store.sealed_intent(&hash).unwrap().unwrap();
        assert_eq!(got.intent_hash, hash);
        assert_eq!(got.envelope, env);
        assert_eq!(got.sealed_at_ms, 123);
    }

    #[test]
    fn stage_and_issue_challenge_tracks_nonce() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let env = envelope();
        let staged = store
            .stage_entry(&env, AssuranceLevel::Convenience, 100)
            .unwrap();
        assert_eq!(staged.state, AuthEntryState::Staged);
        assert_eq!(staged.nonce_state, NonceState::Unused);
        assert_eq!(staged.nonce, None);

        let challenge = store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap();
        assert_eq!(challenge.intent_hash, staged.intent_hash);
        assert_eq!(challenge.server_nonce, "nonce-1");
        assert_eq!(challenge.assurance, AssuranceLevel::Convenience);

        let entry = store.auth_entry("requests", "req_1").unwrap().unwrap();
        assert_eq!(entry.state, AuthEntryState::Challenged);
        assert_eq!(entry.nonce.as_deref(), Some("nonce-1"));
        assert_eq!(entry.nonce_state, NonceState::Unused);
    }

    #[test]
    fn stage_entry_is_idempotent_for_same_entry_and_rejects_collisions() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let env = envelope();
        let first = store
            .stage_entry(&env, AssuranceLevel::Convenience, 100)
            .unwrap();
        let second = store
            .stage_entry(&env, AssuranceLevel::Convenience, 101)
            .unwrap();
        assert_eq!(second.intent_hash, first.intent_hash);
        assert_eq!(second.updated_ms, first.updated_ms);
        assert!(
            store
                .stage_entry(&env, AssuranceLevel::Hardened, 102)
                .is_err()
        );
        let changed = CanonicalEnvelope::new(
            env.header.clone(),
            env.subject_kind.clone(),
            env.subject_schema.clone(),
            br#"{"amount":"2"}"#.to_vec(),
        );
        assert!(
            store
                .stage_entry(&changed, AssuranceLevel::Convenience, 103)
                .is_err()
        );
    }

    #[test]
    fn consume_approval_burns_nonce_and_replay_fails() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let env = envelope();
        store
            .stage_entry(&env, AssuranceLevel::Convenience, 100)
            .unwrap();
        store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap();
        let entry = store.auth_entry("requests", "req_1").unwrap().unwrap();
        let sealed = store.sealed_intent(&entry.intent_hash).unwrap().unwrap();
        let approval = approval_for(&entry, &sealed);

        store
            .consume_verified_approval_transactionally(&approval, 150)
            .unwrap();
        let consumed = store.auth_entry("requests", "req_1").unwrap().unwrap();
        assert_eq!(consumed.state, AuthEntryState::Approved);
        assert_eq!(consumed.nonce_state, NonceState::Consumed);

        let replay = store.consume_verified_approval_transactionally(&approval, 151);
        assert!(replay.is_err());

        let (prev_digest, digest): (String, String) = store
            .conn
            .query_row(
                "SELECT prev_digest, digest FROM audit WHERE event = 'approval_consumed'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(prev_digest, "0".repeat(64));
        assert_eq!(digest.len(), 64);
        assert_ne!(digest, "0".repeat(64));
    }

    #[test]
    fn inflated_expiry_approval_is_denied_and_does_not_burn_nonce() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let env = envelope();
        store
            .stage_entry(&env, AssuranceLevel::Convenience, 100)
            .unwrap();
        store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap();
        let entry = store.auth_entry("requests", "req_1").unwrap().unwrap();
        let sealed = store.sealed_intent(&entry.intent_hash).unwrap().unwrap();
        let mut approval = approval_for(&entry, &sealed);
        // A compromised client extends the window it signs over; the daemon
        // must hold it to the expiry persisted at challenge issuance.
        approval.expiry_ms = u64::MAX;

        let err = store
            .consume_verified_approval_transactionally(&approval, 150)
            .unwrap_err();
        assert!(err.to_string().contains("issued challenge"), "{err}");
        let still_unused = store.auth_entry("requests", "req_1").unwrap().unwrap();
        assert_eq!(still_unused.nonce_state, NonceState::Unused);

        // The honest approval (matching issued expiry) still consumes.
        let approval = approval_for(&entry, &sealed);
        store
            .consume_verified_approval_transactionally(&approval, 150)
            .unwrap();
    }

    #[test]
    fn consumed_nonce_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.sqlite");
        let approval = {
            let mut store = AuthStore::open(&path).unwrap();
            let env = envelope();
            store
                .stage_entry(&env, AssuranceLevel::Convenience, 100)
                .unwrap();
            store
                .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
                .unwrap();
            let entry = store.auth_entry("requests", "req_1").unwrap().unwrap();
            let sealed = store.sealed_intent(&entry.intent_hash).unwrap().unwrap();
            let approval = approval_for(&entry, &sealed);
            store
                .consume_verified_approval_transactionally(&approval, 150)
                .unwrap();
            approval
        };

        let mut reopened = AuthStore::open(&path).unwrap();
        let entry = reopened.auth_entry("requests", "req_1").unwrap().unwrap();
        assert_eq!(entry.nonce_state, NonceState::Consumed);
        assert!(
            reopened
                .consume_verified_approval_transactionally(&approval, 151)
                .is_err()
        );
    }

    #[test]
    fn mismatched_approval_does_not_burn_nonce() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let env = envelope();
        store
            .stage_entry(&env, AssuranceLevel::Convenience, 100)
            .unwrap();
        store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap();
        let entry = store.auth_entry("requests", "req_1").unwrap().unwrap();
        let sealed = store.sealed_intent(&entry.intent_hash).unwrap().unwrap();
        let mut approval = approval_for(&entry, &sealed);
        approval.intent_hash = "f".repeat(64);

        assert!(
            store
                .consume_verified_approval_transactionally(&approval, 150)
                .is_err()
        );
        let still_unused = store.auth_entry("requests", "req_1").unwrap().unwrap();
        assert_eq!(still_unused.nonce_state, NonceState::Unused);
    }

    #[tokio::test]
    async fn rejecting_signature_verifier_fails_before_nonce_burn() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.sqlite");
        let mut store = AuthStore::open(&path).unwrap();
        let env = envelope();
        store
            .stage_entry(&env, AssuranceLevel::Convenience, 100)
            .unwrap();
        store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap();
        let entry = store.auth_entry("requests", "req_1").unwrap().unwrap();
        let sealed = store.sealed_intent(&entry.intent_hash).unwrap().unwrap();
        let approval = approval_for(&entry, &sealed);
        let verifier = StoreApprovalVerifier::new(store, RejectingApprovalSignatureVerifier);

        let err = verifier
            .verify_and_consume(approval, 150)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("signature verifier is not installed"),
            "{err}"
        );

        drop(verifier);
        let reopened = AuthStore::open(&path).unwrap();
        let entry = reopened.auth_entry("requests", "req_1").unwrap().unwrap();
        assert_eq!(entry.nonce_state, NonceState::Unused);
    }

    #[tokio::test]
    async fn store_writer_trait_stages_and_issues_challenge() {
        let verifier = StoreApprovalVerifier::new(
            AuthStore::open_in_memory_for_tests().unwrap(),
            RejectingApprovalSignatureVerifier,
        );
        let env = envelope();
        let staged =
            AuthStoreWriter::stage_entry(&verifier, env.clone(), AssuranceLevel::Hardened, 100)
                .await
                .unwrap();
        assert_eq!(staged.surface, "requests");
        assert_eq!(staged.entry_id, "req_1");
        assert_eq!(staged.assurance, AssuranceLevel::Hardened);

        let challenge =
            AuthStoreWriter::issue_challenge(&verifier, "requests", "req_1", "nonce-1", 250, 101)
                .await
                .unwrap();
        assert_eq!(challenge.server_nonce, "nonce-1");
        assert_eq!(challenge.assurance, AssuranceLevel::Hardened);

        let duplicate = AuthStoreWriter::stage_entry(&verifier, env, AssuranceLevel::Hardened, 102)
            .await
            .unwrap();
        assert_eq!(duplicate.intent_hash, staged.intent_hash);
        assert_eq!(duplicate.state, AuthEntryState::Challenged);
        assert_eq!(duplicate.nonce.as_deref(), Some("nonce-1"));
    }

    #[test]
    fn approval_credentials_persist_and_revoke() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.sqlite");
        {
            let mut store = AuthStore::open(&path).unwrap();
            store
                .register_approval_credential(&ApprovalCredentialRecord {
                    wallet: "my-wallet".into(),
                    credential_id: "cred-1".into(),
                    signer_kind: SignerKind::PasskeyBrowser,
                    assurance: AssuranceLevel::Hardened,
                    public_key_json: serde_json::json!({"credential":"placeholder"}),
                    registered_ms: 100,
                    revoked_ms: None,
                })
                .unwrap();
            let stored = store
                .approval_credential("my-wallet", "cred-1")
                .unwrap()
                .unwrap();
            assert_eq!(stored.assurance, AssuranceLevel::Hardened);
            assert_eq!(stored.signer_kind, SignerKind::PasskeyBrowser);
            assert_eq!(stored.revoked_ms, None);
            store
                .revoke_approval_credential("my-wallet", "cred-1", 200)
                .unwrap();
        }

        let reopened = AuthStore::open(&path).unwrap();
        let stored = reopened
            .approval_credential("my-wallet", "cred-1")
            .unwrap()
            .unwrap();
        assert_eq!(stored.revoked_ms, Some(200));
    }

    #[test]
    fn approval_credentials_reject_password_hardened_registration() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let err = store
            .register_approval_credential(&ApprovalCredentialRecord {
                wallet: "my-wallet".into(),
                credential_id: "cred-1".into(),
                signer_kind: SignerKind::Password,
                assurance: AssuranceLevel::Hardened,
                public_key_json: serde_json::json!({"credential":"placeholder"}),
                registered_ms: 100,
                revoked_ms: None,
            })
            .unwrap_err();
        assert!(err.to_string().contains("does not satisfy"), "{err}");
        assert!(
            store
                .approval_credential("my-wallet", "cred-1")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn hardened_approval_requires_matching_review_session() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let env = envelope();
        store
            .stage_entry(&env, AssuranceLevel::Hardened, 100)
            .unwrap();
        store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap();
        let entry = store.auth_entry("requests", "req_1").unwrap().unwrap();
        let sealed = store.sealed_intent(&entry.intent_hash).unwrap().unwrap();
        let mut approval = approval_for(&entry, &sealed);
        approval.signer_kind = SignerKind::PasskeyCtap;

        let err = store
            .consume_verified_approval_transactionally(&approval, 150)
            .unwrap_err();
        assert!(err.to_string().contains("review_session_id"), "{err}");
        let still_unused = store.auth_entry("requests", "req_1").unwrap().unwrap();
        assert_eq!(still_unused.nonce_state, NonceState::Unused);
    }

    #[test]
    fn hardened_approval_consumes_matching_review_session() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let env = envelope();
        store
            .stage_entry(&env, AssuranceLevel::Hardened, 100)
            .unwrap();
        store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap();
        let session = store
            .issue_review_session("review-1", "requests", "req_1", 220, 102)
            .unwrap();
        assert_eq!(session.consumed_ms, None);

        let entry = store.auth_entry("requests", "req_1").unwrap().unwrap();
        let sealed = store.sealed_intent(&entry.intent_hash).unwrap().unwrap();
        let mut approval = approval_for(&entry, &sealed);
        approval.signer_kind = SignerKind::PasskeyCtap;
        approval.review_session_id = Some("review-1".into());

        store
            .consume_verified_approval_transactionally(&approval, 150)
            .unwrap();
        let consumed_entry = store.auth_entry("requests", "req_1").unwrap().unwrap();
        assert_eq!(consumed_entry.nonce_state, NonceState::Consumed);
        let consumed_session = store.review_session("review-1").unwrap().unwrap();
        assert_eq!(consumed_session.consumed_ms, Some(150));

        let replay = store.consume_verified_approval_transactionally(&approval, 151);
        assert!(replay.is_err());
    }

    #[test]
    fn reservation_totals_count_only_active_rows() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        store
            .create_reservation("res_1", "my-wallet", "requests", 10, 100)
            .unwrap();
        store
            .create_reservation("res_2", "my-wallet", "hyperliquid", 20, 101)
            .unwrap();
        store
            .create_reservation("res_3", "other-wallet", "requests", 30, 102)
            .unwrap();
        assert_eq!(
            store.active_reservation_total("my-wallet", None).unwrap(),
            30
        );
        assert_eq!(
            store
                .active_reservation_total("my-wallet", Some("requests"))
                .unwrap(),
            10
        );

        let committed = store
            .transition_reservation(
                "res_1",
                ReservationState::Active,
                ReservationState::Committed,
                110,
            )
            .unwrap();
        assert_eq!(committed.state, ReservationState::Committed);
        assert_eq!(committed.updated_ms, 110);
        assert_eq!(
            store.active_reservation_total("my-wallet", None).unwrap(),
            20
        );
    }

    #[test]
    fn reservation_state_survives_restart_and_duplicate_ids_fail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.sqlite");
        {
            let mut store = AuthStore::open(&path).unwrap();
            store
                .create_reservation("res_1", "my-wallet", "requests", 10, 100)
                .unwrap();
            assert!(
                store
                    .create_reservation("res_1", "my-wallet", "requests", 10, 101)
                    .is_err()
            );
            store
                .transition_reservation(
                    "res_1",
                    ReservationState::Active,
                    ReservationState::Released,
                    110,
                )
                .unwrap();
        }

        let store = AuthStore::open(&path).unwrap();
        let reservation = store.reservation("res_1").unwrap().unwrap();
        assert_eq!(reservation.state, ReservationState::Released);
        assert_eq!(
            store.active_reservation_total("my-wallet", None).unwrap(),
            0
        );
    }

    fn valuation_quote() -> ValuationQuote {
        ValuationQuote {
            asset_id: "base:0x0000000000000000000000000000000000000001".into(),
            amount_base_units: "1000000".into(),
            usd_micro: 1_250_000,
            source: "test-oracle".into(),
            quote_timestamp_ms: 1_000,
            fetched_at_ms: 1_000,
            max_age_ms: 30_000,
            confidence_ppm: Some(990_000),
            stablecoin_assumption: false,
        }
    }

    #[test]
    fn reservation_with_valuation_persists_snapshot_and_uses_quote_amount() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let policy = ValuationPolicy {
            min_confidence_ppm: Some(950_000),
            ..ValuationPolicy::default()
        };
        let quote = valuation_quote();
        let reservation = store
            .create_reservation_with_valuation(
                "res_quote",
                "my-wallet",
                "requests",
                &quote,
                &policy,
                10_000,
            )
            .unwrap();
        assert_eq!(reservation.amount_micro_usd, quote.usd_micro);
        assert_eq!(
            store.active_reservation_total("my-wallet", None).unwrap(),
            quote.usd_micro
        );
        let snapshot = store.valuation_snapshot("res_quote").unwrap().unwrap();
        assert_eq!(snapshot, quote);
    }

    #[test]
    fn stale_valuation_rejects_reservation_without_writing_rows() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let policy = ValuationPolicy::default();
        let quote = valuation_quote();
        let err = store
            .create_reservation_with_valuation(
                "res_stale",
                "my-wallet",
                "requests",
                &quote,
                &policy,
                40_001,
            )
            .unwrap_err();
        assert!(err.to_string().contains("stale"), "{err}");
        assert!(store.reservation("res_stale").unwrap().is_none());
        assert!(store.valuation_snapshot("res_stale").unwrap().is_none());
    }

    #[test]
    fn price_adapter_amount_conversion_is_fail_closed() {
        assert_eq!(amount_to_usd_micro("1000000", 6, 1.25).unwrap(), 1_250_000);
        assert_eq!(
            amount_to_usd_micro("1500000000000000000", 18, 2.0).unwrap(),
            3_000_000
        );
        assert!(amount_to_usd_micro("not-a-number", 6, 1.0).is_err());
        assert!(amount_to_usd_micro("1000000", 6, f64::NAN).is_err());
        assert!(amount_to_usd_micro("1000000", 6, -1.0).is_err());
    }
}
