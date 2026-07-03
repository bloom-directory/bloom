//! Concrete Sealed Approval authorization store and verifier.
//!
//! The daemon wires [`AuthStore`] and [`StoreApprovalVerifier`] into the VFS
//! handlers, TX engine, and IPC server at startup. VFS-facing crates depend
//! only on `bloom-auth-api`; this crate stays daemon-side so NFS/petal
//! surfaces never pull in the authorization TCB.

pub mod grant_store;

pub use grant_store::InMemoryGrantStore;

use async_trait::async_trait;
use bloom_auth_api::{
    APPROVAL_CHALLENGE_SCHEMA_V1, ApprovalChallenge, ApprovalCredentialRecord,
    ApprovalSignatureVerifier, ApprovalVerifier, AssuranceLevel, AuthApiError, AuthEntryRecord,
    AuthEntryState, AuthStoreView, AuthStoreWriter, CanonicalEnvelope, GrantStore, NonceState,
    PriceOracle, ReservationRecord, ReservationState, ReviewSessionRecord, SealedAction,
    SealedApprovalGrant, SealedIntentRecord, SignedApproval, SignerKind, UnsignedApproval,
    ValuationPolicy, ValuationQuote, WebAuthnAssertionRecord,
};
use bloom_prices::{CoinId, PricesClient};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

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

#[cfg(test)]
#[derive(Debug, Clone, Copy, Default)]
/// Test-only [`ApprovalSignatureVerifier`] that accepts every assertion. Use
/// to exercise verifier + grant-mint flows that don't depend on a real
/// WebAuthn implementation; never wire this into a production code path.
pub struct AcceptingApprovalSignatureVerifier;

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
        _webauthn_assertion: &WebAuthnAssertionRecord,
        _now_ms: u64,
    ) -> Result<(), AuthApiError> {
        Err(AuthApiError::Denied(
            "production approval signature verifier is not installed".into(),
        ))
    }
}

#[cfg(test)]
#[async_trait]
impl ApprovalSignatureVerifier for AcceptingApprovalSignatureVerifier {
    async fn verify_signature(
        &self,
        _unsigned: &UnsignedApproval,
        _webauthn_assertion: &WebAuthnAssertionRecord,
        _now_ms: u64,
    ) -> Result<(), AuthApiError> {
        Ok(())
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
        conn.busy_timeout(Duration::from_secs(5))?;
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

    /// Create/upgrade the schema.
    ///
    /// The sealed-action columns were added for `bloom.sealed_action.v1`
    /// (WS-0). Upgrading an existing database adds them as NULL: legacy
    /// pending rows become void by design (challenge issuance and approval
    /// consumption fail closed on NULL sealed-action metadata; the action is
    /// simply re-stageable), while consumed-nonce history is untouched so
    /// replay denial survives the migration.
    fn migrate(conn: &Connection) -> Result<(), AuthStoreError> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS sealed_intents (
                intent_hash TEXT PRIMARY KEY NOT NULL,
                envelope_json TEXT NOT NULL,
                sealed_at_ms INTEGER NOT NULL,
                sealed_action_json TEXT
            );

            CREATE TABLE IF NOT EXISTS auth_entries (
                surface TEXT NOT NULL,
                action_id TEXT NOT NULL,
                state TEXT NOT NULL,
                intent_hash TEXT NOT NULL REFERENCES sealed_intents(intent_hash),
                assurance TEXT NOT NULL,
                nonce TEXT,
                nonce_state TEXT NOT NULL DEFAULT 'unused',
                challenge_expiry_ms INTEGER,
                reservation_id TEXT,
                updated_ms INTEGER NOT NULL,
                wallet TEXT,
                petal_id TEXT,
                petal_digest TEXT,
                daemon_terms_digest TEXT,
                petal_policy_digest TEXT,
                policy_version INTEGER,
                PRIMARY KEY(surface, action_id)
            );

            CREATE TABLE IF NOT EXISTS approvals (
                surface TEXT NOT NULL,
                action_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                approval_json TEXT NOT NULL,
                signer_kind TEXT NOT NULL,
                assurance TEXT NOT NULL,
                expiry_ms INTEGER NOT NULL,
                consumed_ms INTEGER,
                PRIMARY KEY(surface, action_id, nonce)
            );

            CREATE TABLE IF NOT EXISTS review_sessions (
                review_session_id TEXT PRIMARY KEY NOT NULL,
                surface TEXT NOT NULL,
                action_id TEXT NOT NULL,
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

            CREATE TABLE IF NOT EXISTS action_id_map (
                surface TEXT NOT NULL,
                venue_local_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                wallet TEXT NOT NULL,
                created_ms INTEGER NOT NULL,
                PRIMARY KEY(surface, venue_local_id),
                UNIQUE(action_id)
            );
            "#,
        )?;
        // Upgrade pre-sealed-action databases in place. `CREATE TABLE IF NOT
        // EXISTS` above only covers fresh databases; existing tables gain the
        // new columns here (NULL for legacy rows → fail closed, re-stageable).
        Self::add_column_if_missing(conn, "sealed_intents", "sealed_action_json", "TEXT")?;
        for (column, decl) in [
            ("wallet", "TEXT"),
            ("petal_id", "TEXT"),
            ("petal_digest", "TEXT"),
            ("daemon_terms_digest", "TEXT"),
            ("petal_policy_digest", "TEXT"),
            ("policy_version", "INTEGER"),
        ] {
            Self::add_column_if_missing(conn, "auth_entries", column, decl)?;
        }
        Ok(())
    }

    fn add_column_if_missing(
        conn: &Connection,
        table: &str,
        column: &str,
        decl: &str,
    ) -> Result<(), AuthStoreError> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            if name == column {
                return Ok(());
            }
        }
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"))?;
        Ok(())
    }

    /// Allocate a globally-unique `action_id` and record the
    /// `(surface, venue_local_id) → action_id` mapping so it survives restart.
    ///
    /// The id is derived deterministically from `(surface, venue_local_id)`
    /// (see [`derive_action_id`]), so re-allocating the same pair is idempotent
    /// and two distinct pairs can never collide — including when they are staged
    /// in the same millisecond. `now_ms` is recorded as `created_ms` only; it is
    /// never part of the id. (An earlier `surface-<now_ms>` format collided for
    /// two same-surface actions staged in one millisecond, since the whole id
    /// derived from the clock and the table had no `action_id` uniqueness guard.)
    pub fn allocate_action_id(
        &mut self,
        surface: &str,
        venue_local_id: &str,
        wallet: &str,
        now_ms: u64,
    ) -> Result<String, AuthStoreError> {
        let tx = self.conn.transaction()?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT action_id FROM action_id_map WHERE surface = ?1 AND venue_local_id = ?2",
                params![surface, venue_local_id],
                |row| row.get(0),
            )
            .ok();
        if let Some(id) = existing {
            return Ok(id);
        }
        let action_id = derive_action_id(surface, venue_local_id);
        tx.execute(
            "INSERT OR IGNORE INTO action_id_map(surface, venue_local_id, action_id, wallet, created_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![surface, venue_local_id, &action_id, wallet, now_ms as i64],
        )?;
        // Return the authoritative persisted id. A `None` read-back means the
        // row was not written — i.e. the derived id hit the `UNIQUE(action_id)`
        // guard against a *different* pair (a 128-bit BLAKE3 collision) — so we
        // fail closed rather than hand back an id that maps somewhere else.
        let persisted: Option<String> = tx
            .query_row(
                "SELECT action_id FROM action_id_map WHERE surface = ?1 AND venue_local_id = ?2",
                params![surface, venue_local_id],
                |row| row.get(0),
            )
            .ok();
        tx.commit()?;
        persisted.ok_or_else(|| {
            AuthStoreError::Denied(format!(
                "action_id collision for {surface}/{venue_local_id}"
            ))
        })
    }

    /// Look up the central `action_id` for a `(surface, venue_local_id)` pair.
    pub fn lookup_action_id(
        &self,
        surface: &str,
        venue_local_id: &str,
    ) -> Result<Option<String>, AuthStoreError> {
        let result = self
            .conn
            .query_row(
                "SELECT action_id FROM action_id_map WHERE surface = ?1 AND venue_local_id = ?2",
                params![surface, venue_local_id],
                |row| row.get::<_, String>(0),
            )
            .ok();
        Ok(result)
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

    /// Stage an envelope with restrictive default daemon terms and an empty
    /// Petal policy snapshot.
    // TODO(ws-F..ws-K): converted venue staging should call [`Self::stage_action`]
    // with real plan/policy_checks/terms/snapshot instead.
    pub fn stage_entry(
        &mut self,
        envelope: &CanonicalEnvelope,
        assurance: AssuranceLevel,
        now_ms: u64,
    ) -> Result<AuthEntryRecord, AuthStoreError> {
        let action = SealedAction::seal_with_default_terms(envelope.clone(), assurance, now_ms)
            .map_err(AuthStoreError::from_api)?;
        self.stage_action(&action, now_ms)
    }

    /// Stage a fully-populated [`SealedAction`] (schema
    /// `bloom.sealed_action.v1`) and its auth entry.
    ///
    /// Idempotent for a byte-identical re-stage of the same
    /// `(surface, action_id)`; fails closed when an entry already exists for
    /// a different intent, assurance, or sealed daemon context.
    pub fn stage_action(
        &mut self,
        action: &SealedAction,
        now_ms: u64,
    ) -> Result<AuthEntryRecord, AuthStoreError> {
        action.validate().map_err(AuthStoreError::from_api)?;
        let envelope = &action.envelope;
        let intent_hash = envelope.intent_hash().map_err(AuthStoreError::from_api)?;
        let assurance = action.daemon_terms.assurance;
        let daemon_terms_digest = action
            .daemon_terms_digest()
            .map_err(AuthStoreError::from_api)?;
        let envelope_json = serde_json::to_string(envelope)?;
        let action_json = serde_json::to_string(action)?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO sealed_intents(
                intent_hash, envelope_json, sealed_at_ms, sealed_action_json
             )
             VALUES (?1, ?2, ?3, ?4)",
            params![intent_hash, envelope_json, now_ms as i64, action_json],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO auth_entries(
                surface, action_id, state, intent_hash, assurance, nonce, nonce_state,
                reservation_id, updated_ms, wallet, petal_id, petal_digest,
                daemon_terms_digest, petal_policy_digest, policy_version
             )
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, NULL, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            ",
            params![
                envelope.header.surface,
                envelope.header.action_id,
                AuthEntryState::Staged.as_str(),
                intent_hash,
                assurance.as_str(),
                NonceState::Unused.as_str(),
                now_ms as i64,
                envelope.header.wallet,
                envelope.header.petal_id,
                envelope.header.petal_digest,
                daemon_terms_digest,
                action.petal_policy_digest,
                action.policy_version as i64,
            ],
        )?;
        // Fail closed if the same (surface, action_id) is already staged with
        // a different sealed daemon context (INSERT OR IGNORE keeps the first
        // writer; a divergent re-stage must not silently alias it).
        let (existing_terms_digest, existing_policy_digest, existing_policy_version): (
            Option<String>,
            Option<String>,
            Option<i64>,
        ) = tx.query_row(
            "SELECT daemon_terms_digest, petal_policy_digest, policy_version
             FROM auth_entries WHERE surface = ?1 AND action_id = ?2",
            params![envelope.header.surface, envelope.header.action_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if existing_terms_digest.as_deref() != Some(daemon_terms_digest.as_str())
            || existing_policy_digest.as_deref() != Some(action.petal_policy_digest.as_str())
            || existing_policy_version != Some(action.policy_version as i64)
        {
            return Err(AuthStoreError::Denied(
                "auth entry already exists for different sealed daemon context".into(),
            ));
        }
        tx.commit()?;
        let entry = self
            .auth_entry(&envelope.header.surface, &envelope.header.action_id)?
            .ok_or_else(|| AuthStoreError::Denied("staged entry was not persisted".into()))?;
        if entry.intent_hash != intent_hash || entry.assurance != assurance {
            return Err(AuthStoreError::Denied(
                "auth entry already exists for different intent or assurance".into(),
            ));
        }
        Ok(entry)
    }

    /// Issue the full §5.7 [`ApprovalChallenge`] preimage for a staged entry.
    ///
    /// Fails closed for entries staged before the sealed-action schema (NULL
    /// petal/digest columns): those actions are void and must be re-staged.
    pub fn issue_challenge(
        &mut self,
        surface: &str,
        action_id: &str,
        server_nonce: &str,
        expiry_ms: u64,
        now_ms: u64,
    ) -> Result<ApprovalChallenge, AuthStoreError> {
        let tx = self.conn.transaction()?;
        type PendingEntryRow = (
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<i64>,
            Option<String>,
        );
        let row: PendingEntryRow = tx
            .query_row(
                "SELECT ae.intent_hash, ae.assurance, ae.wallet, ae.petal_id, ae.petal_digest,
                        ae.daemon_terms_digest, ae.petal_policy_digest, ae.policy_version,
                        si.sealed_action_json
                 FROM auth_entries ae
                 JOIN sealed_intents si ON si.intent_hash = ae.intent_hash
                 WHERE ae.surface = ?1 AND ae.action_id = ?2 AND ae.nonce_state = 'unused'",
                params![surface, action_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| AuthStoreError::Denied("entry is not challengeable".into()))?;
        let (
            intent_hash,
            assurance,
            wallet,
            petal_id,
            petal_digest,
            daemon_terms_digest,
            petal_policy_digest,
            policy_version,
            sealed_action_json,
        ) = row;
        let (
            Some(wallet),
            Some(petal_id),
            Some(petal_digest),
            Some(daemon_terms_digest),
            Some(petal_policy_digest),
            Some(policy_version),
            Some(sealed_action_json),
        ) = (
            wallet,
            petal_id,
            petal_digest,
            daemon_terms_digest,
            petal_policy_digest,
            policy_version,
            sealed_action_json,
        )
        else {
            return Err(AuthStoreError::Denied(
                "entry predates the sealed-action schema and is void; re-stage the action".into(),
            ));
        };
        let action: SealedAction = serde_json::from_str(&sealed_action_json)?;
        action.validate().map_err(AuthStoreError::from_api)?;
        let action_intent_hash = action.intent_hash().map_err(AuthStoreError::from_api)?;
        if action_intent_hash != intent_hash {
            return Err(AuthStoreError::Denied(
                "sealed action intent_hash does not match auth entry".into(),
            ));
        }
        let action_daemon_terms_digest = action
            .daemon_terms_digest()
            .map_err(AuthStoreError::from_api)?;
        if wallet != action.wallet()
            || petal_id != action.petal_id()
            || petal_digest != action.petal_digest()
            || daemon_terms_digest != action_daemon_terms_digest
            || petal_policy_digest != action.petal_policy_digest
            || policy_version as u64 != action.policy_version
        {
            return Err(AuthStoreError::Denied(
                "auth entry sealed metadata does not match sealed action".into(),
            ));
        }
        tx.execute(
            "UPDATE auth_entries
             SET state = ?3, nonce = ?4, nonce_state = ?5, challenge_expiry_ms = ?6, updated_ms = ?7
             WHERE surface = ?1 AND action_id = ?2 AND nonce_state = 'unused'",
            params![
                surface,
                action_id,
                AuthEntryState::Challenged.as_str(),
                server_nonce,
                NonceState::Unused.as_str(),
                expiry_ms as i64,
                now_ms as i64,
            ],
        )?;
        tx.commit()?;
        Ok(ApprovalChallenge {
            schema: APPROVAL_CHALLENGE_SCHEMA_V1.to_string(),
            action_id: action.action_id().to_string(),
            wallet: action.wallet().to_string(),
            surface: action.surface().to_string(),
            petal_id: action.petal_id().to_string(),
            petal_digest: action.petal_digest().to_string(),
            intent_hash: action_intent_hash,
            server_nonce: server_nonce.to_string(),
            assurance: parse_assurance(&assurance)?,
            daemon_terms_digest: action_daemon_terms_digest,
            petal_policy_digest: action.petal_policy_digest.clone(),
            policy_version: action.policy_version,
            expiry_ms,
        })
    }

    pub fn issue_review_session(
        &mut self,
        review_session_id: &str,
        surface: &str,
        action_id: &str,
        expires_ms: u64,
        now_ms: u64,
    ) -> Result<ReviewSessionRecord, AuthStoreError> {
        let tx = self.conn.transaction()?;
        let (intent_hash, assurance): (String, String) = tx
            .query_row(
                "SELECT intent_hash, assurance FROM auth_entries
                 WHERE surface = ?1 AND action_id = ?2",
                params![surface, action_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| AuthStoreError::Denied("entry not found".into()))?;
        let existing: Option<ReviewSessionRecord> = tx
            .query_row(
                "SELECT review_session_id, surface, action_id, intent_hash, assurance, expires_ms,
                        consumed_ms, created_ms
                 FROM review_sessions WHERE review_session_id = ?1",
                params![review_session_id],
                |row| {
                    let assurance: String = row.get(4)?;
                    Ok(ReviewSessionRecord {
                        review_session_id: row.get(0)?,
                        surface: row.get(1)?,
                        action_id: row.get(2)?,
                        intent_hash: row.get(3)?,
                        assurance: parse_assurance(&assurance).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                4,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?,
                        expires_ms: row.get::<_, i64>(5)? as u64,
                        consumed_ms: row.get::<_, Option<i64>>(6)?.map(|v| v as u64),
                        created_ms: row.get::<_, i64>(7)? as u64,
                    })
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing.surface == surface
                && existing.action_id == action_id
                && existing.intent_hash == intent_hash
                && existing.assurance == parse_assurance(&assurance)?
                && existing.expires_ms == expires_ms
            {
                if existing.consumed_ms.is_some() {
                    return Err(AuthStoreError::Denied(
                        "review session already consumed".into(),
                    ));
                }
                if now_ms >= existing.expires_ms {
                    return Err(AuthStoreError::Denied("review session expired".into()));
                }
                return Ok(existing);
            }
            return Err(AuthStoreError::Denied(
                "review session id already exists for a different approval".into(),
            ));
        }
        tx.execute(
            "INSERT INTO review_sessions(
                review_session_id, surface, action_id, intent_hash, assurance, expires_ms,
                consumed_ms, created_ms
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
            params![
                review_session_id,
                surface,
                action_id,
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
                "SELECT surface, action_id, intent_hash, assurance, expires_ms, consumed_ms, created_ms
                 FROM review_sessions WHERE review_session_id = ?1",
                params![review_session_id],
                |row| {
                    let surface: String = row.get(0)?;
                    let action_id: String = row.get(1)?;
                    let intent_hash: String = row.get(2)?;
                    let assurance: String = row.get(3)?;
                    let expires_ms: i64 = row.get(4)?;
                    let consumed_ms: Option<i64> = row.get(5)?;
                    let created_ms: i64 = row.get(6)?;
                    Ok((
                        surface,
                        action_id,
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
                |(surface, action_id, intent_hash, assurance, expires_ms, consumed_ms, created_ms)| {
                    Ok(ReviewSessionRecord {
                        review_session_id: review_session_id.to_string(),
                        surface,
                        action_id,
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
        action_id: &str,
    ) -> Result<Option<AuthEntryRecord>, AuthStoreError> {
        self.conn
            .query_row(
                "SELECT state, intent_hash, assurance, nonce, nonce_state, reservation_id, updated_ms
                 FROM auth_entries WHERE surface = ?1 AND action_id = ?2",
                params![surface, action_id],
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
                        action_id: action_id.to_string(),
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
        approval: &SignedApproval,
        now_ms: u64,
    ) -> Result<(), AuthStoreError> {
        let tx = self.conn.transaction()?;
        #[allow(clippy::type_complexity)]
        let row: (
            String,
            String,
            Option<String>,
            String,
            Option<i64>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<i64>,
        ) = tx
            .query_row(
                "SELECT intent_hash, assurance, nonce, nonce_state, challenge_expiry_ms,
                        wallet, petal_id, petal_digest, daemon_terms_digest,
                        petal_policy_digest, policy_version
                 FROM auth_entries
                 WHERE surface = ?1 AND action_id = ?2",
                params![approval.surface, approval.action_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| AuthStoreError::Denied("entry not found".into()))?;
        let (
            entry_intent_hash,
            entry_assurance,
            entry_nonce,
            nonce_state,
            challenge_expiry_ms,
            entry_wallet,
            entry_petal_id,
            entry_petal_digest,
            entry_daemon_terms_digest,
            entry_petal_policy_digest,
            entry_policy_version,
        ) = row;
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
        let Some(challenge_expiry_ms) = challenge_expiry_ms else {
            return Err(AuthStoreError::Denied(
                "entry has no issued challenge".into(),
            ));
        };
        if challenge_expiry_ms != approval.expiry_ms as i64 {
            return Err(AuthStoreError::Denied(
                "approval expiry does not match issued challenge".into(),
            ));
        }
        // Rebuild the exact daemon-issued challenge (§5.7 step 3). Entries
        // staged before the sealed-action schema have NULL petal/digest
        // metadata and fail closed here; they are re-stageable by design.
        let (
            Some(wallet),
            Some(petal_id),
            Some(petal_digest),
            Some(daemon_terms_digest),
            Some(petal_policy_digest),
            Some(policy_version),
        ) = (
            entry_wallet,
            entry_petal_id,
            entry_petal_digest,
            entry_daemon_terms_digest,
            entry_petal_policy_digest,
            entry_policy_version,
        )
        else {
            return Err(AuthStoreError::Denied(
                "entry predates the sealed-action schema and is void; re-stage the action".into(),
            ));
        };
        let issued = ApprovalChallenge {
            schema: APPROVAL_CHALLENGE_SCHEMA_V1.to_string(),
            action_id: approval.action_id.clone(),
            wallet,
            surface: approval.surface.clone(),
            petal_id,
            petal_digest,
            intent_hash: entry_intent_hash,
            server_nonce: approval.server_nonce.clone(),
            assurance: parse_assurance(&entry_assurance)?,
            daemon_terms_digest,
            petal_policy_digest,
            policy_version: policy_version as u64,
            expiry_ms: challenge_expiry_ms as u64,
        };
        let (envelope_json, sealed_at_ms, sealed_action_json): (String, i64, Option<String>) = tx
            .query_row(
            "SELECT envelope_json, sealed_at_ms, sealed_action_json
                 FROM sealed_intents WHERE intent_hash = ?1",
            params![approval.intent_hash],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let envelope: CanonicalEnvelope = serde_json::from_str(&envelope_json)?;
        let action: Option<SealedAction> = sealed_action_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()?;
        approval
            .validate_against_sealed(
                &SealedIntentRecord {
                    intent_hash: approval.intent_hash.clone(),
                    envelope,
                    sealed_at_ms: sealed_at_ms as u64,
                    action,
                },
                &issued,
                now_ms,
            )
            .map_err(AuthStoreError::from_api)?;
        if approval.assurance == AssuranceLevel::Hardened {
            let review_session_id = approval.review_session_id.as_deref().ok_or_else(|| {
                AuthStoreError::Denied("hardened approval requires a review_session_id".into())
            })?;
            let (
                session_surface,
                session_action_id,
                session_intent_hash,
                session_assurance,
                session_expires_ms,
                session_consumed_ms,
            ): (String, String, String, String, i64, Option<i64>) = tx
                .query_row(
                    "SELECT surface, action_id, intent_hash, assurance, expires_ms, consumed_ms
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
                || session_action_id != approval.action_id
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
        // The `signer_kind` column now records the approval's transport
        // (`browser_webauthn` | `native_ctap2`).
        // TODO(ws-L): rename the column to `signer_transport` once legacy
        // signer-kind rows no longer need to be readable in place.
        tx.execute(
            "INSERT INTO approvals(
                surface, action_id, nonce, approval_json, signer_kind, assurance, expiry_ms,
                consumed_ms
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(surface, action_id, nonce) DO UPDATE SET
                approval_json = excluded.approval_json,
                signer_kind = excluded.signer_kind,
                assurance = excluded.assurance,
                expiry_ms = excluded.expiry_ms,
                consumed_ms = excluded.consumed_ms",
            params![
                approval.surface,
                approval.action_id,
                approval.server_nonce,
                approval_json,
                approval.signer_transport.as_str(),
                approval.assurance.as_str(),
                approval.expiry_ms as i64,
                now_ms as i64,
            ],
        )?;
        tx.execute(
            "UPDATE auth_entries
             SET state = ?3, nonce_state = ?4, updated_ms = ?5
             WHERE surface = ?1 AND action_id = ?2 AND nonce = ?6 AND nonce_state = 'unused'",
            params![
                approval.surface,
                approval.action_id,
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
            "action_id": approval.action_id,
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
                "SELECT envelope_json, sealed_at_ms, sealed_action_json
                 FROM sealed_intents WHERE intent_hash = ?1",
                params![intent_hash],
                |row| {
                    let envelope_json: String = row.get(0)?;
                    let sealed_at_ms: i64 = row.get(1)?;
                    let sealed_action_json: Option<String> = row.get(2)?;
                    Ok((envelope_json, sealed_at_ms, sealed_action_json))
                },
            )
            .optional()?
            .map(|(envelope_json, sealed_at_ms, sealed_action_json)| {
                let envelope: CanonicalEnvelope = serde_json::from_str(&envelope_json)?;
                let action: Option<SealedAction> = sealed_action_json
                    .as_deref()
                    .map(serde_json::from_str)
                    .transpose()?;
                Ok(SealedIntentRecord {
                    intent_hash: intent_hash.to_string(),
                    envelope,
                    sealed_at_ms: sealed_at_ms as u64,
                    action,
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
        approval: SignedApproval,
        now_ms: u64,
    ) -> Result<(), AuthApiError> {
        let unsigned = approval.unsigned_payload();
        self.signature_verifier
            .verify_signature(&unsigned, &approval.webauthn_assertion, now_ms)
            .await?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| AuthApiError::Store("auth store mutex poisoned".into()))?;
        store.consume_verified_approval_transactionally(&approval, now_ms)?;
        Ok(())
    }

    async fn verify_and_mint_grant(
        &self,
        approval: SignedApproval,
        grant_store: &dyn GrantStore,
        now_ms: u64,
    ) -> Result<SealedApprovalGrant, AuthApiError> {
        let unsigned = approval.unsigned_payload();
        self.signature_verifier
            .verify_signature(&unsigned, &approval.webauthn_assertion, now_ms)
            .await?;
        // Hold the auth store mutex just long enough to burn the nonce and
        // load the sealed action. Releasing the lock before calling
        // `grant_store.mint` avoids holding both mutexes at once.
        let sealed_action = {
            let mut store = self
                .store
                .lock()
                .map_err(|_| AuthApiError::Store("auth store mutex poisoned".into()))?;
            store.consume_verified_approval_transactionally(&approval, now_ms)?;
            let sealed = store.sealed_intent(&approval.intent_hash)?.ok_or_else(|| {
                AuthApiError::NotFound(format!(
                    "sealed intent {} for approved action",
                    approval.intent_hash
                ))
            })?;
            sealed.action.ok_or_else(|| {
                AuthApiError::Denied(format!(
                    "sealed action is missing for intent_hash {}; re-stage the action",
                    approval.intent_hash
                ))
            })?
        };
        // The nonce has now been burned. Even if `grant_store.mint` fails
        // (e.g. a live grant for the tuple already exists), the caller
        // cannot replay this approval — by design.
        grant_store
            .mint(&sealed_action, approval.expiry_ms, now_ms)
            .await
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

    async fn stage_action(
        &self,
        action: SealedAction,
        now_ms: u64,
    ) -> Result<AuthEntryRecord, AuthApiError> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| AuthApiError::Store("auth store mutex poisoned".into()))?;
        Ok(store.stage_action(&action, now_ms)?)
    }

    async fn issue_challenge(
        &self,
        surface: &str,
        action_id: &str,
        server_nonce: &str,
        expiry_ms: u64,
        now_ms: u64,
    ) -> Result<ApprovalChallenge, AuthApiError> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| AuthApiError::Store("auth store mutex poisoned".into()))?;
        Ok(store.issue_challenge(surface, action_id, server_nonce, expiry_ms, now_ms)?)
    }

    async fn issue_review_session(
        &self,
        review_session_id: &str,
        surface: &str,
        action_id: &str,
        expires_ms: u64,
        now_ms: u64,
    ) -> Result<ReviewSessionRecord, AuthApiError> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| AuthApiError::Store("auth store mutex poisoned".into()))?;
        Ok(
            store.issue_review_session(
                review_session_id,
                surface,
                action_id,
                expires_ms,
                now_ms,
            )?,
        )
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
        "standard" => Ok(AssuranceLevel::Standard),
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

/// Derive a globally-unique, path-safe `action_id` from the
/// `(surface, venue_local_id)` pair. Deterministic (so re-allocation is
/// idempotent) and injective across distinct pairs modulo a 128-bit BLAKE3
/// collision. The `surface` prefix keeps ids human-readable in the outbox; the
/// hash covers `surface` and `venue_local_id` with a separator so no two
/// distinct pairs alias.
fn derive_action_id(surface: &str, venue_local_id: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.action_id.v1");
    hasher.update(surface.as_bytes());
    hasher.update(&[0x1f]);
    hasher.update(venue_local_id.as_bytes());
    let hex = hasher.finalize().to_hex().to_string();
    format!("{surface}-{}", &hex[..32])
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
    use base64::Engine as _;
    use bloom_auth_api::{
        CANONICAL_INTENT_HEADER_SCHEMA_V2, CanonicalEnvelope, CanonicalIntentHeader, ExecutorKind,
        SignerTransport,
        petal_identity::{
            FIRST_PARTY_PETAL_VERSION_V0, PETAL_ID_PAID_HTTP, PLACEHOLDER_DIGEST_PAID_HTTP,
        },
    };

    fn envelope() -> CanonicalEnvelope {
        envelope_for("requests", "req_1")
    }

    /// Build a faithful signed approval for a daemon-issued challenge, the way
    /// a real client would (echoing every daemon-issued field).
    fn approval_for(challenge: &ApprovalChallenge) -> SignedApproval {
        let unsigned = UnsignedApproval::for_challenge(
            challenge,
            SignerTransport::BrowserWebauthn,
            Some("cred-1".into()),
            None,
        );
        let assertion = webauthn_assertion_for(&unsigned);
        unsigned.into_signed(assertion)
    }

    fn webauthn_assertion_for(unsigned: &UnsignedApproval) -> WebAuthnAssertionRecord {
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(unsigned.challenge_hash().unwrap());
        let client_data_json = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": "http://localhost:18734",
        });
        WebAuthnAssertionRecord {
            credential_id: "cred-1".into(),
            authenticator_data_b64: "AA".into(),
            client_data_json_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&client_data_json).unwrap()),
            signature_b64: "AA".into(),
            user_handle_b64: None,
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
        assert_eq!(store.pragma_i64("busy_timeout").unwrap(), 5_000);
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
            .stage_entry(&env, AssuranceLevel::Standard, 100)
            .unwrap();
        assert_eq!(staged.state, AuthEntryState::Staged);
        assert_eq!(staged.nonce_state, NonceState::Unused);
        assert_eq!(staged.nonce, None);

        let challenge = store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap();
        assert_eq!(challenge.schema, APPROVAL_CHALLENGE_SCHEMA_V1);
        assert_eq!(challenge.intent_hash, staged.intent_hash);
        assert_eq!(challenge.server_nonce, "nonce-1");
        assert_eq!(challenge.assurance, AssuranceLevel::Standard);
        // The full §5.7 preimage is daemon-issued from the staged entry.
        assert_eq!(challenge.wallet, "my-wallet");
        assert_eq!(challenge.petal_id, PETAL_ID_PAID_HTTP);
        assert_eq!(challenge.petal_digest, PLACEHOLDER_DIGEST_PAID_HTTP);
        assert_eq!(challenge.daemon_terms_digest.len(), 64);
        assert_eq!(challenge.petal_policy_digest.len(), 64);
        assert_eq!(challenge.policy_version, 0);
        assert_eq!(challenge.expiry_ms, 220);

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
            .stage_entry(&env, AssuranceLevel::Standard, 100)
            .unwrap();
        let second = store
            .stage_entry(&env, AssuranceLevel::Standard, 101)
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
                .stage_entry(&changed, AssuranceLevel::Standard, 103)
                .is_err()
        );
    }

    #[test]
    fn consume_approval_burns_nonce_and_replay_fails() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let env = envelope();
        store
            .stage_entry(&env, AssuranceLevel::Standard, 100)
            .unwrap();
        let challenge = store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap();
        let approval = approval_for(&challenge);

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
    fn challenge_cannot_be_reissued_after_nonce_consumed() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let env = envelope();
        store
            .stage_entry(&env, AssuranceLevel::Standard, 100)
            .unwrap();
        let challenge = store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap();
        let approval = approval_for(&challenge);
        store
            .consume_verified_approval_transactionally(&approval, 150)
            .unwrap();

        // After consumption the nonce is burned — re-challenging must fail.
        let err = store
            .issue_challenge("requests", "req_1", "nonce-2", 300, 200)
            .unwrap_err();
        assert!(err.to_string().contains("not challengeable"), "{err}");
    }

    #[test]
    fn audit_log_chains_multiple_events() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();

        // First entry + consume → genesis audit event.
        let env_a = envelope_for("requests", "req_a");
        store
            .stage_entry(&env_a, AssuranceLevel::Standard, 100)
            .unwrap();
        let challenge_a = store
            .issue_challenge("requests", "req_a", "n-a", 500, 101)
            .unwrap();
        store
            .consume_verified_approval_transactionally(&approval_for(&challenge_a), 150)
            .unwrap();

        // Second entry + consume → chained audit event.
        let env_b = envelope_for("requests", "req_b");
        store
            .stage_entry(&env_b, AssuranceLevel::Standard, 200)
            .unwrap();
        let challenge_b = store
            .issue_challenge("requests", "req_b", "n-b", 500, 201)
            .unwrap();
        store
            .consume_verified_approval_transactionally(&approval_for(&challenge_b), 250)
            .unwrap();

        // Verify chain integrity.
        let rows: Vec<(i64, String, String)> = store
            .conn
            .prepare("SELECT seq, prev_digest, digest FROM audit ORDER BY seq")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(rows.len(), 2, "expected two audit events");
        assert_eq!(
            rows[0].1,
            "0".repeat(64),
            "genesis prev_digest must be zero"
        );
        assert_eq!(
            rows[1].1, rows[0].2,
            "second event's prev_digest must chain to first event's digest"
        );
        assert_ne!(rows[0].2, rows[1].2);
    }

    #[test]
    fn inflated_expiry_approval_is_denied_and_does_not_burn_nonce() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let env = envelope();
        store
            .stage_entry(&env, AssuranceLevel::Standard, 100)
            .unwrap();
        let challenge = store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap();
        let mut approval = approval_for(&challenge);
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
        let approval = approval_for(&challenge);
        store
            .consume_verified_approval_transactionally(&approval, 150)
            .unwrap();
    }

    #[test]
    fn approval_with_drifted_daemon_issued_field_is_denied_without_nonce_burn() {
        // §5.7 step 10: every daemon-issued challenge value must be echoed
        // byte-for-byte; any drift denies and must not burn the nonce.
        type DriftCase = (&'static str, Box<dyn Fn(&mut SignedApproval)>);
        let cases: Vec<DriftCase> = vec![
            ("wallet", Box::new(|a| a.wallet = "other-wallet".into())),
            ("petal_id", Box::new(|a| a.petal_id = "evm-wallet".into())),
            (
                "petal_digest",
                Box::new(|a| a.petal_digest = "first-party-placeholder:evm-wallet:v0".into()),
            ),
            (
                "daemon_terms_digest",
                Box::new(|a| a.daemon_terms_digest = "9".repeat(64)),
            ),
            (
                "petal_policy_digest",
                Box::new(|a| a.petal_policy_digest = "9".repeat(64)),
            ),
            ("policy_version", Box::new(|a| a.policy_version = 42)),
        ];
        for (field, mutate) in cases {
            let mut store = AuthStore::open_in_memory_for_tests().unwrap();
            let env = envelope();
            store
                .stage_entry(&env, AssuranceLevel::Standard, 100)
                .unwrap();
            let challenge = store
                .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
                .unwrap();
            let mut approval = approval_for(&challenge);
            mutate(&mut approval);
            let err = store
                .consume_verified_approval_transactionally(&approval, 150)
                .unwrap_err();
            assert!(
                err.to_string().contains("mismatch") || err.to_string().contains("does not match"),
                "{field}: {err}"
            );
            let still_unused = store.auth_entry("requests", "req_1").unwrap().unwrap();
            assert_eq!(still_unused.nonce_state, NonceState::Unused, "{field}");
            // The faithful echo still consumes.
            store
                .consume_verified_approval_transactionally(&approval_for(&challenge), 150)
                .unwrap();
        }
    }

    #[test]
    fn consumed_nonce_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.sqlite");
        let approval = {
            let mut store = AuthStore::open(&path).unwrap();
            let env = envelope();
            store
                .stage_entry(&env, AssuranceLevel::Standard, 100)
                .unwrap();
            let challenge = store
                .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
                .unwrap();
            let approval = approval_for(&challenge);
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
            .stage_entry(&env, AssuranceLevel::Standard, 100)
            .unwrap();
        let challenge = store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap();
        let mut approval = approval_for(&challenge);
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
            .stage_entry(&env, AssuranceLevel::Standard, 100)
            .unwrap();
        let challenge = store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap();
        let approval = approval_for(&challenge);
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
        assert_eq!(staged.action_id, "req_1");
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
        let challenge = store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap();
        let approval = approval_for(&challenge);

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
        let challenge = store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap();
        let session = store
            .issue_review_session("review-1", "requests", "req_1", 220, 102)
            .unwrap();
        assert_eq!(session.consumed_ms, None);

        let mut approval = approval_for(&challenge);
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
    fn issue_review_session_retries_existing_unconsumed_match() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let env = envelope();
        store
            .stage_entry(&env, AssuranceLevel::Hardened, 100)
            .unwrap();
        store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap();

        let first = store
            .issue_review_session("review-1", "requests", "req_1", 220, 102)
            .unwrap();
        let retry = store
            .issue_review_session("review-1", "requests", "req_1", 220, 150)
            .unwrap();

        assert_eq!(retry.review_session_id, first.review_session_id);
        assert_eq!(retry.created_ms, first.created_ms);
        assert_eq!(retry.consumed_ms, None);
    }

    #[test]
    fn issue_review_session_retry_rejects_consumed_match() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        stage_and_challenge(&mut store, "requests", "req_1", "n1", "sess-1");
        store
            .conn
            .execute(
                "UPDATE review_sessions SET consumed_ms = 150 WHERE review_session_id = 'sess-1'",
                [],
            )
            .unwrap();

        let err = store
            .issue_review_session("sess-1", "requests", "req_1", 500, 200)
            .unwrap_err();
        assert!(
            err.to_string().contains("review session already consumed"),
            "{err}"
        );
    }

    // -------------------------------------------------------
    // Cross-action replay: a review session issued for one
    // action must NOT validate an approval for a different one.
    // -------------------------------------------------------

    fn envelope_for(surface: &str, action_id: &str) -> CanonicalEnvelope {
        CanonicalEnvelope::new(
            CanonicalIntentHeader {
                schema: CANONICAL_INTENT_HEADER_SCHEMA_V2.into(),
                wallet: "my-wallet".into(),
                surface: surface.into(),
                action_id: action_id.into(),
                petal_id: PETAL_ID_PAID_HTTP.into(),
                petal_digest: PLACEHOLDER_DIGEST_PAID_HTTP.into(),
                petal_version: FIRST_PARTY_PETAL_VERSION_V0.into(),
                executor_kind: ExecutorKind::FirstParty,
                network: "base".into(),
                account: "default".into(),
                action_kind: "x402_payment".into(),
                value_movement: true,
                authority_change: false,
                expires_ms: 600_000,
            },
            "paid_http",
            "paid_http.v1",
            br#"{"amount":"1.00"}"#.to_vec(),
        )
    }

    /// Stage a hardened entry, issue a challenge, and issue a review session.
    fn stage_and_challenge(
        store: &mut AuthStore,
        surface: &str,
        action_id: &str,
        nonce: &str,
        session_id: &str,
    ) -> ApprovalChallenge {
        let env = envelope_for(surface, action_id);
        store
            .stage_entry(&env, AssuranceLevel::Hardened, 100)
            .unwrap();
        let challenge = store
            .issue_challenge(surface, action_id, nonce, 500, 101)
            .unwrap();
        store
            .issue_review_session(session_id, surface, action_id, 500, 102)
            .unwrap();
        challenge
    }

    #[test]
    fn cross_action_replay_via_action_id_mismatch_rejected() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        // Action A gets a review session.
        stage_and_challenge(&mut store, "requests", "req_1", "n1", "sess-A");
        // Action B is a different action_id on the same surface.
        let challenge_b = stage_and_challenge(&mut store, "requests", "req_2", "n2", "sess-B");

        let mut approval_b = approval_for(&challenge_b);
        // Attacker: attach A's session to B's approval.
        approval_b.review_session_id = Some("sess-A".into());

        let err = store
            .consume_verified_approval_transactionally(&approval_b, 200)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("review session does not match approval"),
            "{err}"
        );
        // Session A must NOT be consumed.
        assert_eq!(
            store.review_session("sess-A").unwrap().unwrap().consumed_ms,
            None
        );
    }

    #[test]
    fn cross_action_replay_via_surface_mismatch_rejected() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        stage_and_challenge(&mut store, "requests", "req_1", "n1", "sess-A");
        let challenge_b = stage_and_challenge(&mut store, "outbox", "tx_1", "n2", "sess-B");

        let mut approval_b = approval_for(&challenge_b);
        approval_b.review_session_id = Some("sess-A".into());

        let err = store
            .consume_verified_approval_transactionally(&approval_b, 200)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("review session does not match approval"),
            "{err}"
        );
    }

    #[test]
    fn review_session_expired_rejected() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        // Challenge TTL = 1000, but session TTL = 300.
        let env = envelope_for("requests", "req_1");
        store
            .stage_entry(&env, AssuranceLevel::Hardened, 100)
            .unwrap();
        let challenge = store
            .issue_challenge("requests", "req_1", "n1", 1000, 101)
            .unwrap();
        store
            .issue_review_session("sess-1", "requests", "req_1", 300, 102)
            .unwrap();

        let mut approval = approval_for(&challenge);
        approval.review_session_id = Some("sess-1".into());

        // Consume at t=400 — approval is valid (400 < 1000) but session expired (400 >= 300).
        let err = store
            .consume_verified_approval_transactionally(&approval, 400)
            .unwrap_err();
        assert!(err.to_string().contains("review session expired"), "{err}");
    }

    #[test]
    fn review_session_already_consumed_rejected() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let challenge = stage_and_challenge(&mut store, "requests", "req_1", "n1", "sess-1");

        // Simulate a prior consume of the session (e.g. concurrent tx won the race).
        store
            .conn
            .execute(
                "UPDATE review_sessions SET consumed_ms = 150 WHERE review_session_id = 'sess-1'",
                [],
            )
            .unwrap();

        let mut approval = approval_for(&challenge);
        approval.review_session_id = Some("sess-1".into());

        let err = store
            .consume_verified_approval_transactionally(&approval, 200)
            .unwrap_err();
        assert!(
            err.to_string().contains("review session already consumed"),
            "{err}"
        );
    }

    #[test]
    fn review_session_not_found_rejected() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let challenge = stage_and_challenge(&mut store, "requests", "req_1", "n1", "sess-1");

        let mut approval = approval_for(&challenge);
        approval.review_session_id = Some("nonexistent".into());

        let err = store
            .consume_verified_approval_transactionally(&approval, 200)
            .unwrap_err();
        assert!(
            err.to_string().contains("review session not found"),
            "{err}"
        );
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

    #[test]
    fn action_id_map_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("auth.sqlite");

        let id1 = {
            let mut store = AuthStore::open(&db_path).unwrap();
            store
                .allocate_action_id("outbox", "0001-a", "alice", 1_000)
                .unwrap()
        };
        assert!(!id1.is_empty());

        // Reopen the same DB file (simulates daemon restart).
        let mut store2 = AuthStore::open(&db_path).unwrap();
        let lookup = store2.lookup_action_id("outbox", "0001-a").unwrap();
        assert_eq!(lookup.as_deref(), Some(id1.as_str()));

        // Re-allocating the same (surface, venue_local_id) returns the same id.
        let id1b = store2
            .allocate_action_id("outbox", "0001-a", "alice", 2_000)
            .unwrap();
        assert_eq!(id1, id1b);

        // A different venue_local_id gets a different action_id.
        let id2 = store2
            .allocate_action_id("outbox", "0002-b", "alice", 3_000)
            .unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn same_millisecond_actions_get_distinct_action_ids() {
        // Regression: an earlier `surface-<now_ms>` id collided for two actions
        // staged in the same millisecond on the same surface (the whole id came
        // from the clock and the table had no `action_id` uniqueness guard),
        // corrupting the shared central-outbox slot. Ids now derive from
        // `(surface, venue_local_id)`, so a shared timestamp is irrelevant.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("auth.sqlite");
        let mut store = AuthStore::open(&db_path).unwrap();
        let now = 1_720_000_000_000;

        let a = store
            .allocate_action_id("evm", "0001-a", "alice", now)
            .unwrap();
        let b = store
            .allocate_action_id("evm", "0002-b", "alice", now)
            .unwrap();
        assert_ne!(a, b, "same-ms distinct actions must not share an action_id");

        // Same pair at the same instant is still idempotent.
        let a_again = store
            .allocate_action_id("evm", "0001-a", "alice", now)
            .unwrap();
        assert_eq!(a, a_again);

        // Both rows persisted and each resolves back to its own id.
        assert_eq!(
            store.lookup_action_id("evm", "0001-a").unwrap().as_deref(),
            Some(a.as_str())
        );
        assert_eq!(
            store.lookup_action_id("evm", "0002-b").unwrap().as_deref(),
            Some(b.as_str())
        );
    }

    // -------------------------------------------------------
    // Sealed actions (bloom.sealed_action.v1) and migration
    // -------------------------------------------------------

    #[test]
    fn stage_action_persists_full_sealed_action_and_challenge_digests_match() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let action =
            SealedAction::seal_with_default_terms(envelope(), AssuranceLevel::Standard, 100)
                .unwrap();
        let staged = store.stage_action(&action, 100).unwrap();

        let sealed = store.sealed_intent(&staged.intent_hash).unwrap().unwrap();
        assert_eq!(sealed.action.as_ref(), Some(&action));
        assert_eq!(sealed.envelope, action.envelope);

        let challenge = store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap();
        assert_eq!(
            challenge.daemon_terms_digest,
            action.daemon_terms_digest().unwrap()
        );
        assert_eq!(challenge.petal_policy_digest, action.petal_policy_digest);
        assert_eq!(challenge.policy_version, action.policy_version);
        assert_eq!(challenge.petal_id, action.petal_id());
        assert_eq!(challenge.petal_digest, action.petal_digest());
        assert_eq!(challenge.wallet, action.wallet());

        // A faithful client echo of the issued challenge consumes.
        store
            .consume_verified_approval_transactionally(&approval_for(&challenge), 150)
            .unwrap();
    }

    #[test]
    fn issue_challenge_requires_stored_sealed_action() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let action =
            SealedAction::seal_with_default_terms(envelope(), AssuranceLevel::Standard, 100)
                .unwrap();
        let staged = store.stage_action(&action, 100).unwrap();
        store
            .conn
            .execute(
                "UPDATE sealed_intents SET sealed_action_json = NULL WHERE intent_hash = ?1",
                params![staged.intent_hash],
            )
            .unwrap();

        let err = store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap_err();
        assert!(err.to_string().contains("re-stage"), "{err}");
    }

    #[test]
    fn issue_challenge_rejects_auth_entry_metadata_drift_from_sealed_action() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let action =
            SealedAction::seal_with_default_terms(envelope(), AssuranceLevel::Standard, 100)
                .unwrap();
        store.stage_action(&action, 100).unwrap();
        store
            .conn
            .execute(
                "UPDATE auth_entries SET daemon_terms_digest = ?3 WHERE surface = ?1 AND action_id = ?2",
                params!["requests", "req_1", "9".repeat(64)],
            )
            .unwrap();

        let err = store
            .issue_challenge("requests", "req_1", "nonce-1", 220, 101)
            .unwrap_err();
        assert!(err.to_string().contains("sealed metadata"), "{err}");
    }

    #[test]
    fn restaging_same_action_id_with_different_daemon_context_is_denied() {
        let mut store = AuthStore::open_in_memory_for_tests().unwrap();
        let action =
            SealedAction::seal_with_default_terms(envelope(), AssuranceLevel::Standard, 100)
                .unwrap();
        store.stage_action(&action, 100).unwrap();

        // Same envelope, wider daemon terms: must not silently alias the
        // already-sealed entry.
        let mut widened = action.clone();
        widened.daemon_terms.allowed_sign_intents = vec!["evm.tx.sign".into()];
        let err = store.stage_action(&widened, 101).unwrap_err();
        assert!(
            err.to_string().contains("different sealed daemon context"),
            "{err}"
        );
    }

    /// Simulate a database created before the sealed-action schema, then open
    /// it with the current code: consumed-nonce history (replay denial) must
    /// survive, while legacy pending rows become void and re-stageable.
    #[test]
    fn migration_from_pre_sealed_action_schema_preserves_replay_denial() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE sealed_intents (
                    intent_hash TEXT PRIMARY KEY NOT NULL,
                    envelope_json TEXT NOT NULL,
                    sealed_at_ms INTEGER NOT NULL
                );
                CREATE TABLE auth_entries (
                    surface TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    intent_hash TEXT NOT NULL REFERENCES sealed_intents(intent_hash),
                    assurance TEXT NOT NULL,
                    nonce TEXT,
                    nonce_state TEXT NOT NULL DEFAULT 'unused',
                    challenge_expiry_ms INTEGER,
                    reservation_id TEXT,
                    updated_ms INTEGER NOT NULL,
                    PRIMARY KEY(surface, action_id)
                );
                INSERT INTO sealed_intents(intent_hash, envelope_json, sealed_at_ms)
                VALUES ('legacy-hash-consumed', '{"legacy":"v1-envelope"}', 100);
                INSERT INTO sealed_intents(intent_hash, envelope_json, sealed_at_ms)
                VALUES ('legacy-hash-pending', '{"legacy":"v1-envelope-2"}', 100);
                INSERT INTO auth_entries(
                    surface, action_id, state, intent_hash, assurance, nonce, nonce_state,
                    challenge_expiry_ms, reservation_id, updated_ms
                )
                VALUES ('requests', 'req_old_consumed', 'approved', 'legacy-hash-consumed',
                        'standard', 'old-nonce', 'consumed', 220, NULL, 150);
                INSERT INTO auth_entries(
                    surface, action_id, state, intent_hash, assurance, nonce, nonce_state,
                    challenge_expiry_ms, reservation_id, updated_ms
                )
                VALUES ('requests', 'req_old_pending', 'challenged', 'legacy-hash-pending',
                        'standard', 'pending-nonce', 'unused', 220, NULL, 150);
                "#,
            )
            .unwrap();
        }

        let mut store = AuthStore::open(&path).unwrap();

        // 1. Consumed-nonce history survives: the entry still reads as
        //    consumed and any replay attempt is denied.
        let consumed = store
            .auth_entry("requests", "req_old_consumed")
            .unwrap()
            .unwrap();
        assert_eq!(consumed.nonce_state, NonceState::Consumed);
        let replay = SignedApproval {
            schema: bloom_auth_api::APPROVAL_SCHEMA_V1.into(),
            action_id: "req_old_consumed".into(),
            wallet: "my-wallet".into(),
            surface: "requests".into(),
            petal_id: PETAL_ID_PAID_HTTP.into(),
            petal_digest: PLACEHOLDER_DIGEST_PAID_HTTP.into(),
            intent_hash: "legacy-hash-consumed".into(),
            server_nonce: "old-nonce".into(),
            assurance: AssuranceLevel::Standard,
            daemon_terms_digest: "0".repeat(64),
            petal_policy_digest: "0".repeat(64),
            policy_version: 0,
            expiry_ms: 220,
            signer_transport: SignerTransport::BrowserWebauthn,
            credential_id: "cred-1".into(),
            review_session_id: None,
            webauthn_assertion: WebAuthnAssertionRecord {
                credential_id: "cred-1".into(),
                authenticator_data_b64: "AA".into(),
                client_data_json_b64: "e30".into(),
                signature_b64: "AA".into(),
                user_handle_b64: None,
            },
        };
        let err = store
            .consume_verified_approval_transactionally(&replay, 151)
            .unwrap_err();
        assert!(
            err.to_string().contains("already consumed"),
            "replay must stay denied after migration: {err}"
        );

        // 2. Legacy pending rows are void: challenge issuance fails closed.
        let err = store
            .issue_challenge("requests", "req_old_pending", "n-new", 500, 200)
            .unwrap_err();
        assert!(err.to_string().contains("re-stage"), "{err}");

        // 3. New actions stage and consume normally on the migrated database.
        let env = envelope_for("requests", "req_new");
        store
            .stage_entry(&env, AssuranceLevel::Standard, 300)
            .unwrap();
        let challenge = store
            .issue_challenge("requests", "req_new", "n-1", 900, 301)
            .unwrap();
        store
            .consume_verified_approval_transactionally(&approval_for(&challenge), 400)
            .unwrap();
    }

    // -------------------------------------------------------
    // verify_and_mint_grant: end-to-end grant service flow
    // -------------------------------------------------------

    use bloom_auth_api::{DaemonGrantTerms, PetalPolicySnapshot, SealedAction};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    /// Build a sealed action whose daemon terms allow `evm.tx.sign` (so the
    /// minted grant can actually be consumed) and accept up to 2 signatures.
    fn multi_sig_action() -> SealedAction {
        let env = envelope_for("requests", "req_grant");
        let mut snapshot = PetalPolicySnapshot::minimal(&env.header);
        snapshot.policy_version = 0;
        SealedAction::new(
            env,
            "plan".into(),
            Vec::new(),
            DaemonGrantTerms {
                max_ttl_secs: 60,
                max_signatures: 2,
                allowed_sign_intents: vec!["evm.tx.sign".into()],
                assurance: AssuranceLevel::Standard,
                extra: BTreeMap::new(),
            },
            snapshot,
            100,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn verify_and_mint_grant_happy_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.sqlite");
        let mut store = AuthStore::open(&path).unwrap();
        let action = multi_sig_action();
        store.stage_action(&action, 100).unwrap();
        let challenge = store
            .issue_challenge("requests", "req_grant", "nonce-grant", 500, 101)
            .unwrap();
        let approval = approval_for(&challenge);

        let verifier = StoreApprovalVerifier::new(store, AcceptingApprovalSignatureVerifier);
        let grant_store: Arc<dyn GrantStore> = Arc::new(InMemoryGrantStore::new());
        let grant = verifier
            .verify_and_mint_grant(approval, grant_store.as_ref(), 200)
            .await
            .unwrap();
        assert_eq!(grant.action_id, "req_grant");
        assert_eq!(grant.wallet, "my-wallet");
        assert_eq!(grant.max_signatures, 2);
        assert_eq!(grant.consumed_signature_count, 0);
        assert!(!grant.revoked);
        assert!(grant.expiry_ms > 200);

        // The minted grant can drive a real signature consume.
        let snapshot = grant_store
            .consume_signature(&grant.grant_id, "evm.tx.sign", 250)
            .await
            .unwrap();
        assert_eq!(snapshot.consumed_signature_count, 1);
        assert_eq!(snapshot.max_signatures, 2);
    }

    #[tokio::test]
    async fn verify_and_mint_grant_denied_if_signature_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.sqlite");
        let mut store = AuthStore::open(&path).unwrap();
        let action = multi_sig_action();
        store.stage_action(&action, 100).unwrap();
        let challenge = store
            .issue_challenge("requests", "req_grant", "nonce-grant", 500, 101)
            .unwrap();
        let approval = approval_for(&challenge);

        let verifier = StoreApprovalVerifier::new(store, RejectingApprovalSignatureVerifier);
        let grant_store: Arc<dyn GrantStore> = Arc::new(InMemoryGrantStore::new());
        let err = verifier
            .verify_and_mint_grant(approval, grant_store.as_ref(), 200)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("signature verifier is not installed"),
            "{err}"
        );

        // Nonce must NOT be burned when signature verification fails.
        drop(verifier);
        let reopened = AuthStore::open(&path).unwrap();
        let entry = reopened
            .auth_entry("requests", "req_grant")
            .unwrap()
            .unwrap();
        assert_eq!(entry.nonce_state, NonceState::Unused);
        // The grant store has no rows.
        let active = reopened_grant(&grant_store, 250).await;
        assert!(active.is_none());
    }

    #[tokio::test]
    async fn verify_and_mint_grant_denies_if_grant_tuple_already_live() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.sqlite");
        let mut store = AuthStore::open(&path).unwrap();
        let action = multi_sig_action();
        store.stage_action(&action, 100).unwrap();
        let challenge1 = store
            .issue_challenge("requests", "req_grant", "nonce-1", 500, 101)
            .unwrap();
        let approval1 = approval_for(&challenge1);

        let verifier = StoreApprovalVerifier::new(store, AcceptingApprovalSignatureVerifier);
        let grant_store: Arc<dyn GrantStore> = Arc::new(InMemoryGrantStore::new());
        let first = verifier
            .verify_and_mint_grant(approval1, grant_store.as_ref(), 200)
            .await
            .unwrap();
        assert_eq!(first.action_id, "req_grant");
        assert_eq!(first.consumed_signature_count, 0);

        // Manually roll the auth entry back to "challenged" with a fresh
        // nonce so we can re-issue a challenge and observe the
        // grant-store-side "live grant" rejection (the verify-and-mint path
        // is otherwise blocked at the nonce-consume step).
        drop(verifier);
        {
            let raw = AuthStore::open(&path).unwrap();
            raw.conn
                .execute(
                    "UPDATE auth_entries
                     SET state = 'challenged', nonce = 'nonce-2', nonce_state = 'unused',
                         challenge_expiry_ms = 900, updated_ms = 300
                     WHERE surface = 'requests' AND action_id = 'req_grant'",
                    [],
                )
                .unwrap();
        }
        let mut store2 = AuthStore::open(&path).unwrap();
        let challenge2 = store2
            .issue_challenge("requests", "req_grant", "nonce-2", 900, 301)
            .unwrap();
        let approval2 = approval_for(&challenge2);
        let verifier2 = StoreApprovalVerifier::new(store2, AcceptingApprovalSignatureVerifier);
        let err = verifier2
            .verify_and_mint_grant(approval2, grant_store.as_ref(), 400)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("live grant"),
            "mint must fail closed with a 'live grant' message: {err}"
        );
    }

    async fn reopened_grant(
        grant_store: &Arc<dyn GrantStore>,
        now_ms: u64,
    ) -> Option<SealedApprovalGrant> {
        grant_store
            .get_active(
                "my-wallet",
                "req_grant",
                bloom_auth_api::petal_identity::PETAL_ID_PAID_HTTP,
                bloom_auth_api::petal_identity::PLACEHOLDER_DIGEST_PAID_HTTP,
                now_ms,
            )
            .await
            .unwrap()
    }
}
