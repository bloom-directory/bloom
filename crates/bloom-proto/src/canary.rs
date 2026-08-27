//! The isolated Solana mainnet-beta canary authorization.
//!
//! Bloom's ordinary build refuses mainnet-beta at three independent layers:
//! config validation rejects `allow_broadcast` on the pinned mainnet genesis,
//! daemon boot refuses to construct an engine for a chain whose *live* genesis
//! is mainnet-beta, and the broadcast client refuses again immediately before
//! sending. This module does not weaken any of them. It adds a fourth thing
//! they can consult — and only when the binary was deliberately compiled with
//! the non-default `mainnet-canary` feature.
//!
//! The shape is deliberately hostile to accident:
//!
//! * **Compile-time.** Without the `mainnet-canary` feature none of this is
//!   reachable; [`authorization`] is a function that returns `None` and the
//!   guards keep their existing unconditional refusals. A production binary
//!   cannot be talked into a canary by any file, flag, or environment
//!   variable, because the code that would read them is not in it.
//! * **Out of band.** The authorization is a separate file named by
//!   [`AUTHORIZATION_ENV`], never a config key. `config.toml` therefore has no
//!   spelling that enables mainnet, which keeps the blast radius of a bad
//!   config edit exactly where it is today.
//! * **Bound to one artifact.** The authorization carries the SHA-256 of the
//!   binary it was issued for and is refused by any other binary, so it cannot
//!   be reused against a later, differently-built Machine.
//! * **Bound to one transaction.** One wallet, one key fingerprint, one
//!   destination, one amount, a fee ceiling, a balance ceiling, an expiry, and
//!   a transaction ceiling that must be exactly 1, spent through a durable
//!   single-use ledger.
//! * **Typed acknowledgement.** The operator must reproduce, verbatim, a
//!   sentence derived from those same fields. A boilerplate "yes" does not
//!   parse, and editing any bound value invalidates the acknowledgement that
//!   was written for the old one.
//!
//! None of this replaces Broker policy, semantic verification, or the human
//! approval ceremony. Those still run exactly as they do on devnet; the canary
//! only decides whether mainnet-beta is permissible *at all*, and it can only
//! ever narrow what follows.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Build-time environment variable that must be set to compile the canary.
pub const ARTIFACT_LABEL_ENV: &str = "BLOOM_MAINNET_CANARY_ARTIFACT";

/// Compiling the canary requires deliberately labelling the artifact.
///
/// This exists so that a broad build — `--all-features` in particular — cannot
/// quietly produce a release binary that is able to reach mainnet-beta. The
/// feature alone is not enough; the builder must also set
/// [`ARTIFACT_LABEL_ENV`], which no ordinary release path does. The failure is
/// a compile error rather than a runtime check, so the artifact simply cannot
/// exist by accident.
#[cfg(feature = "mainnet-canary")]
const _CANARY_ARTIFACT_MUST_BE_LABELLED: () = {
    if option_env!("BLOOM_MAINNET_CANARY_ARTIFACT").is_none() {
        panic!(
            "the `mainnet-canary` feature builds a NON-PRODUCTION artifact that can broadcast to \
             Solana mainnet-beta. It must never be enabled by a release or `--all-features` build. \
             To build a deliberately labelled canary artifact, set \
             BLOOM_MAINNET_CANARY_ARTIFACT=1 in the build environment."
        );
    }
};

/// How this binary must be described wherever an artifact is identified.
pub const fn artifact_label() -> &'static str {
    if cfg!(feature = "mainnet-canary") {
        "NON-PRODUCTION-MAINNET-CANARY"
    } else {
        "production"
    }
}

/// Environment variable naming the authorization file. Read only when the
/// `mainnet-canary` feature is compiled in.
pub const AUTHORIZATION_ENV: &str = "BLOOM_SOLANA_MAINNET_CANARY_AUTHORIZATION";

/// Schema marker. A future incompatible revision takes a new value rather than
/// silently reinterpreting an old operator's file.
pub const AUTHORIZATION_SCHEMA: &str = "bloom.solana-mainnet-canary/1";

/// The canary is a single-transaction instrument by construction.
pub const MAX_TRANSACTIONS: u32 = 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanaryError {
    #[error("mainnet canary: {0}")]
    Invalid(String),
    #[error("mainnet canary authorization already spent: {0}")]
    Spent(String),
    #[error("mainnet canary: reading {path}: {kind:?}")]
    Io {
        path: String,
        kind: std::io::ErrorKind,
    },
}

impl CanaryError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

/// An operator-issued, artifact-bound authorization for exactly one bounded
/// mainnet-beta transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryAuthorization {
    pub schema: String,
    /// Lowercase hex SHA-256 of the Machine binary this authorizes.
    pub artifact_sha256: String,
    /// The `solana_chains` key this authorization applies to.
    pub chain: String,
    pub wallet: String,
    /// Exact selected key fingerprint (hex), as reported by `wallet address`.
    pub key_fingerprint: String,
    /// Frozen Solana derivation path of that key.
    pub derivation_path: String,
    /// Base58 source address the key derives to.
    pub source_address: String,
    /// Base58 destination. The only address this authorization can pay.
    pub destination: String,
    /// Ceiling on the funded balance; the total loss budget.
    pub max_balance_lamports: u64,
    /// The exact transfer amount. Not a ceiling.
    pub transfer_lamports: u64,
    pub max_fee_lamports: u64,
    /// Must equal [`MAX_TRANSACTIONS`].
    pub max_transactions: u32,
    /// Unix milliseconds after which this authorization is dead.
    pub expires_ms: u128,
    /// Must equal [`CanaryAuthorization::canonical_acknowledgement`].
    pub acknowledgement: String,
}

impl CanaryAuthorization {
    /// The exact sentence the operator must reproduce in `acknowledgement`.
    ///
    /// Every bound value appears here, so editing any of them after the fact
    /// invalidates the acknowledgement written for the previous values. This
    /// is what stops an authorization from being quietly re-pointed at a
    /// different destination or a larger amount.
    pub fn canonical_acknowledgement(&self) -> String {
        format!(
            "I authorize Bloom to broadcast exactly {transfer} lamports on Solana mainnet-beta \
             from {source} ({path}, fingerprint {fingerprint}) to {destination}, paying at most \
             {fee} lamports in fees, with at most {balance} lamports at risk, expiring at \
             {expiry} ms. I accept that these funds may be lost.",
            transfer = self.transfer_lamports,
            source = self.source_address,
            path = self.derivation_path,
            fingerprint = self.key_fingerprint,
            destination = self.destination,
            fee = self.max_fee_lamports,
            balance = self.max_balance_lamports,
            expiry = self.expires_ms,
        )
    }

    /// Structural validation, independent of the running binary and clock.
    pub fn validate_shape(&self) -> Result<(), CanaryError> {
        if self.schema != AUTHORIZATION_SCHEMA {
            return Err(CanaryError::invalid(format!(
                "unknown schema '{}', expected '{AUTHORIZATION_SCHEMA}'",
                self.schema
            )));
        }
        if self.max_transactions != MAX_TRANSACTIONS {
            return Err(CanaryError::invalid(format!(
                "max_transactions must be exactly {MAX_TRANSACTIONS}, found {}",
                self.max_transactions
            )));
        }
        for (label, value) in [
            ("chain", &self.chain),
            ("wallet", &self.wallet),
            ("key_fingerprint", &self.key_fingerprint),
            ("derivation_path", &self.derivation_path),
            ("source_address", &self.source_address),
            ("destination", &self.destination),
            ("artifact_sha256", &self.artifact_sha256),
        ] {
            if value.trim().is_empty() {
                return Err(CanaryError::invalid(format!("{label} must not be empty")));
            }
        }
        if self.source_address == self.destination {
            return Err(CanaryError::invalid(
                "destination must differ from the source address",
            ));
        }
        if self.transfer_lamports == 0 {
            return Err(CanaryError::invalid("transfer_lamports must be non-zero"));
        }
        // The debit is the transfer plus the fee, and both must fit inside the
        // stated total loss budget — otherwise "max balance" would not bound
        // the loss it claims to bound.
        let debit = self
            .transfer_lamports
            .checked_add(self.max_fee_lamports)
            .ok_or_else(|| CanaryError::invalid("transfer plus fee overflows"))?;
        if debit > self.max_balance_lamports {
            return Err(CanaryError::invalid(format!(
                "transfer {} + fee {} exceeds the {} lamport balance cap",
                self.transfer_lamports, self.max_fee_lamports, self.max_balance_lamports
            )));
        }
        if self.acknowledgement != self.canonical_acknowledgement() {
            return Err(CanaryError::invalid(
                "acknowledgement does not match the canonical sentence for these exact values",
            ));
        }
        Ok(())
    }

    /// Full validation against this binary, this clock, and this chain.
    pub fn validate_for(
        &self,
        chain: &str,
        artifact_sha256: &str,
        now_ms: u128,
    ) -> Result<(), CanaryError> {
        self.validate_shape()?;
        if !self.chain.eq_ignore_ascii_case(chain) {
            return Err(CanaryError::invalid(format!(
                "authorization names chain '{}', not '{chain}'",
                self.chain
            )));
        }
        if !self
            .artifact_sha256
            .eq_ignore_ascii_case(artifact_sha256.trim())
        {
            return Err(CanaryError::invalid(format!(
                "authorization is bound to artifact {}, but this binary is {artifact_sha256}",
                self.artifact_sha256
            )));
        }
        if now_ms > self.expires_ms {
            return Err(CanaryError::invalid(format!(
                "authorization expired at {} ms (now {now_ms} ms)",
                self.expires_ms
            )));
        }
        Ok(())
    }

    /// Refuse a transfer that does not match every bound value exactly.
    ///
    /// The amount is compared for equality, not as a ceiling: the operator
    /// authorized one specific debit, and a smaller one is still not the one
    /// they were shown.
    pub fn authorizes_transfer(
        &self,
        wallet: &str,
        key_fingerprint: &str,
        source_address: &str,
        destination: &str,
        lamports: u64,
        fee_lamports: u64,
    ) -> Result<(), CanaryError> {
        if wallet != self.wallet {
            return Err(CanaryError::invalid(format!(
                "wallet '{wallet}' is not the authorized wallet '{}'",
                self.wallet
            )));
        }
        if !key_fingerprint.eq_ignore_ascii_case(&self.key_fingerprint) {
            return Err(CanaryError::invalid(
                "signing key is not the authorized key fingerprint",
            ));
        }
        if source_address != self.source_address {
            return Err(CanaryError::invalid(format!(
                "source '{source_address}' is not the authorized source '{}'",
                self.source_address
            )));
        }
        if destination != self.destination {
            return Err(CanaryError::invalid(format!(
                "destination '{destination}' is not the authorized destination '{}'",
                self.destination
            )));
        }
        if lamports != self.transfer_lamports {
            return Err(CanaryError::invalid(format!(
                "amount {lamports} is not the authorized amount {}",
                self.transfer_lamports
            )));
        }
        if fee_lamports > self.max_fee_lamports {
            return Err(CanaryError::invalid(format!(
                "fee {fee_lamports} exceeds the authorized maximum {}",
                self.max_fee_lamports
            )));
        }
        Ok(())
    }

    /// Refuse a funded balance above the stated total loss budget.
    pub fn authorizes_balance(&self, lamports: u64) -> Result<(), CanaryError> {
        if lamports > self.max_balance_lamports {
            return Err(CanaryError::invalid(format!(
                "funded balance {lamports} exceeds the authorized cap {}",
                self.max_balance_lamports
            )));
        }
        Ok(())
    }
}

/// A loaded authorization together with the file it came from, so the
/// single-use ledger can live beside it.
#[derive(Debug, Clone)]
pub struct LoadedAuthorization {
    pub authorization: CanaryAuthorization,
    pub path: PathBuf,
}

impl LoadedAuthorization {
    /// Path of the durable single-use ledger for this authorization.
    pub fn spend_ledger_path(&self) -> PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(".spent");
        self.path.with_file_name(name)
    }

    /// Whether this authorization has already been spent.
    pub fn is_spent(&self) -> bool {
        self.spend_ledger_path().exists()
    }

    /// Claim the single permitted broadcast.
    ///
    /// The ledger is created with `create_new`, so two racing claimants cannot
    /// both win, and it is written *before* the send rather than after: a
    /// crash between claiming and sending must leave the canary spent. The
    /// alternative — recording afterwards — would allow an ambiguous send to
    /// be retried automatically, which is exactly the outcome the canary is
    /// designed to make impossible.
    pub fn claim_single_use(&self, note: &str) -> Result<(), CanaryError> {
        let path = self.spend_ledger_path();
        match std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
        {
            Ok(mut file) => {
                use std::io::Write as _;
                let _ = writeln!(file, "{note}");
                let _ = file.sync_all();
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(CanaryError::Spent(path.display().to_string()))
            }
            Err(error) => Err(CanaryError::Io {
                path: path.display().to_string(),
                kind: error.kind(),
            }),
        }
    }
}

/// Parse an authorization from JSON bytes.
pub fn parse(bytes: &[u8]) -> Result<CanaryAuthorization, CanaryError> {
    serde_json::from_slice(bytes)
        .map_err(|error| CanaryError::invalid(format!("malformed authorization: {error}")))
}

/// Read an authorization from `path`.
pub fn load_from(path: &Path) -> Result<LoadedAuthorization, CanaryError> {
    let bytes = std::fs::read(path).map_err(|error| CanaryError::Io {
        path: path.display().to_string(),
        kind: error.kind(),
    })?;
    Ok(LoadedAuthorization {
        authorization: parse(&bytes)?,
        path: path.to_path_buf(),
    })
}

/// Lowercase hex SHA-256 of the currently running executable.
pub fn running_artifact_sha256() -> Result<String, CanaryError> {
    let exe = std::env::current_exe().map_err(|error| CanaryError::Io {
        path: "current_exe".into(),
        kind: error.kind(),
    })?;
    sha256_file(&exe)
}

/// Lowercase hex SHA-256 of a file.
pub fn sha256_file(path: &Path) -> Result<String, CanaryError> {
    use sha2::{Digest as _, Sha256};
    let mut file = std::fs::File::open(path).map_err(|error| CanaryError::Io {
        path: path.display().to_string(),
        kind: error.kind(),
    })?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|error| CanaryError::Io {
        path: path.display().to_string(),
        kind: error.kind(),
    })?;
    Ok(hex::encode(hasher.finalize()))
}

/// Resolve the authorization held at `path`.
///
/// This is the single place where the capability decision is made, and it is
/// a function rather than a branch so that the production behaviour can be
/// tested directly instead of inferred.
///
/// Without the `mainnet-canary` feature it takes no argument it could act on:
/// the path is ignored and the answer is always `None`, so a production binary
/// has no code path that could enable mainnet-beta.
#[cfg(not(feature = "mainnet-canary"))]
pub fn authorization_at(_path: &Path) -> Option<LoadedAuthorization> {
    None
}

/// See the `not(feature)` twin above.
#[cfg(feature = "mainnet-canary")]
pub fn authorization_at(path: &Path) -> Option<LoadedAuthorization> {
    match load_from(path) {
        Ok(loaded) => Some(loaded),
        Err(error) => {
            tracing::error!(%error, "solana.mainnet_canary_authorization_unreadable");
            None
        }
    }
}

/// The authorization in force for this process, if any.
///
/// A production build never reads [`AUTHORIZATION_ENV`], because
/// [`authorization_at`] could not act on it anyway.
pub fn authorization() -> Option<LoadedAuthorization> {
    if !capability_compiled_in() {
        return None;
    }
    let path = std::env::var_os(AUTHORIZATION_ENV)?;
    authorization_at(Path::new(&path))
}

/// Whether this binary was built with the canary capability at all.
pub const fn capability_compiled_in() -> bool {
    cfg!(feature = "mainnet-canary")
}

/// A validated authorization permitting mainnet-beta for `chain`, or `None`.
///
/// Every failure is `None` — an unreadable file, a mismatched artifact, an
/// expired window, a spent ledger — because the caller's correct response to
/// all of them is identical: keep refusing mainnet-beta.
pub fn authorization_for(chain: &str, now_ms: u128) -> Option<LoadedAuthorization> {
    let loaded = authorization()?;
    let artifact = match running_artifact_sha256() {
        Ok(hash) => hash,
        Err(error) => {
            tracing::error!(%error, "solana.mainnet_canary_artifact_hash_failed");
            return None;
        }
    };
    if let Err(error) = loaded.authorization.validate_for(chain, &artifact, now_ms) {
        tracing::error!(%error, chain, "solana.mainnet_canary_authorization_rejected");
        return None;
    }
    if loaded.is_spent() {
        tracing::error!(chain, "solana.mainnet_canary_authorization_already_spent");
        return None;
    }
    Some(loaded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization_fixture() -> CanaryAuthorization {
        let mut auth = CanaryAuthorization {
            schema: AUTHORIZATION_SCHEMA.into(),
            artifact_sha256: "ab".repeat(32),
            chain: "solana-mainnet-canary".into(),
            wallet: "canary".into(),
            key_fingerprint: "cd".repeat(32),
            derivation_path: "m/44'/501'/0'/0'".into(),
            source_address: "SoURCE1111111111111111111111111111111111111".into(),
            destination: "DeST22222222222222222222222222222222222222".into(),
            max_balance_lamports: 2_000_000,
            transfer_lamports: 1_000_000,
            max_fee_lamports: 10_000,
            max_transactions: MAX_TRANSACTIONS,
            expires_ms: 10_000,
            acknowledgement: String::new(),
        };
        auth.acknowledgement = auth.canonical_acknowledgement();
        auth
    }

    #[test]
    fn a_well_formed_authorization_validates_for_its_own_artifact_and_chain() {
        let auth = authorization_fixture();
        auth.validate_for("solana-mainnet-canary", &"ab".repeat(32), 9_999)
            .expect("the fixture must validate");
        // Chain matching is case-insensitive but not fuzzy.
        auth.validate_for("SOLANA-MAINNET-CANARY", &"ab".repeat(32), 0)
            .expect("chain comparison is case-insensitive");
    }

    #[test]
    fn a_boilerplate_acknowledgement_is_refused() {
        let mut auth = authorization_fixture();
        auth.acknowledgement = "yes".into();
        let error = auth.validate_shape().expect_err("'yes' must not authorize");
        assert!(format!("{error}").contains("acknowledgement"), "{error}");
    }

    #[test]
    fn editing_a_bound_value_invalidates_the_acknowledgement_written_for_the_old_one() {
        let mut auth = authorization_fixture();
        // The operator was shown — and signed for — 1_000_000 lamports.
        auth.transfer_lamports = 1_500_000;
        let error = auth
            .validate_shape()
            .expect_err("a re-pointed amount must not keep its old acknowledgement");
        assert!(format!("{error}").contains("acknowledgement"), "{error}");

        let mut auth = authorization_fixture();
        auth.destination = "OtherDestination1111111111111111111111111".into();
        let error = auth
            .validate_shape()
            .expect_err("a re-pointed destination must not keep its old acknowledgement");
        assert!(format!("{error}").contains("acknowledgement"), "{error}");
    }

    #[test]
    fn the_transaction_ceiling_is_exactly_one() {
        for count in [0, 2, 100] {
            let mut auth = authorization_fixture();
            auth.max_transactions = count;
            auth.acknowledgement = auth.canonical_acknowledgement();
            let error = auth.validate_shape().expect_err("only 1 is permitted");
            assert!(format!("{error}").contains("max_transactions"), "{error}");
        }
    }

    #[test]
    fn the_balance_cap_must_actually_bound_the_debit() {
        let mut auth = authorization_fixture();
        auth.max_balance_lamports = auth.transfer_lamports; // no room for the fee
        auth.acknowledgement = auth.canonical_acknowledgement();
        let error = auth
            .validate_shape()
            .expect_err("a cap that cannot cover transfer+fee is not a loss bound");
        assert!(format!("{error}").contains("balance cap"), "{error}");
    }

    #[test]
    fn another_artifact_expired_window_or_other_chain_is_refused() {
        let auth = authorization_fixture();
        let wrong_artifact = auth
            .validate_for("solana-mainnet-canary", &"ff".repeat(32), 0)
            .expect_err("a different binary must not inherit the authorization");
        assert!(format!("{wrong_artifact}").contains("bound to artifact"));

        let expired = auth
            .validate_for("solana-mainnet-canary", &"ab".repeat(32), 10_001)
            .expect_err("an expired authorization is dead");
        assert!(format!("{expired}").contains("expired"));

        let other_chain = auth
            .validate_for("solana-devnet", &"ab".repeat(32), 0)
            .expect_err("an authorization is scoped to one chain");
        assert!(format!("{other_chain}").contains("names chain"));
    }

    #[test]
    fn a_transfer_must_match_every_bound_value() {
        let auth = authorization_fixture();
        let key = "cd".repeat(32);
        let other_key = "ee".repeat(32);
        let source = auth.source_address.clone();
        let destination = auth.destination.clone();
        let ok =
            |w: &str, k: &str, s: &str, d: &str, l, f| auth.authorizes_transfer(w, k, s, d, l, f);
        ok("canary", &key, &source, &destination, 1_000_000, 5_000)
            .expect("the exact authorized transfer must pass");

        assert!(ok("other", &key, &source, &destination, 1_000_000, 5_000).is_err());
        assert!(
            ok(
                "canary",
                &other_key,
                &source,
                &destination,
                1_000_000,
                5_000
            )
            .is_err()
        );
        assert!(ok("canary", &key, "Elsewhere", &destination, 1_000_000, 5_000).is_err());
        assert!(ok("canary", &key, &source, "Elsewhere", 1_000_000, 5_000).is_err());
        // A *smaller* amount is still not the amount that was authorized.
        assert!(ok("canary", &key, &source, &destination, 999_999, 5_000).is_err());
        assert!(ok("canary", &key, &source, &destination, 1_000_000, 10_001).is_err());
    }

    #[test]
    fn the_balance_cap_is_enforced_against_the_funded_account() {
        let auth = authorization_fixture();
        auth.authorizes_balance(2_000_000)
            .expect("at the cap is fine");
        assert!(auth.authorizes_balance(2_000_001).is_err());
    }

    #[test]
    fn the_single_use_ledger_admits_exactly_one_claim() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.json");
        std::fs::write(&path, b"{}").unwrap();
        let loaded = LoadedAuthorization {
            authorization: authorization_fixture(),
            path,
        };
        assert!(!loaded.is_spent());
        loaded
            .claim_single_use("first")
            .expect("the first claim wins");
        assert!(loaded.is_spent());
        let error = loaded
            .claim_single_use("second")
            .expect_err("a second broadcast must be impossible");
        assert!(matches!(error, CanaryError::Spent(_)), "{error:?}");
    }

    #[test]
    fn a_production_build_has_no_canary_capability_at_all() {
        // A perfectly valid authorization, readable, unexpired, on disk.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.json");
        let auth = authorization_fixture();
        std::fs::write(&path, serde_json::to_vec(&auth).unwrap()).unwrap();

        #[cfg(not(feature = "mainnet-canary"))]
        {
            // The default feature set is what ships. If either assertion ever
            // fails, a release build has gained the ability to reach
            // mainnet-beta.
            assert!(!capability_compiled_in());
            assert!(
                authorization_at(&path).is_none(),
                "a production build must refuse a valid authorization file outright"
            );
            assert!(authorization().is_none());
        }
        #[cfg(feature = "mainnet-canary")]
        {
            assert!(capability_compiled_in());
            let loaded =
                authorization_at(&path).expect("the canary build reads a valid authorization");
            assert_eq!(loaded.authorization, auth);
        }
    }

    #[test]
    fn round_trips_through_json() {
        let auth = authorization_fixture();
        let encoded = serde_json::to_vec(&auth).unwrap();
        assert_eq!(parse(&encoded).unwrap(), auth);
        assert!(parse(b"not json").is_err());
    }
}

/// Whether config validation may accept a mainnet-beta chain with broadcast
/// enabled.
///
/// This is the *first* of four gates, and deliberately the weakest: it only
/// asks whether a canary-capable binary holds an authorization naming this
/// chain. Artifact binding, expiry, the single-use ledger, and every per-value
/// cap are re-checked later against live facts, at boot and again immediately
/// before the send. Doing full validation here would tie config loading to a
/// clock and the filesystem for no safety gain — a config that parses still
/// cannot broadcast.
///
/// In a production build this is unconditionally `false`.
pub fn config_permits_mainnet_chain(chain: &str) -> bool {
    match authorization() {
        Some(loaded) => loaded.authorization.chain.eq_ignore_ascii_case(chain),
        None => false,
    }
}
