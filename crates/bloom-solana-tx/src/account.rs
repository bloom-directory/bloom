//! Choosing which derived account to transact with.
//!
//! A BIP-39 wallet can hold several active children for the same derivation
//! profile. `wallet_id` plus profile therefore does not name a key, and the
//! projection's ordering is not a selection criterion: it is not stable, not
//! user-visible, and not bound to anything the user approved. Selecting by
//! order would let a transfer spend from an account nobody chose.
//!
//! Accounts are named by public-key fingerprint, which is what
//! `SealedApprovalTerms::key_ref` and `SignOperationIdentity::key_ref` already
//! bind, so the value a user names is the value the approval commits to.

use bloom_broker_api::{AccountLifecycleState, DerivationProfile, DerivedAccountPublic};

/// Why a derived account could not be chosen.
///
/// Every variant names the accounts that were available, because an error that
/// only reports "ambiguous" gives the caller no way to proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountSelectionError {
    /// The wallet has no active account for the profile.
    None { wallet: String, candidates: String },
    /// No active account matches the given fingerprint.
    NoMatch {
        wallet: String,
        selector: String,
        candidates: String,
    },
    /// The fingerprint prefix matches more than one active account.
    AmbiguousSelector {
        wallet: String,
        selector: String,
        candidates: String,
    },
    /// Several accounts are active and none was named.
    AmbiguousWallet {
        wallet: String,
        count: usize,
        candidates: String,
    },
}

impl std::fmt::Display for AccountSelectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None { wallet, .. } => {
                write!(formatter, "wallet '{wallet}' has no active derived account")
            }
            Self::NoMatch {
                wallet,
                selector,
                candidates,
            } => write!(
                formatter,
                "wallet '{wallet}' has no active account whose fingerprint starts with \
                 '{selector}'; active accounts: {candidates}"
            ),
            Self::AmbiguousSelector {
                wallet,
                selector,
                candidates,
            } => write!(
                formatter,
                "fingerprint '{selector}' is ambiguous for wallet '{wallet}'; active accounts: \
                 {candidates}"
            ),
            Self::AmbiguousWallet {
                wallet,
                count,
                candidates,
            } => write!(
                formatter,
                "wallet '{wallet}' has {count} active accounts; name one by fingerprint. Active \
                 accounts: {candidates}"
            ),
        }
    }
}

impl std::error::Error for AccountSelectionError {}

/// Name every candidate by the fingerprint that selects it and the derivation
/// path that identifies it to a human.
pub fn describe(accounts: &[&DerivedAccountPublic]) -> String {
    accounts
        .iter()
        .map(|account| {
            format!(
                "{} ({})",
                account.key_ref.public_key_fingerprint.as_str(),
                account.path,
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The wallet's active accounts for `profile`, in projection order.
///
/// Order is presentational. Callers must not treat the first element as a
/// default.
pub fn active_accounts(
    accounts: &[DerivedAccountPublic],
    profile: DerivationProfile,
) -> Vec<&DerivedAccountPublic> {
    accounts
        .iter()
        .filter(|account| {
            account.derivation_profile == profile
                && account.lifecycle == AccountLifecycleState::Active
        })
        .collect()
}

/// Choose exactly one active account.
///
/// `selector` is a public-key fingerprint or a unique prefix of one, compared
/// case-insensitively. Omitting it is valid only when a single active account
/// exists; with several, selection fails rather than guessing.
pub fn select<'a>(
    wallet: &str,
    active: &[&'a DerivedAccountPublic],
    selector: Option<&str>,
) -> Result<&'a DerivedAccountPublic, AccountSelectionError> {
    let candidates = describe(active);
    match selector {
        Some(selector) => {
            let selector = selector.trim().to_ascii_lowercase();
            let mut matched = active.iter().filter(|account| {
                account
                    .key_ref
                    .public_key_fingerprint
                    .as_str()
                    .starts_with(&selector)
            });
            let first = *matched
                .next()
                .ok_or_else(|| AccountSelectionError::NoMatch {
                    wallet: wallet.to_owned(),
                    selector: selector.clone(),
                    candidates: candidates.clone(),
                })?;
            if matched.next().is_some() {
                return Err(AccountSelectionError::AmbiguousSelector {
                    wallet: wallet.to_owned(),
                    selector,
                    candidates,
                });
            }
            Ok(first)
        }
        None => match active {
            [only] => Ok(only),
            [] => Err(AccountSelectionError::None {
                wallet: wallet.to_owned(),
                candidates,
            }),
            _ => Err(AccountSelectionError::AmbiguousWallet {
                wallet: wallet.to_owned(),
                count: active.len(),
                candidates,
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_broker_api::{
        Base64UrlBytes, CryptoSuite, Digest32, KeyRef, KeySpec, PublicKeyEncoding, Token,
        WalletSeedProfile,
    };

    fn account(
        account_number: u32,
        fingerprint: &str,
        lifecycle: AccountLifecycleState,
    ) -> DerivedAccountPublic {
        DerivedAccountPublic {
            key_ref: KeyRef {
                backend: Token::new("local").unwrap(),
                backend_instance: Token::new("primary").unwrap(),
                locator: format!("wallet/derived/{account_number}"),
                key_spec: KeySpec::Ed25519,
                public_key_fingerprint: Digest32::new(fingerprint.to_owned()).unwrap(),
                derivation: None,
            },
            wallet_seed_profile: WalletSeedProfile::Bip39MulticurveV1,
            derivation_profile: DerivationProfile::Bip44SolanaSlip10Ed25519V1,
            path: format!("m/44'/501'/{account_number}'/0'"),
            canonical_public_key: Base64UrlBytes::from_bytes(&[account_number as u8; 44]),
            public_key_encoding: PublicKeyEncoding::Ed25519SpkiDer,
            public_key_fingerprint: Digest32::new(fingerprint.to_owned()).unwrap(),
            supported_crypto_suites: vec![CryptoSuite::Ed25519Message],
            chain_projections: Vec::new(),
            lifecycle,
        }
    }

    fn fingerprint(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    #[test]
    fn two_active_children_can_each_be_selected_independently() {
        let zero = account(0, &fingerprint(0xa1), AccountLifecycleState::Active);
        let one = account(1, &fingerprint(0xb2), AccountLifecycleState::Active);
        let active = vec![&zero, &one];

        // Account 1 is selectable without retiring account 0, which is the
        // usability gap the previous first-match behaviour left open.
        let chosen = select("w", &active, Some(&fingerprint(0xb2))).unwrap();
        assert_eq!(chosen.path, "m/44'/501'/1'/0'");
        let chosen = select("w", &active, Some(&fingerprint(0xa1))).unwrap();
        assert_eq!(chosen.path, "m/44'/501'/0'/0'");
    }

    #[test]
    fn a_unique_prefix_selects_and_a_shared_one_refuses() {
        let zero = account(0, &fingerprint(0xa1), AccountLifecycleState::Active);
        let one = account(1, &fingerprint(0xb2), AccountLifecycleState::Active);
        let active = vec![&zero, &one];

        assert_eq!(
            select("w", &active, Some("a1a1")).unwrap().path,
            "m/44'/501'/0'/0'"
        );
        // Case is not part of the identity.
        assert_eq!(
            select("w", &active, Some("A1A1")).unwrap().path,
            "m/44'/501'/0'/0'"
        );

        // The empty prefix matches everything, so it must not resolve to the
        // first account.
        let error = select("w", &active, Some("")).unwrap_err();
        assert!(
            matches!(error, AccountSelectionError::AmbiguousSelector { .. }),
            "{error:?}"
        );
        assert!(error.to_string().contains(&fingerprint(0xa1)));
        assert!(error.to_string().contains(&fingerprint(0xb2)));
    }

    #[test]
    fn omitting_the_selector_with_two_active_children_fails_and_names_both() {
        let zero = account(0, &fingerprint(0xa1), AccountLifecycleState::Active);
        let one = account(1, &fingerprint(0xb2), AccountLifecycleState::Active);
        let error = select("w", &[&zero, &one], None).unwrap_err();

        assert!(
            matches!(
                error,
                AccountSelectionError::AmbiguousWallet { count: 2, .. }
            ),
            "{error:?}"
        );
        let message = error.to_string();
        assert!(message.contains(&fingerprint(0xa1)), "{message}");
        assert!(message.contains(&fingerprint(0xb2)), "{message}");
        assert!(message.contains("m/44'/501'/0'/0'"), "{message}");
        assert!(message.contains("m/44'/501'/1'/0'"), "{message}");
    }

    #[test]
    fn a_single_active_child_still_resolves_without_a_selector() {
        let only = account(0, &fingerprint(0xa1), AccountLifecycleState::Active);
        assert_eq!(
            select("w", &[&only], None).unwrap().path,
            "m/44'/501'/0'/0'"
        );
    }

    #[test]
    fn a_retired_child_is_neither_active_nor_selectable() {
        let accounts = vec![
            account(0, &fingerprint(0xa1), AccountLifecycleState::Retired),
            account(1, &fingerprint(0xb2), AccountLifecycleState::Active),
        ];
        let active = active_accounts(&accounts, DerivationProfile::Bip44SolanaSlip10Ed25519V1);
        assert_eq!(active.len(), 1);

        // Retiring account 0 leaves account 1 unambiguous...
        assert_eq!(select("w", &active, None).unwrap().path, "m/44'/501'/1'/0'");
        // ...and account 0 can no longer be named.
        let error = select("w", &active, Some(&fingerprint(0xa1))).unwrap_err();
        assert!(
            matches!(error, AccountSelectionError::NoMatch { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn a_foreign_fingerprint_is_refused_and_names_the_real_children() {
        let zero = account(0, &fingerprint(0xa1), AccountLifecycleState::Active);
        let error = select("w", &[&zero], Some(&fingerprint(0xc3))).unwrap_err();
        assert!(
            matches!(error, AccountSelectionError::NoMatch { .. }),
            "{error:?}"
        );
        assert!(error.to_string().contains(&fingerprint(0xa1)));
    }

    #[test]
    fn a_different_profile_is_never_an_active_solana_candidate() {
        let mut evm = account(0, &fingerprint(0xa1), AccountLifecycleState::Active);
        evm.derivation_profile = DerivationProfile::Bip44EvmSecp256k1V1;
        let solana = account(1, &fingerprint(0xb2), AccountLifecycleState::Active);
        let accounts = vec![evm, solana];

        let active = active_accounts(&accounts, DerivationProfile::Bip44SolanaSlip10Ed25519V1);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].path, "m/44'/501'/1'/0'");

        // EVM keeps its own single-account behaviour, unchanged.
        let evm_active = active_accounts(&accounts, DerivationProfile::Bip44EvmSecp256k1V1);
        assert_eq!(evm_active.len(), 1);
        assert!(select("w", &evm_active, None).is_ok());
    }
}
