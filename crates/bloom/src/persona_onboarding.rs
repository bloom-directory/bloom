//! Compile a saved preference into exact public, owner-reviewed session terms.
//! The compiler never activates authority and never treats venue settings as caps.
use anyhow::{Context, Result, bail};
use bloom_broker_api::*;
use bloom_daemon::Daemon;
use bloom_machine_client::PersonaSessionProposal;
use bloom_proto::persona::{PersonaConfig, PersonaPreset};
use sha2::{Digest as _, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const ORDER_CLASS: &str = "polymarket.order.poly1271";
const DAY_MS: u64 = 86_400_000;
const MAX_SIGNATURES: u64 = 4096;

/// Basic onboarding covers account 0 of the explicitly selected existing wallet.
/// Other accounts need explicit reviewed proposals. Broader native scopes require
/// reviewed asset/fee unit caps; price hints are not authority.
pub(crate) async fn compile_proposals(
    daemon: &Daemon,
    wallet: &str,
    account: u32,
) -> Result<Vec<PersonaSessionProposal>> {
    if account != 0 {
        bail!(
            "basic persona activation covers account 0 of the selected wallet; other accounts require explicit reviewed proposals"
        );
    }
    let config = bloom_proto::Config::load(&daemon.home.config_path())?;
    let profile = config.persona.unwrap_or_default();
    if !config.petals.setup.contains_key("polymarket") {
        bail!(
            "Polymarket was not selected during setup; choose its policy scope before proposing a buy session"
        );
    }
    profile.validate().map_err(anyhow::Error::msg)?;
    if profile.preset == PersonaPreset::Custodian {
        bail!("Custodian has no reusable session to activate");
    }
    let broker = daemon.broker_client().context("Broker unavailable")?;
    let wallet_id = Token::new(wallet.to_owned())?;
    let descriptor = broker.wallet(wallet_id.clone()).await?;
    let snapshot = broker.policy(wallet_id.clone()).await?;
    if descriptor.wallet_id != wallet_id || snapshot.wallet_id != wallet_id {
        bail!("Broker wallet or policy projection differs from the selected wallet");
    }
    if snapshot.version != descriptor.policy_version
        || snapshot.policy_digest != descriptor.policy_digest
    {
        bail!("wallet policy changed while compiling; retry activation");
    }
    let policy: CanonicalWalletPolicy =
        serde_json::from_slice(&snapshot.canonical_policy.decode())?;
    if policy.wallet_id != wallet_id {
        bail!("policy wallet differs from selected wallet");
    }
    let duration_ms = profile
        .session_duration_secs
        .checked_mul(1000)
        .context("session duration overflow")?;
    if duration_ms > policy.maximum_approval_lifetime_ms {
        bail!("requested session duration exceeds the signed wallet lifetime ceiling");
    }
    let suite = CryptoSuite::Secp256k1Keccak256Recoverable;
    let key_ref = if let Some(root) = descriptor.root_key_ref.as_ref() {
        if !descriptor.key_refs.contains(root) || root.derivation.is_some() {
            bail!("selected wallet has no unambiguous account 0 owner root");
        }
        let keys = broker.keys(wallet_id.clone()).await?;
        let key = keys
            .iter()
            .find(|key| {
                &key.key_ref == root
                    && key.role == KeyRole::WalletRoot
                    && key.supported_crypto_suites.contains(&suite)
            })
            .context("wallet has no authoritative EVM root signing key")?;
        key.key_ref.clone()
    } else {
        let accounts = broker.wallet_accounts(wallet_id.clone()).await?;
        if accounts.wallet_id != wallet_id {
            bail!("Broker account projection differs from the selected wallet");
        }
        let candidates = accounts
            .accounts
            .iter()
            .filter(|entry| {
                entry.lifecycle == AccountLifecycleState::Active
                    && entry.derivation_profile == DerivationProfile::Bip44EvmSecp256k1V1
                    && entry.path == "m/44'/60'/0'/0/0"
                    && matches!(&entry.key_ref.derivation, Some(DerivationRef::Bip39Multicurve { profile: DerivationProfile::Bip44EvmSecp256k1V1, path, .. }) if path == &entry.path)
                    && entry.supported_crypto_suites.contains(&suite)
                    && descriptor.key_refs.contains(&entry.key_ref)
            })
            .collect::<Vec<_>>();
        let [entry] = candidates.as_slice() else {
            bail!(
                "selected wallet/account 0 has no unique active EVM owner key; choose an existing EVM account before activating"
            );
        };
        entry.validate()?;
        entry.key_ref.clone()
    };
    let installed = daemon.petals.store().resolve_petal_owner("polymarket")?
        .context("install Polymarket before activating its bounded buy session; other classes currently require exact review")?;
    let package_hash = Digest32::new(installed)?;
    if !policy.allowed_petal_packages.contains(&package_hash) {
        bail!(
            "installed Polymarket package is not allowed by the signed policy; complete policy setup before activation"
        );
    }
    let catalog = daemon
        .persona_provenance_catalog()
        .context("installer provenance is unavailable")?;
    let class = Token::new(ORDER_CLASS)?;
    let mut routes = catalog
        .records
        .iter()
        .filter_map(|record| {
            let ProvenanceSubject::Petal {
                package_hash: hash,
                route,
            } = &record.subject
            else {
                return None;
            };
            (hash == &package_hash
                && record
                    .operation_classes
                    .iter()
                    .any(|entry| entry.operation_class == class && entry.fee_asset.is_none()))
            .then_some((route.clone(), record))
        })
        .collect::<Vec<_>>();
    routes.sort_by(|a, b| a.0.cmp(&b.0));
    if routes.is_empty() {
        bail!("installed package has no installer-certified fee-free Polymarket order route");
    }
    let route_grants = routes
        .iter()
        .map(|(route, record)| {
            Ok(PetalRouteGrant {
                route: route.clone(),
                allowed_operation_classes: vec![class.clone()],
                provenance_digest: record.digest()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let primary = &route_grants[0];
    let selector = ApprovalSelector::Petal {
        package_hash: package_hash.clone(),
        route: primary.route.clone(),
        allowed_operation_classes: vec![class],
        route_grants: route_grants.clone(),
        required_claim_assurance: ClaimAssuranceLevel::MachineAsserted,
    };
    let now_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    // Repeated activation resumes the frozen grant, even if exhausted. It must
    // never reset an existing budget simply because its counters were consumed.
    let existing = daemon.persona_sessions(wallet).await?;
    if existing.iter().any(|status| {
        !status.locally_disabled
            && status.account == account
            && status.authority.state == ApprovalLifecycleState::Orphaned
            && status.terms.expires_at_ms.get() > now_ms
    }) {
        bail!(
            "a persona grant was orphaned after restart; inspect `bloom wallet persona status {wallet}`, then explicitly stop it and activate a freshly reviewed session. Retrying activation will not reset its budget"
        );
    }
    if let Some(status) = existing.iter().find(|status| {
        !status.locally_disabled
            && status.account == account
            && status.persona == profile.preset.as_str()
            && status.terms.key_ref == key_ref
            && status.terms.selector == selector
            && status.terms.policy_digest == descriptor.policy_digest
            && status.terms.policy_version == descriptor.policy_version
            && status.terms.wallet_revocation_epoch == descriptor.wallet_revocation_epoch
            && status.terms.expires_at_ms.get() > now_ms
            && matches!(
                status.authority.state,
                ApprovalLifecycleState::Prepared
                    | ApprovalLifecycleState::AwaitingCeremony
                    | ApprovalLifecycleState::Active
                    | ApprovalLifecycleState::Exhausted
            )
            && profile_matches(&status.terms, &profile, &descriptor)
    }) {
        return Ok(vec![proposal(
            profile.preset,
            account,
            status.terms.clone(),
        )?]);
    }
    // Config changes, package replacement and policy changes are reconciled
    // before proposing fresh authority. Local disable persists before revokes.
    if existing.iter().any(|status| !status.locally_disabled) {
        daemon
            .stop_persona_sessions(wallet, "persona scope or profile changed")
            .await?;
    }
    let budget = budget(&descriptor, &key_ref, &profile, now_ms)?;
    let terms = SealedApprovalTerms {
        subject: ApprovalSubject::Petal {
            package_hash,
            route: primary.route.clone(),
            agent_id: None,
        },
        wallet_id,
        key_ref: key_ref.clone(),
        allowed_crypto_suites: vec![suite],
        selector,
        limits: budget.limits.clone(),
        activation_mode: if key_ref.backend.as_str() == "local" {
            ActivationMode::BootBound
        } else {
            ActivationMode::BackendManaged
        },
        wallet_revocation_epoch: descriptor.wallet_revocation_epoch,
        policy_version: descriptor.policy_version,
        policy_digest: descriptor.policy_digest,
        provenance_digest: primary.provenance_digest.clone(),
        request_nonce: RequestNonce::new(hex::encode(
            &Sha256::digest(serde_jcs::to_vec(&budget)?)[..16],
        ))?,
        issued_at_ms: DecimalU64::new(now_ms),
        not_before_ms: budget.not_before_ms.clone(),
        expires_at_ms: budget.expires_at_ms.clone(),
        renewal_of: None,
        session_budget: Some(budget),
    };
    Ok(vec![proposal(profile.preset, account, terms)?])
}

fn budget(
    wallet: &WalletPublic,
    key: &KeyRef,
    profile: &PersonaConfig,
    now: u64,
) -> Result<SessionBudget> {
    let duration = profile
        .session_duration_secs
        .checked_mul(1000)
        .context("duration overflow")?;
    let days = duration
        .checked_add(DAY_MS - 1)
        .context("duration overflow")?
        / DAY_MS;
    let lifetime = profile
        .daily_usd_micros
        .checked_mul(days)
        .context("lifetime budget overflow")?;
    let asset = AssetId {
        chain: Token::new("polygon")?,
        asset: "pusd".into(),
    };
    let per_action = DecimalU256::parse(profile.per_action_usd_micros.to_string())?;
    let windows = vec![ValueWindow {
        maximum: DecimalU256::parse(profile.daily_usd_micros.to_string())?,
        duration_ms: DecimalU64::new(DAY_MS),
    }];
    let limits = ApprovalLimits {
        max_operations: DecimalU64::new(MAX_SIGNATURES),
        max_signatures: DecimalU64::new(MAX_SIGNATURES),
        operation_rate_limits: vec![],
        signature_rate_limits: vec![],
        value_limits: vec![ValueLimit {
            asset: asset.clone(),
            lifetime: DecimalU256::parse(lifetime.to_string())?,
            rolling_windows: windows.clone(),
        }],
    };
    let budget = SessionBudget {
        wallet_id: wallet.wallet_id.clone(),
        policy_version: wallet.policy_version.clone(),
        policy_digest: wallet.policy_digest.clone(),
        wallet_revocation_epoch: wallet.wallet_revocation_epoch.clone(),
        member_keys: vec![key.clone()],
        limits,
        nominal_asset_scales: vec![SessionAssetScale {
            asset: asset.clone(),
            units_per_nominal_unit: DecimalU256::parse("1000000")?,
        }],
        nominal_limits: SessionNominalLimits {
            per_action: per_action.clone(),
            lifetime: DecimalU256::parse(lifetime.to_string())?,
            rolling_windows: windows,
        },
        per_action_value_limits: vec![SessionValueCeiling {
            asset,
            maximum: per_action,
        }],
        not_before_ms: DecimalU64::new(now),
        expires_at_ms: DecimalU64::new(now.checked_add(duration).context("expiry overflow")?),
    };
    budget.validate()?;
    Ok(budget)
}

fn profile_matches(
    terms: &SealedApprovalTerms,
    profile: &PersonaConfig,
    wallet: &WalletPublic,
) -> bool {
    let Some(existing) = &terms.session_budget else {
        return false;
    };
    let Ok(expected) = budget(
        wallet,
        &terms.key_ref,
        profile,
        existing.not_before_ms.get(),
    ) else {
        return false;
    };
    existing == &expected
        && terms.limits == expected.limits
        && terms.allowed_crypto_suites == vec![CryptoSuite::Secp256k1Keccak256Recoverable]
        && terms.not_before_ms == expected.not_before_ms
        && terms.expires_at_ms == expected.expires_at_ms
}

fn proposal(
    preset: PersonaPreset,
    account: u32,
    terms: SealedApprovalTerms,
) -> Result<PersonaSessionProposal> {
    let approval_id = terms.approval_id()?;
    let id = Sha256::digest(
        [
            b"bloom.persona.prepare.v1\0".as_slice(),
            approval_id.as_str().as_bytes(),
        ]
        .concat(),
    );
    let facts = serde_json::json!({ "schema": "bloom.machine.persona-session-facts.v1", "persona": preset.as_str(), "account": account, "terms": &terms });
    Ok(PersonaSessionProposal {
        schema_version: 1,
        persona: preset.as_str().into(),
        account,
        prepare_operation_id: OperationId::from_bytes(id.into()),
        terms,
        canonical_plan_facts_digest: Digest32::from_bytes(
            Sha256::digest(serde_jcs::to_vec(&facts)?).into(),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet() -> (WalletPublic, KeyRef) {
        let key = KeyRef {
            backend: Token::new("local").unwrap(),
            backend_instance: Token::new("local-default").unwrap(),
            locator: "key-1".into(),
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: Digest32::new("11".repeat(32)).unwrap(),
            derivation: None,
        };
        (
            WalletPublic {
                wallet_id: Token::new("main").unwrap(),
                wallet_kind: Token::new("raw").unwrap(),
                root_key_ref: Some(key.clone()),
                key_refs: vec![key.clone()],
                policy_version: DecimalU64::new(2),
                policy_digest: Digest32::new("22".repeat(32)).unwrap(),
                wallet_revocation_epoch: DecimalU64::new(0),
            },
            key,
        )
    }

    #[test]
    fn compiled_degen_budget_has_one_shared_daily_cap_and_conservative_partial_day_lifetime() {
        let (wallet, key) = wallet();
        let mut profile = PersonaConfig::suggested(PersonaPreset::Degen);
        profile.session_duration_secs = 86_401;
        let compiled = budget(&wallet, &key, &profile, 10_000).unwrap();
        assert_eq!(compiled.nominal_limits.lifetime.as_str(), "20000000000");
        assert_eq!(
            compiled.nominal_limits.rolling_windows[0].maximum.as_str(),
            "10000000000"
        );
        let value = SessionAssetAmount {
            asset: compiled.per_action_value_limits[0].asset.clone(),
            amount: DecimalU256::parse("1000000000").unwrap(),
        };
        assert_eq!(
            compiled.action_nominal_quantity(&[value]).unwrap().as_str(),
            "1000000000"
        );
        let shares = SessionAssetAmount {
            asset: AssetId {
                chain: Token::new("polygon").unwrap(),
                asset: "erc1155:ctf:42".into(),
            },
            amount: DecimalU256::parse("1").unwrap(),
        };
        assert!(compiled.action_nominal_quantity(&[shares]).is_err());
    }

    #[test]
    fn compiled_budget_binds_the_selected_existing_wallet_key_and_policy() {
        let (mut selected, mut key) = wallet();
        let profile = PersonaConfig::suggested(PersonaPreset::Trader);
        let main = budget(&selected, &key, &profile, 10_000).unwrap();
        selected.wallet_id = Token::new("existing-wallet").unwrap();
        selected.policy_version = DecimalU64::new(7);
        selected.policy_digest = Digest32::new("44".repeat(32)).unwrap();
        selected.wallet_revocation_epoch = DecimalU64::new(3);
        key.locator = "existing-wallet-root".into();
        key.public_key_fingerprint = Digest32::new("55".repeat(32)).unwrap();
        selected.root_key_ref = Some(key.clone());
        selected.key_refs = vec![key.clone()];
        let compiled = budget(&selected, &key, &profile, 10_000).unwrap();
        assert_eq!(compiled.wallet_id, selected.wallet_id);
        assert_eq!(compiled.policy_version, selected.policy_version);
        assert_eq!(compiled.policy_digest, selected.policy_digest);
        assert_eq!(
            compiled.wallet_revocation_epoch,
            selected.wallet_revocation_epoch
        );
        assert_eq!(compiled.member_keys, vec![key]);
        assert_ne!(compiled.budget_id().unwrap(), main.budget_id().unwrap());
    }

    #[test]
    fn compiled_budget_rejects_overflow_and_custodian_cannot_compile() {
        let (wallet, key) = wallet();
        let mut profile = PersonaConfig::suggested(PersonaPreset::Trader);
        profile.session_duration_secs = u64::MAX;
        assert!(budget(&wallet, &key, &profile, 10_000).is_err());
        assert!(budget(&wallet, &key, &PersonaConfig::default(), 10_000).is_err());
    }
}
