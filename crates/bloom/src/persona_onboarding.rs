//! Compile a saved preference into exact public, owner-reviewed session terms.
//! The compiler never activates authority and never treats venue settings as caps.
use anyhow::{Context, Result, bail};
use bloom_broker_api::*;
use bloom_daemon::Daemon;
use bloom_machine_client::{PersonaSessionMember, PersonaSessionProposal, PersonaSessionSelection};
use bloom_proto::persona::PersonaPreset;
use sha2::{Digest as _, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const ORDER_CLASS: &str = "polymarket.order.poly1271";
const DAY_MS: u64 = 86_400_000;
const MAX_SIGNATURES: u64 = 4096;

/// Convenience selection for the first reference Petal on an explicit account.
/// Arbitrary certified Petal/native selections use compile_selection below.
pub(crate) async fn compile_proposals(
    daemon: &Daemon,
    wallet: &str,
    account: u32,
) -> Result<Vec<PersonaSessionProposal>> {
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
        if account != 0 || !descriptor.key_refs.contains(root) || root.derivation.is_some() {
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
                    && entry.path == format!("m/44'/60'/{account}'/0/0")
                    && matches!(&entry.key_ref.derivation, Some(DerivationRef::Bip39Multicurve { profile: DerivationProfile::Bip44EvmSecp256k1V1, path, .. }) if path == &entry.path)
                    && entry.supported_crypto_suites.contains(&suite)
                    && descriptor.key_refs.contains(&entry.key_ref)
            })
            .collect::<Vec<_>>();
        let [entry] = candidates.as_slice() else {
            bail!(
                "selected wallet/account has no unique active EVM owner key; choose an existing EVM account before activating"
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
                && record.operation_classes.iter().any(|entry| {
                    entry.operation_class == class
                        && entry.fee_asset.is_none()
                        && entry.economic_effects_schema == Some(1)
                }))
            .then_some((route.clone(), record))
        })
        .collect::<Vec<_>>();
    routes.sort_by(|a, b| a.0.cmp(&b.0));
    if routes.is_empty() {
        bail!(
            "installed package lacks an installer-certified generic effects v1 BUY route; existing owner approval remains available"
        );
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
        limits: ApprovalLimits {
            max_operations: DecimalU64::new(MAX_SIGNATURES),
            max_signatures: DecimalU64::new(MAX_SIGNATURES),
            operation_rate_limits: vec![],
            signature_rate_limits: vec![],
            value_limits: vec![],
        },
        activation_mode: if key_ref.backend.as_str() == "local" {
            ActivationMode::BootBound
        } else {
            ActivationMode::BackendManaged
        },
        wallet_revocation_epoch: descriptor.wallet_revocation_epoch,
        policy_version: descriptor.policy_version,
        policy_digest: descriptor.policy_digest,
        provenance_digest: primary.provenance_digest.clone(),
        request_nonce: RequestNonce::from_bytes(rand::random()),
        issued_at_ms: DecimalU64::new(now_ms),
        not_before_ms: DecimalU64::new(now_ms),
        expires_at_ms: DecimalU64::new(now_ms.checked_add(duration_ms).context("expiry overflow")?),
        renewal_of: None,
        session_budget: None,
    };
    compile_selection(
        daemon,
        wallet,
        PersonaSessionSelection {
            assets: vec![AssetId {
                chain: Token::new("evm-137")?,
                asset: "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb".into(),
            }],
            members: vec![PersonaSessionMember {
                account,
                key_ref: terms.key_ref,
                subject: terms.subject,
                selector: terms.selector,
                provenance_digest: terms.provenance_digest,
                allowed_crypto_suites: terms.allowed_crypto_suites,
            }],
        },
    )
    .await
}

/// Compile an explicitly selected set of native/Petal members into one reviewed
/// pool. Quotes are Broker observations; no Petal or Machine price is accepted.
pub(crate) async fn compile_selection(
    daemon: &Daemon,
    wallet: &str,
    selection: PersonaSessionSelection,
) -> Result<Vec<PersonaSessionProposal>> {
    let profile = bloom_proto::Config::load(&daemon.home.config_path())?
        .persona
        .unwrap_or_default();
    profile.validate().map_err(anyhow::Error::msg)?;
    if profile.preset == PersonaPreset::Custodian {
        bail!("Custodian retains individual owner approval");
    }
    if selection.members.is_empty()
        || selection.members.len() > 128
        || selection.assets.is_empty()
        || selection.assets.len() > 128
    {
        bail!("select 1–128 members and priced assets");
    }
    let broker = daemon.broker_client().context("Broker unavailable")?;
    let wallet_id = Token::new(wallet)?;
    let descriptor = broker.wallet(wallet_id.clone()).await?;
    let snapshot = broker.policy(wallet_id.clone()).await?;
    if snapshot.policy_digest != descriptor.policy_digest
        || snapshot.version != descriptor.policy_version
    {
        bail!("wallet policy changed while compiling session");
    }
    let policy: CanonicalWalletPolicy =
        serde_json::from_slice(&snapshot.canonical_policy.decode())?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let duration = profile
        .session_duration_secs
        .checked_mul(1000)
        .context("session duration overflow")?;
    if duration > policy.maximum_approval_lifetime_ms {
        bail!("session exceeds wallet approval lifetime");
    }
    let expiry = now
        .checked_add(duration)
        .context("session expiry overflow")?;
    let count = u64::try_from(selection.members.len())?;
    let allocation = MAX_SIGNATURES / count;
    if allocation < 2 {
        bail!("too many session members for structural backstops");
    }
    // Activation retries resume the complete frozen pool, including exhausted
    // members; quoting again must never manufacture replacement authority.
    let existing = daemon.persona_sessions(wallet).await?;
    let active = existing
        .iter()
        .filter(|s| !s.locally_disabled && s.terms.expires_at_ms.get() > now)
        .collect::<Vec<_>>();
    if active
        .iter()
        .any(|s| s.authority.state == ApprovalLifecycleState::Orphaned)
    {
        bail!(
            "retained session was orphaned; inspect status and explicitly stop before reviewing replacement authority"
        );
    }
    if !active.is_empty() {
        let matches = active.len() == selection.members.len()
            && selection.members.iter().all(|m| {
                active.iter().any(|s| {
                    s.account == m.account
                        && s.terms.key_ref == m.key_ref
                        && s.terms.subject == m.subject
                        && selection_scope_matches(&s.terms.selector, &m.selector)
                        && s.terms.allowed_crypto_suites == m.allowed_crypto_suites
                        && s.terms.provenance_digest == m.provenance_digest
                        && s.terms.policy_digest == descriptor.policy_digest
                        && s.persona == profile.preset.as_str()
                        && s.terms.session_budget.as_ref().is_some_and(|b| {
                            b.usd_policy.as_ref().is_some_and(|p| {
                                p.assets.len() == selection.assets.len()
                                    && p.assets.iter().all(|a| selection.assets.contains(&a.asset))
                            }) && b.nominal_limits.per_action.as_str()
                                == profile.per_action_usd_micros.to_string()
                                && b.nominal_limits.rolling_windows.iter().any(|w| {
                                    w.duration_ms.get() == DAY_MS
                                        && w.maximum.as_str()
                                            == profile.daily_usd_micros.to_string()
                                })
                                && b.expires_at_ms.get().checked_sub(b.not_before_ms.get())
                                    == Some(duration)
                        })
                })
            });
        if matches {
            return active
                .iter()
                .map(|s| proposal(profile.preset, s.account, s.terms.clone()))
                .collect();
        }
        bail!(
            "a different session is retained; stop it before reviewing changed members, assets or pricing"
        );
    }
    let pricing = broker.session_prices(selection.assets.clone()).await?;
    let caps = pricing
        .assets
        .iter()
        .map(|asset| {
            let quote = pricing
                .quotes
                .iter()
                .find(|q| q.asset == asset.asset)
                .context("Broker omitted review quote")?;
            Ok(SessionValueCeiling {
                asset: asset.asset.clone(),
                maximum: raw_cap(
                    profile.per_action_usd_micros,
                    asset.decimals,
                    &quote.price_usd,
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let lifetime = profile
        .daily_usd_micros
        .checked_mul(
            duration
                .checked_add(DAY_MS - 1)
                .context("duration overflow")?
                / DAY_MS,
        )
        .context("lifetime USD overflow")?;
    let limits = ApprovalLimits {
        max_operations: DecimalU64::new(allocation),
        max_signatures: DecimalU64::new(allocation),
        operation_rate_limits: vec![],
        signature_rate_limits: vec![],
        value_limits: vec![],
    };
    let mut templates = Vec::new();
    for member in selection.members {
        if !descriptor.key_refs.contains(&member.key_ref)
            || matches!(member.selector, ApprovalSelector::Exact { .. })
        {
            bail!("member must select an existing exact key and reusable scope");
        }
        let mut selector = member.selector;
        if let ApprovalSelector::SystemSession { scope } = &mut selector {
            // Reviewed recipients come from explicit selection. Suggested raw
            // caps use the review price once and are immutable afterwards.
            if scope.per_action_value_limits.is_empty() {
                scope.per_action_value_limits = caps
                    .iter()
                    .filter(|c| {
                        scope
                            .chains
                            .iter()
                            .any(|chain| chain.chain() == &c.asset.chain)
                    })
                    .cloned()
                    .collect();
            }
            scope.validate()?;
        }
        let terms = SealedApprovalTerms {
            session_budget: None,
            subject: member.subject,
            wallet_id: wallet_id.clone(),
            key_ref: member.key_ref.clone(),
            allowed_crypto_suites: member.allowed_crypto_suites,
            selector,
            limits: limits.clone(),
            activation_mode: if member.key_ref.backend.as_str() == "local" {
                ActivationMode::BootBound
            } else {
                ActivationMode::BackendManaged
            },
            wallet_revocation_epoch: descriptor.wallet_revocation_epoch.clone(),
            policy_version: descriptor.policy_version.clone(),
            policy_digest: descriptor.policy_digest.clone(),
            provenance_digest: member.provenance_digest,
            request_nonce: RequestNonce::from_bytes(rand::random()),
            issued_at_ms: DecimalU64::new(now),
            not_before_ms: DecimalU64::new(now),
            expires_at_ms: DecimalU64::new(expiry),
            renewal_of: None,
        };
        templates.push((member.account, terms));
    }
    let mut member_templates = templates
        .iter()
        .map(|(_, terms)| terms.clone())
        .collect::<Vec<_>>();
    member_templates.sort_by_key(|terms| {
        session_member_scope_digest(terms)
            .expect("validated serializable terms")
            .as_str()
            .to_owned()
    });
    let mut allocations = templates
        .iter()
        .map(|(_, t)| {
            Ok(SessionMemberAllocation {
                scope_digest: session_member_scope_digest(t)?,
                limits: t.limits.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    allocations.sort_by(|a, b| a.scope_digest.as_str().cmp(b.scope_digest.as_str()));
    let mut keys = templates
        .iter()
        .map(|(_, t)| t.key_ref.clone())
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| serde_jcs::to_vec(key).unwrap_or_default());
    keys.dedup();
    let mut pool_limits = limits;
    pool_limits.max_operations = DecimalU64::new(allocation * count);
    pool_limits.max_signatures = DecimalU64::new(allocation * count);
    let budget = SessionBudget {
        usd_policy: Some(SessionUsdPolicy {
            schema_version: 2,
            budget_nonce: RequestNonce::from_bytes(rand::random()),
            member_scope_digests: allocations.iter().map(|a| a.scope_digest.clone()).collect(),
            member_backstop_allocations: allocations,
            member_templates,
            assets: pricing.assets,
            pricing_policy_digest: session_pricing_policy_digest(),
        }),
        wallet_id,
        policy_version: descriptor.policy_version,
        policy_digest: descriptor.policy_digest,
        wallet_revocation_epoch: descriptor.wallet_revocation_epoch,
        member_keys: keys,
        limits: pool_limits,
        nominal_asset_scales: vec![],
        nominal_limits: SessionNominalLimits {
            per_action: DecimalU256::parse(profile.per_action_usd_micros.to_string())?,
            lifetime: DecimalU256::parse(lifetime.to_string())?,
            rolling_windows: vec![ValueWindow {
                maximum: DecimalU256::parse(profile.daily_usd_micros.to_string())?,
                duration_ms: DecimalU64::new(DAY_MS),
            }],
        },
        per_action_value_limits: caps,
        not_before_ms: DecimalU64::new(now),
        expires_at_ms: DecimalU64::new(expiry),
    };
    budget.validate()?;
    let proposals = templates
        .into_iter()
        .map(|(account, mut terms)| {
            terms.session_budget = Some(budget.clone());
            terms.validate()?;
            proposal(profile.preset, account, terms)
        })
        .collect::<Result<Vec<_>>>()?;
    broker.stage_persona_sessions(&proposals).await?;
    Ok(proposals)
}

fn selection_scope_matches(stored: &ApprovalSelector, selected: &ApprovalSelector) -> bool {
    match (stored, selected) {
        (
            ApprovalSelector::SystemSession { scope: a },
            ApprovalSelector::SystemSession { scope: b },
        ) if b.per_action_value_limits.is_empty() => {
            let mut a = a.clone();
            a.per_action_value_limits.clear();
            a == *b
        }
        _ => stored == selected,
    }
}

fn raw_cap(microdollars: u64, decimals: u8, price: &str) -> Result<DecimalU256> {
    // Invert the review quote exactly; round down so the suggested cap cannot
    // exceed the reviewed per-action USD amount through rounding.
    use num_bigint::BigUint;
    let mut p = price.split('.');
    let whole = p.next().unwrap_or("");
    let fraction = p.next().unwrap_or("");
    if p.next().is_some()
        || whole.is_empty()
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
        || fraction.len() > 36
        || decimals > 77
    {
        bail!("invalid Broker review price");
    }
    let price: BigUint = format!("{whole}{fraction}").parse()?;
    if price == BigUint::from(0u8) {
        bail!("zero Broker review price");
    }
    let raw = BigUint::from(microdollars)
        * BigUint::from(10u8).pow(decimals as u32 + fraction.len() as u32)
        / (price * BigUint::from(1_000_000u64));
    if raw == BigUint::from(0u8) {
        bail!("USD limit cannot fund one raw asset unit");
    }
    Ok(DecimalU256::parse(raw.to_string())?)
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
    #[test]
    fn operator_selection_example_is_the_current_typed_contract() {
        let selection: PersonaSessionSelection = serde_json::from_str(include_str!(
            "../../../docs/examples/generic-session-selection.json"
        ))
        .unwrap();
        assert_eq!(selection.members.len(), 2);
        assert_eq!(selection.assets.len(), 4);
        assert!(matches!(
            selection.members[0].selector,
            ApprovalSelector::SystemSession { .. }
        ));
        assert!(matches!(
            selection.members[1].selector,
            ApprovalSelector::Petal { .. }
        ));
    }

    #[test]
    fn fixed_raw_caps_use_review_price_and_round_down() {
        assert_eq!(
            raw_cap(100_000_000, 6, "0.999417").unwrap().as_str(),
            "100058334"
        );
        assert_eq!(raw_cap(1_000_000, 9, "3").unwrap().as_str(), "333333333");
        assert!(raw_cap(1, 0, "10").is_err());
        assert!(raw_cap(1_000_000, 6, "0").is_err());
        assert!(raw_cap(1_000_000, 6, "NaN").is_err());
        assert!(raw_cap(1_000_000, 6, "1e3").is_err());
    }
}
