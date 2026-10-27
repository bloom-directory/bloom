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
const U256_MAX: &str =
    "115792089237316195423570985008687907853269984665640564039457584007913129639935";

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
        bail!("Institutional has no reusable session to activate");
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
    compile_selection(
        daemon,
        wallet,
        PersonaSessionSelection {
            token_allowances: vec![],
            assets: vec![AssetId {
                chain: Token::new("evm-137")?,
                asset: "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb".into(),
            }],
            members: vec![PersonaSessionMember {
                account,
                key_ref,
                subject: ApprovalSubject::Petal {
                    package_hash,
                    route: primary.route.clone(),
                    agent_id: None,
                },
                selector,
                provenance_digest: primary.provenance_digest.clone(),
                allowed_crypto_suites: vec![suite],
            }],
        },
    )
    .await
}

/// Compile explicit native/Petal selections into independent token allowances.
/// Each exact deployment uses raw units; no price enters authority.
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
        bail!("Institutional retains individual owner approval");
    }
    if selection.members.is_empty()
        || selection.members.len() > 128
        || selection.assets.is_empty()
        || selection.assets.len() > 128
    {
        bail!("select 1–128 members and tokens");
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
    if policy.maximum_approval_lifetime_ms != STANDING_APPROVAL_POLICY_LIFETIME_MS {
        bail!(
            "wallet policy does not permit standing token allowances; review the updated policy first"
        );
    }
    let expiry = u64::MAX;
    let assets = selection
        .assets
        .iter()
        .map(|a| {
            approved_session_asset(a).context("token identity has no reviewed display metadata")
        })
        .collect::<Result<Vec<_>>>()?;
    if selection.token_allowances.iter().enumerate().any(|(i, v)| {
        !selection.assets.contains(&v.asset)
            || selection.token_allowances[..i]
                .iter()
                .any(|x| x.asset == v.asset)
    }) {
        bail!("explicit token allowances must name unique selected assets");
    }
    let token_limits = assets.iter().map(|asset| {
        let (action,rolling)=if let Some(explicit)=selection.token_allowances.iter().find(|v|v.asset==asset.asset) {
            (explicit.per_action.clone(),explicit.per_window.clone())
        } else {
            let (action,rolling)=profile.token_amounts(&asset.symbol).context("token needs an explicit raw-unit allowance; native gas is never inferred from token prices")?;
            (token_units(action,asset.decimals)?,token_units(rolling,asset.decimals)?)
        };
        use std::str::FromStr;
        if action.as_str()=="0" || rolling.as_str()=="0" || num_bigint::BigUint::from_str(action.as_str())? > num_bigint::BigUint::from_str(rolling.as_str())? {bail!("token allowance must be positive and per-action must not exceed rolling capacity");}
        Ok((SessionValueCeiling {asset:asset.asset.clone(),maximum:action},ValueLimit {asset:asset.asset.clone(),lifetime:DecimalU256::parse(U256_MAX)?,rolling_windows:vec![ValueWindow {maximum:rolling,duration_ms:DecimalU64::new(profile.window_secs*1000)}]}))
    }).collect::<Result<Vec<_>>>()?;
    let caps = token_limits
        .iter()
        .map(|(a, _)| a.clone())
        .collect::<Vec<_>>();
    // Activation retries resume the complete frozen pool, including exhausted
    // members; retrying must never manufacture replacement authority.
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
                            b.token_policy.as_ref().is_some_and(|p| {
                                p.assets.len() == selection.assets.len()
                                    && p.assets.iter().all(|a| selection.assets.contains(&a.asset))
                            }) && b.per_action_value_limits == caps
                                && b.limits.value_limits
                                    == token_limits
                                        .iter()
                                        .map(|(_, v)| v.clone())
                                        .collect::<Vec<_>>()
                                && b.expires_at_ms.get() == u64::MAX
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
            "a different session is retained; stop it before reviewing changed members or tokens"
        );
    }
    let limits = ApprovalLimits {
        max_operations: DecimalU64::new(u64::MAX),
        max_signatures: DecimalU64::new(u64::MAX),
        operation_rate_limits: vec![SlidingWindow {
            duration_ms: DecimalU64::new(60_000),
            maximum: DecimalU64::new(120),
        }],
        signature_rate_limits: vec![SlidingWindow {
            duration_ms: DecimalU64::new(60_000),
            maximum: DecimalU64::new(512),
        }],
        value_limits: vec![],
    };
    // A single Petal/account owns each independent allowance. All its reviewed
    // routes share that allowance; duplicate members cannot multiply it.
    for (index, member) in selection.members.iter().enumerate() {
        if selection.members[..index].iter().any(|other| {
            other.key_ref == member.key_ref
                && match (&other.subject, &member.subject) {
                    (
                        ApprovalSubject::Petal {
                            package_hash: a, ..
                        },
                        ApprovalSubject::Petal {
                            package_hash: b, ..
                        },
                    ) => a == b,
                    (
                        ApprovalSubject::System {
                            component_id: a, ..
                        },
                        ApprovalSubject::System {
                            component_id: b, ..
                        },
                    ) => a == b,
                    _ => false,
                }
        }) {
            bail!("combine routes into one allowance per Petal and account");
        }
    }
    let mut templates = Vec::new();
    for member in selection.members {
        if !descriptor.key_refs.contains(&member.key_ref)
            || matches!(member.selector, ApprovalSelector::Exact { .. })
        {
            bail!("member must select an existing exact key and reusable scope");
        }
        let mut selector = member.selector;
        if let ApprovalSelector::SystemSession { scope } = &mut selector {
            // Reviewed recipients come from explicit selection. Raw caps use
            // the selected token quantities and are immutable after approval.
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
                ActivationMode::DurableLocal {
                    provider_tier: Token::new("local-passkey")?,
                    maximum_rearm_until_ms: DecimalU64::new(u64::MAX),
                }
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
    let proposals = templates
        .into_iter()
        .map(|(account, mut terms)| {
            let scope = session_member_scope_digest(&terms)?;
            let mut budget = SessionBudget {
                token_policy: Some(SessionTokenPolicy {
                    schema_version: 3,
                    budget_nonce: RequestNonce::from_bytes(rand::random()),
                    member_scope_digests: vec![scope.clone()],
                    member_templates: vec![terms.clone()],
                    member_backstop_allocations: vec![SessionMemberAllocation {
                        scope_digest: scope,
                        limits: terms.limits.clone(),
                    }],
                    assets: assets.clone(),
                }),
                wallet_id: wallet_id.clone(),
                policy_version: descriptor.policy_version.clone(),
                policy_digest: descriptor.policy_digest.clone(),
                wallet_revocation_epoch: descriptor.wallet_revocation_epoch.clone(),
                member_keys: vec![terms.key_ref.clone()],
                limits: terms.limits.clone(),
                per_action_value_limits: caps.clone(),
                not_before_ms: DecimalU64::new(now),
                expires_at_ms: DecimalU64::new(expiry),
            };
            budget.limits.value_limits = token_limits.iter().map(|(_, v)| v.clone()).collect();
            budget.validate()?;
            terms.session_budget = Some(budget);
            terms.validate()?;
            proposal(profile.preset, account, terms)
        })
        .collect::<Result<Vec<_>>>()?;
    broker.stage_persona_sessions(&proposals).await?;
    Ok(proposals)
}

fn token_units(value: &str, decimals: u8) -> Result<DecimalU256> {
    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or("");
    let fraction = parts.next().unwrap_or("");
    if whole.is_empty()
        || parts.next().is_some()
        || fraction.len() > decimals as usize
        || decimals > 77
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
    {
        bail!("invalid token amount precision");
    }
    let raw = format!(
        "{whole}{fraction}{}",
        "0".repeat(decimals as usize - fraction.len())
    );
    let raw = raw.trim_start_matches('0');
    if raw.is_empty() {
        bail!("token allowance must be positive");
    }
    Ok(DecimalU256::parse(raw)?)
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
    fn exact_token_amounts_never_use_market_prices() {
        assert_eq!(token_units("100", 6).unwrap().as_str(), "100000000");
        assert_eq!(
            token_units("0.025", 18).unwrap().as_str(),
            "25000000000000000"
        );
        for value in ["0", "NaN", "1e3", "-1", "0.0000001"] {
            assert!(token_units(value, 6).is_err());
        }
    }
}
