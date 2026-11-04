//! Compile a saved preference into exact public, owner-reviewed session terms.
//! The compiler never activates authority and never treats venue settings as caps.
use anyhow::{Context, Result, bail};
use bloom_broker_api::*;
use bloom_daemon::Daemon;
use bloom_machine_client::{PersonaSessionMember, PersonaSessionProposal, PersonaSessionSelection};
use bloom_proto::persona::PersonaPreset;
use sha2::{Digest as _, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const U256_MAX: &str =
    "115792089237316195423570985008687907853269984665640564039457584007913129639935";

/// Discover routes from installer-certified declarations. Names and operation
/// class spelling never decide eligibility; token policy and exact keys do.
pub(super) fn certified_petal_selection(
    package_hash: &Digest32,
    catalog: &ProvenanceCatalog,
    account: u32,
    key_ref: &KeyRef,
    capability_schemas: &[Token],
) -> Result<Option<PersonaSessionSelection>> {
    if !capability_schemas
        .iter()
        .any(|s| s.as_str() == DECLARED_EFFECTS_CAPABILITY)
    {
        return Ok(None);
    }
    let mut route_grants = Vec::new();
    let mut bounded = false;
    for record in &catalog.records {
        let ProvenanceSubject::Petal {
            package_hash: hash,
            route,
        } = &record.subject
        else {
            continue;
        };
        if hash != package_hash {
            continue;
        }
        let mut route_classes = record
            .operation_classes
            .iter()
            .filter(|class| class.economic_effects_schema == Some(1))
            .map(|class| {
                bounded |= !class.zero_spend;
                class.operation_class.clone()
            })
            .collect::<Vec<_>>();
        route_classes.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        route_classes.dedup();
        if route_classes.is_empty() {
            continue;
        }
        route_grants.push(PetalRouteGrant {
            route: route.clone(),
            allowed_operation_classes: route_classes,
            provenance_digest: record.digest()?,
        });
    }
    if route_grants.is_empty() {
        return Ok(None);
    }
    route_grants.sort_by(|a, b| a.route.cmp(&b.route));
    if route_grants.windows(2).any(|w| w[0].route == w[1].route) {
        bail!("ambiguous certified Petal route");
    }
    let assets = if bounded && key_ref.key_spec == KeySpec::Secp256k1 {
        known_tokens()
            .iter()
            .filter(|token| {
                bloom_proto::persona::PersonaConfig::suggested(PersonaPreset::Trader)
                    .token_amounts(&token.symbol)
                    .is_some()
            })
            .map(|token| {
                Ok(AssetId {
                    chain: Token::new(format!("evm-{}", token.chain_id))?,
                    asset: token.address.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        vec![]
    };
    let suites = CryptoSuite::ALL
        .into_iter()
        .filter(|suite| suite.key_spec() == key_ref.key_spec)
        .collect();
    let primary = &route_grants[0];
    Ok(Some(PersonaSessionSelection {
        token_allowances: vec![],
        assets,
        members: vec![PersonaSessionMember {
            account,
            key_ref: key_ref.clone(),
            subject: ApprovalSubject::Petal {
                package_hash: package_hash.clone(),
                route: primary.route.clone(),
                agent_id: None,
            },
            selector: ApprovalSelector::Petal {
                package_hash: package_hash.clone(),
                route: primary.route.clone(),
                allowed_operation_classes: primary.allowed_operation_classes.clone(),
                route_grants: route_grants.clone(),
                required_claim_assurance: ClaimAssuranceLevel::MachineAsserted,
            },
            provenance_digest: primary.provenance_digest.clone(),
            allowed_crypto_suites: suites,
        }],
    }))
}

fn certified_zero_spend_classes(
    catalog: &ProvenanceCatalog,
    package_hash: &Digest32,
    selector: &ApprovalSelector,
) -> Vec<Token> {
    let ApprovalSelector::Petal {
        route,
        allowed_operation_classes,
        route_grants,
        ..
    } = selector
    else {
        return vec![];
    };
    let grants = if route_grants.is_empty() {
        vec![(route.as_str(), allowed_operation_classes)]
    } else {
        route_grants
            .iter()
            .map(|grant| (grant.route.as_str(), &grant.allowed_operation_classes))
            .collect()
    };
    let mut classes = grants
        .iter()
        .flat_map(|(_, classes)| classes.iter())
        .cloned()
        .collect::<Vec<_>>();
    classes.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    classes.dedup();
    // Consent applies to exact selected routes. A shared class is zero-spend
    // only when every selected occurrence has that installer certification.
    classes.retain(|class| grants.iter().filter(|(_,classes)| classes.contains(class)).all(|(route,_)| {
        catalog.records.iter().any(|record| matches!(&record.subject,
            ProvenanceSubject::Petal {package_hash: hash, route: certified_route} if hash == package_hash && certified_route == route)
            && record.operation_classes.iter().any(|entry| entry.operation_class == *class
                && entry.zero_spend && entry.economic_effects_schema == Some(1)))
    }));
    classes
}

async fn compile_petal_proposals(
    daemon: &Daemon,
    wallet: &str,
    account: u32,
) -> Result<Vec<PersonaSessionProposal>> {
    let config = bloom_proto::Config::load(&daemon.home.config_path())?;
    let broker = daemon.broker_client().context("Broker unavailable")?;
    let wallet_id = Token::new(wallet)?;
    let descriptor = broker.wallet(wallet_id.clone()).await?;
    let snapshot = broker.policy(wallet_id.clone()).await?;
    if snapshot.wallet_id != wallet_id
        || descriptor.wallet_id != wallet_id
        || snapshot.version != descriptor.policy_version
        || snapshot.policy_digest != descriptor.policy_digest
    {
        bail!("wallet policy changed while discovering reusable profiles");
    }
    let policy: CanonicalWalletPolicy =
        serde_json::from_slice(&snapshot.canonical_policy.decode())?;
    if policy.wallet_id != wallet_id {
        bail!("policy wallet differs from selected wallet");
    }
    let catalog = daemon
        .persona_provenance_catalog()
        .context("installer provenance unavailable")?;
    let MachineBrokerResponse::BrokerCapabilities(capabilities) = broker
        .request(MachineBrokerRequest::BrokerCapabilities(Empty {}))
        .await?
    else {
        bail!("Broker capability response mismatch");
    };
    let mut proposals = Vec::new();
    // One independent allowance per exact package/account. All certified routes
    // within that package share it; discovering more routes cannot refill it.
    for name in config.petals.setup.keys() {
        let Some(installed) = daemon.petals.store().resolve_petal_owner(name)? else {
            continue;
        };
        let package_hash = Digest32::new(installed)?;
        let mut selections = Vec::new();
        let mut selected_key_specs = Vec::new();
        for suite in CryptoSuite::ALL {
            if selected_key_specs.contains(&suite.key_spec()) {
                continue;
            }
            selected_key_specs.push(suite.key_spec());
            let Ok(key) = selected_account_key(daemon, wallet, account, suite).await else {
                continue;
            };
            if let Some(mut selection) = certified_petal_selection(
                &package_hash,
                &catalog,
                account,
                &key,
                &capabilities.schemas,
            )? {
                selection.assets.retain(|asset| {
                    config
                        .chains
                        .values()
                        .any(|chain| asset.chain.as_str() == format!("evm-{}", chain.chain_id))
                });
                selections.push(selection);
            }
        }
        if selections.is_empty() {
            continue;
        }
        if !policy.allowed_petal_packages.contains(&package_hash) {
            bail!("selected Petal {name} is not allowed by the signed wallet policy");
        }
        for selection in selections {
            proposals.extend(compile_selection(daemon, wallet, selection).await?);
        }
    }
    Ok(proposals)
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
    if selection.members.is_empty() || selection.members.len() > 128 || selection.assets.len() > 128
    {
        bail!("select 1–128 members and at most 128 tokens");
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
        .filter(|s| {
            !s.locally_disabled
                && s.terms.expires_at_ms.get() > now
                && selection.members.iter().any(|m| {
                    same_allowance_owner(&s.terms.subject, &s.terms.key_ref, &m.subject, &m.key_ref)
                })
        })
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
        if let ApprovalSelector::NativeSession { scope } = &mut selector {
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
            let petal_policy = if let ApprovalSubject::Petal { package_hash, .. } = &terms.subject {
                let catalog = daemon
                    .persona_provenance_catalog()
                    .context("installer provenance unavailable")?;
                let zero_spend_classes =
                    certified_zero_spend_classes(&catalog, package_hash, &terms.selector);
                Some(PetalSessionPolicy {
                    persona: match profile.preset {
                        PersonaPreset::Trader => PetalSessionPersona::Trader,
                        PersonaPreset::Degen => PetalSessionPersona::Degen,
                        PersonaPreset::Custodian => unreachable!(),
                    },
                    zero_spend_rate_limit: (!zero_spend_classes.is_empty()).then(|| {
                        SlidingWindow {
                            maximum: DecimalU64::new(
                                profile.zero_spend_hourly_cap().expect("automatic persona"),
                            ),
                            duration_ms: DecimalU64::new(3_600_000),
                        }
                    }),
                    zero_spend_classes,
                })
            } else {
                None
            };
            let mut budget = SessionBudget {
                petal_policy,
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

/// Public review data uses the same exact deployments and raw preset quantities
/// as compilation. This is presentation only; installer provenance and grants
/// still decide authority.
pub(crate) fn onboarding_display_data(daemon: &Daemon) -> Result<serde_json::Value> {
    let config = bloom_proto::Config::load(&daemon.home.config_path())?;
    let catalog = daemon.persona_provenance_catalog();
    let mut assets = Vec::new();
    for token in known_tokens().iter().filter(|token| {
        config
            .chains
            .values()
            .any(|chain| chain.chain_id == token.chain_id)
    }) {
        let mut limits = serde_json::Map::new();
        for preset in [PersonaPreset::Trader, PersonaPreset::Degen] {
            let profile = bloom_proto::persona::PersonaConfig::suggested(preset);
            if let Some((action, window)) = profile.token_amounts(&token.symbol) {
                limits.insert(preset.as_str().into(),serde_json::json!({"per_action":token_units(action,token.decimals)?,"per_window":token_units(window,token.decimals)?,"window_secs":profile.window_secs.to_string()}));
            }
        }
        if !limits.is_empty() {
            assets.push(serde_json::json!({"chain":format!("evm-{}",token.chain_id),"asset":token.address,"symbol":token.symbol,"decimals":token.decimals,"limits":limits}));
        }
    }
    let mut petals = Vec::new();
    for name in crate::default_policy::onboarding_petals(daemon)? {
        let hash = daemon.petals.store().resolve_petal_owner(&name)?;
        let records=catalog.as_ref().map(|catalog|catalog.records.iter().filter(|record|matches!(&record.subject,ProvenanceSubject::Petal {package_hash,..} if Some(package_hash.as_str())==hash.as_deref())).collect::<Vec<_>>()).unwrap_or_default();
        let mut zero_spend_classes = records
            .iter()
            .flat_map(|r| &r.operation_classes)
            .filter(|class| class.zero_spend && class.economic_effects_schema == Some(1))
            .map(|class| class.operation_class.clone())
            .collect::<Vec<_>>();
        zero_spend_classes.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        zero_spend_classes.dedup();
        let display_name = records
            .iter()
            .find_map(|r| r.package_display_name.as_deref())
            .unwrap_or_else(|| crate::default_policy::petal_label(&name));
        petals.push(serde_json::json!({"id":name,"package_hash":hash,"display_name":display_name,"assets":assets,"zero_spend_classes":zero_spend_classes}));
    }
    let rate = |preset| {
        let profile = bloom_proto::persona::PersonaConfig::suggested(preset);
        serde_json::json!({"maximum":profile.zero_spend_hourly_cap().unwrap().to_string(),"duration_ms":"3600000"})
    };
    Ok(
        serde_json::json!({"petals":petals,"zero_spend_rate_limits":{"trader":rate(PersonaPreset::Trader),"degen":rate(PersonaPreset::Degen)}}),
    )
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
            ApprovalSelector::NativeSession { scope: a },
            ApprovalSelector::NativeSession { scope: b },
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

/// Choose the same authoritative EVM account for native and Petal permissions.
async fn selected_evm_key(daemon: &Daemon, wallet: &str, account: u32) -> Result<KeyRef> {
    selected_account_key(
        daemon,
        wallet,
        account,
        CryptoSuite::Secp256k1Keccak256Recoverable,
    )
    .await
}

// Match the wallet VFS account numbering: EVM uses address indices under
// hardened account zero; Solana uses hardened account indices.
fn selected_account_path(key_spec: KeySpec, account: u32) -> (DerivationProfile, String) {
    match key_spec {
        KeySpec::Secp256k1 => (
            DerivationProfile::Bip44EvmSecp256k1V1,
            format!("m/44'/60'/0'/0/{account}"),
        ),
        KeySpec::Ed25519 => (
            DerivationProfile::Bip44SolanaSlip10Ed25519V1,
            format!("m/44'/501'/{account}'/0'"),
        ),
    }
}

async fn selected_account_key(
    daemon: &Daemon,
    wallet: &str,
    account: u32,
    suite: CryptoSuite,
) -> Result<KeyRef> {
    let broker = daemon.broker_client().context("Broker unavailable")?;
    let wallet_id = Token::new(wallet)?;
    let descriptor = broker.wallet(wallet_id.clone()).await?;
    let (derivation_profile, path) = selected_account_path(suite.key_spec(), account);
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
            .context("wallet has no authoritative signing key for the selected suite")?;
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
                    && entry.derivation_profile == derivation_profile
                    && entry.path == path
                    && matches!(&entry.key_ref.derivation, Some(DerivationRef::Bip39Multicurve { profile, path, .. }) if *profile == derivation_profile && path == &entry.path)
                    && entry.supported_crypto_suites.contains(&suite)
                    && descriptor.key_refs.contains(&entry.key_ref)
            })
            .collect::<Vec<_>>();
        let [entry] = candidates.as_slice() else {
            bail!(
                "selected wallet/account has no unique active owner key for this signing profile"
            );
        };
        entry.validate()?;
        entry.key_ref.clone()
    };
    Ok(key_ref)
}

/// Degen combines independent native-wallet transfer and selected Petal grants.
pub(crate) async fn compile_proposals(
    daemon: &Daemon,
    wallet: &str,
    account: u32,
) -> Result<Vec<PersonaSessionProposal>> {
    let config = bloom_proto::Config::load(&daemon.home.config_path())?;
    let profile = config.persona.clone().unwrap_or_default();
    let mut proposals = Vec::new();
    if profile.preset == PersonaPreset::Degen {
        let chain_ids: Vec<u64> = [1, 137]
            .into_iter()
            .filter(|id| config.chains.values().any(|c| c.chain_id == *id))
            .collect();
        let selection = degen_transfer_selection(daemon, wallet, account, &chain_ids).await?;
        proposals.extend(compile_selection(daemon, wallet, selection).await?);
    }
    proposals.extend(compile_petal_proposals(daemon, wallet, account).await?);
    if proposals.is_empty() {
        bail!(no_supported_scope_message(profile.preset));
    }
    Ok(proposals)
}

fn no_supported_scope_message(preset: PersonaPreset) -> &'static str {
    match preset {
        PersonaPreset::Trader => {
            "Trader has no supported reusable scope for the selected installed Petals and Broker capabilities. Individual owner approval remains required. Review a supported Petal release and its wallet policy before activating Trader."
        }
        PersonaPreset::Custodian => "Institutional retains individual owner approval",
        PersonaPreset::Degen => {
            "Degen has no supported reusable scope for the selected account, configured networks, installed Petals and Broker capabilities. Individual owner approval remains required."
        }
    }
}

/// Curated exact contracts only. These gas quantities are displayed for owner review.
fn degen_transfer_assets(
    chain_ids: &[u64],
) -> Result<(
    Vec<AssetId>,
    Vec<bloom_machine_client::PersonaTokenAllowance>,
)> {
    let profile = bloom_proto::persona::PersonaConfig::suggested(PersonaPreset::Degen);
    let mut assets: Vec<AssetId> = known_tokens()
        .iter()
        .filter(|t| {
            chain_ids.contains(&t.chain_id)
                && matches!(t.chain_id, 1 | 137)
                && profile.token_amounts(&t.symbol).is_some()
        })
        .map(|t| AssetId {
            chain: Token::new(format!("evm-{}", t.chain_id)).expect("fixed chain"),
            asset: t.address.clone(),
        })
        .collect();
    assets.sort_by(|a, b| (&a.chain, &a.asset).cmp(&(&b.chain, &b.asset)));
    assets.dedup();
    let mut gas = Vec::new();
    for id in chain_ids.iter().filter(|id| matches!(id, 1 | 137)) {
        let asset = AssetId {
            chain: Token::new(format!("evm-{id}"))?,
            asset: "native".into(),
        };
        let (action, window) = if *id == 1 {
            ("0.005", "0.05")
        } else {
            ("1", "10")
        };
        gas.push(bloom_machine_client::PersonaTokenAllowance {
            asset: asset.clone(),
            per_action: token_units(action, 18)?,
            per_window: token_units(window, 18)?,
        });
        assets.push(asset);
    }
    Ok((assets, gas))
}
async fn degen_transfer_selection(
    daemon: &Daemon,
    wallet: &str,
    account: u32,
    chain_ids: &[u64],
) -> Result<PersonaSessionSelection> {
    let (assets, token_allowances) = degen_transfer_assets(chain_ids)?;
    let tokens: Vec<_> = assets
        .iter()
        .filter(|a| a.asset != "native")
        .cloned()
        .collect();
    if tokens.is_empty() {
        bail!(
            "Degen transfers currently support configured Ethereum and Polygon chains; none are configured"
        );
    }
    let catalog = daemon
        .persona_provenance_catalog()
        .context("installer provenance unavailable")?;
    let record = catalog.records.iter().find(|r| matches!(&r.subject,ProvenanceSubject::System {component_id,operation_class} if component_id.as_str()=="bloom-machine" && operation_class.as_str()=="transaction.confirm")).context("native transfer provenance unavailable")?;
    Ok(PersonaSessionSelection {
        assets,
        token_allowances,
        members: vec![PersonaSessionMember {
            account,
            key_ref: selected_evm_key(daemon, wallet, account).await?,
            subject: ApprovalSubject::System {
                component_id: Token::new("bloom-machine")?,
                operation_class: Token::new("transaction.confirm")?,
            },
            selector: ApprovalSelector::NativeSession {
                scope: SystemSessionScope {
                    component_id: Token::new("bloom-machine")?,
                    actions: vec![SystemSessionAction::Erc20Transfer],
                    chains: chain_ids
                        .iter()
                        .filter(|id| matches!(id, 1 | 137))
                        .map(|id| {
                            Ok(SystemSessionChain::Evm {
                                chain: Token::new(format!("evm-{id}"))?,
                                chain_id: DecimalU64::new(*id),
                            })
                        })
                        .collect::<Result<Vec<_>>>()?,
                    destinations: vec![],
                    any_erc20_recipient: true,
                    tokens,
                    per_action_value_limits: vec![],
                },
            },
            provenance_digest: record.digest()?,
            allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
        }],
    })
}

fn same_allowance_owner(
    a: &ApprovalSubject,
    ak: &KeyRef,
    b: &ApprovalSubject,
    bk: &KeyRef,
) -> bool {
    ak == bk
        && match (a, b) {
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
                    component_id: a,
                    operation_class: ac,
                },
                ApprovalSubject::System {
                    component_id: b,
                    operation_class: bc,
                },
            ) => a == b && ac == bc,
            _ => a == b,
        }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsupported_trader_explains_release_and_capability_requirements() {
        let message = no_supported_scope_message(PersonaPreset::Trader);
        assert!(message.contains("Trader has no supported reusable scope"));
        assert!(message.contains("Individual owner approval remains required"));
        assert!(!message.contains("choose Degen"));
    }

    #[test]
    fn signing_profiles_use_the_authoritative_account_numbering() {
        assert_eq!(
            selected_account_path(KeySpec::Secp256k1, 1),
            (
                DerivationProfile::Bip44EvmSecp256k1V1,
                "m/44'/60'/0'/0/1".into()
            )
        );
        assert_eq!(
            selected_account_path(KeySpec::Ed25519, 1),
            (
                DerivationProfile::Bip44SolanaSlip10Ed25519V1,
                "m/44'/501'/1'/0'".into()
            )
        );
    }
    #[test]
    fn discovery_is_generic_and_requires_signed_effects_metadata() {
        let explicit: PersonaSessionSelection = serde_json::from_str(include_str!(
            "../../../docs/examples/generic-session-selection.json"
        ))
        .unwrap();
        let key = explicit.members[0].key_ref.clone();
        let hash = Digest32::from_bytes([7; 32]);
        let advertised = vec![Token::new(DECLARED_EFFECTS_CAPABILITY).unwrap()];
        let record = |route: &str| ProvenanceRecord {
            package_display_name: Some("An unrelated reviewed package".into()),
            subject: ProvenanceSubject::Petal {
                package_hash: hash.clone(),
                route: route.into(),
            },
            publisher: Token::new("test-publisher").unwrap(),
            petal_lineage: None,
            operation_classes: vec![ProvenanceOperationClass {
                zero_spend: false,
                economic_effects_schema: Some(1),
                operation_class: Token::new(format!("{route}.action")).unwrap(),
                fee_asset: None,
            }],
            installer_key_id: Token::new("test-installer").unwrap(),
            installer_signature: Base64UrlBytes::from_bytes(&[0; 64]),
        };
        let mut catalog = ProvenanceCatalog {
            schema: PROVENANCE_CATALOG_SCHEMA.into(),
            records: vec![record("r2"), record("r1")],
        };
        let selected = certified_petal_selection(&hash, &catalog, 3, &key, &advertised)
            .unwrap()
            .unwrap();
        assert_eq!(selected.members[0].account, 3);
        let ApprovalSelector::Petal {
            allowed_operation_classes,
            route_grants,
            ..
        } = &selected.members[0].selector
        else {
            panic!("Petal selection")
        };
        assert_eq!(
            allowed_operation_classes,
            &[Token::new("r1.action").unwrap()]
        );
        assert_eq!(
            route_grants[1].allowed_operation_classes,
            [Token::new("r2.action").unwrap()]
        );
        assert!(!selected.assets.is_empty());
        catalog.records[0].operation_classes[0].zero_spend = true; // r2 is secondary.
        assert_eq!(
            certified_zero_spend_classes(&catalog, &hash, &selected.members[0].selector),
            [Token::new("r2.action").unwrap()]
        );
        let mut unrelated = record("unselected");
        unrelated.operation_classes[0].operation_class = Token::new("r1.action").unwrap();
        unrelated.operation_classes[0].zero_spend = true;
        catalog.records.push(unrelated);
        assert_eq!(
            certified_zero_spend_classes(&catalog, &hash, &selected.members[0].selector),
            [Token::new("r2.action").unwrap()],
            "unselected route certification must not opt in another route"
        );
        // Fee metadata is a generic policy input, never a route eligibility ban.
        for record in &mut catalog.records {
            record.operation_classes[0].fee_asset = Some(ProvenanceFeeAsset {
                chain: Token::new("evm-137").unwrap(),
                asset: "native".into(),
            });
        }
        assert!(
            certified_petal_selection(&hash, &catalog, 3, &key, &advertised)
                .unwrap()
                .is_some()
        );
        assert!(
            certified_petal_selection(&hash, &catalog, 3, &key, &[])
                .unwrap()
                .is_none()
        );
        for record in &mut catalog.records {
            record.operation_classes[0].zero_spend = true;
        }
        assert!(
            certified_petal_selection(&hash, &catalog, 3, &key, &advertised)
                .unwrap()
                .unwrap()
                .assets
                .is_empty()
        );
        for record in &mut catalog.records {
            record.operation_classes[0].economic_effects_schema = None;
        }
        assert!(
            certified_petal_selection(&hash, &catalog, 3, &key, &advertised)
                .unwrap()
                .is_none()
        );
        catalog.records = vec![record("r1"), record("r1")];
        assert!(certified_petal_selection(&hash, &catalog, 3, &key, &advertised).is_err());
    }

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
            ApprovalSelector::NativeSession { .. }
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
    #[test]
    fn degen_native_defaults_are_exact_supported_assets_with_separate_gas_caps() {
        let (assets, gas) = degen_transfer_assets(&[1, 137, 8453]).unwrap();
        assert!(
            assets
                .iter()
                .all(|a| matches!(a.chain.as_str(), "evm-1" | "evm-137"))
        );
        assert!(
            assets
                .iter()
                .any(|a| a.asset == "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
        );
        assert_eq!(gas.len(), 2);
        assert_eq!(gas[0].per_action.as_str(), "5000000000000000");
        assert_eq!(gas[0].per_window.as_str(), "50000000000000000");
        assert!(assets.iter().all(|a| approved_session_asset(a).is_some()));
        assert!(degen_transfer_assets(&[8453]).unwrap().0.is_empty());
    }
    #[test]
    fn allowance_resume_isolated_by_owner_without_multiplying_changed_routes() {
        let selection: PersonaSessionSelection = serde_json::from_str(include_str!(
            "../../../docs/examples/generic-session-selection.json"
        ))
        .unwrap();
        let native = &selection.members[0];
        let petal = &selection.members[1];
        assert!(!same_allowance_owner(
            &native.subject,
            &native.key_ref,
            &petal.subject,
            &native.key_ref
        ));
        assert!(same_allowance_owner(
            &native.subject,
            &native.key_ref,
            &native.subject,
            &native.key_ref
        ));
        let mut replacement = petal.subject.clone();
        if let ApprovalSubject::Petal { package_hash, .. } = &mut replacement {
            *package_hash = Digest32::from_bytes([99; 32]);
        }
        assert!(
            !same_allowance_owner(&petal.subject, &petal.key_ref, &replacement, &petal.key_ref,),
            "replacement packages require a fresh owner-reviewed allowance, not a continuation"
        );
        let mut next_route = petal.subject.clone();
        if let ApprovalSubject::Petal { route, .. } = &mut next_route {
            *route = "different-route".into();
        }
        assert!(same_allowance_owner(
            &petal.subject,
            &petal.key_ref,
            &next_route,
            &petal.key_ref
        ));
    }
}
