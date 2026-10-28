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

/// Discover only profiles backed by a compiled Broker verifier and the exact
/// installed package's signed route/effects declarations. Package names and
/// UI preferences never stand in for provenance or authorize a signature.
fn certified_petal_selection(
    package_hash: &Digest32,
    catalog: &ProvenanceCatalog,
    account: u32,
    key_ref: &KeyRef,
    capability_schemas: &[Token],
) -> Result<Option<PersonaSessionSelection>> {
    let mut route_grants = Vec::new();
    let mut classes = Vec::new();
    let mut assets = Vec::new();
    let mut suites = Vec::new();
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
        let mut route_classes = Vec::new();
        for profile in reusable_signing_profiles() {
            if !profile.is_advertised(capability_schemas) {
                continue;
            }
            if !record
                .operation_classes
                .iter()
                .any(|class| profile.matches_certified_class(class))
            {
                continue;
            }
            if profile.crypto_suite.key_spec() != key_ref.key_spec {
                continue;
            }
            route_classes.push(Token::new(profile.operation_class)?);
            if !suites.contains(&profile.crypto_suite) {
                suites.push(profile.crypto_suite);
            }
            for asset in profile.token_assets() {
                if !assets.contains(&asset) {
                    assets.push(asset);
                }
            }
        }
        route_classes.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        route_classes.dedup();
        if route_classes.is_empty() {
            continue;
        }
        for class in &route_classes {
            if !classes.contains(class) {
                classes.push(class.clone());
            }
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
    classes.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    assets.sort_by(|a, b| (&a.chain, &a.asset).cmp(&(&b.chain, &b.asset)));
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
                allowed_operation_classes: classes,
                route_grants: route_grants.clone(),
                required_claim_assurance: ClaimAssuranceLevel::MachineAsserted,
            },
            provenance_digest: primary.provenance_digest.clone(),
            allowed_crypto_suites: suites,
        }],
    }))
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
        let mut selected = None;
        let mut selected_key_specs = Vec::new();
        for suite in CryptoSuite::ALL {
            if selected_key_specs.contains(&suite.key_spec()) {
                continue;
            }
            let supported = reusable_signing_profiles().iter().any(|profile| {
                profile.crypto_suite == suite
                    && profile.is_advertised(&capabilities.schemas)
                    && catalog.records.iter().any(|record| {
                        matches!(&record.subject, ProvenanceSubject::Petal { package_hash: hash, .. } if hash == &package_hash)
                            && record.operation_classes.iter().any(|class| profile.matches_certified_class(class))
                    })
            });
            if !supported {
                continue;
            }
            selected_key_specs.push(suite.key_spec());
            let key = selected_account_key(daemon, wallet, account, suite).await?;
            if let Some(selection) = certified_petal_selection(
                &package_hash,
                &catalog,
                account,
                &key,
                &capabilities.schemas,
            )? {
                if selected.is_some() {
                    bail!(
                        "multiple key profiles for one Petal require an explicit account selection"
                    );
                }
                selected = Some(selection);
            }
        }
        let Some(selection) = selected else {
            continue;
        };
        if !policy.allowed_petal_packages.contains(&package_hash) {
            bail!("selected Petal {name} is not allowed by the signed wallet policy");
        }
        proposals.extend(compile_selection(daemon, wallet, selection).await?);
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
        bail!(
            "no supported reusable scope was selected; choose Degen transfers or a supported Petal"
        );
    }
    Ok(proposals)
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
            selector: ApprovalSelector::SystemSession {
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
    fn discovery_uses_certified_profiles_not_package_names_or_schema_alone() {
        let explicit: PersonaSessionSelection = serde_json::from_str(include_str!(
            "../../../docs/examples/generic-session-selection.json"
        ))
        .unwrap();
        let key = explicit.members[0].key_ref.clone();
        let hash = Digest32::from_bytes([7; 32]);
        let profile = &reusable_signing_profiles()[0];
        let advertised = vec![Token::new(profile.capability_schema()).unwrap()];
        let record = |route: &str| ProvenanceRecord {
            subject: ProvenanceSubject::Petal {
                package_hash: hash.clone(),
                route: route.into(),
            },
            publisher: Token::new("test-publisher").unwrap(),
            petal_lineage: None,
            operation_classes: vec![ProvenanceOperationClass {
                economic_effects_schema: Some(1),
                operation_class: Token::new(profile.operation_class).unwrap(),
                fee_asset: None,
            }],
            installer_key_id: Token::new("test-installer").unwrap(),
            installer_signature: Base64UrlBytes::from_bytes(&[0; 64]),
        };
        let mut catalog = ProvenanceCatalog {
            schema: PROVENANCE_CATALOG_SCHEMA.into(),
            records: vec![record("r000002"), record("r000001")],
        };
        let selection = certified_petal_selection(&hash, &catalog, 3, &key, &advertised)
            .unwrap()
            .unwrap();
        assert!(
            certified_petal_selection(&hash, &catalog, 3, &key, &[])
                .unwrap()
                .is_none()
        );
        assert_eq!(selection.members.len(), 1);
        assert_eq!(selection.members[0].account, 3);
        assert_eq!(selection.assets, profile.token_assets());
        let ApprovalSelector::Petal { route_grants, .. } = &selection.members[0].selector else {
            panic!("Petal scope expected")
        };
        assert_eq!(route_grants.len(), 2);
        assert_eq!(route_grants[0].route, "r000001");
        assert!(
            certified_petal_selection(
                &Digest32::from_bytes([8; 32]),
                &catalog,
                3,
                &key,
                &advertised
            )
            .unwrap()
            .is_none()
        );
        for r in &mut catalog.records {
            r.operation_classes[0].operation_class = Token::new("example.unknown").unwrap();
        }
        assert!(
            certified_petal_selection(&hash, &catalog, 3, &key, &advertised)
                .unwrap()
                .is_none()
        );
        catalog.records = vec![record("r000001")];
        catalog.records[0].operation_classes[0].economic_effects_schema = None;
        assert!(
            certified_petal_selection(&hash, &catalog, 3, &key, &advertised)
                .unwrap()
                .is_none()
        );
        catalog.records[0].operation_classes[0].economic_effects_schema = Some(2);
        assert!(
            certified_petal_selection(&hash, &catalog, 3, &key, &advertised)
                .unwrap()
                .is_none()
        );
        catalog.records = vec![record("r000001"), record("r000001")];
        assert!(certified_petal_selection(&hash, &catalog, 3, &key, &advertised).is_err());
        catalog.records = vec![record("r000001")];
        let wrong_key = explicit.members[1].key_ref.clone();
        assert!(
            certified_petal_selection(&hash, &catalog, 3, &wrong_key, &advertised)
                .unwrap()
                .is_none()
        );
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
