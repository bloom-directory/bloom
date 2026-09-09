//! `wallets/<wallet>/<n>/...`: one numbered account.
//!
//! A number is a presentation of two derivation paths, EVM
//! `m/44'/60'/0'/0/<n>` and Solana `m/44'/501'/<n>'/0'`, computed here from
//! the authenticated projection and never stored or sent anywhere. The
//! directory re-roots the wallet's chain views at that account's keys: the
//! same balance, nonce and outbox code as `wallets/<wallet>/chains/...`, with
//! the sender fixed to the account's key for the chain's family instead of
//! the wallet's canonical initial key.
//!
//! Writes go through the same outbox code with the sender fixed: an EVM stage
//! is built for the account's address and later signed by the key the
//! transaction engine resolves from that address; a Solana stage pins the
//! account's fingerprint. Pending controls under `<n>/` act only on entries
//! that account staged.

use super::*;
use bloom_broker_api::{AccountLifecycleState, DerivationProfile, DerivedAccountPublic};

/// One family's key inside an account.
#[derive(Clone, Debug)]
struct FamilyKey {
    key_ref: bloom_broker_api::KeyRef,
    /// Display address in the family's encoding; the same value on every
    /// network of the family.
    address: String,
    fingerprint: String,
    /// Empty for a legacy root or imported single key, which has no path.
    path: String,
    lifecycle: AccountLifecycleState,
    /// The projection entry, when the key is a derived child. `None` for a
    /// legacy root, which the Solana helpers never need.
    derived: Option<DerivedAccountPublic>,
}

/// A numbered account as the mounted tree presents it.
#[derive(Clone, Debug)]
pub(super) struct AccountView {
    number: u32,
    evm: Option<FamilyKey>,
    solana: Option<FamilyKey>,
    freshness: bloom_machine_client::ProjectionFreshness,
}

/// The account number a derived child's path encodes, or `None` for a path
/// outside the default mapping (an EVM child under a non-zero hardened
/// account), which the account tree does not present.
pub(crate) fn account_number(account: &DerivedAccountPublic) -> Option<u32> {
    let path = account.path.as_str();
    let digits = match account.derivation_profile {
        DerivationProfile::Bip44EvmSecp256k1V1 => path.strip_prefix("m/44'/60'/0'/0/")?,
        DerivationProfile::Bip44SolanaSlip10Ed25519V1 => {
            path.strip_prefix("m/44'/501'/")?.strip_suffix("'/0'")?
        }
    };
    parse_account_segment(digits)
}

/// A path segment that names an account: decimal digits, canonical spelling,
/// inside the non-hardened BIP-32 range.
pub(super) fn parse_account_segment(segment: &str) -> Option<u32> {
    if segment.is_empty()
        || segment.len() > 10
        || !segment.bytes().all(|byte| byte.is_ascii_digit())
        || (segment.len() > 1 && segment.starts_with('0'))
    {
        return None;
    }
    segment
        .parse::<u32>()
        .ok()
        .filter(|number| *number < (1_u32 << 31))
}

fn lifecycle_label(lifecycle: AccountLifecycleState) -> &'static str {
    match lifecycle {
        AccountLifecycleState::Active => "active",
        AccountLifecycleState::Retired => "retired",
    }
}

fn family_json(family: Option<&FamilyKey>) -> serde_json::Value {
    match family {
        None => serde_json::json!({ "state": "missing" }),
        Some(key) => serde_json::json!({
            "state": lifecycle_label(key.lifecycle),
            "address": key.address,
            "public_key_fingerprint": key.fingerprint,
            "path": if key.path.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(key.path.clone()) },
            "key_ref": key.key_ref,
        }),
    }
}

impl WalletsHandler {
    /// Every account the wallet presents, ordered by number. A legacy or
    /// imported single-key wallet is account 0 from its projection; a BIP-39
    /// wallet's accounts come from the authenticated `wallet.accounts`
    /// projection, grouped by the number their paths encode.
    async fn account_views(&self, wallet: &str) -> Result<Vec<AccountView>, HandlerError> {
        let projection = self.wallet_projection(wallet).await?;
        if projection.wallet.root_key_ref.is_some() {
            let key = projection.primary_key().map_err(err_be)?;
            return Ok(vec![AccountView {
                number: 0,
                evm: Some(FamilyKey {
                    key_ref: key.key_ref.clone(),
                    address: projection.primary_address().map_err(err_be)?.to_owned(),
                    fingerprint: key.key_ref.public_key_fingerprint.as_str().to_owned(),
                    path: String::new(),
                    lifecycle: AccountLifecycleState::Active,
                    derived: None,
                }),
                solana: None,
                freshness: projection.freshness,
            }]);
        }
        // The numbered tree renders from the wallet projection's cached,
        // authenticated account inventory: listings, stats and reads carry no
        // authority side effects and stay truthful about freshness even while
        // the Broker edge is down (a stale projection is marked as such).
        // Authority changes and offline signing still go through the Broker
        // and remain refused while it is unreachable.
        let accounts = &projection.accounts;
        let mut views: std::collections::BTreeMap<u32, AccountView> =
            std::collections::BTreeMap::new();
        for account in &accounts.accounts {
            let Some(number) = account_number(account) else {
                continue;
            };
            let family = FamilyKey {
                key_ref: account.key_ref.clone(),
                address: account
                    .chain_projections
                    .first()
                    .map(|projection| projection.address.clone())
                    .unwrap_or_default(),
                fingerprint: account.public_key_fingerprint.as_str().to_owned(),
                path: account.path.clone(),
                lifecycle: account.lifecycle,
                derived: Some(account.clone()),
            };
            let view = views.entry(number).or_insert_with(|| AccountView {
                number,
                evm: None,
                solana: None,
                freshness: projection.freshness,
            });
            match account.derivation_profile {
                DerivationProfile::Bip44EvmSecp256k1V1 => view.evm = Some(family),
                DerivationProfile::Bip44SolanaSlip10Ed25519V1 => view.solana = Some(family),
            }
        }
        Ok(views.into_values().collect())
    }

    async fn account_view(&self, wallet: &str, number: u32) -> Result<AccountView, HandlerError> {
        self.account_views(wallet)
            .await?
            .into_iter()
            .find(|view| view.number == number)
            .ok_or_else(|| {
                HandlerError::not_found(format!("wallet '{wallet}' has no account {number}"))
            })
    }

    /// Directory entries for the wallet's numbered accounts.
    pub(super) async fn account_number_entries(
        &self,
        wallet: &str,
    ) -> Result<Vec<Entry>, HandlerError> {
        Ok(self
            .account_views(wallet)
            .await?
            .into_iter()
            .map(|view| Entry::dir(&view.number.to_string()))
            .collect())
    }

    /// `accounts.json` with the number each entry's path encodes added,
    /// so a reader never re-derives the mapping.
    pub(super) fn accounts_json_with_numbers(
        accounts: &bloom_broker_api::WalletAccountsPublic,
    ) -> Result<Vec<u8>, HandlerError> {
        let mut value = serde_json::to_value(accounts).map_err(err_be)?;
        if let (Some(serde_json::Value::Array(entries)), Some(numbers)) = (
            value.get_mut("accounts"),
            Some(
                accounts
                    .accounts
                    .iter()
                    .map(account_number)
                    .collect::<Vec<_>>(),
            ),
        ) {
            for (entry, number) in entries.iter_mut().zip(numbers) {
                if let serde_json::Value::Object(fields) = entry {
                    fields.insert("number".into(), serde_json::json!(number));
                }
            }
        }
        let mut out = serde_json::to_vec_pretty(&value).map_err(err_be)?;
        out.push(b'\n');
        Ok(out)
    }

    fn account_json(&self, wallet: &str, view: &AccountView) -> Result<Vec<u8>, HandlerError> {
        let mut out = serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "bloom.account.v1",
            "wallet": wallet,
            "number": view.number,
            "freshness": view.freshness,
            "evm": family_json(view.evm.as_ref()),
            "solana": family_json(view.solana.as_ref()),
        }))
        .map_err(err_be)?;
        out.push(b'\n');
        Ok(out)
    }

    fn evm_family<'a>(view: &'a AccountView, chain: &str) -> Result<&'a FamilyKey, HandlerError> {
        view.evm.as_ref().ok_or_else(|| {
            HandlerError::not_found(format!(
                "account {} has no EVM key; chain '{chain}' cannot be read through it",
                view.number
            ))
        })
    }

    fn solana_family<'a>(
        view: &'a AccountView,
        chain: &str,
    ) -> Result<(&'a FamilyKey, SolanaAccount), HandlerError> {
        let family = view.solana.as_ref().ok_or_else(|| {
            HandlerError::not_found(format!(
                "account {} has no Solana key; chain '{chain}' cannot be read through it",
                view.number
            ))
        })?;
        let derived = family
            .derived
            .as_ref()
            .ok_or_else(|| HandlerError::backend("Solana account without a projection entry"))?;
        Ok((family, SolanaAccount::from_projection(derived)?))
    }

    fn evm_address(family: &FamilyKey) -> Result<alloy::primitives::Address, HandlerError> {
        family
            .address
            .parse()
            .map_err(|error| HandlerError::backend(format!("invalid projected address: {error}")))
    }

    fn account_dir_entries() -> Vec<Entry> {
        vec![
            Entry::file("account.json"),
            Entry::dir("chains"),
            Entry::dir("petals"),
            Entry::dir("sessions"),
        ]
    }

    fn account_petal_handler(
        &self,
        wallet: &str,
        view: &AccountView,
    ) -> Result<Arc<dyn Handler>, HandlerError> {
        let account_petals = self.account_petals.read();
        let petals = account_petals
            .as_ref()
            .ok_or_else(|| HandlerError::not_found("account Petal runtime is unavailable"))?;
        Ok(petals.for_account(AccountPetalContext {
            wallet: wallet.to_owned(),
            number: view.number,
            evm_fingerprint: view.evm.as_ref().map(|key| key.fingerprint.clone()),
            solana_fingerprint: view.solana.as_ref().map(|key| key.fingerprint.clone()),
            freshness: view.freshness,
        }))
    }

    fn account_sessions(
        &self,
        wallet: &str,
        view: &AccountView,
    ) -> Result<Vec<AccountSessionEntry>, HandlerError> {
        let petals = self.account_petals.read();
        let Some(petals) = petals.as_ref() else {
            return Ok(Vec::new());
        };
        petals.sessions(&AccountPetalContext {
            wallet: wallet.to_owned(),
            number: view.number,
            evm_fingerprint: view.evm.as_ref().map(|key| key.fingerprint.clone()),
            solana_fingerprint: view.solana.as_ref().map(|key| key.fingerprint.clone()),
            freshness: view.freshness,
        })
    }

    fn chain_name_entries(&self) -> Vec<Entry> {
        let mut names: std::collections::BTreeSet<String> =
            self.chains.list_names().into_iter().collect();
        names.extend(self.solana_chain_names());
        if let Some(solana) = &self.solana {
            names.extend(solana.keys().cloned());
        }
        names.into_iter().map(|name| Entry::dir(&name)).collect()
    }

    pub(super) async fn lookup_account(
        &self,
        wallet: &str,
        number: u32,
        rest: &[String],
    ) -> Result<Entry, HandlerError> {
        let view = self.account_view(wallet, number).await?;
        match rest {
            [] => Ok(Entry::dir(&number.to_string())),
            [dir, petal_rest @ ..] if dir == "petals" => {
                self.account_petal_handler(wallet, &view)?
                    .lookup(
                        &petal_rest
                            .iter()
                            .fold(VfsPath::root(), |path, segment| path.join(segment)),
                    )
                    .await
            }
            [dir, sessions_rest @ ..] if dir == "sessions" => {
                let sessions = self.account_sessions(wallet, &view)?;
                Self::lookup_account_session(&sessions, sessions_rest)
            }
            [leaf] if leaf == "account.json" => Ok(Entry::file(leaf)),
            [dir] if dir == "chains" => Ok(Entry::dir("chains")),
            [dir, chain, chain_rest @ ..] if dir == "chains" => {
                if self.is_solana_chain(chain) {
                    let (family, _) = Self::solana_family(&view, chain)?;
                    return self
                        .lookup_account_solana_chain(wallet, family, chain, chain_rest)
                        .await;
                }
                let family = Self::evm_family(&view, chain)?;
                self.lookup_account_evm_chain(wallet, family, chain, chain_rest)
                    .await
            }
            _ => Err(HandlerError::not_found(rest.join("/"))),
        }
    }

    pub(super) async fn read_account(
        &self,
        wallet: &str,
        number: u32,
        rest: &[String],
    ) -> Result<Vec<u8>, HandlerError> {
        let view = self.account_view(wallet, number).await?;
        match rest {
            [leaf] if leaf == "account.json" => self.account_json(wallet, &view),
            [dir, petal_rest @ ..] if dir == "petals" => {
                self.account_petal_handler(wallet, &view)?
                    .read(
                        &petal_rest
                            .iter()
                            .fold(VfsPath::root(), |path, segment| path.join(segment)),
                    )
                    .await
            }
            [dir, mount, slot, leaf] if dir == "sessions" && leaf == "session.json" => {
                let sessions = self.account_sessions(wallet, &view)?;
                sessions
                    .iter()
                    .find(|session| session.petal_mount == *mount && session.key_slot == *slot)
                    .map(|session| session.document.clone())
                    .ok_or_else(|| HandlerError::not_found(rest.join("/")))
            }
            [dir, chain, chain_rest @ ..] if dir == "chains" => {
                if self.is_solana_chain(chain) {
                    let (family, account) = Self::solana_family(&view, chain)?;
                    return self
                        .read_account_solana_chain(wallet, family, &account, chain, chain_rest)
                        .await;
                }
                let family = Self::evm_family(&view, chain)?;
                self.read_account_evm_chain(wallet, family, chain, chain_rest)
                    .await
            }
            _ => Err(HandlerError::NotAFile(rest.join("/"))),
        }
    }

    pub(super) async fn list_account(
        &self,
        wallet: &str,
        number: u32,
        rest: &[String],
    ) -> Result<Vec<Entry>, HandlerError> {
        let view = self.account_view(wallet, number).await?;
        match rest {
            [] => Ok(Self::account_dir_entries()),
            [dir, petal_rest @ ..] if dir == "petals" => {
                self.account_petal_handler(wallet, &view)?
                    .list(
                        &petal_rest
                            .iter()
                            .fold(VfsPath::root(), |path, segment| path.join(segment)),
                    )
                    .await
            }
            [dir] if dir == "sessions" => {
                let sessions = self.account_sessions(wallet, &view)?;
                let mounts: std::collections::BTreeSet<&str> = sessions
                    .iter()
                    .map(|session| session.petal_mount.as_str())
                    .collect();
                Ok(mounts.into_iter().map(Entry::dir).collect())
            }
            [dir, mount] if dir == "sessions" => {
                let sessions = self.account_sessions(wallet, &view)?;
                let slots: std::collections::BTreeSet<&str> = sessions
                    .iter()
                    .filter(|session| session.petal_mount == *mount)
                    .map(|session| session.key_slot.as_str())
                    .collect();
                if slots.is_empty() {
                    return Err(HandlerError::not_found(rest.join("/")));
                }
                Ok(slots.into_iter().map(Entry::dir).collect())
            }
            [dir, mount, slot] if dir == "sessions" => {
                let sessions = self.account_sessions(wallet, &view)?;
                Self::lookup_account_session(&sessions, &[mount.clone(), slot.clone()])?;
                let mut entries = vec![Entry::file("session.json")];
                if sessions.iter().any(|session| {
                    session.petal_mount == *mount && session.key_slot == *slot && session.stoppable
                }) {
                    entries.push(Entry::writable_file("stop"));
                }
                Ok(entries)
            }
            [dir] if dir == "chains" => Ok(self.chain_name_entries()),
            [dir, chain, chain_rest @ ..] if dir == "chains" => {
                if self.is_solana_chain(chain) {
                    let (family, _) = Self::solana_family(&view, chain)?;
                    return self
                        .list_account_solana_chain(wallet, family, chain, chain_rest)
                        .await;
                }
                let family = Self::evm_family(&view, chain)?;
                self.list_account_evm_chain(wallet, family, chain, chain_rest)
                    .await
            }
            _ => Err(HandlerError::NotADir(rest.join("/"))),
        }
    }

    /// Writes under `<n>/chains/<c>/outbox/`: the wallet's outbox surface
    /// with the sender fixed to this account's key for the chain's family.
    /// Policy stays wallet-wide, so the same advisory policy applies.
    pub(super) async fn write_account(
        &self,
        wallet: &str,
        number: u32,
        rest: &[String],
        data: &[u8],
    ) -> Result<(), HandlerError> {
        let view = self.account_view(wallet, number).await?;
        if let [dir, petal_rest @ ..] = rest
            && dir == "petals"
        {
            return self
                .account_petal_handler(wallet, &view)?
                .write(
                    &petal_rest
                        .iter()
                        .fold(VfsPath::root(), |path, segment| path.join(segment)),
                    data,
                )
                .await;
        }
        if let [dir, mount, slot, leaf] = rest
            && dir == "sessions"
            && leaf == "stop"
        {
            let content = std::str::from_utf8(data)
                .map_err(|_| HandlerError::invalid("non-utf8 stop content"))?;
            if content.trim().is_empty() {
                return Err(HandlerError::invalid(
                    "stop requires non-empty content (e.g. 'y')",
                ));
            }
            let petals = {
                let guard = self.account_petals.read();
                guard.as_ref().cloned().ok_or_else(|| {
                    HandlerError::not_found("account Petal runtime is unavailable")
                })?
            };
            let context = AccountPetalContext {
                wallet: wallet.to_owned(),
                number: view.number,
                evm_fingerprint: view.evm.as_ref().map(|key| key.fingerprint.clone()),
                solana_fingerprint: view.solana.as_ref().map(|key| key.fingerprint.clone()),
                freshness: view.freshness,
            };
            return petals.stop_session(&context, mount, slot).await;
        }
        let [dir, chain, sub, chain_rest @ ..] = rest else {
            return Err(HandlerError::PermissionDenied);
        };
        if dir != "chains" || sub != "outbox" {
            return Err(HandlerError::PermissionDenied);
        }
        if self.is_solana_chain(chain) {
            let (family, _) = Self::solana_family(&view, chain)?;
            let engine = self.solana_engine(chain).ok_or_else(|| {
                HandlerError::not_found(format!(
                    "chain '{chain}' is configured for reads only; staging is unavailable"
                ))
            })?;
            return self
                .write_solana_outbox(
                    wallet,
                    chain,
                    chain_rest,
                    data,
                    &engine,
                    Some(Self::solana_sender(family)),
                )
                .await;
        }
        let family = Self::evm_family(&view, chain)?;
        let from = Self::evm_address(family)?;
        let projection = self.wallet_projection(wallet).await?;
        let policy = crate::advisory_evm_policy(&projection, chain).map_err(err_be)?;
        self.write_outbox_from(
            wallet,
            chain,
            from,
            &policy,
            Some(&family.address),
            chain_rest,
            data,
        )
        .await
    }

    fn solana_sender(family: &FamilyKey) -> SolanaSender<'_> {
        SolanaSender {
            fingerprint: &family.fingerprint,
            address: &family.address,
        }
    }

    // ----- EVM -----

    async fn lookup_account_evm_chain(
        &self,
        wallet: &str,
        family: &FamilyKey,
        chain: &str,
        rest: &[String],
    ) -> Result<Entry, HandlerError> {
        self.chains
            .get(chain)
            .ok_or_else(|| HandlerError::not_found(format!("chain '{chain}'")))?;
        match rest {
            [] => Ok(Entry::dir(chain)),
            [leaf]
                if matches!(
                    leaf.as_str(),
                    "balance" | "balance.raw" | "balance.json" | "nonce"
                ) =>
            {
                Ok(Entry::file(leaf))
            }
            [dir] if dir == "outbox" => Ok(Entry::dir("outbox")),
            [dir, leaf] if dir == "outbox" && leaf == "new.tx" => {
                Ok(Entry::writable_file("new.tx"))
            }
            [dir, state] if dir == "outbox" => {
                parse_state_seg(state)?;
                Ok(Entry::dir(state))
            }
            [dir, state, id] if dir == "outbox" => {
                let entry = self.account_evm_outbox_entry(wallet, family, chain, state, id)?;
                Ok(Entry::dir(id).with_modified_ms(entry.staged.created_ms))
            }
            [dir, state, id, fname] if dir == "outbox" => {
                let entry = self.account_evm_outbox_entry(wallet, family, chain, state, id)?;
                if entry.state == OutboxState::Pending
                    && EVM_PENDING_CONTROLS.contains(&fname.as_str())
                {
                    return Ok(
                        Entry::writable_file(fname).with_modified_ms(entry.staged.created_ms)
                    );
                }
                open_regular_outbox_artifact(&entry.dir, fname)?;
                Ok(Entry::file(fname).with_modified_ms(entry.staged.created_ms))
            }
            _ => Err(HandlerError::not_found(rest.join("/"))),
        }
    }

    async fn read_account_evm_chain(
        &self,
        wallet: &str,
        family: &FamilyKey,
        chain: &str,
        rest: &[String],
    ) -> Result<Vec<u8>, HandlerError> {
        let client = self
            .chains
            .get(chain)
            .ok_or_else(|| HandlerError::not_found(format!("chain '{chain}'")))?;
        let address = Self::evm_address(family)?;
        match rest {
            [leaf] if leaf == "balance" => {
                let balance = client.balance(address).await.map_err(err_be)?;
                let spec = client.spec();
                Ok(crate::handlers::balances::display_line(
                    balance,
                    spec.native_decimals,
                    &spec.native_symbol,
                ))
            }
            [leaf] if leaf == "balance.raw" => {
                let balance = client.balance(address).await.map_err(err_be)?;
                Ok(crate::handlers::balances::raw_line(balance))
            }
            [leaf] if leaf == "balance.json" => {
                let balance = client.balance(address).await.map_err(err_be)?;
                let spec = client.spec();
                Ok(crate::handlers::balances::balance_json(
                    chain,
                    "native",
                    None,
                    &spec.native_symbol,
                    spec.native_decimals,
                    balance,
                ))
            }
            [leaf] if leaf == "nonce" => {
                let nonce = client.nonce(address).await.map_err(err_be)?;
                Ok(format!("{nonce}\n").into_bytes())
            }
            [dir, state, id, fname] if dir == "outbox" => {
                let entry = self.account_evm_outbox_entry(wallet, family, chain, state, id)?;
                let mut file = open_regular_outbox_artifact(&entry.dir, fname)?;
                let mut bytes = Vec::new();
                std::io::Read::read_to_end(&mut file, &mut bytes)?;
                Ok(bytes)
            }
            _ => Err(HandlerError::NotAFile(rest.join("/"))),
        }
    }

    async fn list_account_evm_chain(
        &self,
        wallet: &str,
        family: &FamilyKey,
        chain: &str,
        rest: &[String],
    ) -> Result<Vec<Entry>, HandlerError> {
        self.chains
            .get(chain)
            .ok_or_else(|| HandlerError::not_found(format!("chain '{chain}'")))?;
        match rest {
            [] => Ok(vec![
                Entry::file("balance"),
                Entry::file("balance.raw"),
                Entry::file("balance.json"),
                Entry::file("nonce"),
                Entry::dir("outbox"),
            ]),
            [dir] if dir == "outbox" => Ok(vec![
                Entry::writable_file("new.tx"),
                Entry::dir("pending"),
                Entry::dir("sent"),
                Entry::dir("failed"),
            ]),
            [dir, state] if dir == "outbox" => {
                let st = parse_state_seg(state)?;
                let ids = self
                    .tx_engine
                    .outbox
                    .list(wallet, chain, st)
                    .map_err(err_be)?;
                let mut entries = Vec::new();
                for id in ids {
                    let Ok(entry) = self.tx_engine.outbox.read_in_state(wallet, chain, &id, st)
                    else {
                        continue;
                    };
                    if entry.staged.from.eq_ignore_ascii_case(&family.address) {
                        entries.push(Entry::dir(&id).with_modified_ms(entry.staged.created_ms));
                    }
                }
                Ok(entries)
            }
            [dir, state, id] if dir == "outbox" => {
                let entry = self.account_evm_outbox_entry(wallet, family, chain, state, id)?;
                let mut out = Vec::new();
                if let Ok(read_dir) = std::fs::read_dir(&entry.dir) {
                    for item in read_dir.flatten() {
                        if let Some(name) = item.file_name().to_str()
                            && item.file_type().map(|t| t.is_file()).unwrap_or(false)
                            && !EVM_PENDING_CONTROLS.contains(&name)
                        {
                            out.push(Entry::file(name));
                        }
                    }
                }
                if entry.state == OutboxState::Pending {
                    for control in EVM_PENDING_CONTROLS {
                        out.push(Entry::writable_file(control));
                    }
                }
                Ok(out)
            }
            _ => Err(HandlerError::NotADir(rest.join("/"))),
        }
    }

    /// The outbox entry at `state/id`, only if this account's key staged it.
    /// Another account's entry is not found here, never exposed.
    fn account_evm_outbox_entry(
        &self,
        wallet: &str,
        family: &FamilyKey,
        chain: &str,
        state: &str,
        id: &str,
    ) -> Result<bloom_tx::outbox::OutboxEntry, HandlerError> {
        let st = parse_state_seg(state)?;
        let entry = self
            .tx_engine
            .outbox
            .read_in_state(wallet, chain, id, st)
            .map_err(err_be)?;
        if !entry.staged.from.eq_ignore_ascii_case(&family.address) {
            return Err(HandlerError::not_found(format!("outbox/{state}/{id}")));
        }
        Ok(entry)
    }

    // ----- Solana -----

    async fn lookup_account_solana_chain(
        &self,
        wallet: &str,
        family: &FamilyKey,
        chain: &str,
        rest: &[String],
    ) -> Result<Entry, HandlerError> {
        match rest {
            [] => Ok(Entry::dir(chain)),
            [leaf] if Self::SOLANA_ACCOUNT_LEAVES.contains(&leaf.as_str()) => Ok(Entry::file(leaf)),
            [dir] if dir == "outbox" => Ok(Entry::dir("outbox")),
            [dir, leaf] if dir == "outbox" && leaf == "new.tx" => {
                self.solana_engine(chain).ok_or_else(|| {
                    HandlerError::not_found(format!(
                        "chain '{chain}' is configured for reads only; staging is unavailable"
                    ))
                })?;
                Ok(Entry::writable_file("new.tx"))
            }
            [dir, state] if dir == "outbox" && solana_state(state).is_some() => {
                Ok(Entry::dir(state))
            }
            [dir, state, id] if dir == "outbox" => {
                let entry = self.account_solana_outbox_entry(wallet, family, chain, state, id)?;
                Ok(Entry::dir(id).with_modified_ms(entry.staged.created_ms))
            }
            [dir, state, id, fname] if dir == "outbox" => {
                let entry = self.account_solana_outbox_entry(wallet, family, chain, state, id)?;
                if solana_state(state) == Some(bloom_solana_tx::outbox::SolanaOutboxState::Pending)
                    && SOLANA_PENDING_CONTROLS.contains(&fname.as_str())
                {
                    return Ok(
                        Entry::writable_file(fname).with_modified_ms(entry.staged.created_ms)
                    );
                }
                if !is_public_solana_outbox_artifact(fname) {
                    return Err(HandlerError::not_found(fname));
                }
                open_regular_outbox_artifact(&entry.dir, fname)?;
                Ok(Entry::file(fname).with_modified_ms(entry.staged.created_ms))
            }
            _ => Err(HandlerError::not_found(rest.join("/"))),
        }
    }

    async fn read_account_solana_chain(
        &self,
        wallet: &str,
        family: &FamilyKey,
        account: &SolanaAccount,
        chain: &str,
        rest: &[String],
    ) -> Result<Vec<u8>, HandlerError> {
        match rest {
            [leaf] if leaf == "address" => Ok(format!("{}\n", account.address).into_bytes()),
            [leaf] if matches!(leaf.as_str(), "balance" | "balance.raw" | "balance.json") => {
                let lamports = self.solana_balance(chain, &account.address).await?;
                Ok(Self::solana_balance_bytes(leaf, chain, account, lamports))
            }
            [dir, state, id, fname] if dir == "outbox" => {
                if !is_public_solana_outbox_artifact(fname) {
                    return Err(HandlerError::not_found(fname));
                }
                let entry = self.account_solana_outbox_entry(wallet, family, chain, state, id)?;
                let mut file = open_regular_outbox_artifact(&entry.dir, fname)?;
                let mut bytes = Vec::new();
                std::io::Read::read_to_end(&mut file, &mut bytes)?;
                Ok(bytes)
            }
            _ => Err(HandlerError::NotAFile(rest.join("/"))),
        }
    }

    async fn list_account_solana_chain(
        &self,
        wallet: &str,
        family: &FamilyKey,
        chain: &str,
        rest: &[String],
    ) -> Result<Vec<Entry>, HandlerError> {
        let engine = self.solana_engine(chain);
        match rest {
            [] => {
                let mut entries: Vec<Entry> = Self::SOLANA_ACCOUNT_LEAVES
                    .iter()
                    .map(|leaf| Entry::file(leaf))
                    .collect();
                if engine.is_some() {
                    entries.push(Entry::dir("outbox"));
                }
                Ok(entries)
            }
            [dir] if dir == "outbox" => Ok(vec![
                Entry::writable_file("new.tx"),
                Entry::dir("pending"),
                Entry::dir("sent"),
                Entry::dir("failed"),
            ]),
            [dir, state] if dir == "outbox" => {
                let st = solana_state(state)
                    .ok_or_else(|| HandlerError::not_found(format!("outbox state '{state}'")))?;
                let engine = engine.ok_or_else(|| {
                    HandlerError::not_found(format!(
                        "chain '{chain}' is configured for reads only; staging is unavailable"
                    ))
                })?;
                let ids = engine
                    .outbox()
                    .list(wallet, chain, st)
                    .map_err(solana_outbox_err)?;
                let mut entries = Vec::new();
                for id in ids {
                    let Ok(entry) = engine.outbox().read_in_state(wallet, chain, &id, st) else {
                        continue;
                    };
                    if solana_entry_belongs(&entry.staged, &Self::solana_sender(family)) {
                        entries.push(Entry::dir(&id).with_modified_ms(entry.staged.created_ms));
                    }
                }
                Ok(entries)
            }
            [dir, state, id] if dir == "outbox" => {
                let entry = self.account_solana_outbox_entry(wallet, family, chain, state, id)?;
                let mut out = Vec::new();
                if let Ok(read_dir) = std::fs::read_dir(&entry.dir) {
                    for item in read_dir.flatten() {
                        if let Some(name) = item.file_name().to_str()
                            && item.file_type().map(|t| t.is_file()).unwrap_or(false)
                            && is_public_solana_outbox_artifact(name)
                        {
                            out.push(Entry::file(name));
                        }
                    }
                }
                if solana_state(state) == Some(bloom_solana_tx::outbox::SolanaOutboxState::Pending)
                {
                    for control in SOLANA_PENDING_CONTROLS {
                        out.push(Entry::writable_file(control));
                    }
                }
                Ok(out)
            }
            _ => Err(HandlerError::NotADir(rest.join("/"))),
        }
    }

    fn lookup_account_session(
        sessions: &[AccountSessionEntry],
        rest: &[String],
    ) -> Result<Entry, HandlerError> {
        match rest {
            [mount] => sessions
                .iter()
                .any(|session| session.petal_mount == *mount)
                .then(|| Entry::dir(mount))
                .ok_or_else(|| HandlerError::not_found(rest.join("/"))),
            [mount, slot] => sessions
                .iter()
                .find(|session| session.petal_mount == *mount && session.key_slot == *slot)
                .map(|_| Entry::dir(slot))
                .ok_or_else(|| HandlerError::not_found(rest.join("/"))),
            [mount, slot, leaf] if leaf == "session.json" => sessions
                .iter()
                .find(|session| session.petal_mount == *mount && session.key_slot == *slot)
                .map(|_| Entry::file("session.json"))
                .ok_or_else(|| HandlerError::not_found(rest.join("/"))),
            [mount, slot, leaf] if leaf == "stop" => sessions
                .iter()
                .find(|session| session.petal_mount == *mount && session.key_slot == *slot)
                .filter(|session| session.stoppable)
                .map(|_| Entry::writable_file("stop"))
                .ok_or_else(|| HandlerError::not_found(rest.join("/"))),
            _ => Err(HandlerError::not_found(rest.join("/"))),
        }
    }

    fn account_solana_outbox_entry(
        &self,
        wallet: &str,
        family: &FamilyKey,
        chain: &str,
        state: &str,
        id: &str,
    ) -> Result<bloom_solana_tx::outbox::SolanaOutboxEntry, HandlerError> {
        let st = solana_state(state)
            .ok_or_else(|| HandlerError::not_found(format!("outbox state '{state}'")))?;
        let engine = self.solana_engine(chain).ok_or_else(|| {
            HandlerError::not_found(format!(
                "chain '{chain}' is configured for reads only; staging is unavailable"
            ))
        })?;
        let entry = engine
            .outbox()
            .read_in_state(wallet, chain, id, st)
            .map_err(solana_outbox_err)?;
        if !solana_entry_belongs(&entry.staged, &Self::solana_sender(family)) {
            return Err(HandlerError::not_found(format!("outbox/{state}/{id}")));
        }
        Ok(entry)
    }
}

/// One persisted `wallets/<w>/new` request: the identity a retry must match,
/// the ceremony it launched, and, once Signer has numbered it, the account
/// the returned paths encode.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AccountCreationRecord {
    schema: String,
    wallet_id: String,
    request_id: String,
    operation_id: bloom_broker_api::OperationId,
    ceremony_url: String,
    ceremony_expires_at_ms: bloom_broker_api::DecimalU64,
    state: AccountCreationState,
    /// Set only from the authenticated custody receipt's derivation paths,
    /// never guessed before Signer numbers the account.
    number: Option<u32>,
    created_at_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum AccountCreationState {
    Pending,
    Created,
}

const ACCOUNT_CREATION_SCHEMA: &str = "bloom.machine.account-creation.v1";
const ACCOUNT_CREATIONS_SCHEMA: &str = "bloom.machine.account-creations.v1";

/// Build one of the two fixed family requests created for every account number.
fn family_request(family: &str) -> Result<bloom_broker_api::DerivedAccountRequest, HandlerError> {
    let (profile, role) = match family {
        "evm" => (
            bloom_broker_api::DerivationProfile::Bip44EvmSecp256k1V1,
            "primary-evm",
        ),
        "solana" => (
            bloom_broker_api::DerivationProfile::Bip44SolanaSlip10Ed25519V1,
            "solana-account",
        ),
        other => {
            return Err(HandlerError::invalid(format!(
                "unknown family '{other}'; supported families are \"evm\" and \"solana\""
            )));
        }
    };
    Ok(bloom_broker_api::DerivedAccountRequest {
        derivation_profile: profile,
        requested_role: bloom_broker_api::Token::new(role)
            .map_err(|error| HandlerError::invalid(error.to_string()))?,
        account: None,
    })
}

/// The same request id must always mean the same request, so the id a shell
/// writes has to be a safe single path segment before it reaches storage.
fn validate_request_id(request_id: &str) -> Result<(), HandlerError> {
    let valid = !request_id.is_empty()
        && request_id.len() <= 64
        && request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !request_id.starts_with('.');
    if valid {
        Ok(())
    } else {
        Err(HandlerError::invalid(
            "request_id must be 1-64 characters of [A-Za-z0-9._-] and not start with '.'",
        ))
    }
}

impl WalletsHandler {
    /// The Machine-local storage root for one wallet's creation requests.
    /// The wallet id is hashed into the directory name: ids may contain `/`,
    /// and a request id is never interpolated next to an unhashed id.
    fn account_creation_root(&self, wallet: &str) -> std::path::PathBuf {
        let digest = sha2::Sha256::digest(wallet.as_bytes());
        self.policy_projection_root
            .join("account-creations")
            .join(bloom_broker_api::Digest32::from_bytes(digest.into()).as_str())
    }

    fn account_creation_path(&self, wallet: &str, request_id: &str) -> std::path::PathBuf {
        self.account_creation_root(wallet)
            .join(format!("{request_id}.json"))
    }

    /// `wallets/<w>/new` write: start or resume one account-creation
    /// ceremony. The custody operation id is derived from the wallet and the
    /// request id, so a retry with the same `request_id` returns the same
    /// pending ceremony or, after success, the same account; Signer chooses
    /// the number.
    pub(super) async fn create_account(
        &self,
        wallet: &str,
        data: &[u8],
    ) -> Result<(), HandlerError> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AccountCreationRequest {
            request_id: String,
        }

        let request: AccountCreationRequest = serde_json::from_slice(data)
            .map_err(|error| HandlerError::invalid(format!("bad creation request: {error}")))?;
        let request_id = request.request_id.as_str();
        validate_request_id(request_id)?;
        let requests = vec![family_request("evm")?, family_request("solana")?];

        let path = self.account_creation_path(wallet, request_id);
        if path.exists() {
            let record: AccountCreationRecord = read_json(&path)?;
            if record.wallet_id != wallet {
                return Err(HandlerError::backend(
                    "stored account-creation record names a different wallet",
                ));
            }
            self.refresh_and_render_record(record, &path).await?;
            return Ok(());
        }

        let projection = self.wallet_projection(wallet).await?;
        if projection.wallet.root_key_ref.is_some() {
            return Err(HandlerError::invalid(
                "account creation requires a BIP-39 wallet; imported and legacy wallets have no \
                 derivation capability",
            ));
        }
        let broker = self.custody_broker()?;
        let operation_id = bloom_broker_api::OperationId::from_bytes(
            sha2::Sha256::digest(
                format!("bloom-account-creation/v1\0{wallet}\0{request_id}").as_bytes(),
            )
            .into(),
        );
        let wallet_id = bloom_broker_api::Token::new(wallet.to_owned())
            .map_err(|error| HandlerError::invalid(error.to_string()))?;
        let anchor = requests
            .iter()
            .find(|request| {
                request.derivation_profile
                    == bloom_broker_api::DerivationProfile::Bip44EvmSecp256k1V1
            })
            .unwrap_or(&requests[0]);
        let profile = anchor.derivation_profile;
        let expires_at_ms = now_ms_u64().saturating_add(30 * 60 * 1_000);
        let terms = bloom_broker_api::AccountTerms {
            schema: bloom_broker_api::Token::new(bloom_broker_api::ACCOUNT_TERMS_SCHEMA)
                .map_err(|error| HandlerError::invalid(error.to_string()))?,
            wallet_id: wallet_id.clone(),
            seed_profile: bloom_broker_api::WalletSeedProfile::Bip39MulticurveV1,
            derivations: requests.clone(),
            retire_key_fingerprint: None,
            path_template: profile.path_template().to_owned(),
            key_spec: profile.key_spec(),
            allowed_crypto_suites: profile.frozen_crypto_suites().to_vec(),
            policy_version: projection.policy.version.clone(),
            revocation_epoch: projection.wallet.wallet_revocation_epoch.clone(),
            replay_id: operation_id.clone(),
            expires_at_ms: bloom_broker_api::DecimalU64::new(expires_at_ms),
            audit_purpose: bloom_broker_api::Token::new("allocate-derived-account")
                .map_err(|error| HandlerError::invalid(error.to_string()))?,
        };
        let prepared = broker
            .account_allocate(bloom_broker_api::CustodyPrepareRequest {
                ceremony_kind: bloom_broker_api::CeremonyKind::AccountAllocate,
                custody_operation_id: operation_id.clone(),
                wallet_id: Some(wallet_id),
                key_ref: None,
                exact_terms_digest: terms
                    .request_digest()
                    .map_err(|error| HandlerError::backend(error.to_string()))?,
                expected_input_class: bloom_broker_api::Token::new("generic-custody-v1")
                    .map_err(|error| HandlerError::invalid(error.to_string()))?,
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: None,
                derivation_requests: requests,
                account_terms: Some(terms),
            })
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        let record = AccountCreationRecord {
            schema: ACCOUNT_CREATION_SCHEMA.to_owned(),
            wallet_id: wallet.to_owned(),
            request_id: request_id.to_owned(),
            operation_id,
            ceremony_url: prepared.ceremony_url.clone(),
            ceremony_expires_at_ms: prepared.ceremony_expires_at_ms,
            state: AccountCreationState::Pending,
            number: None,
            created_at_ms: now_ms_u64(),
        };
        std::fs::create_dir_all(self.account_creation_root(wallet))?;
        write_atomic_json(&path, &record)?;
        // The caller reads `new` back for the status document: the ceremony
        // URL now, and the assigned number once Signer has committed it.
        Ok(())
    }

    /// Re-check a pending ceremony and render the record. Completion is read
    /// only from the authenticated receipt: every returned child must belong
    /// to this wallet, include both fixed profiles, and share one number.
    async fn refresh_and_render_record(
        &self,
        mut record: AccountCreationRecord,
        path: &std::path::Path,
    ) -> Result<Vec<u8>, HandlerError> {
        if record.state == AccountCreationState::Created {
            return Self::render_record(&record, true);
        }
        let broker = self.custody_broker()?;
        let status = broker
            .ceremony_status(record.operation_id.clone())
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        if status.state != bloom_broker_api::CeremonyState::Succeeded {
            // Still pending (or terminal-failed, which the ceremony URL
            // surfaces); the record stays as it is.
            return Self::render_record(&record, false);
        }
        let receipt = broker
            .custody_result(bloom_broker_api::OperationRequest {
                operation_id: record.operation_id.clone(),
            })
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        if !receipt
            .wallet_id
            .as_ref()
            .is_some_and(|wallet| wallet.as_str() == record.wallet_id)
            || receipt.public_key_refs.len() != 2
        {
            return Err(HandlerError::backend(
                "account-creation receipt contradicts the stored request",
            ));
        }
        let mut number: Option<u32> = None;
        let mut seen = std::collections::HashSet::new();
        for child in &receipt.public_key_refs {
            let Some(bloom_broker_api::DerivationRef::Bip39Multicurve {
                wallet_seed_ref,
                profile,
                path: derivation_path,
            }) = child.derivation.clone()
            else {
                return Err(HandlerError::backend(
                    "account-creation receipt carries a non-derived child",
                ));
            };
            if wallet_seed_ref.as_str() != record.wallet_id
                || !seen.insert(profile)
                || !matches!(
                    profile,
                    bloom_broker_api::DerivationProfile::Bip44EvmSecp256k1V1
                        | bloom_broker_api::DerivationProfile::Bip44SolanaSlip10Ed25519V1
                )
            {
                return Err(HandlerError::backend(
                    "account-creation receipt family set contradicts the stored request",
                ));
            }
            let digits = match profile {
                bloom_broker_api::DerivationProfile::Bip44EvmSecp256k1V1 => derivation_path
                    .strip_prefix("m/44'/60'/0'/0/")
                    .ok_or_else(|| HandlerError::backend("unexpected EVM path in receipt"))?,
                bloom_broker_api::DerivationProfile::Bip44SolanaSlip10Ed25519V1 => derivation_path
                    .strip_prefix("m/44'/501'/")
                    .and_then(|rest| rest.strip_suffix("'/0'"))
                    .ok_or_else(|| HandlerError::backend("unexpected Solana path in receipt"))?,
            };
            let child_number: u32 = digits
                .parse()
                .map_err(|error| HandlerError::backend(format!("bad account path: {error}")))?;
            match number {
                Some(previous) if previous != child_number => {
                    return Err(HandlerError::backend(
                        "account-creation receipt families disagree on the account number",
                    ));
                }
                None => number = Some(child_number),
                _ => {}
            }
        }
        record.state = AccountCreationState::Created;
        record.number = number;
        write_atomic_json(path, &record)?;
        Self::render_record(&record, true)
    }

    fn render_record(
        record: &AccountCreationRecord,
        already_created: bool,
    ) -> Result<Vec<u8>, HandlerError> {
        let mut out = serde_json::to_vec_pretty(&serde_json::json!({
            "schema": ACCOUNT_CREATIONS_SCHEMA,
            "request_id": record.request_id,
            "state": record.state,
            "ceremony_url": record.ceremony_url,
            "ceremony_expires_at_ms": record.ceremony_expires_at_ms,
            "number": record.number,
            "already_created": already_created,
        }))
        .map_err(err_be)?;
        out.push(b'\n');
        Ok(out)
    }

    /// `wallets/<w>/new` read: every stored creation request for the wallet,
    /// pending ones re-checked against the ceremony.
    pub(super) async fn account_creation_status(
        &self,
        wallet: &str,
    ) -> Result<Vec<u8>, HandlerError> {
        let root = self.account_creation_root(wallet);
        let mut requests: Vec<serde_json::Value> = Vec::new();
        let Ok(entries) = std::fs::read_dir(&root) else {
            // No creation request has ever been stored for this wallet.
            let mut out = serde_json::to_vec_pretty(&serde_json::json!({
                "schema": ACCOUNT_CREATIONS_SCHEMA,
                "wallet": wallet,
                "requests": requests,
            }))
            .map_err(err_be)?;
            out.push(b'\n');
            return Ok(out);
        };
        let mut paths: Vec<std::path::PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().map(|ext| ext == "json").unwrap_or(false))
            .collect();
        paths.sort();
        for path in paths {
            let record: AccountCreationRecord = read_json(&path)?;
            if record.wallet_id != wallet {
                continue;
            }
            let rendered = self.refresh_and_render_record(record, &path).await?;
            requests.push(
                serde_json::from_slice(&rendered)
                    .map_err(|error| HandlerError::backend(error.to_string()))?,
            );
        }
        let mut out = serde_json::to_vec_pretty(&serde_json::json!({
            "schema": ACCOUNT_CREATIONS_SCHEMA,
            "wallet": wallet,
            "requests": requests,
        }))
        .map_err(err_be)?;
        out.push(b'\n');
        Ok(out)
    }
}

/// The virtual write sinks a pending EVM entry advertises.
const EVM_PENDING_CONTROLS: [&str; 4] = ["confirm", "confirm.override", "replace", "cancel"];
/// The virtual write sinks a pending Solana entry advertises.
const SOLANA_PENDING_CONTROLS: [&str; 3] = ["confirm", "cancel", "restage"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_segments_are_canonical_decimal_numbers() {
        assert_eq!(parse_account_segment("0"), Some(0));
        assert_eq!(parse_account_segment("17"), Some(17));
        assert_eq!(parse_account_segment("2147483647"), Some(2_147_483_647));
        for rejected in ["", "01", "-1", "1a", "2147483648", "chains", "00"] {
            assert_eq!(parse_account_segment(rejected), None, "{rejected:?}");
        }
    }

    fn derived(profile: DerivationProfile, path: &str) -> DerivedAccountPublic {
        let (key_spec, encoding, public_key) = match profile {
            DerivationProfile::Bip44EvmSecp256k1V1 => (
                bloom_broker_api::KeySpec::Secp256k1,
                bloom_broker_api::PublicKeyEncoding::Secp256k1SpkiDer,
                vec![2u8; 88],
            ),
            DerivationProfile::Bip44SolanaSlip10Ed25519V1 => (
                bloom_broker_api::KeySpec::Ed25519,
                bloom_broker_api::PublicKeyEncoding::Ed25519SpkiDer,
                vec![3u8; 44],
            ),
        };
        DerivedAccountPublic {
            key_ref: bloom_broker_api::KeyRef {
                backend: bloom_broker_api::Token::new("local").unwrap(),
                backend_instance: bloom_broker_api::Token::new("w").unwrap(),
                locator: path.to_owned(),
                key_spec,
                public_key_fingerprint: bloom_broker_api::Digest32::from_bytes([7; 32]),
                derivation: None,
            },
            wallet_seed_profile: bloom_broker_api::WalletSeedProfile::Bip39MulticurveV1,
            derivation_profile: profile,
            path: path.to_owned(),
            canonical_public_key: bloom_broker_api::Base64UrlBytes::from_bytes(&public_key),
            public_key_encoding: encoding,
            public_key_fingerprint: bloom_broker_api::Digest32::from_bytes([7; 32]),
            supported_crypto_suites: profile.frozen_crypto_suites().to_vec(),
            chain_projections: Vec::new(),
            lifecycle: AccountLifecycleState::Active,
        }
    }

    #[test]
    fn account_numbers_come_from_the_default_paths_only() {
        let evm = DerivationProfile::Bip44EvmSecp256k1V1;
        let solana = DerivationProfile::Bip44SolanaSlip10Ed25519V1;
        assert_eq!(account_number(&derived(evm, "m/44'/60'/0'/0/0")), Some(0));
        assert_eq!(account_number(&derived(evm, "m/44'/60'/0'/0/12")), Some(12));
        assert_eq!(
            account_number(&derived(solana, "m/44'/501'/0'/0'")),
            Some(0)
        );
        assert_eq!(
            account_number(&derived(solana, "m/44'/501'/12'/0'")),
            Some(12)
        );
        // A different hardened account is a different tree, not a number.
        assert_eq!(account_number(&derived(evm, "m/44'/60'/1'/0/0")), None);
        assert_eq!(account_number(&derived(solana, "m/44'/501'/1'/1'")), None);
    }
}
