//! `wallets/<wallet>/...` — managed wallets and the outbox write surface.
//!
//! This handler wires keystore + chain + tx engine together. Reads expose
//! wallet metadata and per-chain balance/nonce; writes go through the
//! outbox stage-confirm flow.
//!
//! Paths handled:
//! - `wallets/`                                                     — list wallets
//! - `wallets/new`                                                  — write to create wallet (plain name or TOML spec)
//! - `wallets/<wallet>/address`                                     — checksummed address
//! - `wallets/<wallet>/public_key`                                  — secp256k1 pubkey hex
//! - `wallets/<wallet>/kind`                                        — local/watch
//! - `wallets/<wallet>/policy.toml`                                 — read+write policy
//! - `wallets/<wallet>/chains/<chain>/balance(.eth|.raw)`           — native balance
//! - `wallets/<wallet>/chains/<chain>/nonce`
//! - `wallets/<wallet>/chains/<chain>/outbox/new.tx`                — write to stage
//! - `wallets/<wallet>/chains/<chain>/outbox/pending/<id>/<file>`   — read staged
//! - `wallets/<wallet>/chains/<chain>/outbox/pending/<id>/confirm`  — write to broadcast
//! - `wallets/<wallet>/chains/<chain>/outbox/sent/<id>/<file>`      — read sent
//! - `wallets/<wallet>/chains/<chain>/outbox/failed/<id>/<file>`    — read failed

use std::sync::Arc;

use alloy::signers::SignerSync;
use async_trait::async_trait;
use bloom_chain::ChainRegistry;
use bloom_keystore::Keystore;
use bloom_proto::{AddressBook, HomeWritePermit, RawIntent, format_units};
use bloom_tx::{
    intent_parser,
    outbox::OutboxState,
    tx_engine::{TxEngine, TxEngineError},
};

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

#[derive(Clone)]
pub struct WalletsHandler {
    pub keystore: Keystore,
    pub chains: ChainRegistry,
    pub tx_engine: TxEngine,
    pub address_book: Arc<AddressBook>,
    pub home_write_permit: Option<Arc<HomeWritePermit>>,
    pub mempool_indexes:
        Arc<std::collections::BTreeMap<String, Arc<bloom_mempool::PendingTxIndex>>>,
}

impl WalletsHandler {
    pub fn new(
        keystore: Keystore,
        chains: ChainRegistry,
        tx_engine: TxEngine,
        address_book: AddressBook,
    ) -> Self {
        Self {
            keystore,
            chains,
            tx_engine,
            address_book: Arc::new(address_book),
            home_write_permit: None,
            mempool_indexes: Arc::new(std::collections::BTreeMap::new()),
        }
    }

    pub fn with_home_write_permit(mut self, permit: Arc<HomeWritePermit>) -> Self {
        self.home_write_permit = Some(permit);
        self
    }

    pub fn with_home_write_permit_opt(mut self, permit: Option<Arc<HomeWritePermit>>) -> Self {
        self.home_write_permit = permit;
        self
    }

    pub fn with_mempool_indexes(
        mut self,
        indexes: std::collections::BTreeMap<String, Arc<bloom_mempool::PendingTxIndex>>,
    ) -> Self {
        self.mempool_indexes = Arc::new(indexes);
        self
    }

    fn write_permit(&self) -> Result<&HomeWritePermit, HandlerError> {
        self.home_write_permit.as_deref().ok_or_else(|| {
            HandlerError::backend(
                "wallet write surface is not attached to a home write permit; refusing mutation",
            )
        })
    }

    fn wallet_dir_entries(kind: bloom_keystore::WalletKind) -> Vec<Entry> {
        let mut entries = vec![
            Entry::file("address"),
            Entry::file("public_key"),
            Entry::file("kind"),
            Entry::file("policy.toml"),
            Entry::dir("chains"),
            Entry::dir("sign"),
        ];
        if kind == bloom_keystore::WalletKind::PasskeyGated {
            entries.push(Entry::writable_file("unlock-passkey"));
        }
        entries
    }

    fn sign_dir_entries() -> Vec<Entry> {
        vec![
            Entry::writable_file("message"),
            Entry::writable_file("hash"),
            Entry::writable_file("typed_data"),
        ]
    }

    fn outbox_dir_entries() -> Vec<Entry> {
        vec![
            Entry::file("new.tx"),
            Entry::dir("pending"),
            Entry::dir("sent"),
            Entry::dir("failed"),
        ]
    }
}

fn err_be(e: impl std::fmt::Display) -> HandlerError {
    HandlerError::backend(e.to_string())
}

/// Parse a state segment (`pending` / `sent` / `failed`) into an
/// [`OutboxState`], rejecting anything else as NotFound.
fn parse_state_seg(s: &str) -> Result<OutboxState, HandlerError> {
    OutboxState::parse(s).ok_or_else(|| HandlerError::not_found(format!("outbox state '{}'", s)))
}

fn split_confirm_review_hash(confirm_text: &str) -> (&str, Option<&str>) {
    let mut lines = confirm_text.lines();
    let first = lines.next().unwrap_or(confirm_text).trim();
    let review_hash = lines.find_map(|line| {
        line.trim()
            .strip_prefix("review_hash=")
            .map(str::trim)
            .filter(|s| !s.is_empty())
    });
    (first, review_hash)
}

#[async_trait]
impl Handler for WalletsHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let r = self.lookup_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(
                path = %path.to_string_path(),
                error = %e,
                "wallets.lookup_err"
            );
        }
        r
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let r = self.read_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(
                path = %path.to_string_path(),
                error = %e,
                "wallets.read_err"
            );
        }
        r
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let r = self.write_inner(path, data).await;
        if let Err(e) = &r {
            tracing::debug!(
                path = %path.to_string_path(),
                bytes = data.len(),
                error = %e,
                "wallets.write_err"
            );
        }
        r
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let r = self.list_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(
                path = %path.to_string_path(),
                error = %e,
                "wallets.list_err"
            );
        }
        r
    }

    /// Defense-in-depth gate against the mount layer rendering at
    /// GETATTR. Sign / outbox-control paths are write-only sinks (mode
    /// 0o644) so the mount-side mode-bit check already skips them, but
    /// we declare them side-effecting here too so any future caller
    /// that bypasses the mode check still cannot trigger a sign or
    /// broadcast just by stat'ing.
    fn is_read_side_effecting(&self, path: &VfsPath) -> bool {
        let segs = path.segments();
        // wallets/<w>/sign/<kind>
        if segs.len() == 3
            && segs[1] == "sign"
            && matches!(segs[2].as_str(), "message" | "hash" | "typed_data")
        {
            return true;
        }
        // wallets/<w>/chains/<c>/outbox/pending/<id>/{confirm,replace,cancel}
        if segs.len() == 7
            && segs[1] == "chains"
            && segs[3] == "outbox"
            && segs[4] == "pending"
            && matches!(segs[6].as_str(), "confirm" | "replace" | "cancel")
        {
            return true;
        }
        false
    }
}

impl WalletsHandler {
    async fn lookup_inner(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segs = path.segments();
        if segs.is_empty() {
            return Ok(Entry::dir(""));
        }
        if segs.len() == 1 && segs[0] == "new" {
            return Ok(Entry::writable_file("new"));
        }
        let wallet = &segs[0];
        let info = self.keystore.info(wallet).map_err(err_be)?;
        if segs.len() == 1 {
            return Ok(Entry::dir(wallet));
        }
        match segs[1].as_str() {
            "address" | "public_key" | "kind" => Ok(Entry::file(&segs[1])),
            "policy.toml" => Ok(Entry::writable_file("policy.toml")),
            "unlock-passkey" if info.kind == bloom_keystore::WalletKind::PasskeyGated => {
                Ok(Entry::writable_file("unlock-passkey"))
            }
            "sign" => match segs.len() {
                2 => Ok(Entry::dir("sign")),
                3 if matches!(segs[2].as_str(), "message" | "hash" | "typed_data") => {
                    Ok(Entry::writable_file(&segs[2]))
                }
                _ => Err(HandlerError::not_found(path.to_string_path())),
            },
            "chains" => match segs.len() {
                2 => Ok(Entry::dir("chains")),
                3 => {
                    let _ = self
                        .chains
                        .get(&segs[2])
                        .ok_or_else(|| HandlerError::not_found(format!("chain '{}'", segs[2])))?;
                    Ok(Entry::dir(&segs[2]))
                }
                _ => self.lookup_chain(wallet, &segs[2], &segs[3..]).await,
            },
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn read_inner(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = path.segments();
        if segs.is_empty() {
            return Err(HandlerError::NotAFile(path.to_string_path()));
        }
        if segs.len() == 1 && segs[0] == "new" {
            return Ok(b"# write a wallet name (plain text) or a TOML spec to create a wallet\n# examples:\n#   echo alice > /wallets/new\n#   printf 'name = \"alice\"\\nkind = \"local\"\\n' > /wallets/new\n# kind: local | import (with private_key) | watch (with address)\n".to_vec());
        }
        let wallet = &segs[0];
        let info = self.keystore.info(wallet).map_err(err_be)?;
        match segs.get(1).map(|s| s.as_str()).unwrap_or("") {
            "address" => {
                Ok(format!("{}\n", bloom_proto::checksum_address(&info.address)).into_bytes())
            }
            "public_key" => Ok(format!("0x{}\n", info.pubkey_hex).into_bytes()),
            "kind" => {
                let s = match info.kind {
                    bloom_keystore::WalletKind::Local => "local",
                    bloom_keystore::WalletKind::Watch => "watch",
                    bloom_keystore::WalletKind::PasskeyGated => "passkey",
                };
                Ok(format!("{}\n", s).into_bytes())
            }
            "policy.toml" => {
                let body = toml::to_string_pretty(&info.policy).map_err(err_be)?;
                Ok(body.into_bytes())
            }
            "chains" if segs.len() >= 4 => self.read_chain(wallet, &segs[2], &segs[3..]).await,
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn write_inner(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let segs = path.segments();
        if segs.is_empty() {
            return Err(HandlerError::PermissionDenied);
        }
        if segs.len() == 1 && segs[0] == "new" {
            return self.write_new_wallet(data).await;
        }
        let wallet = &segs[0];
        let info = self.keystore.info(wallet).map_err(err_be)?;
        if segs.len() >= 4 && segs[1] == "chains" && segs[3] == "outbox" {
            return self.write_outbox(wallet, &segs[2], &segs[4..], data).await;
        }
        if segs.len() == 3 && segs[1] == "sign" {
            return self.write_sign(wallet, &segs[2], data).await;
        }
        if segs.len() == 2 && segs[1] == "policy.toml" {
            self.keystore.write_policy(wallet, data).map_err(err_be)?;
            return Ok(());
        }
        // PasskeyGated wallet: browser WebAuthn authentication ceremony.
        if segs.len() == 2 && segs[1] == "unlock-passkey" {
            if info.kind != bloom_keystore::WalletKind::PasskeyGated {
                return Err(HandlerError::invalid(
                    "unlock-passkey only applies to passkey wallets",
                ));
            }
            if self.keystore.signer(wallet).is_ok() {
                return Ok(()); // already unlocked — ceremony not needed
            }
            self.keystore.unlock_passkey(wallet).await.map_err(err_be)?;
            return Ok(());
        }
        Err(HandlerError::PermissionDenied)
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segs = path.segments();
        if segs.is_empty() {
            let infos = self.keystore.list().map_err(err_be)?;
            let mut out: Vec<Entry> = infos.into_iter().map(|i| Entry::dir(&i.name)).collect();
            out.push(Entry::writable_file("new"));
            return Ok(out);
        }
        let wallet = &segs[0];
        let info = self.keystore.info(wallet).map_err(err_be)?;
        match segs.len() {
            1 => Ok(Self::wallet_dir_entries(info.kind)),
            2 if segs[1] == "chains" => Ok(self
                .chains
                .list_names()
                .into_iter()
                .map(|n| Entry::dir(&n))
                .collect()),
            2 if segs[1] == "sign" => Ok(Self::sign_dir_entries()),
            n if n >= 3 && segs[1] == "chains" => {
                self.list_chain(wallet, &segs[2], &segs[3..]).await
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }
}

impl WalletsHandler {
    async fn lookup_chain(
        &self,
        _wallet: &str,
        chain: &str,
        rest: &[String],
    ) -> Result<Entry, HandlerError> {
        let _client = self
            .chains
            .get(chain)
            .ok_or_else(|| HandlerError::not_found(format!("chain '{}'", chain)))?;
        match rest {
            [] => Ok(Entry::dir(chain)),
            [s] if s == "balance" || s == "balance.eth" || s == "balance.raw" || s == "nonce" => {
                Ok(Entry::file(s))
            }
            [s] if s == "pending_external.jsonl" || s == "nonce_conflicts.json" => {
                Ok(Entry::file(s))
            }
            [s] if s == "outbox" => Ok(Entry::dir("outbox")),
            [s, ..] if s == "outbox" => self.lookup_outbox(_wallet, chain, &rest[1..]).await,
            _ => Err(HandlerError::not_found(rest.join("/"))),
        }
    }

    async fn lookup_outbox(
        &self,
        wallet: &str,
        chain: &str,
        rest: &[String],
    ) -> Result<Entry, HandlerError> {
        match rest {
            [] => Ok(Entry::dir("outbox")),
            [s] if s == "new.tx" => Ok(Entry::writable_file("new.tx")),
            [s] if s == "pending" || s == "sent" || s == "failed" => Ok(Entry::dir(s)),
            [state, id] => {
                let st = parse_state_seg(state)?;
                // Confirm the entry actually lives in the requested state
                // (fix #8): a stale path like `outbox/sent/<pending-id>`
                // should NotFound, not silently succeed.
                self.tx_engine
                    .outbox
                    .read_in_state(wallet, chain, id, st)
                    .map_err(err_be)?;
                Ok(Entry::dir(id))
            }
            [state, id, fname] => {
                let st = parse_state_seg(state)?;
                self.tx_engine
                    .outbox
                    .read_in_state(wallet, chain, id, st)
                    .map_err(err_be)?;
                // Pending entries advertise the writable controls
                // (`confirm`, `replace`, `cancel`) even when those files
                // don't yet exist on disk — they are virtual write sinks.
                if st == OutboxState::Pending
                    && (fname == "confirm" || fname == "replace" || fname == "cancel")
                {
                    Ok(Entry::writable_file(fname))
                } else {
                    Ok(Entry::file(fname))
                }
            }
            _ => Err(HandlerError::not_found(rest.join("/"))),
        }
    }

    /// Collect the set of tx hashes (lowercased `0x...` hex) that bloom
    /// itself has staged or sent for `(wallet, chain)`. Used to filter
    /// the mempool-index snapshot so we don't double-count our own txs
    /// as "external pending" / "nonce conflict".
    fn bloom_staged_hashes(&self, wallet: &str, chain: &str) -> std::collections::HashSet<String> {
        let mut out = std::collections::HashSet::new();
        for st in [OutboxState::Pending, OutboxState::Sent] {
            let ids = match self.tx_engine.outbox.list(wallet, chain, st) {
                Ok(v) => v,
                Err(_) => continue,
            };
            for id in ids {
                let Ok(entry) = self.tx_engine.outbox.read_in_state(wallet, chain, &id, st) else {
                    continue;
                };
                if let Some(h) = entry.staged.tx_hash.as_deref() {
                    out.insert(h.to_lowercase());
                }
            }
        }
        out
    }

    /// Read bloom's outbox view of nonces for `(wallet, chain)` in the
    /// given state. Returns `(sorted_unique_nonces, nonce -> hashes)`
    /// where the hash list contains only entries that already have a
    /// `tx_hash` (pending entries may not).
    fn bloom_outbox_nonces(
        &self,
        wallet: &str,
        chain: &str,
        state: OutboxState,
    ) -> (Vec<u64>, std::collections::BTreeMap<u64, Vec<String>>) {
        let mut by_nonce: std::collections::BTreeMap<u64, Vec<String>> =
            std::collections::BTreeMap::new();
        let mut nonces: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        let ids = match self.tx_engine.outbox.list(wallet, chain, state) {
            Ok(v) => v,
            Err(_) => return (Vec::new(), by_nonce),
        };
        for id in ids {
            let Ok(entry) = self
                .tx_engine
                .outbox
                .read_in_state(wallet, chain, &id, state)
            else {
                continue;
            };
            nonces.insert(entry.staged.nonce);
            if let Some(h) = entry.staged.tx_hash.as_deref() {
                by_nonce
                    .entry(entry.staged.nonce)
                    .or_default()
                    .push(h.to_lowercase());
            }
        }
        (nonces.into_iter().collect(), by_nonce)
    }

    async fn read_chain(
        &self,
        wallet: &str,
        chain: &str,
        rest: &[String],
    ) -> Result<Vec<u8>, HandlerError> {
        let info = self.keystore.info(wallet).map_err(err_be)?;
        let client = self
            .chains
            .get(chain)
            .ok_or_else(|| HandlerError::not_found(format!("chain '{}'", chain)))?;
        match rest {
            [s] if s == "balance" || s == "balance.raw" => {
                let bal = client.balance(info.address).await.map_err(err_be)?;
                Ok(format!("{}\n", bal).into_bytes())
            }
            [s] if s == "balance.eth" => {
                let bal = client.balance(info.address).await.map_err(err_be)?;
                let spec = client.spec();
                Ok(format!(
                    "{} {}\n",
                    format_units(bal, spec.native_decimals),
                    spec.native_symbol
                )
                .into_bytes())
            }
            [s] if s == "nonce" => {
                let n = client.nonce(info.address).await.map_err(err_be)?;
                Ok(format!("{}\n", n).into_bytes())
            }
            [s, state, id, fname] if s == "outbox" => {
                let st = parse_state_seg(state)?;
                // Honour the path's state segment (fix #8): only read from
                // the requested state, NotFound otherwise.
                let entry = self
                    .tx_engine
                    .outbox
                    .read_in_state(wallet, chain, id, st)
                    .map_err(err_be)?;
                let path = entry.dir.join(fname.as_str());
                let bytes = std::fs::read(&path).map_err(HandlerError::Io)?;
                Ok(bytes)
            }
            [s] if s == "pending_external.jsonl" => {
                // Cross-reference against the outbox so we don't surface
                // bloom's own txs as "external pending". A tx is external
                // iff its hash is NOT in the union of pending+sent outbox
                // entries for this wallet+chain (pending entries may have
                // no hash yet — those are dropped from the exclusion set).
                let idx = match self.mempool_indexes.get(chain) {
                    Some(i) => i,
                    None => return Ok(Vec::new()),
                };
                let own_hashes = self.bloom_staged_hashes(wallet, chain);
                let mut out = Vec::new();
                for tx in idx
                    .snapshot()
                    .into_iter()
                    .filter(|t| t.from == info.address)
                {
                    let hex = format!("{:?}", tx.hash).to_lowercase();
                    if own_hashes.contains(&hex) {
                        continue;
                    }
                    serde_json::to_writer(&mut out, &tx).map_err(err_be)?;
                    out.push(b'\n');
                }
                Ok(out)
            }
            [s] if s == "nonce_conflicts.json" => {
                // A real conflict is a (nonce, hash) the mempool index
                // observed for this wallet that doesn't match any of
                // bloom's own outbox entries at that nonce. Report the
                // raw observed_nonces set for backward compat, and add
                // the outbox-side view + the computed conflict list.
                let (observed, mempool_by_nonce) = match self.mempool_indexes.get(chain) {
                    Some(i) => {
                        let snap = i.snapshot();
                        let observed = i.observed_nonces(info.address);
                        // (nonce -> hash) for this address in the mempool.
                        // Multiple entries at the same nonce are possible
                        // (replacements). We surface them all as candidate
                        // conflicts and let the dedupe against our own
                        // hashes filter them out below.
                        let mut by_nonce: std::collections::BTreeMap<u64, Vec<String>> =
                            std::collections::BTreeMap::new();
                        for tx in snap.into_iter().filter(|t| t.from == info.address) {
                            let hex = format!("{:?}", tx.hash).to_lowercase();
                            by_nonce.entry(tx.nonce).or_default().push(hex);
                        }
                        (observed, by_nonce)
                    }
                    None => (Vec::new(), std::collections::BTreeMap::new()),
                };
                let (pending_nonces, pending_by_nonce) =
                    self.bloom_outbox_nonces(wallet, chain, OutboxState::Pending);
                let (sent_nonces, sent_by_nonce) =
                    self.bloom_outbox_nonces(wallet, chain, OutboxState::Sent);
                // Union of nonces we ourselves staged or sent: any nonce
                // the mempool also sees here is a candidate for conflict.
                let mut conflicts: Vec<serde_json::Value> = Vec::new();
                let mut outbox_by_nonce: std::collections::BTreeMap<u64, Vec<String>> =
                    std::collections::BTreeMap::new();
                for (n, hs) in pending_by_nonce.iter().chain(sent_by_nonce.iter()) {
                    outbox_by_nonce
                        .entry(*n)
                        .or_default()
                        .extend(hs.iter().cloned());
                }
                for (nonce, mempool_hashes) in mempool_by_nonce.iter() {
                    let Some(outbox_hashes) = outbox_by_nonce.get(nonce) else {
                        continue;
                    };
                    for mh in mempool_hashes {
                        // Only flag when the mempool's hash isn't one of
                        // our own — i.e. someone else (or a re-broadcast
                        // we don't recognise) is occupying our nonce.
                        if outbox_hashes.iter().any(|oh| oh == mh) {
                            continue;
                        }
                        // Pick any outbox hash at this nonce for the
                        // report; callers can cross-reference if they
                        // want more detail.
                        let outbox_hash = outbox_hashes.first().cloned();
                        conflicts.push(serde_json::json!({
                            "nonce": nonce,
                            "mempool_hash": mh,
                            "outbox_hash": outbox_hash,
                        }));
                    }
                }
                let body = serde_json::json!({
                    "address": bloom_proto::checksum_address(&info.address),
                    "observed_nonces": observed,
                    "outbox_pending_nonces": pending_nonces,
                    "outbox_sent_nonces": sent_nonces,
                    "conflicts": conflicts,
                });
                serde_json::to_vec_pretty(&body).map_err(err_be)
            }
            _ => Err(HandlerError::NotAFile(rest.join("/"))),
        }
    }

    async fn list_chain(
        &self,
        wallet: &str,
        chain: &str,
        rest: &[String],
    ) -> Result<Vec<Entry>, HandlerError> {
        let _info = self.keystore.info(wallet).map_err(err_be)?;
        let _client = self
            .chains
            .get(chain)
            .ok_or_else(|| HandlerError::not_found(format!("chain '{}'", chain)))?;
        match rest {
            [] => Ok(vec![
                Entry::file("balance"),
                Entry::file("balance.eth"),
                Entry::file("balance.raw"),
                Entry::file("nonce"),
                Entry::file("pending_external.jsonl"),
                Entry::file("nonce_conflicts.json"),
                Entry::dir("outbox"),
            ]),
            [s] if s == "outbox" => Ok(Self::outbox_dir_entries()),
            [s, state] if s == "outbox" => {
                let st = match state.as_str() {
                    "pending" => OutboxState::Pending,
                    "sent" => OutboxState::Sent,
                    "failed" => OutboxState::Failed,
                    _ => return Err(HandlerError::not_found(state.clone())),
                };
                let ids = self
                    .tx_engine
                    .outbox
                    .list(wallet, chain, st)
                    .map_err(err_be)?;
                Ok(ids.into_iter().map(|n| Entry::dir(&n)).collect())
            }
            [s, state, id] if s == "outbox" => {
                let st = parse_state_seg(state)?;
                // The state segment is authoritative (fix #8): if the id
                // isn't in this state we report NotFound rather than
                // shadowing whatever lives at the other states.
                let entry = self
                    .tx_engine
                    .outbox
                    .read_in_state(wallet, chain, id, st)
                    .map_err(err_be)?;
                let mut out = Vec::new();
                if let Ok(rd) = std::fs::read_dir(&entry.dir) {
                    for r in rd.flatten() {
                        if let Some(n) = r.file_name().to_str() {
                            if r.file_type().map(|t| t.is_file()).unwrap_or(false) {
                                // Pending entries' control files (confirm /
                                // replace / cancel) are writable; everything
                                // else is read-only metadata.
                                if entry.state == OutboxState::Pending
                                    && (n == "confirm" || n == "replace" || n == "cancel")
                                {
                                    out.push(Entry::writable_file(n));
                                } else {
                                    out.push(Entry::file(n));
                                }
                            } else {
                                out.push(Entry::dir(n));
                            }
                        }
                    }
                }
                // Always advertise the pending control files even before
                // they've been written, so agents can `echo y > confirm`
                // (and similarly for replace / cancel — fix #10).
                if entry.state == OutboxState::Pending {
                    for ctrl in ["confirm", "replace", "cancel"] {
                        if !out.iter().any(|e| e.name == ctrl) {
                            out.push(Entry::writable_file(ctrl));
                        }
                    }
                }
                Ok(out)
            }
            _ => Err(HandlerError::NotADir(rest.join("/"))),
        }
    }

    async fn write_outbox(
        &self,
        wallet: &str,
        chain: &str,
        rest: &[String],
        data: &[u8],
    ) -> Result<(), HandlerError> {
        let info = self.keystore.info(wallet).map_err(err_be)?;
        let client = self
            .chains
            .get(chain)
            .ok_or_else(|| HandlerError::not_found(format!("chain '{}'", chain)))?;
        match rest {
            // outbox/new.tx — stage
            [s] if s == "new.tx" => {
                let body = std::str::from_utf8(data)
                    .map_err(|_| HandlerError::invalid("non-utf8 intent"))?;
                let intent: RawIntent = intent_parser::parse(body).map_err(err_be)?;
                let staged = self
                    .tx_engine
                    .stage(
                        self.write_permit()?,
                        wallet,
                        info.address,
                        intent,
                        &client,
                        &info.policy,
                        Some(&self.address_book),
                    )
                    .await
                    .map_err(err_be)?;
                tracing::info!(wallet, chain, id = %staged.id, "outbox.staged");
                Ok(())
            }
            // outbox/pending/<id>/confirm — broadcast
            [state, id, fname] if state == "pending" && fname == "confirm" => {
                // Fix #9: confirm must have non-empty content. Quietly
                // accepting an empty body (the old behaviour) made every
                // empty `> confirm` a footgun that broadcast a tx.
                let confirm_text = std::str::from_utf8(data)
                    .map_err(|_| HandlerError::invalid("non-utf8 confirm content"))?
                    .trim();
                if confirm_text.is_empty() {
                    return Err(HandlerError::invalid(
                        "confirm requires non-empty content (e.g. 'y' or override token)",
                    ));
                }
                if confirm_text.eq_ignore_ascii_case("cancel") {
                    self.write_permit()?;
                    self.tx_engine
                        .outbox
                        .cancel(wallet, chain, id)
                        .map_err(err_be)?;
                    return Ok(());
                }
                let (confirm_text, reviewed_intent_hash) = split_confirm_review_hash(confirm_text);
                let signer = self
                    .keystore
                    .signer(wallet)
                    .map_err(|_| HandlerError::PermissionDenied)?;
                let _staged = self
                    .tx_engine
                    .confirm(
                        self.write_permit()?,
                        wallet,
                        chain,
                        id,
                        &client,
                        &signer,
                        &info.policy,
                        confirm_text,
                        reviewed_intent_hash,
                    )
                    .await
                    .map_err(|e| match e {
                        TxEngineError::EnsoQuoteStale { .. } => {
                            HandlerError::invalid(e.to_string())
                        }
                        other => err_be(other),
                    })?;
                Ok(())
            }
            // outbox/pending/<id>/cancel — fire a self-send replacement.
            // Same content rules as confirm (fix #9 / #10).
            [state, id, fname] if state == "pending" && fname == "cancel" => {
                let cancel_text = std::str::from_utf8(data)
                    .map_err(|_| HandlerError::invalid("non-utf8 cancel content"))?
                    .trim();
                if cancel_text.is_empty() {
                    return Err(HandlerError::invalid(
                        "cancel requires non-empty content (e.g. 'y' or override token)",
                    ));
                }
                let signer = self
                    .keystore
                    .signer(wallet)
                    .map_err(|_| HandlerError::PermissionDenied)?;
                let _ = self
                    .tx_engine
                    .cancel(
                        self.write_permit()?,
                        wallet,
                        chain,
                        id,
                        &client,
                        &signer,
                        10,
                        &info.policy,
                        None,
                    )
                    .await
                    .map_err(err_be)?;
                Ok(())
            }
            // outbox/pending/<id>/replace — restage with bumped fees from
            // the same intent body the user provides (fix #10). Body is a
            // RawIntent (TOML/JSON/shell). The original is left in place so
            // diff against the bumped tx is visible; the engine writes
            // `replacement_intent.json` alongside.
            [state, id, fname] if state == "pending" && fname == "replace" => {
                let body = std::str::from_utf8(data)
                    .map_err(|_| HandlerError::invalid("non-utf8 replace intent"))?;
                if body.trim().is_empty() {
                    return Err(HandlerError::invalid(
                        "replace requires a non-empty intent body",
                    ));
                }
                let intent: RawIntent = intent_parser::parse(body).map_err(err_be)?;
                let signer = self
                    .keystore
                    .signer(wallet)
                    .map_err(|_| HandlerError::PermissionDenied)?;
                // Bump at >= 10% (mempool floor) and substitute the
                // calldata derived from the new intent — same nonce,
                // possibly different to / value / data. Use the
                // address book the handler holds so name lookups in
                // the body resolve identically to a fresh stage.
                let _ = self
                    .tx_engine
                    .replace_with_intent(
                        self.write_permit()?,
                        wallet,
                        chain,
                        id,
                        &client,
                        &signer,
                        10,
                        Some(intent),
                        Some(self.address_book.as_ref()),
                        &info.policy,
                        None,
                    )
                    .await
                    .map_err(err_be)?;
                Ok(())
            }
            _ => Err(HandlerError::PermissionDenied),
        }
    }

    async fn write_sign(&self, wallet: &str, kind: &str, data: &[u8]) -> Result<(), HandlerError> {
        let signer = self
            .keystore
            .signer(wallet)
            .map_err(|_| HandlerError::PermissionDenied)?;
        let sig_hex = match kind {
            "message" => {
                let msg = std::str::from_utf8(data)
                    .map_err(|_| HandlerError::invalid("non-utf8 message"))?
                    .trim_end_matches('\n');
                let sig = signer.sign_message_sync(msg.as_bytes()).map_err(err_be)?;
                hex_signature(&sig)
            }
            "hash" => {
                let s = std::str::from_utf8(data)
                    .map_err(|_| HandlerError::invalid("non-utf8 hash"))?
                    .trim();
                let bytes =
                    decode_hex(s).map_err(|e| HandlerError::invalid(format!("hex: {e}")))?;
                if bytes.len() != 32 {
                    return Err(HandlerError::invalid("hash must be 32 bytes"));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                let h = alloy::primitives::B256::from(arr);
                let sig = signer.sign_hash_sync(&h).map_err(err_be)?;
                hex_signature(&sig)
            }
            "typed_data" => {
                let body = std::str::from_utf8(data)
                    .map_err(|_| HandlerError::invalid("non-utf8 typed_data"))?;
                let typed: alloy_dyn_abi::eip712::TypedData = serde_json::from_str(body)
                    .map_err(|e| HandlerError::invalid(format!("typed_data json: {e}")))?;
                let hash = typed
                    .eip712_signing_hash()
                    .map_err(|e| HandlerError::invalid(format!("typed_data hash: {e}")))?;
                let sig = signer.sign_hash_sync(&hash).map_err(err_be)?;
                hex_signature(&sig)
            }
            _ => return Err(HandlerError::PermissionDenied),
        };
        // Persist last-signature on disk so callers can read it back via the
        // companion `.sig` path. Living next to the writable file keeps the
        // surface stateless from the daemon's point of view.
        let dir = self.keystore.root().join(wallet).join("sign");
        std::fs::create_dir_all(&dir).map_err(HandlerError::Io)?;
        std::fs::write(dir.join(format!("{kind}.sig")), &sig_hex).map_err(HandlerError::Io)?;
        tracing::info!(wallet, kind, "wallet.signed");
        Ok(())
    }

    async fn write_new_wallet(&self, data: &[u8]) -> Result<(), HandlerError> {
        let body = std::str::from_utf8(data)
            .map_err(|_| HandlerError::invalid("wallets/new body must be utf-8"))?
            .trim();
        if body.is_empty() {
            return Err(HandlerError::invalid("wallets/new body is empty"));
        }

        let spec = parse_new_wallet_spec(body)?;
        let env_pass = std::env::var("BLOOM_PASSPHRASE").ok();
        let pass = spec
            .passphrase
            .as_deref()
            .or(env_pass.as_deref())
            .unwrap_or("");

        let info = match spec.kind.as_str() {
            "local" => {
                if pass.is_empty() {
                    return Err(HandlerError::invalid(
                        "passphrase required (set BLOOM_PASSPHRASE or include 'passphrase' in the TOML spec)",
                    ));
                }
                self.keystore
                    .create_local(&spec.name, pass)
                    .map_err(err_be)?
            }
            "import" => {
                if pass.is_empty() {
                    return Err(HandlerError::invalid(
                        "passphrase required (set BLOOM_PASSPHRASE or include 'passphrase' in the TOML spec)",
                    ));
                }
                let key = spec
                    .private_key
                    .as_deref()
                    .ok_or_else(|| HandlerError::invalid("import requires private_key"))?;
                self.keystore
                    .import_hex(&spec.name, key, pass)
                    .map_err(err_be)?
            }
            "watch" => {
                let addr_str = spec
                    .address
                    .as_deref()
                    .ok_or_else(|| HandlerError::invalid("watch requires address"))?;
                let addr: alloy::primitives::Address = addr_str
                    .parse()
                    .map_err(|e| HandlerError::invalid(format!("address: {e}")))?;
                self.keystore.add_watch(&spec.name, addr).map_err(err_be)?
            }
            // PasskeyGated: opens a browser WebAuthn registration ceremony.
            "passkey" => self
                .keystore
                .create_passkey(&spec.name)
                .await
                .map_err(err_be)?,
            // PasskeyGated from an existing hex private key.
            "passkey-import" => {
                let key = spec
                    .private_key
                    .as_deref()
                    .ok_or_else(|| HandlerError::invalid("passkey-import requires private_key"))?;
                self.keystore
                    .import_passkey(&spec.name, key)
                    .await
                    .map_err(err_be)?
            }
            other => {
                return Err(HandlerError::invalid(format!(
                    "unknown wallet kind '{other}'; expected local|import|watch|passkey|passkey-import"
                )));
            }
        };
        tracing::info!(wallet=%info.name, address=%info.address, kind=?info.kind, "wallet.created");
        Ok(())
    }
}

#[derive(Default)]
struct NewWalletSpec {
    name: String,
    kind: String,
    passphrase: Option<String>,
    address: Option<String>,
    private_key: Option<String>,
}

fn parse_new_wallet_spec(body: &str) -> Result<NewWalletSpec, HandlerError> {
    let trimmed = body.trim();
    if !trimmed.contains('=') && !trimmed.contains('\n') {
        return Ok(NewWalletSpec {
            name: trimmed.to_string(),
            kind: "local".into(),
            ..Default::default()
        });
    }
    let table: toml::Table = trimmed
        .parse()
        .map_err(|e| HandlerError::invalid(format!("toml: {e}")))?;
    let name = table
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| HandlerError::invalid("name required"))?
        .to_string();
    let kind = table
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("local")
        .to_string();
    Ok(NewWalletSpec {
        name,
        kind,
        passphrase: table
            .get("passphrase")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        address: table
            .get("address")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        private_key: table
            .get("private_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    })
}

fn hex_signature(sig: &alloy::primitives::Signature) -> String {
    let bytes = sig.as_bytes();
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    s.push_str(&hex::encode(bytes));
    s.push('\n');
    s
}

fn decode_hex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s.trim_start_matches("0x"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, B256, Signature};
    use bloom_proto::AddressBook;
    use bloom_tx::outbox::Outbox;
    use bloom_tx::tx_engine::TxEngine;
    use std::str::FromStr;

    struct Fixture {
        _tmp: tempfile::TempDir,
        handler: WalletsHandler,
        wallet_name: String,
        wallet_addr: Address,
        sign_dir: std::path::PathBuf,
    }

    fn make_handler() -> Fixture {
        make_handler_with_chain(false)
    }

    /// Build a wallet fixture; when `with_chain` is true a stub `anvil`
    /// chain is registered (RPC URL is unreachable, so any test that
    /// triggers an actual broadcast will surface as an RPC error rather
    /// than silently succeeding). Outbox-state tests don't need the chain
    /// to be reachable.
    fn make_handler_with_chain(with_chain: bool) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let ks_root = tmp.path().join("keystore");
        let outbox_root = tmp.path().join("outbox");
        let keystore = bloom_keystore::Keystore::new(&ks_root).unwrap();
        let info = keystore.create_local("alice", "passphrase").unwrap();
        keystore.unlock("alice", "passphrase").unwrap();
        let chains = ChainRegistry::new();
        if with_chain {
            let spec = bloom_proto::ChainSpec {
                name: "anvil".into(),
                chain_id: 31337,
                rpc_urls: vec!["http://127.0.0.1:1".into()],
                rpc_endpoints: Vec::new(),
                allow_broadcast: true,
                etherscan_api_url: None,
                display_name: None,
                native_symbol: "ETH".into(),
                native_decimals: 18,
                legacy_tx: false,
            };
            chains.add(bloom_chain::ChainClient::new(spec).unwrap());
        }
        let outbox = Outbox::new(&outbox_root).unwrap();
        let tx_engine = TxEngine::new(outbox, 60_000, false);
        let address_book = AddressBook::default();
        let home = bloom_proto::HomeDir::at(tmp.path().join("home"));
        let permit = Arc::new(HomeWritePermit::acquire(&home).unwrap());
        let handler = WalletsHandler::new(keystore, chains, tx_engine, address_book)
            .with_home_write_permit(permit);
        let sign_dir = ks_root.join("alice").join("sign");
        Fixture {
            _tmp: tmp,
            handler,
            wallet_name: "alice".to_string(),
            wallet_addr: info.address,
            sign_dir,
        }
    }

    /// Write a synthetic staged tx directly into the outbox so the tests
    /// that drive confirm/replace/cancel don't have to spin up a chain.
    fn seed_pending(f: &Fixture, id: &str) {
        let staged = bloom_proto::StagedTx {
            id: id.into(),
            wallet: f.wallet_name.clone(),
            chain: "anvil".into(),
            chain_id: 31337,
            from: bloom_proto::checksum_address(&f.wallet_addr),
            to: "0x0000000000000000000000000000000000000002".into(),
            value_wei: "0".into(),
            data_hex: "0x".into(),
            gas_limit: 21000,
            max_fee_per_gas: Some("100".into()),
            max_priority_fee_per_gas: Some("10".into()),
            gas_price: None,
            nonce: 0,
            policy_checks: vec![],
            created_ms: 0,
            // Far in the future so expiry never trips during tests.
            expires_ms: u128::MAX,
            status: bloom_proto::TxStatus::Pending,
            tx_hash: None,
            token: None,
            nft: None,
            usd_value: None,
        };
        f.handler
            .tx_engine
            .outbox
            .write_pending(&staged, "p")
            .unwrap();
    }

    fn read_sig_file(path: &std::path::Path) -> Signature {
        let raw = std::fs::read_to_string(path).unwrap();
        Signature::from_str(raw.trim()).unwrap()
    }

    #[tokio::test]
    async fn personal_sign_recovers_to_wallet_address() {
        let f = make_handler();
        let p = VfsPath::parse(&format!("/{}/sign/message", f.wallet_name)).unwrap();
        let msg = b"hello world";
        f.handler.write(&p, msg).await.unwrap();

        let sig = read_sig_file(&f.sign_dir.join("message.sig"));
        let bytes: [u8; 65] = sig.into();
        assert_eq!(bytes.len(), 65);

        let recovered = sig.recover_address_from_msg(msg).unwrap();
        assert_eq!(recovered, f.wallet_addr);
    }

    #[tokio::test]
    async fn sign_hash_with_known_digest_recovers_to_wallet_address() {
        let f = make_handler();
        // Precomputed digest = keccak256("hello") (just any deterministic 32-byte value).
        let digest_hex = "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";
        let digest = B256::from_str(digest_hex).unwrap();

        let p = VfsPath::parse(&format!("/{}/sign/hash", f.wallet_name)).unwrap();
        f.handler.write(&p, digest_hex.as_bytes()).await.unwrap();

        let sig = read_sig_file(&f.sign_dir.join("hash.sig"));
        let bytes: [u8; 65] = sig.into();
        assert_eq!(bytes.len(), 65);

        let recovered = sig.recover_address_from_prehash(&digest).unwrap();
        assert_eq!(recovered, f.wallet_addr);
    }

    #[tokio::test]
    async fn typed_data_signature_recovers_to_wallet_address() {
        let f = make_handler();
        let addr_hex = bloom_proto::checksum_address(&f.wallet_addr);
        let json = serde_json::json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"}
                ],
                "Mail": [
                    {"name": "from", "type": "address"},
                    {"name": "to", "type": "address"},
                    {"name": "contents", "type": "string"}
                ]
            },
            "primaryType": "Mail",
            "domain": {
                "name": "Test",
                "version": "1",
                "chainId": 1
            },
            "message": {
                "from": addr_hex,
                "to": addr_hex,
                "contents": "hi"
            }
        });
        let body = serde_json::to_vec(&json).unwrap();

        // Compute the expected signing hash for recovery on our side.
        let typed: alloy_dyn_abi::eip712::TypedData = serde_json::from_slice(&body).unwrap();
        let expected_hash = typed.eip712_signing_hash().unwrap();

        let p = VfsPath::parse(&format!("/{}/sign/typed_data", f.wallet_name)).unwrap();
        f.handler.write(&p, &body).await.unwrap();

        let sig = read_sig_file(&f.sign_dir.join("typed_data.sig"));
        let recovered = sig.recover_address_from_prehash(&expected_hash).unwrap();
        assert_eq!(recovered, f.wallet_addr);
    }

    #[tokio::test]
    async fn invalid_hex_hash_returns_invalid() {
        let f = make_handler();
        let p = VfsPath::parse(&format!("/{}/sign/hash", f.wallet_name)).unwrap();
        // Not valid hex.
        let r = f.handler.write(&p, b"0xZZZZ").await;
        assert!(matches!(r, Err(HandlerError::Invalid(_))), "got: {:?}", r);

        // Valid hex but wrong length (should also be Invalid).
        let r2 = f.handler.write(&p, b"0xdeadbeef").await;
        assert!(matches!(r2, Err(HandlerError::Invalid(_))), "got: {:?}", r2);
    }

    #[tokio::test]
    async fn write_new_wallet_toml_creates_local_wallet() {
        let f = make_handler();
        let p = VfsPath::parse("/new").unwrap();
        f.handler
            .write(
                &p,
                b"name = \"bob\"\nkind = \"local\"\npassphrase = \"p\"\n",
            )
            .await
            .unwrap();
        let info = f.handler.keystore.info("bob").unwrap();
        assert!(matches!(info.kind, bloom_keystore::WalletKind::Local));
    }

    /// Writing a plain name string without BLOOM_PASSPHRASE or a TOML
    /// passphrase must return an Invalid error — empty passphrases are
    /// no longer accepted for local wallets.
    #[tokio::test]
    async fn write_new_wallet_plain_name_rejected_without_passphrase() {
        let f = make_handler();
        let p = VfsPath::parse("/new").unwrap();
        let r = f.handler.write(&p, b"bob").await;
        assert!(
            matches!(r, Err(HandlerError::Invalid(_))),
            "expected Invalid error for plain name without passphrase, got: {r:?}"
        );
    }

    #[tokio::test]
    async fn write_new_wallet_toml_creates_watch_wallet() {
        let f = make_handler();
        let p = VfsPath::parse("/new").unwrap();
        let body =
            b"name = \"observer\"\nkind = \"watch\"\naddress = \"0x0000000000000000000000000000000000000001\"\n";
        f.handler.write(&p, body).await.unwrap();
        let info = f.handler.keystore.info("observer").unwrap();
        assert!(matches!(info.kind, bloom_keystore::WalletKind::Watch));
    }

    #[tokio::test]
    async fn write_new_wallet_toml_imports_private_key() {
        let f = make_handler();
        let p = VfsPath::parse("/new").unwrap();
        // Anvil's first signer; use just for deterministic round-trip check.
        let key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let body = format!(
            "name = \"imported\"\nkind = \"import\"\nprivate_key = \"{}\"\npassphrase = \"x\"\n",
            key
        );
        f.handler.write(&p, body.as_bytes()).await.unwrap();
        let info = f.handler.keystore.info("imported").unwrap();
        assert_eq!(
            format!("{:?}", info.address).to_lowercase(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }

    #[tokio::test]
    async fn list_root_includes_new() {
        let f = make_handler();
        let p = VfsPath::parse("/").unwrap();
        let entries = f.handler.list(&p).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"alice"));
        assert!(names.contains(&"new"));
    }

    #[tokio::test]
    async fn list_sign_dir_returns_three_writable_files() {
        let f = make_handler();
        let p = VfsPath::parse(&format!("/{}/sign", f.wallet_name)).unwrap();
        let entries = f.handler.list(&p).await.unwrap();
        assert_eq!(entries.len(), 3);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"message"));
        assert!(names.contains(&"hash"));
        assert!(names.contains(&"typed_data"));
        for e in &entries {
            assert!(matches!(e.kind, crate::handler::EntryKind::File));
        }
    }

    /// Fix #8: reading `outbox/sent/<pending-id>/intent.json` must
    /// NotFound, even though the id exists in `pending`. Before the fix
    /// the read silently followed the id wherever it lived.
    #[tokio::test]
    async fn outbox_read_honours_state_segment() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-test");
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/sent/0001-test/intent.json",
            f.wallet_name
        ))
        .unwrap();
        let r = f.handler.read(&p).await;
        assert!(r.is_err(), "expected NotFound but got {r:?}");
    }

    /// Fix #8: listing `outbox/sent/<pending-id>/` must NotFound when
    /// the entry isn't actually in `sent`.
    #[tokio::test]
    async fn outbox_list_honours_state_segment() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-test");
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/sent/0001-test",
            f.wallet_name
        ))
        .unwrap();
        let r = f.handler.list(&p).await;
        assert!(r.is_err(), "expected NotFound, got {r:?}");
    }

    /// Fix #9: writing an empty body to `pending/<id>/confirm` must
    /// surface as Invalid rather than broadcasting.
    #[tokio::test]
    async fn confirm_empty_body_rejected() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-test");
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/pending/0001-test/confirm",
            f.wallet_name
        ))
        .unwrap();
        let r = f.handler.write(&p, b"").await;
        assert!(matches!(r, Err(HandlerError::Invalid(_))), "got: {r:?}");
        // Whitespace-only is also rejected.
        let r = f.handler.write(&p, b"   \n\t").await;
        assert!(matches!(r, Err(HandlerError::Invalid(_))), "got: {r:?}");
    }

    #[tokio::test]
    async fn confirm_cancel_discards_pending_locally() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-test");
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/pending/0001-test/confirm",
            f.wallet_name
        ))
        .unwrap();
        f.handler.write(&p, b"cancel").await.unwrap();

        let entry = f
            .handler
            .tx_engine
            .outbox
            .read(&f.wallet_name, "anvil", "0001-test")
            .unwrap();
        assert_eq!(entry.state, OutboxState::Failed);
        assert!(!entry.dir.join("broadcast_attempted.json").exists());
        assert!(!entry.dir.join("raw_tx").exists());
    }

    #[test]
    fn confirm_review_hash_metadata_is_split_from_confirm_text() {
        let (confirm, hash) = split_confirm_review_hash("y\nreview_hash=abc123\n");
        assert_eq!(confirm, "y");
        assert_eq!(hash, Some("abc123"));

        let (confirm, hash) = split_confirm_review_hash("override");
        assert_eq!(confirm, "override");
        assert_eq!(hash, None);
    }

    /// Fix #2 + #10: writing `outbox/sent/<id>/confirm` is not a valid
    /// route and must not rebroadcast. (Also covers the path-routing
    /// half of fix #2 — the engine layer is covered in tx_engine tests.)
    #[tokio::test]
    async fn confirm_path_only_valid_for_pending() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-test");
        // Move id to sent so it's no longer pending.
        let entry = f
            .handler
            .tx_engine
            .outbox
            .read(&f.wallet_name, "anvil", "0001-test")
            .unwrap();
        f.handler
            .tx_engine
            .outbox
            .transition(&entry, OutboxState::Sent)
            .unwrap();
        // Path that points at sent — must be permission denied (no route).
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/sent/0001-test/confirm",
            f.wallet_name
        ))
        .unwrap();
        let r = f.handler.write(&p, b"y").await;
        assert!(
            matches!(r, Err(HandlerError::PermissionDenied)),
            "got: {r:?}"
        );
        // Path under pending/<id> still resolves but the engine rejects
        // because the id isn't actually pending.
        let p2 = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/pending/0001-test/confirm",
            f.wallet_name
        ))
        .unwrap();
        let r2 = f.handler.write(&p2, b"y").await;
        assert!(r2.is_err(), "expected error from engine, got {r2:?}");
    }

    /// Fix #10: cancel route exists, demands a non-empty body, and
    /// rejects non-pending ids.
    #[tokio::test]
    async fn cancel_route_demands_body() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-test");
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/pending/0001-test/cancel",
            f.wallet_name
        ))
        .unwrap();
        let r = f.handler.write(&p, b"").await;
        assert!(matches!(r, Err(HandlerError::Invalid(_))), "got: {r:?}");
    }

    /// Fix #10: replace route exists and demands a non-empty body.
    #[tokio::test]
    async fn replace_route_demands_body() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-test");
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/pending/0001-test/replace",
            f.wallet_name
        ))
        .unwrap();
        let r = f.handler.write(&p, b"").await;
        assert!(matches!(r, Err(HandlerError::Invalid(_))), "got: {r:?}");
    }

    /// Fix #10: list of `pending/<id>/` advertises the writable control
    /// files (confirm, replace, cancel) even before they've been written.
    #[tokio::test]
    async fn list_pending_advertises_control_files() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-test");
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/outbox/pending/0001-test",
            f.wallet_name
        ))
        .unwrap();
        let entries = f.handler.list(&p).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"confirm"), "names={names:?}");
        assert!(names.contains(&"replace"), "names={names:?}");
        assert!(names.contains(&"cancel"), "names={names:?}");
    }

    #[tokio::test]
    async fn list_pending_returns_seeded_ids() {
        let f = make_handler_with_chain(true);
        seed_pending(&f, "0001-21699");
        let p = VfsPath::parse(&format!("/{}/chains/anvil/outbox/pending", f.wallet_name)).unwrap();
        let entries = f.handler.list(&p).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"0001-21699"), "names={names:?}");
    }

    #[tokio::test]
    async fn pending_external_includes_index_txs_for_wallet_address() {
        let f = make_handler_with_chain(true);
        use alloy::primitives::{B256, Bytes, U256};
        use bloom_mempool::{PendingTx, PendingTxIndex, TxFees};

        let idx = PendingTxIndex::new(8);
        let mut other = [0u8; 20];
        other[0] = 9;
        let other_addr = Address::from(other);

        let mut h1 = [0u8; 32];
        h1[0] = 1;
        idx.insert(PendingTx {
            hash: B256::from(h1),
            from: f.wallet_addr,
            to: None,
            nonce: 0,
            value: U256::ZERO,
            gas_limit: 21_000,
            fees: TxFees::Legacy { gas_price: 1 },
            input: Bytes::new(),
            observed_at: std::time::SystemTime::now(),
        });
        let mut h2 = [0u8; 32];
        h2[0] = 2;
        idx.insert(PendingTx {
            hash: B256::from(h2),
            from: other_addr,
            to: None,
            nonce: 0,
            value: U256::ZERO,
            gas_limit: 21_000,
            fees: TxFees::Legacy { gas_price: 1 },
            input: Bytes::new(),
            observed_at: std::time::SystemTime::now(),
        });

        let mut map = std::collections::BTreeMap::new();
        map.insert("anvil".to_string(), idx);
        let handler = f.handler.clone().with_mempool_indexes(map);

        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/pending_external.jsonl",
            f.wallet_name
        ))
        .unwrap();
        let body = handler.read(&p).await.unwrap();
        let lines: Vec<&[u8]> = body
            .split(|c| *c == b'\n')
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(lines.len(), 1, "only the wallet's own tx should appear");
    }

    #[tokio::test]
    async fn nonce_conflicts_reports_observed_nonces_for_wallet_address() {
        let f = make_handler_with_chain(true);
        use alloy::primitives::{B256, Bytes, U256};
        use bloom_mempool::{PendingTx, PendingTxIndex, TxFees};

        let idx = PendingTxIndex::new(8);
        for (hash_b, nonce) in [(1u8, 3u64), (2u8, 5u64)] {
            let mut h = [0u8; 32];
            h[0] = hash_b;
            idx.insert(PendingTx {
                hash: B256::from(h),
                from: f.wallet_addr,
                to: None,
                nonce,
                value: U256::ZERO,
                gas_limit: 21_000,
                fees: TxFees::Legacy { gas_price: 1 },
                input: Bytes::new(),
                observed_at: std::time::SystemTime::now(),
            });
        }
        let mut map = std::collections::BTreeMap::new();
        map.insert("anvil".to_string(), idx);
        let handler = f.handler.clone().with_mempool_indexes(map);

        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/nonce_conflicts.json",
            f.wallet_name
        ))
        .unwrap();
        let body = handler.read(&p).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["observed_nonces"], serde_json::json!([3, 5]));
        // checksum address is non-empty hex
        assert!(v["address"].as_str().unwrap().starts_with("0x"));
    }

    /// Helper: construct a passkey wallet on disk (no browser ceremony needed).
    /// Returns the wallet's address.
    fn seed_passkey_wallet(f: &Fixture, name: &str) -> Address {
        let info = f.handler.keystore.create_local(name, "passphrase").unwrap();
        f.handler.keystore.unlock(name, "passphrase").unwrap();
        let wallet_dir = f._tmp.path().join("keystore").join(name);
        std::fs::write(wallet_dir.join("kind"), b"passkey").unwrap();
        f.handler.keystore.sign_policy(name).unwrap();
        info.address
    }

    /// Passkey wallet: dir lists `unlock-passkey`, lookup gives writable file,
    /// and `kind` reads "passkey".
    #[tokio::test]
    async fn passkey_wallet_vfs_properties() {
        let f = make_handler();
        let _addr = seed_passkey_wallet(&f, "pk");

        // listing includes unlock-passkey
        let entries = f
            .handler
            .list(&VfsPath::parse("/pk").unwrap())
            .await
            .unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"unlock-passkey"), "names={names:?}");

        // unlock-passkey is a writable file
        let entry = f
            .handler
            .lookup(&VfsPath::parse("/pk/unlock-passkey").unwrap())
            .await
            .unwrap();
        assert!(matches!(entry.kind, crate::handler::EntryKind::File));
        assert_eq!(entry.mode, 0o644);

        // kind reads "passkey"
        let bytes = f
            .handler
            .read(&VfsPath::parse("/pk/kind").unwrap())
            .await
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&bytes).trim(), "passkey");
    }

    /// Local wallet: `kind` reads "local", `unlock-passkey` is not exposed
    /// (lookup → NotFound, write → Invalid, list → absent).
    #[tokio::test]
    async fn local_wallet_passkey_properties() {
        let f = make_handler();

        // kind reads "local"
        let bytes = f
            .handler
            .read(&VfsPath::parse("/alice/kind").unwrap())
            .await
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&bytes).trim(), "local");

        // unlock-passkey resolves to NotFound
        let r = f
            .handler
            .lookup(&VfsPath::parse("/alice/unlock-passkey").unwrap())
            .await;
        assert!(matches!(r, Err(HandlerError::NotFound(_))), "got {r:?}");

        // writing to unlock-passkey is Invalid
        let r = f
            .handler
            .write(&VfsPath::parse("/alice/unlock-passkey").unwrap(), b"unlock")
            .await;
        assert!(matches!(r, Err(HandlerError::Invalid(_))), "got {r:?}");

        // listing does NOT contain unlock-passkey
        let entries = f
            .handler
            .list(&VfsPath::parse("/alice").unwrap())
            .await
            .unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(!names.contains(&"unlock-passkey"), "names={names:?}");
    }

    #[tokio::test]
    async fn pending_external_returns_empty_when_no_index_for_chain() {
        let f = make_handler_with_chain(true);
        // Don't install any mempool index.
        let p = VfsPath::parse(&format!(
            "/{}/chains/anvil/pending_external.jsonl",
            f.wallet_name
        ))
        .unwrap();
        let body = f.handler.read(&p).await.unwrap();
        assert!(body.is_empty());
    }
}
