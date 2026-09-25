//! VFS router for installed Petal packages.
//!
//! The daemon mounts this handler at `petals/`. The first path segment selects
//! an installed Petal package; the remaining path is passed to the matched
//! Petal route artifact.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use async_trait::async_trait;
use bloom_proto::config::PetalRuntimeConfig;
use bloom_proto::{AuditLog, AuditRecord};
use bloom_vfs::handler::{Entry, EntryKind, Handler, HandlerError};
use bloom_vfs::handlers::wallets::AccountPetalContext;
use bloom_vfs::path::VfsPath;
use parking_lot::RwLock;

use crate::abi::{DispatchEntry, DispatchEntryKind, DispatchOp, DispatchRequest, DispatchResponse};
use crate::error::PetalError;
use crate::host::PetalHost;
use crate::package::{RouteIndex, scoped_original_path, scoped_route_index};
use crate::runner::{PETAL_DOCUMENT_NAMES, PetalRunner};
use crate::vm::{COMPONENT_NOT_A_DIR_CODE, COMPONENT_UNSUPPORTED_CODE, RunOptions};

type ScopedRouteIndexes = Arc<(RouteIndex, RouteIndex)>;
type ScopedRouteCache = Arc<RwLock<BTreeMap<String, ScopedRouteIndexes>>>;

#[derive(Clone)]
pub struct PetalRouter {
    runner: PetalRunner,
    host: Arc<dyn PetalHost>,
    runtime_petals: BTreeMap<String, PetalRuntimeConfig>,
    audit: Option<Arc<AuditLog>>,
    audit_effect_lock: Arc<tokio::sync::Mutex<()>>,
    account: Option<AccountPetalContext>,
    scoped_routes: ScopedRouteCache,
}

impl PetalRouter {
    pub fn new(runner: PetalRunner, host: Arc<dyn PetalHost>) -> Self {
        Self {
            runner,
            host,
            runtime_petals: BTreeMap::new(),
            audit: None,
            audit_effect_lock: Arc::new(tokio::sync::Mutex::new(())),
            account: None,
            scoped_routes: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    pub fn with_audit(mut self, audit: Arc<AuditLog>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Retained temporarily for daemon API compatibility. Petal writes are
    /// synchronous in this iteration so VFS callers receive execution errors.
    pub fn with_async_write_switch(self, _enabled: Arc<AtomicBool>) -> Self {
        self
    }

    pub fn with_runtime_petals(
        mut self,
        runtime_petals: BTreeMap<String, PetalRuntimeConfig>,
    ) -> Result<Self, PetalError> {
        for (mount, app) in &runtime_petals {
            if app.endpoints.is_empty() {
                continue;
            }
            match self
                .runner
                .validate_app_endpoint_bindings(mount, &app.endpoints)
            {
                Ok(()) | Err(PetalError::NotFound(_)) => {}
                Err(err) => return Err(err),
            }
        }
        self.runtime_petals = runtime_petals;
        Ok(self)
    }

    fn run_options(&self, mount: &str) -> RunOptions {
        let Some(app) = self.runtime_petals.get(mount) else {
            return RunOptions::default();
        };
        let mut runtime_settings = app.values.clone();
        runtime_settings.extend(
            app.endpoints
                .iter()
                .map(|(key, value)| (format!("endpoint.{key}"), value.clone())),
        );
        RunOptions {
            runtime_settings,
            endpoint_bindings: app.endpoints.clone(),
            ..RunOptions::default()
        }
    }

    fn mount_path(path: &VfsPath) -> Result<(&str, String), HandlerError> {
        let [mount, rest @ ..] = path.segments() else {
            return Err(HandlerError::NotFound(path.to_string_path()));
        };
        let rest = rest.join("/");
        Ok((mount, rest))
    }

    fn is_petal(&self, mount: &str) -> bool {
        self.runner.resolve_petal_mount(mount).is_ok()
            && self.account.as_ref().is_none_or(|account| {
                account.number == 0 || self.runner.petal_account_aware(mount).unwrap_or(false)
            })
    }

    fn require_account_mount(&self, path: &VfsPath) -> Result<(), HandlerError> {
        if let (Some(account), Some(mount)) = (&self.account, path.segments().first())
            && account.number != 0
            && !self
                .runner
                .petal_account_aware(mount)
                .map_err(map_petal_err)?
        {
            return Err(HandlerError::not_found(format!(
                "petal '{mount}' does not declare [account] aware = true; it cannot run under account {}",
                account.number
            )));
        }
        Ok(())
    }

    fn is_petal_document(path: &str) -> bool {
        PETAL_DOCUMENT_NAMES.contains(&path)
    }

    fn add_petal_documents(mut entries: Vec<Entry>) -> Vec<Entry> {
        entries.retain(|entry| !Self::is_petal_document(&entry.name));
        entries.extend(PETAL_DOCUMENT_NAMES.map(Entry::read_only_file));
        entries
    }

    fn scoped_indexes(&self, mount: &str) -> Result<ScopedRouteIndexes, HandlerError> {
        let hash = self
            .runner
            .resolve_petal_mount(mount)
            .map_err(map_petal_err)?;
        if let Some(indexes) = self.scoped_routes.read().get(&hash) {
            return Ok(indexes.clone());
        }
        let original = self
            .runner
            .load_petal_route_index(mount)
            .map_err(map_petal_err)?;
        let scoped = scoped_route_index(&original).map_err(map_petal_err)?;
        let indexes = Arc::new((original, scoped));
        self.scoped_routes.write().insert(hash, indexes.clone());
        Ok(indexes)
    }

    fn scoped_path(
        &self,
        mount: &str,
        op: DispatchOp,
        path: &str,
        wallet: &str,
    ) -> Result<String, HandlerError> {
        let indexes = self.scoped_indexes(mount)?;
        let (original, scoped) = indexes.as_ref();
        let direct = scoped_original_path(original, scoped, path, None, wallet);
        let special = match op {
            DispatchOp::Lookup => Some("$lookup"),
            DispatchOp::List => Some("$index"),
            _ => None,
        };
        direct
            .or_else(|| {
                special.and_then(|special| {
                    scoped_original_path(original, scoped, path, Some(special), wallet)
                })
            })
            .ok_or_else(|| {
                HandlerError::not_found(format!("petals/{mount}/wallets/{wallet}/{path}"))
            })
    }

    async fn wallet_entries(&self) -> Result<Vec<Entry>, HandlerError> {
        let entries = self.host.vfs_list("wallets").await.map_err(map_host_err)?;
        Ok(entries
            .into_iter()
            .filter(|entry| {
                entry.kind == crate::host::HostVfsEntryKind::Dir && entry.name != "registrations"
            })
            .map(|entry| Entry::dir(&entry.name))
            .collect())
    }

    async fn account_entries(&self, wallet: &str) -> Result<Vec<Entry>, HandlerError> {
        let entries = self
            .host
            .vfs_list(&format!("wallets/{wallet}"))
            .await
            .map_err(map_host_err)?;
        Ok(entries
            .into_iter()
            .filter(|entry| {
                entry.kind == crate::host::HostVfsEntryKind::Dir
                    && canonical_account(&entry.name).is_some()
            })
            .map(|entry| Entry::dir(&entry.name))
            .collect())
    }

    async fn account_context(
        &self,
        wallet: &str,
        number: &str,
    ) -> Result<AccountPetalContext, HandlerError> {
        let number = canonical_account(number)
            .ok_or_else(|| HandlerError::not_found("invalid account number"))?;
        let bytes = self
            .host
            .vfs_read(&format!("wallets/{wallet}/{number}/account.json"))
            .await
            .map_err(map_host_err)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        if value.get("schema").and_then(|v| v.as_str()) != Some("bloom.account.v1")
            || value.get("wallet").and_then(|v| v.as_str()) != Some(wallet)
            || value.get("number").and_then(|v| v.as_u64()) != Some(number as u64)
        {
            return Err(HandlerError::backend(
                "wallet account projection identity mismatch",
            ));
        }
        let fingerprint = |family: &str| {
            value
                .get(family)
                .and_then(|v| v.get("public_key_fingerprint"))
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        };
        let freshness = serde_json::from_value(
            value
                .get("freshness")
                .cloned()
                .ok_or_else(|| HandlerError::backend("account freshness missing"))?,
        )
        .map_err(|error| HandlerError::backend(error.to_string()))?;
        let context = AccountPetalContext {
            wallet: wallet.to_owned(),
            number,
            evm_fingerprint: fingerprint("evm"),
            solana_fingerprint: fingerprint("solana"),
            freshness,
        };
        if context.evm_fingerprint.is_none() && context.solana_fingerprint.is_none() {
            return Err(HandlerError::not_found(format!(
                "wallet '{wallet}' has no signing family for account {number}"
            )));
        }
        Ok(context)
    }

    async fn scoped_account<'a>(
        &self,
        path: &'a VfsPath,
    ) -> Result<(&'a str, String, AccountPetalContext), HandlerError> {
        let [mount, wallets, wallet, number, rest @ ..] = path.segments() else {
            return Err(HandlerError::not_found(path.to_string_path()));
        };
        if wallets != "wallets" || !self.is_petal(mount) {
            return Err(HandlerError::not_found(path.to_string_path()));
        }
        let account = self.account_context(wallet, number).await?;
        if account.number != 0
            && !self
                .runner
                .petal_account_aware(mount)
                .map_err(map_petal_err)?
        {
            return Err(HandlerError::not_found(format!(
                "petal '{mount}' does not declare [account] aware = true"
            )));
        }
        Ok((mount, rest.join("/"), account))
    }

    fn metadata_route_path(&self, path: &VfsPath, op: DispatchOp) -> Option<(String, String)> {
        let [mount, wallets, wallet, number, rest @ ..] = path.segments() else {
            return None;
        };
        if wallets != "wallets" || canonical_account(number).is_none() || !self.is_petal(mount) {
            return None;
        }
        let original = self.scoped_path(mount, op, &rest.join("/"), wallet).ok()?;
        Some((mount.clone(), original))
    }

    fn project_scoped_list(
        original: &RouteIndex,
        scoped: &RouteIndex,
        path: &str,
        entries: Vec<DispatchEntry>,
    ) -> Result<Vec<Entry>, HandlerError> {
        let mut visible = BTreeMap::new();
        for entry in entries {
            let child = if path.is_empty() {
                entry.name.clone()
            } else {
                format!("{path}/{}", entry.name)
            };
            if scoped.match_route(&child).is_some()
                || scoped
                    .routes
                    .iter()
                    .any(|route| crate::runner::route_has_descendant(&route.pattern, &child))
            {
                let entry = entry_to_vfs(entry)?;
                visible.insert(entry.name.clone(), entry);
            }
        }
        // Filename captures collapse their parent directory into one file.
        // The guest still lists the old directory, so supply that file from
        // the immutable projected index and omit the now-unreachable parent.
        for route in &original.routes {
            if !route
                .pattern
                .split('/')
                .next_back()
                .is_some_and(|last| last.starts_with("[wallet]."))
            {
                continue;
            }
            let Some(projected) = scoped
                .routes
                .iter()
                .find(|candidate| candidate.route_id == route.route_id)
            else {
                continue;
            };
            let Some((parent, name)) = projected.pattern.rsplit_once('/') else {
                if !path.is_empty() {
                    continue;
                }
                let name = projected.pattern.as_str();
                visible
                    .entry(name.to_owned())
                    .or_insert_with(|| Entry::read_only_file(name));
                continue;
            };
            if parent == path && !name.starts_with('[') {
                visible
                    .entry(name.to_owned())
                    .or_insert_with(|| Entry::read_only_file(name));
            }
        }
        Ok(visible.into_values().collect())
    }
}

fn canonical_account(segment: &str) -> Option<u32> {
    if segment.is_empty()
        || (segment.len() > 1 && segment.starts_with('0'))
        || !segment.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    segment.parse().ok()
}

fn map_host_err(error: crate::host::HostError) -> HandlerError {
    match error {
        crate::host::HostError::NotFound(path) => HandlerError::not_found(path),
        crate::host::HostError::Denied(_) => HandlerError::PermissionDenied,
        crate::host::HostError::Invalid(message) => HandlerError::invalid(message),
        other => HandlerError::backend(other.to_string()),
    }
}

impl PetalRouter {
    /// A router preselected for one numbered account. The public Petal mount
    /// resolves the same context from the authenticated wallet projection.
    pub fn for_account(&self, account: AccountPetalContext) -> Arc<dyn Handler> {
        let mut router = self.clone();
        router.account = Some(account);
        Arc::new(router)
    }
}

impl PetalRouter {
    /// Dispatch an installed Petal route on behalf of one numbered account.
    /// Accounts other than 0 run only account-aware Petals: an unaware
    /// package is not found here, with a message naming the Petal and the
    /// missing declaration.
    pub async fn dispatch_for_account(
        &self,
        mount: &str,
        op: DispatchOp,
        path: String,
        body: Vec<u8>,
        account: &AccountPetalContext,
    ) -> Result<DispatchResponse, HandlerError> {
        if account.number != 0 {
            let aware = self
                .runner
                .petal_account_aware(mount)
                .map_err(map_petal_err)?;
            if !aware {
                return Err(HandlerError::not_found(format!(
                    "petal '{mount}' does not declare [account] aware = true; it cannot run \
                     under account {}",
                    account.number
                )));
            }
        }
        let trusted = vec![
            ("bloom.wallet".to_owned(), account.wallet.clone()),
            ("bloom.account".to_owned(), account.number.to_string()),
            (
                "bloom.route_prefix".to_owned(),
                format!("wallets/{}/{}/", account.wallet, account.number),
            ),
        ];
        self.dispatch_with_params(
            mount,
            op,
            path,
            body,
            &trusted,
            Some(account.wallet.clone()),
            Some(account),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn dispatch_with_params(
        &self,
        mount: &str,
        op: DispatchOp,
        path: String,
        body: Vec<u8>,
        trusted_params: &[(String, String)],
        account_wallet: Option<String>,
        account: Option<&AccountPetalContext>,
    ) -> Result<DispatchResponse, HandlerError> {
        // Lookup, list, and ordinary reads are filesystem observations, not
        // security effects. Auditing them both misstates the event stream and
        // makes a single mounted path traversal append (and authenticate) many
        // journal records before NFS reaches the command WRITE. A read is an
        // effect only when its route explicitly declares that property.
        let audit_effect = match op {
            DispatchOp::Write => true,
            DispatchOp::Read => self
                .runner
                .petal_route_effective_metadata(mount, op, &path)
                .map(|(_, metadata)| metadata.side_effecting_read)
                .unwrap_or(true),
            DispatchOp::Lookup | DispatchOp::List => false,
        };
        let _audit_guard = if audit_effect {
            Some(self.audit_effect_lock.lock().await)
        } else {
            None
        };
        let operation = format!("petal.execute.{op:?}").to_ascii_lowercase();
        let payload_digest = blake3::hash(&body).to_hex().to_string();
        let account_identity = account
            .filter(|account| account.number != 0)
            .map(|account| format!("\0{}\0{}", account.wallet, account.number))
            .unwrap_or_default();
        let operation_id = blake3::hash(
            format!(
                "bloom-machine-petal-execution/v1\0{mount}\0{operation}\0{path}\0{payload_digest}\0{}{account_identity}",
                body.len(),
            )
            .as_bytes(),
        )
        .to_hex()
        .to_string();
        let correlation_id = audit_effect
            .then(|| {
                self.audit
                    .as_ref()
                    .map(|audit| format!("{operation_id}:{}", audit.sequence() + 1))
            })
            .flatten();
        if let (Some(audit), Some(correlation_id)) = (&self.audit, &correlation_id) {
            audit
                .append(AuditRecord {
                    ts_ms: 0,
                    kind: "machine.effect.intent".into(),
                    wallet: account_wallet.clone(),
                    chain: None,
                    data: serde_json::json!({
                        "operation": operation,
                        "operation_id": operation_id,
                        "correlation_id": correlation_id,
                        "petal_mount": mount,
                        "route_path": path,
                        "payload_blake3": payload_digest,
                        "payload_size": body.len(),
                    }),
                    prev: String::new(),
                    digest: String::new(),
                })
                .map_err(|error| {
                    HandlerError::backend(format!(
                        "Machine audit unavailable before Petal execution: {error}"
                    ))
                })?;
        }
        let executed = self
            .runner
            .dispatch_petal_route_with_trusted_params(
                mount,
                DispatchRequest {
                    op,
                    path,
                    body,
                    ctx: Vec::new(),
                },
                self.host.clone(),
                None,
                self.run_options(mount),
                trusted_params,
                account,
            )
            .await;
        let (outcome, result_digest) = match &executed {
            Ok(out) => (
                "ok",
                blake3::hash(format!("{:?}", out.response).as_bytes())
                    .to_hex()
                    .to_string(),
            ),
            Err(error) => (
                "error",
                blake3::hash(error.to_string().as_bytes())
                    .to_hex()
                    .to_string(),
            ),
        };
        if let (Some(audit), Some(correlation_id)) = (&self.audit, &correlation_id) {
            audit
                .append(AuditRecord {
                    ts_ms: 0,
                    kind: "machine.effect.result".into(),
                    wallet: None,
                    chain: None,
                    data: serde_json::json!({
                        "operation": operation,
                        "correlation_id": correlation_id,
                        "outcome": outcome,
                        "result_digest_blake3": result_digest,
                    }),
                    prev: String::new(),
                    digest: String::new(),
                })
                .map_err(|error| {
                    HandlerError::backend(format!(
                        "Machine audit unavailable after Petal execution: {error}"
                    ))
                })?;
        }
        Ok(executed.map_err(map_petal_err)?.response)
    }
}

#[async_trait]
impl Handler for PetalRouter {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        self.require_account_mount(path)?;
        match path.segments() {
            [] => Ok(Entry::dir("")),
            [mount] => {
                if !self.is_petal(mount) {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                }
                Ok(Entry::dir(mount))
            }
            [mount, name] if Self::is_petal_document(name) => {
                let bytes = self
                    .runner
                    .petal_document(mount, name)
                    .map_err(map_petal_err)?;
                let mut entry = Entry::read_only_file(name);
                entry.size = bytes.len() as u64;
                Ok(entry)
            }
            [mount, wallets] if wallets == "wallets" && self.is_petal(mount) => {
                Ok(Entry::dir("wallets"))
            }
            [mount, wallets, wallet] if wallets == "wallets" && self.is_petal(mount) => {
                if self
                    .wallet_entries()
                    .await?
                    .iter()
                    .any(|entry| entry.name == *wallet)
                {
                    Ok(Entry::dir(wallet))
                } else {
                    Err(HandlerError::not_found(path.to_string_path()))
                }
            }
            [mount, wallets, wallet, number] if wallets == "wallets" && self.is_petal(mount) => {
                let account = self.account_context(wallet, number).await?;
                if account.number != 0
                    && !self
                        .runner
                        .petal_account_aware(mount)
                        .map_err(map_petal_err)?
                {
                    return Err(HandlerError::not_found(path.to_string_path()));
                }
                Ok(Entry::dir(number))
            }
            _ => {
                let (mount, rest, account) = self.scoped_account(path).await?;
                let original = self.scoped_path(mount, DispatchOp::Lookup, &rest, &account.wallet);
                let original =
                    match original {
                        Ok(original) => original,
                        Err(HandlerError::NotFound(_)) => {
                            let indexes = self.scoped_indexes(mount)?;
                            let scoped = &indexes.1;
                            if scoped.routes.iter().any(|route| {
                                crate::runner::route_has_descendant(&route.pattern, &rest)
                            }) {
                                return Ok(Entry::dir(path.segments().last().expect("non-root")));
                            }
                            return Err(HandlerError::not_found(path.to_string_path()));
                        }
                        Err(error) => return Err(error),
                    };
                match self
                    .dispatch_for_account(
                        mount,
                        DispatchOp::Lookup,
                        original.clone(),
                        Vec::new(),
                        &account,
                    )
                    .await
                {
                    Ok(DispatchResponse::Lookup(entry)) => entry_to_vfs(entry),
                    Ok(DispatchResponse::Error { code, message }) => {
                        Err(dispatch_error(code, message, path.to_string_path()))
                    }
                    Ok(other) => Err(unexpected_response("lookup", other)),
                    Err(HandlerError::NotFound(_))
                        if self
                            .runner
                            .petal_has_descendant(mount, &original)
                            .map_err(map_petal_err)? =>
                    {
                        let name = path
                            .segments()
                            .last()
                            .map(String::as_str)
                            .unwrap_or_default();
                        Ok(Entry::dir(name))
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        self.require_account_mount(path)?;
        let (mount, rest) = Self::mount_path(path)?;
        if !self.is_petal(mount) {
            return Err(HandlerError::NotFound(path.to_string_path()));
        }
        if Self::is_petal_document(&rest) {
            return self
                .runner
                .petal_document(mount, &rest)
                .map_err(map_petal_err);
        }
        let (mount, rest, account) = self.scoped_account(path).await?;
        let original = self.scoped_path(mount, DispatchOp::Read, &rest, &account.wallet)?;
        match self
            .dispatch_for_account(mount, DispatchOp::Read, original, Vec::new(), &account)
            .await?
        {
            DispatchResponse::Read(bytes) => Ok(bytes),
            DispatchResponse::Error { code, message } => {
                Err(dispatch_error(code, message, path.to_string_path()))
            }
            other => Err(unexpected_response("read", other)),
        }
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        self.require_account_mount(path)?;
        let (mount, rest) = Self::mount_path(path)?;
        if rest.is_empty() {
            return Err(HandlerError::PermissionDenied);
        }
        if !self.is_petal(mount) {
            return Err(HandlerError::NotFound(path.to_string_path()));
        }
        if Self::is_petal_document(&rest) {
            return Err(HandlerError::PermissionDenied);
        }
        let (mount, rest, account) = self.scoped_account(path).await?;
        let original = self.scoped_path(mount, DispatchOp::Write, &rest, &account.wallet)?;
        match self
            .dispatch_for_account(mount, DispatchOp::Write, original, data.to_vec(), &account)
            .await?
        {
            DispatchResponse::Write => Ok(()),
            DispatchResponse::Error { code, message } => {
                tracing::debug!(
                    path = %path.to_string_path(),
                    code,
                    message = %message,
                    "petal.write_rejected"
                );
                Err(dispatch_error(code, message, path.to_string_path()))
            }
            other => Err(unexpected_response("write", other)),
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        self.require_account_mount(path)?;
        match path.segments() {
            [] => {
                let mut mounts = BTreeMap::new();
                for (mount, _hash) in self.runner.local_petal_mounts().map_err(map_petal_err)? {
                    if self.is_petal(&mount) {
                        mounts.insert(mount, ());
                    }
                }
                Ok(mounts.into_keys().map(|mount| Entry::dir(&mount)).collect())
            }
            [mount] if self.is_petal(mount) => {
                Ok(Self::add_petal_documents(vec![Entry::dir("wallets")]))
            }
            [mount] => Err(HandlerError::NotFound(mount.to_string())),
            [mount, wallets] if wallets == "wallets" && self.is_petal(mount) => {
                self.wallet_entries().await
            }
            [mount, wallets, wallet] if wallets == "wallets" && self.is_petal(mount) => {
                if !self
                    .wallet_entries()
                    .await?
                    .iter()
                    .any(|entry| entry.name == *wallet)
                {
                    return Err(HandlerError::not_found(path.to_string_path()));
                }
                self.account_entries(wallet).await.map(|entries| {
                    entries
                        .into_iter()
                        .filter(|entry| {
                            entry.name == "0"
                                || self.runner.petal_account_aware(mount).unwrap_or(false)
                        })
                        .collect()
                })
            }
            _ => {
                let (mount, rest, account) = self.scoped_account(path).await?;
                let indexes = self.scoped_indexes(mount)?;
                let (original_index, scoped) = indexes.as_ref();
                let original = self.scoped_path(mount, DispatchOp::List, &rest, &account.wallet);
                match original {
                    Ok(original) => match self
                        .dispatch_for_account(
                            mount,
                            DispatchOp::List,
                            original,
                            Vec::new(),
                            &account,
                        )
                        .await
                    {
                        Ok(DispatchResponse::List(entries)) => {
                            Self::project_scoped_list(original_index, scoped, &rest, entries)
                        }
                        Ok(DispatchResponse::Error { code, message }) => {
                            Err(dispatch_error(code, message, path.to_string_path()))
                        }
                        Ok(other) => Err(unexpected_response("list", other)),
                        Err(HandlerError::NotFound(_)) => {
                            crate::runner::static_list_entries(scoped, &rest)
                                .into_iter()
                                .map(entry_to_vfs)
                                .collect()
                        }
                        Err(e) => Err(e),
                    },
                    Err(HandlerError::NotFound(_)) => {
                        crate::runner::static_list_entries(scoped, &rest)
                            .into_iter()
                            .map(entry_to_vfs)
                            .collect()
                    }
                    Err(error) => Err(error),
                }
            }
        }
    }

    // Repository documents are served by the host, never by a matching guest
    // route. Keep their metadata consistent with lookup/read/write, including
    // before a parameterized route has supplied its runtime metadata.
    fn cache_ttl(&self, path: &VfsPath) -> Option<Duration> {
        if let Some((mount, rest)) = self.metadata_route_path(path, DispatchOp::Read) {
            return self
                .runner
                .petal_route_effective_metadata(&mount, DispatchOp::Read, &rest)
                .ok()
                .filter(|(_, metadata)| !metadata.side_effecting_read)
                .and_then(|(_, metadata)| metadata.cache_ttl_ms)
                .map(Duration::from_millis);
        }
        None
    }

    fn is_read_side_effecting(&self, path: &VfsPath) -> bool {
        if let Some((mount, rest)) = self.metadata_route_path(path, DispatchOp::Read) {
            return self
                .runner
                .petal_route_effective_metadata(&mount, DispatchOp::Read, &rest)
                .ok()
                .map(|(_, metadata)| metadata.side_effecting_read)
                .unwrap_or(false);
        }
        false
    }

    fn is_async_write_command(&self, path: &VfsPath) -> bool {
        if let Some((mount, rest)) = self.metadata_route_path(path, DispatchOp::Write) {
            return self
                .runner
                .petal_route_effective_metadata(&mount, DispatchOp::Write, &rest)
                .ok()
                .map(|(route, metadata)| {
                    route.route.install_metadata.write_async || metadata.write_async
                })
                .unwrap_or(false);
        }
        false
    }
}

fn entry_to_vfs(entry: DispatchEntry) -> Result<Entry, HandlerError> {
    validate_entry_name(&entry.name)?;
    if entry.kind == DispatchEntryKind::Symlink {
        let Some(target) = entry.link_target.as_deref() else {
            return Err(HandlerError::invalid("symlink entry missing link target"));
        };
        validate_link_target(target)?;
    }
    let (kind, default_mode) = match entry.kind {
        DispatchEntryKind::Dir => (EntryKind::Dir, 0o755),
        DispatchEntryKind::File => (EntryKind::File, 0o444),
        DispatchEntryKind::WritableFile => (EntryKind::File, 0o644),
        DispatchEntryKind::ExecutableFile => (EntryKind::File, 0o555),
        DispatchEntryKind::Symlink => (EntryKind::Symlink, 0o777),
    };
    Ok(Entry {
        name: entry.name,
        kind,
        size: entry.size,
        mode: if entry.mode == 0 {
            default_mode
        } else {
            entry.mode
        },
        link_target: entry.link_target,
        modified: None,
    })
}

fn validate_entry_name(name: &str) -> Result<(), HandlerError> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(HandlerError::invalid(format!(
            "dispatch entry name must be a normal path segment: {name:?}"
        )));
    }
    if name.contains('/') || name.contains('\\') || name.bytes().any(|b| b == 0) {
        return Err(HandlerError::invalid(format!(
            "dispatch entry name must be a single path segment: {name:?}"
        )));
    }
    Ok(())
}

fn validate_link_target(target: &str) -> Result<(), HandlerError> {
    if target.is_empty() || target.starts_with('/') {
        return Err(HandlerError::invalid(format!(
            "dispatch symlink target must be mount-relative: {target:?}"
        )));
    }
    if target.contains('\\') || target.bytes().any(|b| b == 0) {
        return Err(HandlerError::invalid(format!(
            "dispatch symlink target contains invalid bytes: {target:?}"
        )));
    }
    if target
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(HandlerError::invalid(format!(
            "dispatch symlink target must not contain dot or empty segments: {target:?}"
        )));
    }
    Ok(())
}

fn dispatch_error(code: i32, message: String, path: String) -> HandlerError {
    match code {
        -1 => HandlerError::NotFound(if message.is_empty() { path } else { message }),
        -2 => HandlerError::PermissionDenied,
        -3 => HandlerError::Invalid(message),
        -4 => HandlerError::Backend(message),
        COMPONENT_NOT_A_DIR_CODE => {
            HandlerError::NotADir(if message.is_empty() { path } else { message })
        }
        COMPONENT_UNSUPPORTED_CODE => HandlerError::Unsupported(message),
        _ => HandlerError::Backend(format!("petal dispatch error {code}: {message}")),
    }
}

fn unexpected_response(op: &str, response: DispatchResponse) -> HandlerError {
    HandlerError::Backend(format!(
        "petal dispatch {op} returned unexpected response: {response:?}"
    ))
}

fn map_petal_err(e: PetalError) -> HandlerError {
    match e {
        PetalError::NotFound(s) => HandlerError::NotFound(s),
        PetalError::InvalidHash(s) => HandlerError::invalid(format!("hash: {s}")),
        PetalError::InvalidName(s) => HandlerError::invalid(format!("name: {s}")),
        PetalError::InvalidWasm(s) => HandlerError::invalid(format!("wasm: {s}")),
        PetalError::CapabilityDenied { petal, cap } => {
            HandlerError::Backend(format!("capability denied: petal={petal} cap={cap}"))
        }
        PetalError::Vm(s) => HandlerError::Backend(format!("vm: {s}")),
        PetalError::Io(e) => HandlerError::Io(e),
        PetalError::Serde(s) => HandlerError::Backend(format!("serde: {s}")),
        PetalError::ModeCapMismatch { mode, cap } => HandlerError::invalid(format!(
            "mode/cap mismatch: mode={mode:?} disallows cap={cap}"
        )),
        PetalError::CapMismatch => HandlerError::invalid(
            "cap mismatch: petal already installed with different capabilities".to_string(),
        ),
        PetalError::ModeConflict { existing } => {
            HandlerError::invalid(format!("mode conflict: existing={existing}"))
        }
        PetalError::ModeUnsupported(s) => HandlerError::invalid(format!("mode unsupported: {s}")),
        PetalError::ChainCall(s) => HandlerError::Backend(format!("chain call: {s}")),
        PetalError::ChainCallTrap { detail, fuel_used } => HandlerError::Backend(format!(
            "chain call trapped after {fuel_used} fuel: {detail}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bloom_vfs::{Handler, Vfs, VfsPath};
    use tempfile::TempDir;

    use super::*;
    use crate::host::{DenyHost, HostError, HostVfsEntry, HostVfsEntryKind, PetalHost};
    use crate::registry::NameRegistry;
    use crate::store::PetalStore;
    use crate::vm::PetalVm;

    struct AccountHost;

    #[async_trait]
    impl PetalHost for AccountHost {
        async fn vfs_lookup(&self, path: &str) -> Result<HostVfsEntry, HostError> {
            Err(HostError::NotFound(path.into()))
        }
        async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
            if path == "wallets/alice/0/account.json" {
                Ok(br#"{"schema":"bloom.account.v1","wallet":"alice","number":0,"freshness":"fresh","evm":{"public_key_fingerprint":"aa"},"solana":{"state":"missing"}}"#.to_vec())
            } else if path == "wallets/alice/1/account.json" {
                Ok(br#"{"schema":"bloom.account.v1","wallet":"alice","number":1,"freshness":"fresh","evm":{"public_key_fingerprint":"bb"},"solana":{"state":"missing"}}"#.to_vec())
            } else {
                Err(HostError::NotFound(path.into()))
            }
        }
        async fn vfs_list(&self, path: &str) -> Result<Vec<HostVfsEntry>, HostError> {
            let names = match path {
                "wallets" => vec!["alice"],
                "wallets/alice" => vec!["0", "1"],
                _ => return Err(HostError::NotFound(path.into())),
            };
            Ok(names
                .into_iter()
                .map(|name| HostVfsEntry {
                    name: name.into(),
                    kind: HostVfsEntryKind::Dir,
                    mode: 0o755,
                    size: None,
                    link_target: None,
                })
                .collect())
        }
        async fn vfs_write(&self, path: &str, _bytes: &[u8]) -> Result<(), HostError> {
            Err(HostError::Denied(path.into()))
        }
    }

    fn runner() -> (TempDir, PetalRunner) {
        let dir = TempDir::new().unwrap();
        let store = PetalStore::open(dir.path().join("store")).unwrap();
        let reg = Arc::new(NameRegistry::open(dir.path().join("reg")).unwrap());
        let vm = PetalVm::new().unwrap();
        (dir, PetalRunner::new(store, reg, vm))
    }

    fn write_package_file(root: &std::path::Path, rel: &str, body: &[u8]) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn write_demo_package(root: &std::path::Path) {
        write_package_file(
            root,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "demo"
"#,
        );
        write_package_file(root, "README.md", b"# demo");
        write_package_file(root, "AGENTS.md", b"# demo agents");
        write_package_file(
            root,
            "petal/demo/hello.txt.wasm",
            include_bytes!("../tests/fixtures/route_component_no_imports.wasm"),
        );
    }

    fn write_dynamic_dir_package(root: &std::path::Path, side_effecting_read: bool) {
        write_package_file(
            root,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "example"

[caps]
allowed = ["bloom:store", "bloom:vfs.read"]

[store]
namespaces = ["wallets"]
"#,
        );
        write_package_file(root, "README.md", b"# example");
        write_package_file(root, "AGENTS.md", b"# example agents");
        let route = if side_effecting_read {
            crate::package::route_fixtures::dynamic_side_effecting_dir_route_component(
                true,
                crate::package::route_fixtures::FixtureVfsImport::ReadOnly,
                &["bloom:store", "bloom:vfs.read"],
                None,
            )
        } else {
            crate::package::route_fixtures::dynamic_dir_route_component(
                true,
                crate::package::route_fixtures::FixtureVfsImport::ReadOnly,
                &["bloom:store", "bloom:vfs.read"],
                None,
            )
        };
        write_package_file(root, "petal/example/[wallet]/$index.wasm", &route);
    }

    fn write_async_failing_package(root: &std::path::Path) {
        write_package_file(
            root,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "example"
"#,
        );
        write_package_file(root, "README.md", b"# example");
        write_package_file(root, "AGENTS.md", b"# example agents");
        write_package_file(
            root,
            "petal/example/operations/[wallet]/submit.wasm",
            &crate::package::route_fixtures::async_failing_write_route_component(),
        );
    }

    #[tokio::test]
    async fn scoped_account_directory_is_synthetic() {
        let (dir, runner) = runner();
        let package = dir.path().join("example-app");
        write_dynamic_dir_package(&package, false);
        runner.store().install_petal_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(AccountHost));
        let route_path = VfsPath::parse("/example/wallets/alice/0").unwrap();
        assert!(router.is_read_side_effecting(&route_path));
        assert_eq!(router.cache_ttl(&route_path), None);
        let vfs = Vfs::builder()
            .mount("petals", Arc::new(router.clone()))
            .build();

        let entry = vfs
            .lookup(&VfsPath::parse("/petals/example/wallets/alice/0").unwrap())
            .await
            .unwrap();
        assert_eq!(entry.name, "0");
        assert_eq!(entry.kind, bloom_vfs::EntryKind::Dir);
        assert_eq!(entry.mode, 0o755);
        assert_eq!(entry.size, 0);
        assert!(router.is_read_side_effecting(&route_path));
        assert_eq!(router.cache_ttl(&route_path), None);
    }

    #[tokio::test]
    async fn parameterized_side_effecting_route_remains_fail_closed_after_lookup() {
        let (dir, runner) = runner();
        let package = dir.path().join("example-app");
        write_dynamic_dir_package(&package, true);
        runner.store().install_petal_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(AccountHost));
        let route_path = VfsPath::parse("/example/wallets/alice/0").unwrap();
        assert!(router.is_read_side_effecting(&route_path));
        let vfs = Vfs::builder()
            .mount("petals", Arc::new(router.clone()))
            .build();

        vfs.lookup(&VfsPath::parse("/petals/example/wallets/alice/0").unwrap())
            .await
            .unwrap();

        assert!(router.is_read_side_effecting(&route_path));
        assert_eq!(router.cache_ttl(&route_path), None);
    }

    #[tokio::test]
    async fn package_documents_do_not_inherit_parameterized_route_metadata() {
        let (dir, runner) = runner();
        let package = dir.path().join("example-app");
        write_dynamic_dir_package(&package, false);
        runner.store().install_petal_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(AccountHost));
        let vfs = Vfs::builder()
            .mount("petals", Arc::new(router.clone()))
            .build();
        assert!(
            vfs.is_read_side_effecting(&VfsPath::parse("/petals/example/wallets/alice/0").unwrap())
        );
        for (name, contents) in [
            ("README.md", b"# example".as_slice()),
            ("AGENTS.md", b"# example agents".as_slice()),
        ] {
            let path = VfsPath::parse(&format!("/petals/example/{name}")).unwrap();
            // NFS uses this gate before rendering a file to determine its size.
            assert!(!vfs.is_read_side_effecting(&path));
            let entry = vfs.lookup(&path).await.unwrap();
            assert_eq!(entry.size, contents.len() as u64);
            assert_eq!(entry.mode, 0o444);
            assert_eq!(vfs.read(&path).await.unwrap(), contents);
            assert!(!vfs.is_async_write_command(&path));
            assert!(matches!(
                vfs.write(&path, b"replace").await,
                Err(HandlerError::PermissionDenied)
            ));
        }
        // The synthetic account directory has no guest TTL to leak to docs.
        assert_eq!(
            router.cache_ttl(&VfsPath::parse("/example/wallets/alice/0").unwrap()),
            None
        );
        for name in PETAL_DOCUMENT_NAMES {
            assert_eq!(
                router.cache_ttl(&VfsPath::parse(&format!("/example/{name}")).unwrap()),
                None
            );
        }
    }

    #[tokio::test]
    async fn package_documents_are_not_async_guest_commands() {
        let (dir, runner) = runner();
        let package = dir.path().join("example-app");
        write_async_failing_package(&package);
        std::fs::rename(
            package.join("petal/example/operations/[wallet]/submit.wasm"),
            package.join("petal/example/operations/[wallet]/submit-old.wasm"),
        )
        .unwrap();
        // Even explicit guest documentation routes cannot override the host's
        // repository documents or attach their command/cache metadata.
        for name in PETAL_DOCUMENT_NAMES {
            write_package_file(
                &package,
                &format!("petal/example/{name}.wasm"),
                &crate::package::route_fixtures::async_failing_write_route_component(),
            );
        }
        runner.store().install_petal_package_dir(&package).unwrap();
        let router = PetalRouter::new(runner, Arc::new(DenyHost));
        assert!(router.is_async_write_command(
            &VfsPath::parse("/example/wallets/alice/0/operations/submit-old").unwrap()
        ));
        for name in PETAL_DOCUMENT_NAMES {
            let path = VfsPath::parse(&format!("/example/{name}")).unwrap();
            assert!(!router.is_async_write_command(&path));
            assert_eq!(router.cache_ttl(&path), None);
        }
    }

    #[tokio::test]
    async fn mounted_petals_vfs_dispatches_installed_petal_routes() {
        let (dir, runner) = runner();
        let package = dir.path().join("demo-app");
        write_demo_package(&package);
        runner.store().install_petal_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(AccountHost));
        let vfs = Vfs::builder().mount("petals", Arc::new(router)).build();

        let apps = vfs.list(&VfsPath::parse("/petals").unwrap()).await.unwrap();
        assert!(apps.iter().any(|entry| entry.name == "demo"));

        let app_entries = vfs
            .list(&VfsPath::parse("/petals/demo").unwrap())
            .await
            .unwrap();
        assert!(app_entries.iter().any(|entry| entry.name == "wallets"));
        let accounts = vfs
            .list(&VfsPath::parse("/petals/demo/wallets/alice").unwrap())
            .await
            .unwrap();
        assert_eq!(
            accounts
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["0"]
        );
        assert!(matches!(
            vfs.lookup(&VfsPath::parse("/petals/demo/wallets/alice/1").unwrap())
                .await,
            Err(HandlerError::NotFound(_))
        ));
        assert!(app_entries.iter().any(|entry| entry.name == "README.md"));
        assert!(app_entries.iter().any(|entry| entry.name == "AGENTS.md"));

        let readme = vfs
            .read(&VfsPath::parse("/petals/demo/README.md").unwrap())
            .await
            .unwrap();
        assert_eq!(readme, b"# demo");

        let agents = vfs
            .read(&VfsPath::parse("/petals/demo/AGENTS.md").unwrap())
            .await
            .unwrap();
        assert_eq!(agents, b"# demo agents");

        let readme_entry = vfs
            .lookup(&VfsPath::parse("/petals/demo/README.md").unwrap())
            .await
            .unwrap();
        assert_eq!(readme_entry.kind, bloom_vfs::EntryKind::File);
        assert_eq!(readme_entry.mode, 0o444);
        assert_eq!(readme_entry.size, 6);

        let write_error = vfs
            .write(
                &VfsPath::parse("/petals/demo/README.md").unwrap(),
                b"replace",
            )
            .await
            .unwrap_err();
        assert!(matches!(write_error, HandlerError::PermissionDenied));

        let bytes = vfs
            .read(&VfsPath::parse("/petals/demo/wallets/alice/0/hello.txt").unwrap())
            .await
            .unwrap();
        assert_eq!(bytes, b"component");
    }

    #[tokio::test]
    async fn mounted_petals_reject_unknown_wallet_and_noncanonical_account_paths() {
        let (dir, runner) = runner();
        let package = dir.path().join("demo-app");
        write_demo_package(&package);
        runner.store().install_petal_package_dir(&package).unwrap();
        let vfs = Vfs::builder()
            .mount(
                "petals",
                Arc::new(PetalRouter::new(runner, Arc::new(AccountHost))),
            )
            .build();

        for path in [
            "/petals/demo/wallets/unknown",
            "/petals/demo/wallets/unknown/0",
            "/petals/demo/wallets/alice/01",
            "/petals/demo/wallets/alice/4294967296",
        ] {
            assert!(
                matches!(
                    vfs.lookup(&VfsPath::parse(path).unwrap()).await,
                    Err(HandlerError::NotFound(_))
                ),
                "unexpectedly resolved {path}"
            );
        }
        for segment in ["", "00", "01", "+1", "-1", "4294967296"] {
            assert_eq!(canonical_account(segment), None, "{segment}");
        }
        assert_eq!(canonical_account("0"), Some(0));
        assert_eq!(canonical_account("1"), Some(1));
    }

    #[test]
    fn guest_listing_projects_wallet_filename_to_parent_file() {
        let (dir, runner) = runner();
        let package = dir.path().join("demo-app");
        write_demo_package(&package);
        runner.store().install_petal_package_dir(&package).unwrap();
        let mut original = runner.load_petal_route_index("demo").unwrap();
        let mut projected_file = original.routes[0].clone();
        projected_file.route_id = "projected-filename".into();
        projected_file.pattern = "obligations/[wallet].json".into();
        original.routes.push(projected_file);
        let scoped = scoped_route_index(&original).unwrap();
        let listing = PetalRouter::project_scoped_list(
            &original,
            &scoped,
            "",
            vec![DispatchEntry {
                name: "obligations".into(),
                kind: DispatchEntryKind::Dir,
                size: 0,
                mode: 0o755,
                ttl_hint_ms: None,
                link_target: None,
            }],
        )
        .unwrap();
        assert_eq!(
            listing
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["obligations.json"]
        );
        assert_eq!(listing[0].kind, EntryKind::File);
    }

    #[test]
    fn router_rejects_undeclared_endpoint_override_before_dispatch() {
        let (dir, runner) = runner();
        let package = dir.path().join("demo-app");
        write_demo_package(&package);
        runner.store().install_petal_package_dir(&package).unwrap();

        let runtime_petals = BTreeMap::from([(
            "demo".to_string(),
            PetalRuntimeConfig {
                endpoints: BTreeMap::from([(
                    "clob".to_string(),
                    "https://clob.internal.example".to_string(),
                )]),
                values: BTreeMap::new(),
            },
        )]);
        let err = match PetalRouter::new(runner, Arc::new(DenyHost))
            .with_runtime_petals(runtime_petals)
        {
            Ok(_) => panic!("undeclared endpoint override unexpectedly accepted"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("endpoint override \"clob\" is not declared"),
            "unexpected router construction error: {err}"
        );
    }

    #[tokio::test]
    async fn write_async_route_errors_are_returned_to_the_vfs_caller() {
        let (dir, runner) = runner();
        let package = dir.path().join("example-app");
        write_async_failing_package(&package);
        runner.store().install_petal_package_dir(&package).unwrap();

        // A true switch used to detach this write and return Ok immediately.
        // The compatibility method is now deliberately a no-op.
        let router = PetalRouter::new(runner, Arc::new(AccountHost))
            .with_async_write_switch(Arc::new(AtomicBool::new(true)));
        let vfs = Vfs::builder().mount("petals", Arc::new(router)).build();
        let path = VfsPath::parse("/petals/example/wallets/alice/0/operations/submit").unwrap();
        assert!(
            vfs.is_async_write_command(&path),
            "mounted component writes must not return handler failures through macOS NFS"
        );

        let error = vfs.write(&path, b"payload").await.unwrap_err();
        assert!(
            error.to_string().contains("component route write"),
            "unexpected write error: {error}"
        );
    }
}
