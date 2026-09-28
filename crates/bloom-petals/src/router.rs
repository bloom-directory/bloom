//! VFS router for installed Petal packages.
//!
//! The daemon mounts this handler at `petals/`. The first path segment selects
//! an installed Petal package; the remaining path is passed to the matched
//! Petal route artifact.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use async_trait::async_trait;
use bloom_proto::config::PetalRuntimeConfig;
use bloom_proto::{AuditLog, AuditRecord};
use bloom_vfs::handler::{Entry, EntryKind, Handler, HandlerError};
use bloom_vfs::handlers::wallets::AccountPetalContext;
use bloom_vfs::path::VfsPath;

use crate::abi::{DispatchEntry, DispatchEntryKind, DispatchOp, DispatchRequest, DispatchResponse};
use crate::error::PetalError;
use crate::host::PetalHost;
use crate::runner::{PETAL_DOCUMENT_NAMES, PetalRunner};
use crate::vm::{COMPONENT_NOT_A_DIR_CODE, COMPONENT_UNSUPPORTED_CODE, RunOptions};

#[derive(Clone)]
pub struct PetalRouter {
    runner: PetalRunner,
    host: Arc<dyn PetalHost>,
    runtime_petals: BTreeMap<String, PetalRuntimeConfig>,
    audit: Option<Arc<AuditLog>>,
    audit_effect_lock: Arc<tokio::sync::Mutex<()>>,
}

impl PetalRouter {
    pub fn new(runner: PetalRunner, host: Arc<dyn PetalHost>) -> Self {
        Self {
            runner,
            host,
            runtime_petals: BTreeMap::new(),
            audit: None,
            audit_effect_lock: Arc::new(tokio::sync::Mutex::new(())),
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
    }

    fn is_petal_document(path: &str) -> bool {
        PETAL_DOCUMENT_NAMES.contains(&path)
    }

    fn add_petal_documents(mut entries: Vec<Entry>) -> Vec<Entry> {
        entries.retain(|entry| !Self::is_petal_document(&entry.name));
        entries.extend(PETAL_DOCUMENT_NAMES.map(Entry::read_only_file));
        entries
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

    fn metadata_route_path(&self, path: &VfsPath, _op: DispatchOp) -> Option<(String, String)> {
        let (mount, rest) = Self::mount_path(path).ok()?;
        (self.is_petal(mount) && !Self::is_petal_document(&rest)).then(|| (mount.to_owned(), rest))
    }

    async fn validate_ancestor(&self, mount: &str, path: &str) -> Result<(), HandlerError> {
        let index = self
            .runner
            .load_petal_route_index(mount)
            .map_err(map_petal_err)?;
        let values = path
            .split('/')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        let mut checked_accounts = BTreeSet::new();
        let mut checked_wallets = BTreeSet::new();
        for route in &index.routes {
            if !crate::runner::route_has_descendant(&route.pattern, path) {
                continue;
            }
            let captures = route.pattern.split('/').zip(&values).collect::<Vec<_>>();
            let wallet = captures
                .iter()
                .find(|(name, _)| *name == "[wallet]")
                .map(|(_, value)| **value);
            let number = captures
                .iter()
                .find(|(name, _)| *name == "[index]")
                .map(|(_, value)| **value);
            if let (Some(wallet), Some(number)) = (wallet, number) {
                if checked_accounts.insert((wallet, number)) {
                    self.account_context(wallet, number).await?;
                }
            } else if let Some(wallet) = wallet
                && checked_wallets.insert(wallet)
                && !self
                    .host
                    .vfs_list("wallets")
                    .await
                    .map_err(map_host_err)?
                    .iter()
                    .any(|entry| {
                        entry.name == wallet && entry.kind == crate::host::HostVfsEntryKind::Dir
                    })
            {
                return Err(HandlerError::not_found(format!("wallets/{wallet}")));
            }
        }
        Ok(())
    }

    async fn discovered_entries(
        &self,
        mount: &str,
        path: &str,
    ) -> Result<Vec<Entry>, HandlerError> {
        let index = self
            .runner
            .load_petal_route_index(mount)
            .map_err(map_petal_err)?;
        let values = path
            .split('/')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        let mut entries = BTreeMap::new();
        let mut listed_paths = BTreeSet::new();
        for route in &index.routes {
            if !crate::runner::route_has_descendant(&route.pattern, path) {
                continue;
            }
            let pattern = route.pattern.split('/').collect::<Vec<_>>();
            let core = match pattern.get(values.len()).copied() {
                Some("[wallet]") if pattern.get(values.len() + 1) == Some(&"[index]") => {
                    "wallets".to_owned()
                }
                Some("[index]")
                    if !values.is_empty() && pattern[values.len() - 1] == "[wallet]" =>
                {
                    format!("wallets/{}", values[values.len() - 1])
                }
                _ => continue,
            };
            if !listed_paths.insert(core.clone()) {
                continue;
            }
            for entry in self.host.vfs_list(&core).await.map_err(map_host_err)? {
                if entry.kind == crate::host::HostVfsEntryKind::Dir
                    && (core == "wallets" && entry.name != "registrations"
                        || core != "wallets" && canonical_account(&entry.name).is_some())
                {
                    entries.insert(entry.name.clone(), Entry::dir(&entry.name));
                }
            }
        }
        Ok(entries.into_values().collect())
    }

    async fn dispatch(
        &self,
        mount: &str,
        op: DispatchOp,
        path: String,
        body: Vec<u8>,
    ) -> Result<DispatchResponse, HandlerError> {
        let matched = self
            .runner
            .petal_route(mount, op, &path)
            .map_err(map_petal_err)?;
        let wallet = matched
            .params
            .iter()
            .find(|(name, _)| name == "wallet")
            .map(|(_, value)| value.as_str());
        let index = matched
            .params
            .iter()
            .find(|(name, _)| name == "index")
            .map(|(_, value)| value.as_str());
        match (wallet, index) {
            (Some(wallet), Some(index)) => {
                let pattern = matched.route.pattern.split('/').collect::<Vec<_>>();
                if !pattern
                    .windows(2)
                    .any(|pair| pair == ["[wallet]", "[index]"])
                {
                    return Err(HandlerError::PermissionDenied);
                }
                let account = self.account_context(wallet, index).await?;
                self.dispatch_for_account(mount, op, path, body, &account)
                    .await
            }
            (_, None) => {
                self.dispatch_with_params(mount, op, path, body, &[], None, None)
                    .await
            }
            (None, Some(_)) => Err(HandlerError::PermissionDenied),
        }
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
    /// Dispatch using the account identity resolved by the host from live core state.
    pub async fn dispatch_for_account(
        &self,
        mount: &str,
        op: DispatchOp,
        path: String,
        body: Vec<u8>,
        account: &AccountPetalContext,
    ) -> Result<DispatchResponse, HandlerError> {
        let trusted = vec![
            ("bloom.wallet".to_owned(), account.wallet.clone()),
            ("bloom.account".to_owned(), account.number.to_string()),
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
        if path.segments().is_empty() {
            return Ok(Entry::dir(""));
        }
        let (mount, rest) = Self::mount_path(path)?;
        if !self.is_petal(mount) {
            return Err(HandlerError::not_found(path.to_string_path()));
        }
        if rest.is_empty() {
            return Ok(Entry::dir(mount));
        }
        if Self::is_petal_document(&rest) {
            let bytes = self
                .runner
                .petal_document(mount, &rest)
                .map_err(map_petal_err)?;
            let mut entry = Entry::read_only_file(&rest);
            entry.size = bytes.len() as u64;
            return Ok(entry);
        }
        match self
            .dispatch(mount, DispatchOp::Lookup, rest.clone(), Vec::new())
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
                    .petal_has_descendant(mount, &rest)
                    .map_err(map_petal_err)? =>
            {
                self.validate_ancestor(mount, &rest).await?;
                Ok(Entry::dir(path.segments().last().expect("non-root")))
            }
            Err(error) => Err(error),
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let (mount, rest) = Self::mount_path(path)?;
        if Self::is_petal_document(&rest) {
            return self
                .runner
                .petal_document(mount, &rest)
                .map_err(map_petal_err);
        }
        match self
            .dispatch(mount, DispatchOp::Read, rest, Vec::new())
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
        let (mount, rest) = Self::mount_path(path)?;
        if rest.is_empty() || Self::is_petal_document(&rest) {
            return Err(HandlerError::PermissionDenied);
        }
        match self
            .dispatch(mount, DispatchOp::Write, rest, data.to_vec())
            .await?
        {
            DispatchResponse::Write => Ok(()),
            DispatchResponse::Error { code, message } => {
                Err(dispatch_error(code, message, path.to_string_path()))
            }
            other => Err(unexpected_response("write", other)),
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        if path.segments().is_empty() {
            return Ok(self
                .runner
                .local_petal_mounts()
                .map_err(map_petal_err)?
                .into_iter()
                .map(|(mount, _)| Entry::dir(&mount))
                .collect());
        }
        let (mount, rest) = Self::mount_path(path)?;
        if !self.is_petal(mount) {
            return Err(HandlerError::not_found(path.to_string_path()));
        }
        self.validate_ancestor(mount, &rest).await?;
        let entries = match self
            .dispatch(mount, DispatchOp::List, rest.clone(), Vec::new())
            .await
        {
            Ok(DispatchResponse::List(entries)) => entries
                .into_iter()
                .map(entry_to_vfs)
                .collect::<Result<Vec<_>, _>>()?,
            Ok(DispatchResponse::Error { code, message }) => {
                return Err(dispatch_error(code, message, path.to_string_path()));
            }
            Ok(other) => return Err(unexpected_response("list", other)),
            Err(HandlerError::NotFound(_)) => self
                .runner
                .petal_static_list(mount, &rest)
                .map_err(map_petal_err)?
                .into_iter()
                .map(entry_to_vfs)
                .collect::<Result<Vec<_>, _>>()?,
            Err(error) => return Err(error),
        };
        let mut entries = entries;
        for entry in self.discovered_entries(mount, &rest).await? {
            if !entries.iter().any(|existing| existing.name == entry.name) {
                entries.push(entry);
            }
        }
        Ok(if rest.is_empty() {
            Self::add_petal_documents(entries)
        } else {
            entries
        })
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
        write_package_file(
            root,
            "petal/example/intents/[wallet]/[index]/$index.wasm",
            &route,
        );
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
            "petal/example/operations/[wallet]/[index]/submit.wasm",
            &crate::package::route_fixtures::async_failing_write_route_component(),
        );
    }

    #[tokio::test]
    async fn explicit_account_directory_uses_guest_metadata() {
        let (dir, runner) = runner();
        let package = dir.path().join("example-app");
        write_dynamic_dir_package(&package, false);
        runner.store().install_petal_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(AccountHost));
        let route_path = VfsPath::parse("/example/intents/alice/0").unwrap();
        assert!(router.is_read_side_effecting(&route_path));
        assert_eq!(router.cache_ttl(&route_path), None);
        let vfs = Vfs::builder()
            .mount("petals", Arc::new(router.clone()))
            .build();

        let entry = vfs
            .lookup(&VfsPath::parse("/petals/example/intents/alice/0").unwrap())
            .await
            .unwrap();
        assert_eq!(entry.name, "alice");
        assert_eq!(entry.kind, bloom_vfs::EntryKind::Dir);
        assert_eq!(entry.mode, 0o755);
        assert_eq!(entry.size, 7);
        assert!(!router.is_read_side_effecting(&route_path));
        assert_eq!(router.cache_ttl(&route_path), Some(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn parameterized_side_effecting_route_remains_fail_closed_after_lookup() {
        let (dir, runner) = runner();
        let package = dir.path().join("example-app");
        write_dynamic_dir_package(&package, true);
        runner.store().install_petal_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(AccountHost));
        let route_path = VfsPath::parse("/example/intents/alice/0").unwrap();
        assert!(router.is_read_side_effecting(&route_path));
        let vfs = Vfs::builder()
            .mount("petals", Arc::new(router.clone()))
            .build();

        vfs.lookup(&VfsPath::parse("/petals/example/intents/alice/0").unwrap())
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
            vfs.is_read_side_effecting(&VfsPath::parse("/petals/example/intents/alice/0").unwrap())
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
        // Unresolved runtime route metadata cannot leak to repository documents.
        assert_eq!(
            router.cache_ttl(&VfsPath::parse("/example/intents/alice/0").unwrap()),
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
            package.join("petal/example/operations/[wallet]/[index]/submit.wasm"),
            package.join("petal/example/operations/[wallet]/[index]/submit-old.wasm"),
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
            &VfsPath::parse("/example/operations/alice/0/submit-old").unwrap()
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
        assert!(app_entries.iter().any(|entry| entry.name == "hello.txt"));
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
            .read(&VfsPath::parse("/petals/demo/hello.txt").unwrap())
            .await
            .unwrap();
        assert_eq!(bytes, b"component");
    }

    #[tokio::test]
    async fn mounted_petals_reject_unknown_wallet_and_noncanonical_account_paths() {
        let (dir, runner) = runner();
        let package = dir.path().join("demo-app");
        write_demo_package(&package);
        write_package_file(
            &package,
            "petal/demo/intents/[wallet]/[index]/hello.txt.wasm",
            include_bytes!("../tests/fixtures/route_component_no_imports.wasm"),
        );
        runner.store().install_petal_package_dir(&package).unwrap();
        let vfs = Vfs::builder()
            .mount(
                "petals",
                Arc::new(PetalRouter::new(runner, Arc::new(AccountHost))),
            )
            .build();

        for path in [
            "/petals/demo/intents/unknown/0/hello.txt",
            "/petals/demo/intents/unknown/0",
            "/petals/demo/intents/alice/01/hello.txt",
            "/petals/demo/intents/alice/4294967296/hello.txt",
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

    #[tokio::test]
    async fn explicit_routes_discover_live_wallets_and_all_allocated_indexes() {
        let (dir, runner) = runner();
        let package = dir.path().join("demo-app");
        write_demo_package(&package);
        write_package_file(
            &package,
            "petal/demo/intents/[wallet]/[index]/hello.txt.wasm",
            include_bytes!("../tests/fixtures/route_component_no_imports.wasm"),
        );
        runner.store().install_petal_package_dir(&package).unwrap();
        let router = PetalRouter::new(runner, Arc::new(AccountHost));
        let names = |entries: Vec<Entry>| {
            entries
                .into_iter()
                .map(|entry| entry.name)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(
                router
                    .list(&VfsPath::parse("demo/intents").unwrap())
                    .await
                    .unwrap()
            ),
            ["alice"]
        );
        assert_eq!(
            names(
                router
                    .list(&VfsPath::parse("demo/intents/alice").unwrap())
                    .await
                    .unwrap()
            ),
            ["0", "1"]
        );
        for index in [0, 1] {
            assert_eq!(
                router
                    .read(
                        &VfsPath::parse(&format!("demo/intents/alice/{index}/hello.txt")).unwrap()
                    )
                    .await
                    .unwrap(),
                b"component"
            );
        }
        assert!(
            router
                .read(&VfsPath::parse("demo/wallets/alice/0/hello.txt").unwrap())
                .await
                .is_err()
        );
    }

    #[derive(Default)]
    struct CountingAccountHost {
        reads: std::sync::atomic::AtomicUsize,
        lists: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl PetalHost for CountingAccountHost {
        async fn vfs_lookup(&self, path: &str) -> Result<HostVfsEntry, HostError> {
            AccountHost.vfs_lookup(path).await
        }
        async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            AccountHost.vfs_read(path).await
        }
        async fn vfs_list(&self, path: &str) -> Result<Vec<HostVfsEntry>, HostError> {
            self.lists
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            AccountHost.vfs_list(path).await
        }
        async fn vfs_write(&self, path: &str, bytes: &[u8]) -> Result<(), HostError> {
            AccountHost.vfs_write(path, bytes).await
        }
    }

    #[tokio::test]
    async fn ancestor_inventory_reads_are_deduplicated_per_invocation() {
        use std::sync::atomic::Ordering;
        let (dir, runner) = runner();
        let package = dir.path().join("demo-app");
        write_demo_package(&package);
        for route in 0..32 {
            write_package_file(
                &package,
                &format!("petal/demo/intents/[wallet]/[index]/file-{route}.txt.wasm"),
                include_bytes!("../tests/fixtures/route_component_no_imports.wasm"),
            );
        }
        runner.store().install_petal_package_dir(&package).unwrap();
        let host = Arc::new(CountingAccountHost::default());
        let router = PetalRouter::new(runner, host.clone());
        router
            .list(&VfsPath::parse("demo/intents").unwrap())
            .await
            .unwrap();
        assert_eq!(host.lists.swap(0, Ordering::Relaxed), 1);
        router
            .list(&VfsPath::parse("demo/intents/alice").unwrap())
            .await
            .unwrap();
        assert_eq!(host.lists.load(Ordering::Relaxed), 2);
        for _ in 0..2 {
            router
                .lookup(&VfsPath::parse("demo/intents/alice/0").unwrap())
                .await
                .unwrap();
        }
        assert_eq!(
            host.reads.load(Ordering::Relaxed),
            2,
            "each invocation rechecks live account state exactly once"
        );
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
        let path = VfsPath::parse("/petals/example/operations/alice/0/submit").unwrap();
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
