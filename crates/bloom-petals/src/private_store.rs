//! Per-petal private key/value storage for component routes.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::host::HostError;
use crate::store::is_valid_hex_hash;

#[derive(Debug, Clone)]
pub struct PrivateStore {
    root: PathBuf,
    account_digest: Option<String>,
}

impl PrivateStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, HostError> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|e| HostError::Backend(format!("store: {e}")))?;
        Ok(Self {
            root,
            account_digest: None,
        })
    }

    pub fn open_account(
        root: impl Into<PathBuf>,
        wallet: &str,
        account: u32,
    ) -> Result<Self, HostError> {
        if account == 0 {
            return Err(HostError::Invalid("account store requires n > 0".into()));
        }
        let mut store = Self::open(root)?;
        store.account_digest = Some(account_digest(wallet, account));
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn get(&self, petal_hash: &str, key: &str) -> Result<Vec<u8>, HostError> {
        let path = self.key_path(petal_hash, key)?;
        let _guard = store_op_guard()?;
        match std::fs::read(&path) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(HostError::NotFound(key.into()))
            }
            Err(e) => Err(HostError::Backend(format!("store get: {e}"))),
        }
    }

    pub fn put(
        &self,
        petal_hash: &str,
        key: &str,
        value: &[u8],
        secret: bool,
    ) -> Result<(), HostError> {
        let path = self.key_path(petal_hash, key)?;
        let dir = path
            .parent()
            .ok_or_else(|| HostError::Invalid("store key has no parent".into()))?;
        let _guard = store_op_guard()?;
        std::fs::create_dir_all(dir)
            .map_err(|e| HostError::Backend(format!("store mkdir: {e}")))?;
        atomic_write(&path, value, secret)
            .map_err(|e| HostError::Backend(format!("store put: {e}")))
    }

    pub fn put_new(
        &self,
        petal_hash: &str,
        key: &str,
        value: &[u8],
        secret: bool,
    ) -> Result<(), HostError> {
        let path = self.key_path(petal_hash, key)?;
        let dir = path
            .parent()
            .ok_or_else(|| HostError::Invalid("store key has no parent".into()))?;
        let _guard = store_op_guard()?;
        std::fs::create_dir_all(dir)
            .map_err(|e| HostError::Backend(format!("store mkdir: {e}")))?;
        create_new_file(&path, value, secret).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                HostError::Denied("store key already exists".into())
            } else {
                HostError::Backend(format!("store put_new: {e}"))
            }
        })
    }

    pub fn list(&self, petal_hash: &str, prefix: &str) -> Result<Vec<String>, HostError> {
        validate_prefix(prefix)?;
        let dir = self.petal_dir(petal_hash)?;
        let _guard = store_op_guard()?;
        let mut out = Vec::new();
        if !dir.exists() {
            return Ok(out);
        }
        collect_files(&dir, &dir, prefix, &mut out)?;
        out.sort();
        Ok(out)
    }

    pub fn del(&self, petal_hash: &str, key: &str) -> Result<(), HostError> {
        let path = self.key_path(petal_hash, key)?;
        let _guard = store_op_guard()?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(HostError::Backend(format!("store del: {e}"))),
        }
    }

    pub fn del_if_value(
        &self,
        petal_hash: &str,
        key: &str,
        expected: &[u8],
    ) -> Result<(), HostError> {
        let path = self.key_path(petal_hash, key)?;
        let _guard = store_op_guard()?;
        let current = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(HostError::NotFound(key.into()));
            }
            Err(e) => return Err(HostError::Backend(format!("store del_if_value read: {e}"))),
        };
        if current != expected {
            return Err(HostError::Denied("store key value changed".into()));
        }
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(HostError::NotFound(key.into()))
            }
            Err(e) => Err(HostError::Backend(format!("store del_if_value: {e}"))),
        }
    }

    fn petal_dir(&self, petal_hash: &str) -> Result<PathBuf, HostError> {
        if !is_valid_hex_hash(petal_hash) {
            return Err(HostError::Invalid("invalid petal hash".into()));
        }
        let package_root = self.root.join(petal_hash);
        Ok(match &self.account_digest {
            Some(digest) => package_root.join(digest),
            None => package_root,
        })
    }

    fn key_path(&self, petal_hash: &str, key: &str) -> Result<PathBuf, HostError> {
        validate_key(key)?;
        Ok(self.petal_dir(petal_hash)?.join(key))
    }
}

/// Stable across package releases and independent of their content hash.
pub fn account_digest(wallet: &str, account: u32) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom-petal-store-account/v1\0");
    hasher.update(&(wallet.len() as u64).to_be_bytes());
    hasher.update(wallet.as_bytes());
    hasher.update(&account.to_be_bytes());
    format!("v1-{}", hasher.finalize().to_hex())
}

/// Copy both package partitions before a successor's first guest invocation.
/// The lock also serializes this with all KV operations in this process.
pub fn carry_forward(
    data_root: &Path,
    accounts_root: &Path,
    predecessor: &str,
    successor: &str,
) -> Result<bool, HostError> {
    if !is_valid_hex_hash(predecessor) || !is_valid_hex_hash(successor) || predecessor == successor
    {
        return Err(HostError::Invalid("invalid carry-forward hashes".into()));
    }
    let _guard = store_op_guard()?;
    let account_zero = copy_partition(data_root, predecessor, successor)?;
    let accounts = copy_partition(accounts_root, predecessor, successor)?;
    Ok(account_zero || accounts)
}

fn copy_partition(root: &Path, predecessor: &str, successor: &str) -> Result<bool, HostError> {
    let source = root.join(predecessor);
    let destination = root.join(successor);
    if destination.exists() || !source.exists() {
        return Ok(false);
    }
    let temporary = root.join(format!(".{successor}.carry.tmp"));
    if temporary.exists() {
        std::fs::remove_dir_all(&temporary)
            .map_err(|e| HostError::Backend(format!("store carry cleanup: {e}")))?;
    }
    std::fs::create_dir_all(root)
        .map_err(|e| HostError::Backend(format!("store carry mkdir: {e}")))?;
    if let Err(error) = copy_directory(&source, &temporary) {
        let _ = std::fs::remove_dir_all(&temporary);
        return Err(HostError::Backend(format!("store carry copy: {error}")));
    }
    std::fs::rename(&temporary, &destination)
        .map_err(|e| HostError::Backend(format!("store carry rename: {e}")))?;
    Ok(true)
}

fn copy_directory(source: &Path, destination: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(source)?;
    if !meta.file_type().is_dir() {
        return Err(std::io::Error::other("store partition is not a directory"));
    }
    std::fs::create_dir(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let meta = std::fs::symlink_metadata(&source_path)?;
        if meta.file_type().is_dir() {
            copy_directory(&source_path, &destination_path)?;
        } else if meta.file_type().is_file() {
            std::fs::copy(&source_path, &destination_path)?;
            std::fs::set_permissions(&destination_path, meta.permissions())?;
        } else {
            return Err(std::io::Error::other(
                "store partition contains a special file",
            ));
        }
    }
    std::fs::set_permissions(destination, meta.permissions())?;
    Ok(())
}

fn store_op_guard() -> Result<MutexGuard<'static, ()>, HostError> {
    static STORE_OP_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    STORE_OP_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| HostError::Backend("store operation lock poisoned".into()))
}

pub fn validate_key(key: &str) -> Result<(), HostError> {
    if key.is_empty() || key.len() > 512 {
        return Err(HostError::Invalid("invalid store key length".into()));
    }
    if key.starts_with('/') || key.contains('\\') || key.contains('\0') {
        return Err(HostError::Invalid("store key is not relative".into()));
    }
    for part in key.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(HostError::Invalid("store key escapes namespace".into()));
        }
    }
    Ok(())
}

fn validate_prefix(prefix: &str) -> Result<(), HostError> {
    if prefix.is_empty() {
        return Ok(());
    }
    let trimmed = prefix.strip_suffix('/').unwrap_or(prefix);
    if trimmed.is_empty() {
        return Err(HostError::Invalid("store prefix is not relative".into()));
    }
    validate_key(trimmed)
}

fn collect_files(
    root: &Path,
    dir: &Path,
    prefix: &str,
    out: &mut Vec<String>,
) -> Result<(), HostError> {
    let rd = std::fs::read_dir(dir).map_err(|e| HostError::Backend(format!("store list: {e}")))?;
    for entry in rd {
        let entry = entry.map_err(|e| HostError::Backend(format!("store list: {e}")))?;
        let path = entry.path();
        let ft = entry
            .file_type()
            .map_err(|e| HostError::Backend(format!("store list: {e}")))?;
        if ft.is_dir() {
            collect_files(root, &path, prefix, out)?;
        } else if ft.is_file() {
            let Ok(rel) = path.strip_prefix(root) else {
                continue;
            };
            if has_hidden_component(rel) {
                continue;
            }
            let key = rel
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            if key.starts_with(prefix) {
                out.push(key);
            }
        }
    }
    Ok(())
}

fn has_hidden_component(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .map(|s| s.starts_with('.'))
            .unwrap_or(true)
    })
}

fn atomic_write(path: &Path, data: &[u8], secret: bool) -> std::io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("path has no parent"))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("path has no file name"))?;
    let tmp = dir.join(format!(".{}.tmp", file_name.to_string_lossy()));
    write_file_with_mode(&tmp, data, secret, false)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn create_new_file(path: &Path, data: &[u8], secret: bool) -> std::io::Result<()> {
    write_file_with_mode(path, data, secret, true)
}

#[cfg(unix)]
fn write_file_with_mode(
    path: &Path,
    data: &[u8],
    secret: bool,
    create_new: bool,
) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mode = if secret { 0o600 } else { 0o644 };
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).mode(mode);
    if create_new {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    let mut file = opts.open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_file_with_mode(
    path: &Path,
    data: &[u8],
    _secret: bool,
    create_new: bool,
) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if create_new {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    use std::io::Write;
    let mut file = opts.open(path)?;
    file.write_all(data)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn key_validation_rejects_escapes() {
        for key in ["", "../x", "a/../b", "/abs", "a//b", ".", "a\\b"] {
            assert!(validate_key(key).is_err(), "{key:?}");
        }
        validate_key("creds/api.json").unwrap();
    }

    #[test]
    fn store_is_namespaced_by_hash() {
        let dir = TempDir::new().unwrap();
        let store = PrivateStore::open(dir.path()).unwrap();
        let other = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        store.put(HASH, "creds/api.json", b"secret", true).unwrap();
        assert_eq!(store.get(HASH, "creds/api.json").unwrap(), b"secret");
        assert!(matches!(
            store.get(other, "creds/api.json"),
            Err(HostError::NotFound(_))
        ));
    }

    #[test]
    fn put_new_refuses_existing_key() {
        let dir = TempDir::new().unwrap();
        let store = PrivateStore::open(dir.path()).unwrap();
        store
            .put_new(HASH, "orders/.lock", b"first", false)
            .unwrap();
        assert!(matches!(
            store.put_new(HASH, "orders/.lock", b"second", false),
            Err(HostError::Denied(_))
        ));
        assert_eq!(store.get(HASH, "orders/.lock").unwrap(), b"first");
    }

    #[test]
    fn del_if_value_only_removes_matching_value() {
        let dir = TempDir::new().unwrap();
        let store = PrivateStore::open(dir.path()).unwrap();
        store.put(HASH, "orders/.lock", b"first", false).unwrap();
        assert!(matches!(
            store.del_if_value(HASH, "orders/.lock", b"second"),
            Err(HostError::Denied(_))
        ));
        assert_eq!(store.get(HASH, "orders/.lock").unwrap(), b"first");
        store.del_if_value(HASH, "orders/.lock", b"first").unwrap();
        assert!(matches!(
            store.get(HASH, "orders/.lock"),
            Err(HostError::NotFound(_))
        ));
    }

    #[test]
    fn list_filters_by_prefix() {
        let dir = TempDir::new().unwrap();
        let store = PrivateStore::open(dir.path()).unwrap();
        store.put(HASH, "orders/a.json", b"a", false).unwrap();
        store.put(HASH, "orders/b.json", b"b", false).unwrap();
        store.put(HASH, "creds/api.json", b"c", true).unwrap();
        assert_eq!(
            store.list(HASH, "orders/").unwrap(),
            vec!["orders/a.json".to_string(), "orders/b.json".to_string()]
        );
    }

    #[test]
    fn list_omits_dotfile_components() {
        let dir = TempDir::new().unwrap();
        let store = PrivateStore::open(dir.path()).unwrap();
        store.put(HASH, "orders/a.json", b"a", false).unwrap();
        let hidden = store.root().join(HASH).join("orders/.a.json.tmp");
        std::fs::write(hidden, b"tmp").unwrap();
        assert_eq!(
            store.list(HASH, "orders/").unwrap(),
            vec!["orders/a.json".to_string()]
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_are_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let store = PrivateStore::open(dir.path()).unwrap();
        store.put(HASH, "creds/api.json", b"secret", true).unwrap();
        let path = store.root().join(HASH).join("creds/api.json");
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn put_new_secret_files_are_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let store = PrivateStore::open(dir.path()).unwrap();
        store
            .put_new(HASH, "creds/new.json", b"secret", true)
            .unwrap();
        let path = store.root().join(HASH).join("creds/new.json");
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn stale_public_temp_file_does_not_weaken_secret_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let store = PrivateStore::open(dir.path()).unwrap();
        let petal_dir = store.root().join(HASH).join("creds");
        std::fs::create_dir_all(&petal_dir).unwrap();
        let tmp = petal_dir.join(".api.json.tmp");
        std::fs::write(&tmp, b"old").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();

        store.put(HASH, "creds/api.json", b"secret", true).unwrap();
        let path = store.root().join(HASH).join("creds/api.json");
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn account_stores_are_wallet_and_number_scoped() {
        let dir = TempDir::new().unwrap();
        let first = PrivateStore::open_account(dir.path(), "alice", 1).unwrap();
        let second = PrivateStore::open_account(dir.path(), "bob", 1).unwrap();
        let third = PrivateStore::open_account(dir.path(), "alice", 2).unwrap();
        first.put(HASH, "setting", b"alice-one", false).unwrap();
        assert!(matches!(
            second.get(HASH, "setting"),
            Err(HostError::NotFound(_))
        ));
        assert!(matches!(
            third.get(HASH, "setting"),
            Err(HostError::NotFound(_))
        ));
        assert_eq!(first.get(HASH, "setting").unwrap(), b"alice-one");
        assert!(
            dir.path()
                .join(HASH)
                .join(account_digest("alice", 1))
                .is_dir()
        );
    }

    #[test]
    fn carry_forward_copies_both_roots_and_preserves_predecessor() {
        let dir = TempDir::new().unwrap();
        let data = dir.path().join("data");
        let accounts = dir.path().join("data-accounts");
        let successor = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let original = PrivateStore::open(&data).unwrap();
        original
            .put(HASH, "settings/value", b"original", false)
            .unwrap();
        original.put(HASH, "secrets/api", b"secret", true).unwrap();
        let account_one = PrivateStore::open_account(&accounts, "alice", 1).unwrap();
        account_one
            .put(HASH, "settings/value", b"account", false)
            .unwrap();
        let other_wallet = PrivateStore::open_account(&accounts, "bob", 1).unwrap();
        other_wallet
            .put(HASH, "settings/value", b"other-wallet", false)
            .unwrap();
        assert!(carry_forward(&data, &accounts, HASH, successor).unwrap());
        assert_eq!(
            original.get(successor, "settings/value").unwrap(),
            b"original"
        );
        assert_eq!(
            PrivateStore::open_account(&accounts, "alice", 1)
                .unwrap()
                .get(successor, "settings/value")
                .unwrap(),
            b"account"
        );
        assert_eq!(
            other_wallet.get(successor, "settings/value").unwrap(),
            b"other-wallet"
        );
        original
            .put(successor, "settings/value", b"changed", false)
            .unwrap();
        assert!(!carry_forward(&data, &accounts, HASH, successor).unwrap());
        assert_eq!(original.get(HASH, "settings/value").unwrap(), b"original");
        assert_eq!(
            original.get(successor, "settings/value").unwrap(),
            b"changed"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(data.join(successor).join("secrets/api"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn concurrent_carry_forward_publishes_one_complete_copy() {
        let dir = TempDir::new().unwrap();
        let data = dir.path().join("data");
        let accounts = dir.path().join("data-accounts");
        let successor = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let original = PrivateStore::open(&data).unwrap();
        original
            .put(HASH, "settings/value", b"complete", false)
            .unwrap();
        let barrier = std::sync::Barrier::new(4);
        let copied = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        carry_forward(&data, &accounts, HASH, successor).unwrap()
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| usize::from(worker.join().unwrap()))
                .sum::<usize>()
        });
        assert_eq!(copied, 1);
        assert_eq!(
            original.get(successor, "settings/value").unwrap(),
            b"complete"
        );
        assert_eq!(original.get(HASH, "settings/value").unwrap(), b"complete");
    }

    #[test]
    fn carry_forward_recovers_stale_temporary_partition() {
        let dir = TempDir::new().unwrap();
        let data = dir.path().join("data");
        let accounts = dir.path().join("data-accounts");
        let successor = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let original = PrivateStore::open(&data).unwrap();
        original.put(HASH, "value", b"complete", false).unwrap();
        let stale = data.join(format!(".{successor}.carry.tmp"));
        std::fs::create_dir(&stale).unwrap();
        std::fs::write(stale.join("value"), b"partial").unwrap();
        assert!(carry_forward(&data, &accounts, HASH, successor).unwrap());
        assert_eq!(original.get(successor, "value").unwrap(), b"complete");
        assert!(!stale.exists());
    }
}
