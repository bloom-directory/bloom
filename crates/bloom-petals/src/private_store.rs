//! Per-petal private key/value storage for component routes.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::host::HostError;
use crate::store::is_valid_hex_hash;

#[derive(Debug, Clone)]
pub struct PrivateStore {
    root: PathBuf,
}

impl PrivateStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, HostError> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|e| HostError::Backend(format!("store: {e}")))?;
        Ok(Self { root })
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
        Ok(self.root.join(petal_hash))
    }

    fn key_path(&self, petal_hash: &str, key: &str) -> Result<PathBuf, HostError> {
        validate_key(key)?;
        Ok(self.petal_dir(petal_hash)?.join(key))
    }
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
}
