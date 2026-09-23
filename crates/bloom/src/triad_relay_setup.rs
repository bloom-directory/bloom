//! Installer-only materialization of signed public relay trust. This does not
//! contact Relay or administer Signer; the installer uses Signer's admin client
//! after the services restart. Never rotate an existing trust pin implicitly.
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

const LIMIT: u64 = 1024 * 1024;

pub fn run(templates: &Path, config: &Path, signer_uid: u32) -> Result<()> {
    if rustix::process::geteuid().as_raw() != 0 || signer_uid == 0 {
        bail!("relay trust installation requires root and an isolated Signer UID");
    }
    install(templates, config, signer_uid, 0)
}

fn read_checked(path: &Path, owners: &[u32], private: bool) -> Result<(Vec<u8>, fs::Metadata)> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )?;
    let file = File::from(fd);
    let m = file.metadata()?;
    if !m.is_file()
        || !owners.contains(&m.uid())
        || m.nlink() != 1
        || m.len() > LIMIT
        || (if private {
            m.mode() & 0o7777 != 0o600
        } else {
            m.mode() & 0o022 != 0
        })
    {
        bail!("unsafe relay setup input: {}", path.display());
    }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        bail!("relay setup input exceeds size limit");
    }
    Ok((bytes, m))
}

fn directory(path: &Path, owners: &[u32], private: bool) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir()
        || !owners.contains(&m.uid())
        || m.mode() & 0o022 != 0
        || (private && m.mode() & 0o777 != 0o700)
    {
        bail!("unsafe relay setup directory: {}", path.display());
    }
    Ok(())
}

fn existing(path: &Path, owner: u32) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(Some(read_checked(path, &[owner], true)?.0)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn atomic_write(config: &Path, path: &Path, bytes: &[u8], uid: u32, gid: u32) -> Result<()> {
    // Stage under a root-only directory even when the final owner is Signer.
    let stage = tempfile::Builder::new()
        .prefix(".relay-trust-")
        .tempdir_in(config)?;
    fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o700))?;
    let mut file = tempfile::NamedTempFile::new_in(stage.path())?;
    file.write_all(bytes)?;
    std::os::unix::fs::chown(file.path(), Some(uid), Some(gid))?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    File::open(path.parent().context("relay destination parent")?)?.sync_all()?;
    Ok(())
}

fn install(templates: &Path, config: &Path, signer_uid: u32, owner: u32) -> Result<()> {
    directory(templates, &[owner], false)?;
    directory(config, &[owner], false)?;
    directory(&config.join("signer"), &[owner, signer_uid], true)?;
    let (ca, _) = read_checked(&templates.join("control-ca.pem"), &[owner], false)?;
    let (key, _) = read_checked(&templates.join("receipt-public-key.hex"), &[owner], false)?;
    let key = std::str::from_utf8(&key)?.trim();
    if key.len() != 64
        || !key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || ca.is_empty()
    {
        bail!("invalid signed relay trust inputs");
    }
    let ca_path = config.join("relay-control-ca.pem");
    let relay_path = config.join("relay.json");
    let expected = json!({"control_ca_pem_path": ca_path, "receipt_public_key_hex": key});
    let old_ca = existing(&ca_path, owner)?;
    if old_ca.as_ref().is_some_and(|old| old != &ca) {
        bail!("relay CA changed; explicit trust rotation is required");
    }
    let old_relay = existing(&relay_path, owner)?;
    if let Some(old) = &old_relay
        && serde_json::from_slice::<Value>(old)? != expected
    {
        bail!("relay configuration changed; explicit trust rotation is required");
    }
    let signer_path = config.join("signer/config.json");
    let (mut bytes, metadata) = read_checked(&signer_path, &[owner, signer_uid], true)?;
    let parsed = serde_json::from_slice::<Value>(&bytes);
    use zeroize::Zeroize;
    bytes.zeroize();
    let mut signer = parsed?;
    let object = signer
        .as_object_mut()
        .context("Signer configuration must be an object")?;
    let old_key = object.get("relay_receipt_public_key_hex");
    if old_key.is_some_and(|old| !old.is_null() && old != key) {
        bail!("Signer relay pin changed; explicit trust rotation is required");
    }
    let update_signer = old_key.is_none_or(Value::is_null);
    // Validate all existing state before the first write. Each write is atomic;
    // a crash between writes is repaired by rerunning with the same signed pins.
    if old_ca.is_none() {
        atomic_write(
            config,
            &ca_path,
            &ca,
            owner,
            rustix::process::getegid().as_raw(),
        )?;
    }
    if old_relay.is_none() {
        atomic_write(
            config,
            &relay_path,
            &serde_json::to_vec_pretty(&expected)?,
            owner,
            rustix::process::getegid().as_raw(),
        )?;
    }
    if update_signer {
        object.insert("relay_receipt_public_key_hex".into(), json!(key));
        let mut output = serde_json::to_vec_pretty(&signer)?;
        let result = atomic_write(
            config,
            &signer_path,
            &output,
            metadata.uid(),
            metadata.gid(),
        );
        output.zeroize();
        result?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn fixture() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        u32,
    ) {
        let root = tempfile::tempdir().unwrap();
        let templates = root.path().join("templates");
        let config = root.path().join("config");
        fs::create_dir(&templates).unwrap();
        fs::create_dir(&config).unwrap();
        fs::create_dir(config.join("signer")).unwrap();
        fs::set_permissions(config.join("signer"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            templates.join("control-ca.pem"),
            include_bytes!("../../../packaging/triad/relay/control-ca.pem"),
        )
        .unwrap();
        fs::write(templates.join("receipt-public-key.hex"), "a".repeat(64)).unwrap();
        fs::write(
            config.join("signer/config.json"),
            br#"{"relay_receipt_public_key_hex":null,"existing_field":{"keep":"unchanged"}}"#,
        )
        .unwrap();
        fs::set_permissions(
            config.join("signer/config.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        (root, templates, config, rustix::process::geteuid().as_raw())
    }
    #[test]
    fn installs_and_retries_without_rewriting_existing_configuration() {
        let (_root, templates, config, uid) = fixture();
        install(&templates, &config, uid, uid).unwrap();
        let path = config.join("signer/config.json");
        let before = fs::read(&path).unwrap();
        let inode = fs::metadata(&path).unwrap().ino();
        let value: Value = serde_json::from_slice(&before).unwrap();
        assert_eq!(value["existing_field"]["keep"], "unchanged");
        assert_eq!(value["relay_receipt_public_key_hex"], "a".repeat(64));
        install(&templates, &config, uid, uid).unwrap();
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
        for name in ["relay.json", "relay-control-ca.pem", "signer/config.json"] {
            assert_eq!(
                fs::metadata(config.join(name)).unwrap().mode() & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn refuses_changed_pin_before_writing_anything() {
        let (_root, templates, config, uid) = fixture();
        let signer = config.join("signer/config.json");
        let bytes =
            serde_json::to_vec(&json!({"relay_receipt_public_key_hex":"b".repeat(64)})).unwrap();
        fs::write(&signer, &bytes).unwrap();
        assert!(install(&templates, &config, uid, uid).is_err());
        assert_eq!(fs::read(signer).unwrap(), bytes);
        assert!(!config.join("relay.json").exists());
        assert!(!config.join("relay-control-ca.pem").exists());
    }
    #[test]
    fn repairs_partial_install_but_rejects_ca_rotation() {
        let (_root, templates, config, uid) = fixture();
        install(&templates, &config, uid, uid).unwrap();
        fs::remove_file(config.join("relay.json")).unwrap();
        install(&templates, &config, uid, uid).unwrap();
        fs::write(templates.join("control-ca.pem"), b"changed").unwrap();
        assert!(install(&templates, &config, uid, uid).is_err());
    }
    #[test]
    fn rejects_symlinked_destination_without_touching_target() {
        let (root, templates, config, uid) = fixture();
        let sentinel = root.path().join("sentinel");
        fs::write(&sentinel, "untouched").unwrap();
        symlink(&sentinel, config.join("relay.json")).unwrap();
        assert!(install(&templates, &config, uid, uid).is_err());
        assert_eq!(fs::read_to_string(sentinel).unwrap(), "untouched");
    }
}
