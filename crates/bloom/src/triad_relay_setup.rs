//! Installer-only materialization of signed public relay trust. This does not
//! contact Relay or administer Signer; the installer uses Signer's admin client
//! after the services restart. An installed pin is replaced only when it is a
//! value an earlier signed release installed (`superseded-pins`); an edited
//! pin, or a newer release's pin met by an older installer, fails.
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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

/// The signed release's pins, and the values earlier releases installed.
struct ReleasePins {
    ca: Vec<u8>,
    keys: Vec<String>,
    superseded_ca_sha256: Vec<String>,
    superseded_keys: Vec<Vec<String>>,
}

fn is_key_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// One to four distinct receipt keys, current first, then its successor.
fn parse_keys<'a>(words: impl Iterator<Item = &'a str>) -> Result<Vec<String>> {
    let keys: Vec<String> = words.map(str::to_owned).collect();
    let distinct = keys.iter().collect::<std::collections::BTreeSet<_>>().len();
    if keys.is_empty()
        || keys.len() > 4
        || distinct != keys.len()
        || !keys.iter().all(|k| is_key_hex(k))
    {
        bail!("invalid signed relay receipt key set");
    }
    Ok(keys)
}

fn read_release(templates: &Path, owner: u32) -> Result<ReleasePins> {
    let (ca, _) = read_checked(&templates.join("control-ca.pem"), &[owner], false)?;
    let (keys, _) = read_checked(&templates.join("receipt-public-keys.hex"), &[owner], false)?;
    let keys = parse_keys(std::str::from_utf8(&keys)?.split_whitespace())?;
    let (history, _) = read_checked(&templates.join("superseded-pins"), &[owner], false)?;
    let mut pins = ReleasePins {
        ca,
        keys,
        superseded_ca_sha256: Vec::new(),
        superseded_keys: Vec::new(),
    };
    for line in std::str::from_utf8(&history)?.lines() {
        let mut words = line.split_whitespace();
        match words.next() {
            None => {}
            Some(word) if word.starts_with('#') => {}
            Some("ca") => match (words.next(), words.next()) {
                (Some(digest), None) if is_key_hex(digest) => {
                    pins.superseded_ca_sha256.push(digest.to_owned());
                }
                _ => bail!("invalid superseded relay CA entry"),
            },
            Some("receipt") => pins.superseded_keys.push(parse_keys(words)?),
            Some(_) => bail!("invalid superseded relay pin entry"),
        }
    }
    if pins.ca.is_empty() || !pins.ca.starts_with(b"-----BEGIN CERTIFICATE-----") {
        bail!("invalid signed relay trust inputs");
    }
    Ok(pins)
}

/// A pinned key set as configuration holds it: a list, or one key as written
/// before pin sets.
fn keys_in(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::String(key) => Some(vec![key.clone()]),
        Value::Array(keys) => keys.iter().map(|k| k.as_str().map(str::to_owned)).collect(),
        _ => None,
    }
}

/// What to do with one installed pin: keep it (already the release's value),
/// replace it (a value an earlier release installed), or refuse (anything
/// else: an edit, or a newer release's pins seen by an older installer).
#[derive(PartialEq)]
enum Pin {
    Absent,
    Current,
    Superseded,
}

fn classify_keys(keys: Option<Vec<String>>, release: &ReleasePins, what: &str) -> Result<Pin> {
    match keys {
        Some(keys) if keys == release.keys => Ok(Pin::Current),
        Some(keys) if release.superseded_keys.contains(&keys) => Ok(Pin::Superseded),
        _ => bail!(
            "{what} is not a pin set this release installs or supersedes; refusing to rotate trust"
        ),
    }
}

fn install(templates: &Path, config: &Path, signer_uid: u32, owner: u32) -> Result<()> {
    directory(templates, &[owner], false)?;
    directory(config, &[owner], false)?;
    directory(&config.join("signer"), &[owner, signer_uid], true)?;
    let release = read_release(templates, owner)?;
    let ca_path = config.join("relay-control-ca.pem");
    let relay_path = config.join("relay.json");
    let expected = json!({"control_ca_pem_path": ca_path, "receipt_public_key_hex": release.keys});

    let ca_pin = match existing(&ca_path, owner)? {
        None => Pin::Absent,
        Some(old) if old == release.ca => Pin::Current,
        Some(old)
            if release
                .superseded_ca_sha256
                .contains(&hex::encode(Sha256::digest(&old))) =>
        {
            Pin::Superseded
        }
        Some(_) => bail!(
            "relay CA is not one this release installs or supersedes; refusing to rotate trust"
        ),
    };
    let relay_pin = match existing(&relay_path, owner)? {
        None => Pin::Absent,
        Some(old) => {
            let old: Value = serde_json::from_slice(&old)?;
            let object = old
                .as_object()
                .context("relay configuration must be an object")?;
            if object.len() != 2 || object.get("control_ca_pem_path") != Some(&json!(ca_path)) {
                bail!("relay configuration changed; refusing to rotate trust");
            }
            match classify_keys(
                object.get("receipt_public_key_hex").and_then(keys_in),
                &release,
                "relay configuration",
            )? {
                Pin::Current if old != expected => Pin::Superseded,
                pin => pin,
            }
        }
    };
    if relay_pin != Pin::Absent && ca_pin == Pin::Absent {
        bail!("relay configuration exists without its CA; refusing to rotate trust");
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
    let signer_pin = match object.get("relay_receipt_public_key_hex") {
        None | Some(Value::Null) => Pin::Absent,
        Some(old) => match classify_keys(keys_in(old), &release, "Signer relay pin")? {
            Pin::Current if old != &json!(release.keys) => Pin::Superseded,
            pin => pin,
        },
    };

    // Every installed pin was checked before the first write. Each write is
    // atomic and each pin is judged on its own, so rerunning after a crash
    // between writes finishes the job.
    if ca_pin != Pin::Current {
        atomic_write(
            config,
            &ca_path,
            &release.ca,
            owner,
            rustix::process::getegid().as_raw(),
        )?;
    }
    if relay_pin != Pin::Current {
        atomic_write(
            config,
            &relay_path,
            &serde_json::to_vec_pretty(&expected)?,
            owner,
            rustix::process::getegid().as_raw(),
        )?;
    }
    if signer_pin != Pin::Current {
        object.insert("relay_receipt_public_key_hex".into(), json!(release.keys));
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

    const OLD_CA: &[u8] = b"-----BEGIN CERTIFICATE-----\nold root\n-----END CERTIFICATE-----\n";

    fn key(c: char) -> String {
        c.to_string().repeat(64)
    }

    /// A release pinning keys a and b over the packaged roots, superseding a
    /// release that pinned key 0 over OLD_CA.
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
        fs::write(
            templates.join("receipt-public-keys.hex"),
            format!("{}\n{}\n", key('a'), key('b')),
        )
        .unwrap();
        fs::write(
            templates.join("superseded-pins"),
            format!(
                "# history\nca {}\nreceipt {}\n",
                hex::encode(Sha256::digest(OLD_CA)),
                key('0')
            ),
        )
        .unwrap();
        write_signer(
            &config,
            json!({"relay_receipt_public_key_hex": null, "existing_field": {"keep": "unchanged"}}),
        );
        (root, templates, config, rustix::process::geteuid().as_raw())
    }

    fn write_signer(config: &Path, value: Value) {
        let path = config.join("signer/config.json");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// The state an earlier release left: OLD_CA and the single legacy key.
    fn install_legacy(config: &Path) {
        let ca_path = config.join("relay-control-ca.pem");
        write_private(&ca_path, OLD_CA);
        write_private(
            &config.join("relay.json"),
            &serde_json::to_vec(
                &json!({"control_ca_pem_path": ca_path, "receipt_public_key_hex": key('0')}),
            )
            .unwrap(),
        );
        write_signer(
            config,
            json!({"relay_receipt_public_key_hex": key('0'), "existing_field": {"keep": "unchanged"}}),
        );
    }

    fn signer(config: &Path) -> Value {
        serde_json::from_slice(&fs::read(config.join("signer/config.json")).unwrap()).unwrap()
    }

    fn snapshot(config: &Path) -> Vec<Option<Vec<u8>>> {
        ["relay.json", "relay-control-ca.pem", "signer/config.json"]
            .iter()
            .map(|name| fs::read(config.join(name)).ok())
            .collect()
    }

    #[test]
    fn installs_and_retries_without_rewriting_existing_configuration() {
        let (_root, templates, config, uid) = fixture();
        install(&templates, &config, uid, uid).unwrap();
        let path = config.join("signer/config.json");
        let before = fs::read(&path).unwrap();
        let inode = fs::metadata(&path).unwrap().ino();
        let value = signer(&config);
        assert_eq!(value["existing_field"]["keep"], "unchanged");
        assert_eq!(
            value["relay_receipt_public_key_hex"],
            json!([key('a'), key('b')])
        );
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
    fn upgrade_adopts_the_release_pins_over_superseded_ones() {
        let (_root, templates, config, uid) = fixture();
        install_legacy(&config);
        install(&templates, &config, uid, uid).unwrap();
        assert_eq!(
            fs::read(config.join("relay-control-ca.pem")).unwrap(),
            fs::read(templates.join("control-ca.pem")).unwrap()
        );
        let relay: Value =
            serde_json::from_slice(&fs::read(config.join("relay.json")).unwrap()).unwrap();
        assert_eq!(relay["receipt_public_key_hex"], json!([key('a'), key('b')]));
        let value = signer(&config);
        assert_eq!(
            value["relay_receipt_public_key_hex"],
            json!([key('a'), key('b')])
        );
        assert_eq!(value["existing_field"]["keep"], "unchanged");
    }

    #[test]
    fn rerun_finishes_an_upgrade_interrupted_between_writes() {
        let (_root, templates, config, uid) = fixture();
        install_legacy(&config);
        // The CA was replaced, then the installer stopped.
        write_private(
            &config.join("relay-control-ca.pem"),
            &fs::read(templates.join("control-ca.pem")).unwrap(),
        );
        install(&templates, &config, uid, uid).unwrap();
        assert_eq!(
            signer(&config)["relay_receipt_public_key_hex"],
            json!([key('a'), key('b')])
        );
    }

    #[test]
    fn refuses_edited_pins_before_writing_anything() {
        for edit in ["signer", "relay", "ca"] {
            let (_root, templates, config, uid) = fixture();
            install_legacy(&config);
            match edit {
                "signer" => write_signer(&config, json!({"relay_receipt_public_key_hex": [key('c')]})),
                "relay" => write_private(
                    &config.join("relay.json"),
                    &serde_json::to_vec(&json!({"control_ca_pem_path": config.join("relay-control-ca.pem"), "receipt_public_key_hex": [key('a'), key('c')]}))
                        .unwrap(),
                ),
                _ => write_private(&config.join("relay-control-ca.pem"), b"changed"),
            }
            let before = snapshot(&config);
            assert!(install(&templates, &config, uid, uid).is_err(), "{edit}");
            assert_eq!(snapshot(&config), before, "{edit}");
        }
    }

    #[test]
    fn an_older_release_refuses_a_newer_release_pins() {
        let (_root, templates, config, uid) = fixture();
        install(&templates, &config, uid, uid).unwrap();
        // The older release pins key 0 over OLD_CA and knows no successor.
        fs::write(templates.join("control-ca.pem"), OLD_CA).unwrap();
        fs::write(templates.join("receipt-public-keys.hex"), key('0')).unwrap();
        fs::write(templates.join("superseded-pins"), "").unwrap();
        let before = snapshot(&config);
        assert!(install(&templates, &config, uid, uid).is_err());
        assert_eq!(snapshot(&config), before);
    }

    #[test]
    fn rejects_malformed_release_pins() {
        for (keys, history) in [
            (String::new(), String::new()),
            (format!("{} {}", key('a'), key('a')), String::new()),
            (key('A'), String::new()),
            (key('a'), "receipt\n".to_owned()),
            (key('a'), "ca abc\n".to_owned()),
            (key('a'), format!("root {}\n", key('0'))),
        ] {
            let (_root, templates, config, uid) = fixture();
            fs::write(templates.join("receipt-public-keys.hex"), &keys).unwrap();
            fs::write(templates.join("superseded-pins"), &history).unwrap();
            assert!(
                install(&templates, &config, uid, uid).is_err(),
                "{keys} {history}"
            );
            assert!(!config.join("relay.json").exists());
        }
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
