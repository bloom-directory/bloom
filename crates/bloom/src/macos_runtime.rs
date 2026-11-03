//! Root provisioning of volatile macOS runtime directories from a pinned enrollment.

use std::{
    fs::{self, DirBuilder},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, chown},
    path::Path,
};

/// Principal IDs from the root-owned enrollment, including Signer's private
/// group rather than an authority-edge group for its administrative socket.
pub struct Principals {
    pub login_uid: u32,
    pub broker_uid: u32,
    pub signer_uid: u32,
    pub signer_gid: u32,
    pub machine_broker_gid: u32,
    pub broker_signer_gid: u32,
    pub revoke_gid: u32,
}

pub fn prepare(root: &Path, principals: Principals) -> io::Result<()> {
    let Principals {
        login_uid,
        broker_uid,
        signer_uid,
        signer_gid,
        machine_broker_gid,
        broker_signer_gid,
        revoke_gid,
    } = principals;
    // The installer leaves this parent root-owned with the inherited daemon
    // group. Its group is immaterial provided nobody else can replace entries.
    match fs::symlink_metadata(root) {
        Ok(metadata)
            if metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o7777 == 0o755 => {}
        Ok(_) => return Err(unsafe_directory(root)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            ensure_directory(root, 0, 0, 0o755)?;
        }
        Err(error) => return Err(error),
    }
    let runtime = root.join(login_uid.to_string());
    ensure_directory(&runtime, 0, 0, 0o711)?;
    // Provision parents before service-owned leaves. Each parent forbids
    // replacement by service principals; existing paths are never repaired.
    for (relative, uid, gid, mode) in [
        ("revoke", 0, 0, 0o711),
        ("machine-broker", broker_uid, machine_broker_gid, 0o710),
        ("broker-signer", signer_uid, broker_signer_gid, 0o710),
        ("signer-admin", signer_uid, signer_gid, 0o700),
        ("revoke/broker", broker_uid, revoke_gid, 0o710),
        ("revoke/signer", signer_uid, revoke_gid, 0o710),
        ("session", login_uid, revoke_gid, 0o710),
        ("containment", 0, 0, 0o755),
        ("status", broker_uid, machine_broker_gid, 0o750),
    ] {
        ensure_directory(&runtime.join(relative), uid, gid, mode)?;
    }
    Ok(())
}

fn unsafe_directory(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("unsafe macOS runtime directory {}", path.display()),
    )
}

fn ensure_directory(path: &Path, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir()
                || metadata.uid() != uid
                || metadata.gid() != gid
                || metadata.mode() & 0o7777 != mode
            {
                return Err(unsafe_directory(path));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // Start private even when umask would otherwise allow traversal.
            DirBuilder::new().mode(0o700).create(path)?;
            chown(path, Some(uid), Some(gid))?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::symlink,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::current_dir().unwrap().join(format!(
                ".runtime-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn ids(&self) -> (u32, u32) {
            let metadata = fs::metadata(&self.0).unwrap();
            (metadata.uid(), metadata.gid())
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn test_principals() -> Principals {
        Principals {
            login_uid: 250500,
            broker_uid: 250501,
            signer_uid: 250502,
            signer_gid: 260500,
            machine_broker_gid: 260501,
            broker_signer_gid: 260502,
            revoke_gid: 260503,
        }
    }

    // Run explicitly as root in a disposable scratch directory. These exercise
    // the same ownership checks used after /var/run is cleared by macOS.
    #[test]
    #[ignore = "requires root to create directories for isolated service principals"]
    fn reboot_recreates_private_signer_admin_and_preserves_existing_contents() {
        let fixture = Fixture::new();
        let root = fixture.0.join("run");
        prepare(&root, test_principals()).unwrap();
        let admin = root.join("250500/signer-admin");
        let metadata = fs::symlink_metadata(&admin).unwrap();
        assert_eq!(metadata.uid(), 250502);
        assert_eq!(metadata.gid(), 260500);
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        fs::write(admin.join("sentinel"), b"preserve").unwrap();
        prepare(&root, test_principals()).unwrap();
        assert_eq!(fs::read(admin.join("sentinel")).unwrap(), b"preserve");
        fs::remove_file(admin.join("sentinel")).unwrap();
        fs::remove_dir(&admin).unwrap();
        prepare(&root, test_principals()).unwrap();
        let metadata = fs::symlink_metadata(&admin).unwrap();
        assert_eq!((metadata.uid(), metadata.gid()), (250502, 260500));
        assert_eq!(metadata.mode() & 0o7777, 0o700);
    }

    #[test]
    #[ignore = "requires root to create directories for isolated service principals"]
    fn signer_admin_rejects_substitution_and_incorrect_security_metadata() {
        for case in ["symlink", "file", "owner", "group", "mode"] {
            let fixture = Fixture::new();
            let root = fixture.0.join("run");
            prepare(&root, test_principals()).unwrap();
            let admin = root.join("250500/signer-admin");
            let substitute = fixture.0.join("substitute");
            fs::create_dir(&substitute).unwrap();
            fs::write(substitute.join("sentinel"), b"preserve").unwrap();
            match case {
                "symlink" => {
                    fs::remove_dir(&admin).unwrap();
                    symlink(&substitute, &admin).unwrap();
                }
                "file" => {
                    fs::remove_dir(&admin).unwrap();
                    fs::write(&admin, b"preserve").unwrap();
                }
                "owner" => chown(&admin, Some(250501), None).unwrap(),
                "group" => chown(&admin, None, Some(260502)).unwrap(),
                "mode" => fs::set_permissions(&admin, fs::Permissions::from_mode(0o710)).unwrap(),
                _ => unreachable!(),
            }
            let before = fs::symlink_metadata(&admin).unwrap();
            assert_eq!(
                prepare(&root, test_principals()).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied,
                "{case}"
            );
            let after = fs::symlink_metadata(&admin).unwrap();
            assert_eq!(
                (before.ino(), before.uid(), before.gid(), before.mode()),
                (after.ino(), after.uid(), after.gid(), after.mode()),
                "must not repair an unsafe {case}"
            );
            assert_eq!(fs::read(substitute.join("sentinel")).unwrap(), b"preserve");
        }
    }

    #[test]
    fn missing_directory_is_created_and_existing_contents_survive() {
        let fixture = Fixture::new();
        let (uid, gid) = fixture.ids();
        let path = fixture.0.join("session");
        ensure_directory(&path, uid, gid, 0o710).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o710);
        fs::write(path.join("sentinel"), b"preserve").unwrap();
        ensure_directory(&path, uid, gid, 0o710).unwrap();
        assert_eq!(fs::read(path.join("sentinel")).unwrap(), b"preserve");
    }

    #[test]
    fn substituted_or_misconfigured_directories_are_rejected() {
        let fixture = Fixture::new();
        let (uid, gid) = fixture.ids();
        let directory = fixture.0.join("directory");
        ensure_directory(&directory, uid, gid, 0o710).unwrap();
        let link = fixture.0.join("link");
        symlink(&directory, &link).unwrap();
        let file = fixture.0.join("file");
        fs::write(&file, b"keep").unwrap();
        for path in [&link, &file] {
            assert!(ensure_directory(path, uid, gid, 0o710).is_err());
        }
        assert!(ensure_directory(&directory, uid + 1, gid, 0o710).is_err());
        assert!(ensure_directory(&directory, uid, gid + 1, 0o710).is_err());
        assert!(ensure_directory(&directory, uid, gid, 0o750).is_err());
        assert_eq!(fs::metadata(&directory).unwrap().mode() & 0o7777, 0o710);
        assert_eq!(fs::read(&file).unwrap(), b"keep");
    }
}
