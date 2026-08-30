//! Minimal authenticated login-session sentinel for the macOS
//! Unix-principal installation profile.

use std::{
    fs,
    io::ErrorKind,
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
        net::UnixListener as StdUnixListener,
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use bloom_service_activation::{SESSION_PROTOCOL_CURRENT, SESSION_PROTOCOL_RANGE};
#[cfg(feature = "triad-dev-harness")]
use bloom_triad_local_transport::load_developer_identity_and_manifest;
use bloom_triad_local_transport::{
    PeerAcl, authenticate_server_one_of, load_identity_and_manifest,
};
use rustix::process::geteuid;
use tokio::{io::AsyncReadExt as _, net::UnixListener, sync::Semaphore};

const SESSION_SERVICE_ID: &str = "bloom-session";
const BROKER_SERVICE_ID: &str = "bloom-broker";

pub async fn run() -> Result<()> {
    let effective_uid = geteuid().as_raw();
    if effective_uid == 0 {
        bail!("the login-session sentinel must not run as root");
    }

    #[cfg(feature = "triad-dev-harness")]
    let developer_root = std::env::var_os("BLOOM_TRIAD_DEVELOPER_ROOT").map(PathBuf::from);
    #[cfg(not(feature = "triad-dev-harness"))]
    let developer_root: Option<PathBuf> = None;
    let config_root = if let Some(root) = developer_root.as_ref() {
        root.join("config")
    } else {
        let enrollment_root = env_path(
            "BLOOM_ENROLLMENT_ROOT",
            "/Library/Application Support/BloomTriad/enrollments",
        );
        let Some(_) = load_enrollment(&enrollment_root, effective_uid)? else {
            // The global LaunchAgent is offered to every GUI login. An
            // unenrolled login is the normal successful no-op case.
            return Ok(());
        };
        env_path(
            "BLOOM_CONFIG_ROOT",
            "/Library/Application Support/BloomTriad/config",
        )
        .join(effective_uid.to_string())
    };
    let identity_path = if developer_root.is_some() {
        config_root.join("session-identity.json")
    } else {
        config_root.join("session/identity.json")
    };
    let manifest_path = config_root.join("edge-manifest.json");
    require_login_owned_private_file(&identity_path, effective_uid)?;
    #[cfg(feature = "triad-dev-harness")]
    let (identity, manifest) = developer_root
        .as_ref()
        .map(|root| {
            load_developer_identity_and_manifest(
                root,
                &identity_path,
                &manifest_path,
                SESSION_SERVICE_ID,
            )
        })
        .unwrap_or_else(|| {
            load_identity_and_manifest(&identity_path, &manifest_path, SESSION_SERVICE_ID)
        })
        .context("load authenticated session identity")?;
    #[cfg(not(feature = "triad-dev-harness"))]
    let (identity, manifest) =
        load_identity_and_manifest(&identity_path, &manifest_path, SESSION_SERVICE_ID)
            .context("load authenticated session identity")?;
    let broker_acl = manifest
        .broker
        .into_acl()
        .context("load pinned Broker session peer")?;
    let signer_acl = manifest
        .signer
        .into_acl()
        .context("load pinned Signer session peer")?;
    if broker_acl.service_id.as_str() != BROKER_SERVICE_ID
        || signer_acl.service_id.as_str() != "bloom-signer"
    {
        bail!("edge manifest has the wrong session peer");
    }
    let socket_gid = manifest
        .session_socket_gid
        .ok_or_else(|| anyhow::anyhow!("edge manifest has no session socket group"))?;

    let session_dir = if let Some(root) = developer_root.as_ref() {
        let runtime = std::env::var_os("BLOOM_TRIAD_DEVELOPER_RUNTIME")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("runtime"));
        let canonical_root = fs::canonicalize(root).context("canonicalize developer root")?;
        let canonical_runtime =
            fs::canonicalize(&runtime).context("canonicalize developer runtime directory")?;
        if !canonical_runtime.starts_with(&canonical_root) {
            bail!("developer runtime directory escapes the declared developer root");
        }
        canonical_runtime.join("session")
    } else {
        env_path("BLOOM_RUNTIME_ROOT", "/private/var/run/bloom")
            .join(effective_uid.to_string())
            .join("session")
    };
    require_session_directory(&session_dir, effective_uid, socket_gid)?;
    let socket_path = session_dir.join("session.sock");
    remove_owned_stale_socket(&socket_path, effective_uid, socket_gid)?;

    let listener = StdUnixListener::bind(&socket_path)
        .with_context(|| format!("bind session sentinel {}", socket_path.display()))?;
    std::os::unix::fs::chown(&socket_path, None, Some(socket_gid))
        .context("set session sentinel socket group")?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))
        .context("set session sentinel socket mode")?;
    require_socket_metadata(&socket_path, effective_uid, socket_gid)?;
    listener
        .set_nonblocking(true)
        .context("make session sentinel socket nonblocking")?;
    let listener = UnixListener::from_std(listener).context("adopt session sentinel socket")?;
    let _socket_guard = SocketGuard {
        path: socket_path,
        uid: effective_uid,
        gid: socket_gid,
    };

    serve_authenticated_services(listener, identity, [broker_acl, signer_acl]).await
}

async fn serve_authenticated_services(
    listener: UnixListener,
    identity: bloom_triad_local_transport::LocalIdentity,
    peers: [PeerAcl; 2],
) -> Result<()> {
    let connections = Arc::new(Semaphore::new(8));
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .context("accept service session connection")?;
        let observed_uid = stream
            .peer_cred()
            .context("inspect session peer credentials")?
            .uid();
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            tracing::warn!("session_sentinel.connection_quota_exhausted");
            continue;
        };
        let identity = identity.clone();
        let peers = peers.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let authenticated = tokio::time::timeout(
                Duration::from_secs(2),
                authenticate_server_one_of(
                    &mut stream,
                    &identity,
                    &peers,
                    SESSION_PROTOCOL_CURRENT,
                    SESSION_PROTOCOL_RANGE,
                ),
            )
            .await;
            let peer = match authenticated {
                Ok(Ok(peer)) => peer,
                _ => {
                    tracing::warn!(observed_uid, "session_sentinel.rejected_peer");
                    return;
                }
            };
            tracing::info!(
                service_id = peer.service_id.as_str(),
                "session_sentinel.service_authenticated"
            );
            let mut unexpected = [0_u8; 1];
            match stream.read(&mut unexpected).await {
                Ok(0) => tracing::info!(
                    service_id = peer.service_id.as_str(),
                    "session_sentinel.service_disconnected"
                ),
                Ok(_) => tracing::warn!(
                    service_id = peer.service_id.as_str(),
                    "session_sentinel.unexpected_channel_data"
                ),
                Err(error) => tracing::warn!(
                    %error,
                    service_id = peer.service_id.as_str(),
                    "session_sentinel.monitor_failed"
                ),
            }
        });
    }
}

fn load_enrollment(root: &Path, effective_uid: u32) -> Result<Option<()>> {
    let path = root.join(format!("{effective_uid}.json"));
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect Bloom enrollment"),
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        bail!("Bloom enrollment is not an immutable root-owned regular file");
    }
    let enrollment: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).context("read Bloom enrollment")?)
            .context("decode Bloom enrollment")?;
    if enrollment.get("schema").and_then(serde_json::Value::as_str)
        != Some("bloom.macos-enrollment.1")
        || enrollment
            .get("login_uid")
            .and_then(serde_json::Value::as_u64)
            != Some(u64::from(effective_uid))
        || !matches!(
            enrollment.get("state").and_then(serde_json::Value::as_str),
            Some("activating" | "active")
        )
    {
        bail!("Bloom enrollment is not valid for this login session");
    }
    Ok(Some(()))
}

fn require_login_owned_private_file(path: &Path, effective_uid: u32) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        bail!("session identity is not a login-owned private regular file");
    }
    Ok(())
}

fn require_session_directory(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    // Deliberately no link-count check. `nlink >= 2` treated the traditional
    // `.`-plus-parent-entry count as evidence of a real directory, but btrfs
    // reports `nlink == 1` for every directory, so this refused a perfectly
    // safe session directory there while proving nothing extra elsewhere
    // (mirrors the Broker's `verified_status_parent`).
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != 0o710
    {
        bail!("session socket directory has the wrong owner, group, mode, or type");
    }
    Ok(())
}

fn remove_owned_stale_socket(path: &Path, uid: u32, gid: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && metadata.uid() == uid
                && metadata.gid() == gid
                && metadata.mode() & 0o777 == 0o660
                && metadata.nlink() == 1 =>
        {
            fs::remove_file(path).context("remove stale session sentinel socket")
        }
        Ok(_) => bail!("refusing to replace a substituted session sentinel socket"),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect session sentinel socket"),
    }
}

fn require_socket_metadata(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("inspect session sentinel socket")?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o777 != 0o660
        || metadata.nlink() != 1
    {
        bail!("session sentinel socket has the wrong owner, group, mode, or type");
    }
    Ok(())
}

fn env_path(name: &str, default: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

struct SocketGuard {
    path: PathBuf,
    uid: u32,
    gid: u32,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.uid() == self.uid
            && metadata.gid() == self.gid
            && metadata.nlink() == 1
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}
