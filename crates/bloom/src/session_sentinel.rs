//! Minimal authenticated login-session sentinel for the installed
//! Unix-principal profiles.

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
const GUI_LOGIN_POLL_INTERVAL: Duration = Duration::from_secs(1);

pub async fn run() -> Result<()> {
    let effective_uid = geteuid().as_raw();
    if effective_uid == 0 {
        bail!("the login-session sentinel must not run as root");
    }

    #[cfg(feature = "triad-dev-harness")]
    let developer_root = std::env::var_os("BLOOM_TRIAD_DEVELOPER_ROOT").map(PathBuf::from);
    #[cfg(not(feature = "triad-dev-harness"))]
    let developer_root: Option<PathBuf> = None;
    let require_gui_login =
        gui_login_is_required(cfg!(target_os = "macos"), developer_root.is_some());
    if require_gui_login && !gui_domain_is_present(effective_uid).await {
        return Ok(());
    }
    let config_root = if let Some(root) = developer_root.as_ref() {
        root.join("config")
    } else {
        let enrollment_root = env_path("BLOOM_ENROLLMENT_ROOT", default_enrollment_root());
        let Some(_) = load_enrollment(&enrollment_root, effective_uid)? else {
            // The global LaunchAgent is offered to every GUI login. An
            // unenrolled login is the normal successful no-op case.
            return Ok(());
        };
        env_path("BLOOM_CONFIG_ROOT", default_config_root()).join(effective_uid.to_string())
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
        env_path("BLOOM_RUNTIME_ROOT", default_runtime_root())
            .join(effective_uid.to_string())
            .join("session")
    };
    require_session_directory(&session_dir, effective_uid, socket_gid)?;
    let socket_path = session_dir.join("session.sock");
    remove_owned_stale_socket(&socket_path, effective_uid, socket_gid)?;

    let listener = StdUnixListener::bind(&socket_path)
        .with_context(|| format!("bind session sentinel {}", socket_path.display()))?;
    let mut pending_socket = PendingSocketGuard::new(socket_path.clone(), effective_uid)?;
    std::os::unix::fs::chown(&socket_path, None, Some(socket_gid))
        .context("set session sentinel socket group")?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))
        .context("set session sentinel socket mode")?;
    require_socket_metadata(&socket_path, effective_uid, socket_gid)?;
    listener
        .set_nonblocking(true)
        .context("make session sentinel socket nonblocking")?;
    let listener = UnixListener::from_std(listener).context("adopt session sentinel socket")?;
    pending_socket.disarm();
    let _socket_guard = SocketGuard {
        path: socket_path,
        uid: effective_uid,
        gid: socket_gid,
    };

    tracing::info!(
        event = "service.identity_loaded",
        service_id = identity.service_id.as_str(),
        enrolled_login_uid = effective_uid
    );
    tracing::info!(event = "service.ready", listener_kind = "unix");
    crate::native_lifecycle("session-sentinel", "ready");

    tokio::select! {
        result = serve_authenticated_services(listener, identity, [broker_acl, signer_acl]) => result,
        result = crate::termination_signal() => {
            result.context("wait for session sentinel shutdown signal")?;
            tracing::info!(event = "service.shutdown", reason = "signal");
            crate::native_lifecycle("session-sentinel", "shutdown");
            Ok(())
        }
        _ = wait_for_gui_logout(require_gui_login, GUI_LOGIN_POLL_INTERVAL, || gui_domain_is_present(effective_uid)) => {
            tracing::info!(event = "service.shutdown", reason = "gui_login_ended");
            crate::native_lifecycle("session-sentinel", "shutdown");
            Ok(())
        }
    }
}

fn gui_login_is_required(is_macos: bool, is_developer: bool) -> bool {
    is_macos && !is_developer
}

async fn gui_domain_is_present(login_uid: u32) -> bool {
    let mut command = tokio::process::Command::new("/bin/launchctl");
    command
        .args(["print", &format!("gui/{login_uid}")])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    match tokio::time::timeout(Duration::from_secs(1), command.status()).await {
        Ok(Ok(status)) if status.success() => true,
        Ok(Ok(status)) => {
            crate::native_lifecycle(
                "session-sentinel",
                &format!("gui_probe_exit_{:?}", status.code()),
            );
            false
        }
        Ok(Err(error)) => {
            crate::native_lifecycle(
                "session-sentinel",
                &format!("gui_probe_spawn_errno_{:?}", error.raw_os_error()),
            );
            false
        }
        Err(_) => {
            crate::native_lifecycle("session-sentinel", "gui_probe_timeout");
            false
        }
    }
}

async fn wait_for_gui_logout<F, Fut>(required: bool, poll_interval: Duration, mut is_present: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    if !required {
        std::future::pending::<()>().await;
    }
    let mut interval = tokio::time::interval(poll_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if !is_present().await {
            return;
        }
    }
}

async fn serve_authenticated_services(
    listener: UnixListener,
    identity: bloom_triad_local_transport::LocalIdentity,
    peers: [PeerAcl; 2],
) -> Result<()> {
    let connections = Arc::new(Semaphore::new(8));
    // Own the authenticated channels: cancelling the listener on logout must
    // close existing service connections even before the runtime exits.
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        while tasks.try_join_next().is_some() {}
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
        tasks.spawn(async move {
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
                Err(error) => {
                    let _ = error;
                    tracing::warn!(
                        error_kind = "channel_read",
                        service_id = peer.service_id.as_str(),
                        "session_sentinel.monitor_failed"
                    )
                }
            }
        });
    }
}

fn enrollment_state_is_usable(state: &str) -> bool {
    state == "active" || (cfg!(target_os = "macos") && state == "activating")
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
        != Some(default_enrollment_schema())
        || enrollment
            .get("login_uid")
            .and_then(serde_json::Value::as_u64)
            != Some(u64::from(effective_uid))
        || !enrollment
            .get("state")
            .and_then(serde_json::Value::as_str)
            .is_some_and(enrollment_state_is_usable)
    {
        bail!("Bloom enrollment is not valid for this login session");
    }
    Ok(Some(()))
}

#[cfg(target_os = "macos")]
fn default_enrollment_root() -> &'static str {
    "/Library/Application Support/BloomTriad/enrollments"
}

#[cfg(not(target_os = "macos"))]
fn default_enrollment_root() -> &'static str {
    "/etc/bloom/enrollments"
}

#[cfg(target_os = "macos")]
fn default_config_root() -> &'static str {
    "/Library/Application Support/BloomTriad/config"
}

#[cfg(not(target_os = "macos"))]
fn default_config_root() -> &'static str {
    "/etc/bloom"
}

#[cfg(target_os = "macos")]
fn default_runtime_root() -> &'static str {
    "/private/var/run/bloom"
}

#[cfg(not(target_os = "macos"))]
fn default_runtime_root() -> &'static str {
    "/run/bloom"
}

#[cfg(target_os = "macos")]
fn default_enrollment_schema() -> &'static str {
    "bloom.macos-enrollment.1"
}

#[cfg(not(target_os = "macos"))]
fn default_enrollment_schema() -> &'static str {
    "bloom.linux-enrollment.1"
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
    // Directory hard links are forbidden by POSIX, so `is_dir` already rules
    // out substitutes; a link-count floor is not portable (btrfs reports
    // nlink=1 for empty directories) and adds no guarantee beyond `is_dir`.
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

struct PendingSocketGuard {
    path: PathBuf,
    uid: u32,
    device: u64,
    inode: u64,
    armed: bool,
}

impl PendingSocketGuard {
    fn new(path: PathBuf, uid: u32) -> Result<Self> {
        let metadata =
            fs::symlink_metadata(&path).context("inspect new session sentinel socket")?;
        Ok(Self {
            path,
            uid,
            device: metadata.dev(),
            inode: metadata.ino(),
            armed: true,
        })
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingSocketGuard {
    fn drop(&mut self) {
        if self.armed
            && let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.uid() == self.uid
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
            && metadata.nlink() == 1
        {
            let _ = fs::remove_file(&self.path);
        }
    }
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

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    #[test]
    fn gui_lifetime_is_required_only_for_installed_macos() {
        assert!(super::gui_login_is_required(true, false));
        assert!(!super::gui_login_is_required(true, true));
        assert!(!super::gui_login_is_required(false, false));
        assert!(!super::gui_login_is_required(false, true));
    }

    #[tokio::test]
    async fn headless_profiles_do_not_inspect_the_gui_domain() {
        let inspected = std::sync::atomic::AtomicBool::new(false);
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(10),
            super::wait_for_gui_logout(false, std::time::Duration::from_millis(1), || {
                inspected.store(true, std::sync::atomic::Ordering::SeqCst);
                std::future::ready(false)
            }),
        )
        .await;
        assert!(result.is_err());
        assert!(!inspected.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn gui_logout_closes_both_authenticated_service_channels() {
        use bloom_broker_api::{BootEpoch, Token};
        use bloom_triad_local_transport::{LocalIdentity, PeerAcl, authenticate_client};
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use tokio::io::AsyncReadExt as _;

        fn identity(service: &str, seed: u8) -> LocalIdentity {
            LocalIdentity {
                service_id: Token::new(service).unwrap(),
                boot_epoch: BootEpoch::from_bytes([seed; 16]),
                application_key_id: Token::new(format!("{service}-app")).unwrap(),
                signing_key: Arc::new(ed25519_dalek::SigningKey::from_bytes(&[seed; 32])),
            }
        }
        fn acl(identity: &LocalIdentity) -> PeerAcl {
            PeerAcl {
                effective_uid: rustix::process::geteuid().as_raw(),
                service_id: identity.service_id.clone(),
                boot_epoch: identity.boot_epoch.clone(),
                application_key_id: identity.application_key_id.clone(),
                application_public_key: identity.signing_key.verifying_key().to_bytes(),
            }
        }

        let temporary = tempfile::tempdir().unwrap();
        let socket = temporary.path().join("session.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let session = identity("bloom-session", 1);
        let broker = identity("bloom-broker", 2);
        let signer = identity("bloom-signer", 3);
        let peers = [acl(&broker), acl(&signer)];
        let session_acl = acl(&session);
        let gui_present = Arc::new(AtomicBool::new(true));
        let observed_gui = gui_present.clone();
        let server = tokio::spawn(async move {
            tokio::select! {
                result = super::serve_authenticated_services(listener, session, peers) => result,
                _ = super::wait_for_gui_logout(true, std::time::Duration::from_millis(5), || {
                    std::future::ready(observed_gui.load(Ordering::SeqCst))
                }) => Ok(()),
            }
        });
        let mut connections = Vec::new();
        for service in [&broker, &signer] {
            let mut stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
            authenticate_client(
                &mut stream,
                service,
                &session_acl,
                bloom_service_activation::SESSION_PROTOCOL_CURRENT,
                bloom_service_activation::SESSION_PROTOCOL_RANGE,
            )
            .await
            .unwrap();
            connections.push(stream);
        }
        assert!(!server.is_finished(), "live GUI login ended the sentinel");
        gui_present.store(false, Ordering::SeqCst);
        tokio::time::timeout(std::time::Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        for mut stream in connections {
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut [0; 1]))
                    .await
                    .unwrap()
                    .unwrap(),
                0,
                "logout retained an authenticated channel"
            );
        }
        assert!(
            tokio::net::UnixStream::connect(&socket).await.is_err(),
            "logout retained the listener"
        );
    }

    #[test]
    fn plain_directory_is_accepted_regardless_of_link_count() {
        let directory = std::env::temp_dir().join(format!(
            "bloom-session-sentinel-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).expect("create session directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o710))
            .expect("set session directory permissions");
        let metadata = std::fs::symlink_metadata(&directory).expect("directory metadata");
        let accepted = super::require_session_directory(&directory, metadata.uid(), metadata.gid());
        let _ = std::fs::remove_dir_all(&directory);
        assert!(
            accepted.is_ok(),
            "plain directory was rejected: {accepted:?}"
        );
    }

    #[test]
    fn activating_enrollment_is_accepted_only_by_macos_sentinel() {
        assert!(super::enrollment_state_is_usable("active"));
        assert_eq!(
            super::enrollment_state_is_usable("activating"),
            cfg!(target_os = "macos")
        );
    }
}
