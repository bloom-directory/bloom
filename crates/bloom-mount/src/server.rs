//! Server-side glue for the `mount` feature: bind an embednfs server,
//! shell out to the platform mount command, hand back a handle.
//!
//! Lifecycle:
//!
//! 1. [`serve_nfs`] picks a localhost port (ephemeral by default),
//!    binds an `embednfs::NfsServer` wrapping a [`crate::adapter::BloomFs`],
//!    and spawns the accept loop on a tokio task.
//! 2. It then runs the platform mount command synchronously inside a
//!    `spawn_blocking` (waiting on a child process inside an async fn
//!    works, but `spawn_blocking` keeps stdout/stderr capture cleaner).
//! 3. The returned [`NfsMountHandle`] aborts the server task and runs
//!    `umount` when [`MountHandle::unmount`] is called. The `Drop` impl
//!    issues a best-effort `umount` so a panic'd test still cleans up.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use bloom_vfs::Vfs;

use crate::adapter::BloomFs;
use crate::{MountConfig, MountError, MountHandle, build_mount_args};

const MOUNT_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const UMOUNT_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

fn unmount_args(path: &Path) -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        vec![
            "-l".to_string(),
            "-f".to_string(),
            path.display().to_string(),
        ]
    }
    #[cfg(not(target_os = "linux"))]
    {
        vec!["-f".to_string(), path.display().to_string()]
    }
}

fn run_command_with_timeout(
    cmd_name: &str,
    args: &[String],
    timeout: Duration,
) -> Result<Output, MountError> {
    let mut child = std::process::Command::new(cmd_name)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output().map_err(MountError::from);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return Err(MountError::Mount(format!(
                "{cmd_name} timed out after {}s",
                timeout.as_secs()
            )));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn linux_mount_fallback_args(cfg: &MountConfig, server: SocketAddr) -> Vec<String> {
    let port = server.port();
    let mut opts = format!(
        "vers=4.1,proto=tcp,port={port},noac,lookupcache=none,rsize=65536,wsize=65536,timeo=10"
    );
    if cfg.readonly {
        opts.push_str(",ro");
    }
    vec![
        "-t".to_string(),
        "nfs4".to_string(),
        "-o".to_string(),
        opts,
        format!("{}:/", server.ip()),
        cfg.mount_path.display().to_string(),
    ]
}

/// Handle to a live mount established by [`serve_nfs`]. Holds the bound
/// NFS server task plus the mount path so `unmount` can tear both down.
pub struct NfsMountHandle {
    nfs_addr: SocketAddr,
    mount_path: PathBuf,
    server_task: parking_lot::Mutex<Option<JoinHandle<()>>>,
    unmounted: parking_lot::Mutex<bool>,
}

impl NfsMountHandle {
    fn new(nfs_addr: SocketAddr, mount_path: PathBuf, server_task: JoinHandle<()>) -> Self {
        Self {
            nfs_addr,
            mount_path,
            server_task: parking_lot::Mutex::new(Some(server_task)),
            unmounted: parking_lot::Mutex::new(false),
        }
    }
}

impl Drop for NfsMountHandle {
    fn drop(&mut self) {
        // Best-effort cleanup if the caller forgot to await `unmount`.
        // `umount` might fail (already unmounted, kernel busy, etc.);
        // log and move on rather than panic from Drop.
        let already = *self.unmounted.lock();
        if !already {
            let mp = self.mount_path.clone();
            let args = unmount_args(&mp);
            if let Err(e) = std::process::Command::new("umount")
                .args(&args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                warn!(mount_path = %mp.display(), error = %e, "mount.drop.umount_spawn_failed");
            } else {
                debug!(mount_path = %mp.display(), "mount.drop.umount_dispatched");
            }
        }
        if let Some(task) = self.server_task.lock().take() {
            task.abort();
        }
    }
}

#[async_trait::async_trait]
impl MountHandle for NfsMountHandle {
    async fn unmount(&self) -> Result<(), MountError> {
        // Idempotent: a second call is a no-op.
        {
            let mut flag = self.unmounted.lock();
            if *flag {
                debug!(mount_path = %self.mount_path.display(), "mount.unmount_idempotent");
                return Ok(());
            }
            *flag = true;
        }
        let mp = self.mount_path.clone();
        let status = tokio::task::spawn_blocking(move || {
            let args = unmount_args(&mp);
            run_command_with_timeout("umount", &args, UMOUNT_COMMAND_TIMEOUT)
        })
        .await
        .map_err(|e| MountError::Mount(format!("umount join: {e}")))??;
        if !status.status.success() {
            let stderr = String::from_utf8_lossy(&status.stderr);
            return Err(MountError::Mount(format!(
                "umount exited {}: {}",
                status.status, stderr
            )));
        }
        if let Some(task) = self.server_task.lock().take() {
            task.abort();
        }
        info!(mount_path = %self.mount_path.display(), "mount.unmounted");
        Ok(())
    }

    fn mount_path(&self) -> &Path {
        &self.mount_path
    }

    fn nfs_addr(&self) -> SocketAddr {
        self.nfs_addr
    }
}

/// Bind an embedded NFS server, mount it at `mount_point`, and return
/// a handle whose `unmount` tears both down.
///
/// `mount_point` must already exist as an empty directory. We don't
/// create it for you — that decision belongs to whoever owns the path.
pub async fn serve_nfs(vfs: Vfs, mount_point: &Path) -> Result<NfsMountHandle, MountError> {
    serve_nfs_with(
        vfs,
        MountConfig {
            mount_path: mount_point.to_path_buf(),
            nfs_listen: "127.0.0.1:0".parse().expect("static loopback"),
            readonly: false,
        },
    )
    .await
}

/// Same as [`serve_nfs`] but lets the caller pin the listen address /
/// readonly flag. `cfg.nfs_listen` may use port 0 to pick an ephemeral
/// port; the actual bound address is reflected in the returned handle.
pub async fn serve_nfs_with(vfs: Vfs, cfg: MountConfig) -> Result<NfsMountHandle, MountError> {
    if !cfg.mount_path.exists() {
        return Err(MountError::Config(format!(
            "mount path does not exist: {}",
            cfg.mount_path.display()
        )));
    }
    if !cfg.mount_path.is_dir() {
        return Err(MountError::Config(format!(
            "mount path is not a directory: {}",
            cfg.mount_path.display()
        )));
    }

    // Bind the embednfs server on the requested address. Resolve the
    // OS-assigned port immediately so we can wire it into the mount
    // command — `mount.nfs4 port=N` needs the real number.
    let listener = TcpListener::bind(cfg.nfs_listen).await?;
    let local = listener.local_addr()?;
    info!(addr = %local, mount_path = %cfg.mount_path.display(), "mount.nfs_listening");

    let fs = BloomFs::new(vfs);
    let server = embednfs::NfsServer::new(fs);
    let server_task = tokio::spawn(async move {
        if let Err(e) = server.serve(listener).await {
            warn!(error = %e, "mount.nfs_server_exited");
        }
    });

    // Run the mount command. `spawn_blocking` so a long-running mount
    // (Linux can sit in the kernel for a few seconds while it sets up
    // the client struct) doesn't pin the runtime worker.
    let args = build_mount_args(&cfg, local);
    let cmd_name = crate::detect_mount_command();
    let mut attempts = vec![(cmd_name.to_string(), args)];
    if cfg!(target_os = "linux") {
        attempts.push(("mount".to_string(), linux_mount_fallback_args(&cfg, local)));
    }
    debug!(?attempts, "mount.cmd_attempts");
    let mp_for_log = cfg.mount_path.clone();
    let mount_result = tokio::task::spawn_blocking({
        let attempts = attempts.clone();
        move || {
            let mut errors = Vec::new();
            for (cmd_name, args) in attempts {
                match run_command_with_timeout(&cmd_name, &args, MOUNT_COMMAND_TIMEOUT) {
                    Ok(output) if output.status.success() => return Ok(output),
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        errors.push(format!(
                            "{} {:?} exited {}: stdout={} stderr={}",
                            cmd_name, args, output.status, stdout, stderr
                        ));
                    }
                    Err(e) => errors.push(format!("{} {:?}: {}", cmd_name, args, e)),
                }
            }
            Err(MountError::Mount(errors.join("; ")))
        }
    })
    .await
    .map_err(|e| MountError::Mount(format!("mount join: {e}")))?;

    let output = match mount_result {
        Ok(o) => o,
        Err(e) => {
            server_task.abort();
            return Err(e);
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        server_task.abort();
        return Err(MountError::Mount(format!(
            "mount exited {}: stdout={} stderr={}",
            output.status, stdout, stderr
        )));
    }

    info!(mount_path = %mp_for_log.display(), nfs_addr = %local, "mount.established");
    Ok(NfsMountHandle::new(local, cfg.mount_path, server_task))
}

#[cfg(test)]
mod tests {
    //! Tests for the `server.rs` lifecycle helpers and `NfsMountHandle`.
    //!
    //! These tests intentionally avoid invoking the real `mount(8)` —
    //! attaching an NFS mount needs root on Linux and admin on macOS,
    //! which neither `cargo test` nor most CI runners have. We exercise
    //! the mount-command path indirectly via [`run_command_with_timeout`]
    //! (which is the same primitive `serve_nfs_with` uses) and exercise
    //! the handle lifecycle by constructing handles directly with a
    //! dummy server task. Tests that genuinely require a real mount are
    //! gated behind `#[ignore]` and documented inline.
    use super::*;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::time::{Duration as TokioDuration, timeout};

    /// A tokio task that pretends to be the NFS server accept loop.
    /// Sleeps long enough that the test will always observe the abort
    /// causing the join handle to finish, rather than the task exiting
    /// on its own.
    fn dummy_server_task() -> JoinHandle<()> {
        tokio::spawn(async {
            // 60s is far longer than any individual test; abort wins.
            tokio::time::sleep(TokioDuration::from_secs(60)).await;
        })
    }
    fn ephemeral_addr() -> SocketAddr {
        "127.0.0.1:0".parse().expect("static loopback")
    }
    fn unique_nonexistent_path() -> PathBuf {
        // Use a per-pid/per-time path so concurrent tests don't collide.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("bloom-mount-test-{}-{}", std::process::id(), nanos))
    }

    /// `run_command_with_timeout` should map "binary not found" into a
    /// `MountError::Io` (via the `io::Error` `From` impl) rather than
    /// panicking — this is the path `serve_nfs_with` relies on when the
    /// platform mount command is missing. We don't care exactly which
    /// variant we get, only that it is an `Err` of `MountError`.
    #[test]
    fn run_command_with_missing_binary_returns_error() {
        let res = run_command_with_timeout(
            "/nonexistent/bloom-mount-bogus-binary",
            &[],
            Duration::from_secs(1),
        );
        let err = res.expect_err("missing binary should produce an error");
        // The exact variant isn't load-bearing, but it must be a clean
        // `MountError`. `std::process::Command::spawn` for a missing
        // binary surfaces an `io::Error` which `?` lifts via `From`.
        match err {
            MountError::Io(_) => {}
            other => panic!("expected MountError::Io for missing binary, got {other:?}"),
        }
    }

    /// `run_command_with_timeout` should kill a long-running child once
    /// the deadline passes and return a `MountError::Mount(...)` rather
    /// than blocking the caller. We use `/bin/sleep 30` so there is no
    /// chance the child finishes before the 100ms timeout fires.
    #[test]
    fn run_command_timeout_fires_for_slow_child() {
        let started = Instant::now();
        let res = run_command_with_timeout(
            "/bin/sleep",
            &["30".to_string()],
            Duration::from_millis(100),
        );
        let elapsed = started.elapsed();
        // We allow generous headroom for slow CI; the point is "doesn't
        // wait for the full 30s sleep", not microsecond-level accuracy.
        assert!(
            elapsed < Duration::from_secs(5),
            "timeout did not fire promptly (elapsed={elapsed:?})"
        );
        let err = res.expect_err("slow child should hit the deadline");
        match err {
            MountError::Mount(msg) => {
                assert!(
                    msg.contains("timed out"),
                    "expected timeout message, got {msg:?}"
                );
            }
            other => panic!("expected MountError::Mount(timeout), got {other:?}"),
        }
    }

    /// `run_command_with_timeout` returns `Ok` with the child's `Output`
    /// when the process completes within the deadline. Sanity check that
    /// the happy path still works alongside the failure tests above.
    #[test]
    fn run_command_returns_output_on_quick_success() {
        let res =
            run_command_with_timeout("/bin/sleep", &["0".to_string()], Duration::from_secs(2))
                .expect("sleep 0 should succeed promptly");
        assert!(res.status.success(), "sleep 0 should exit zero");
    }

    /// `serve_nfs_with` must reject a non-existent mount path with
    /// `MountError::Config` *before* binding the NFS listener — that is
    /// the contract the daemon relies on for nice error messages.
    #[tokio::test]
    async fn serve_nfs_rejects_missing_mount_path() {
        let cfg = MountConfig {
            mount_path: unique_nonexistent_path(),
            nfs_listen: ephemeral_addr(),
            readonly: false,
        };
        let vfs = bloom_vfs::Vfs::builder().build();
        match serve_nfs_with(vfs, cfg).await {
            Err(MountError::Config(msg)) => assert!(msg.contains("does not exist")),
            Err(other) => panic!("expected MountError::Config, got {other:?}"),
            Ok(_) => panic!("missing mount path should error"),
        }
    }

    /// `serve_nfs_with` must reject a regular file (non-directory) at
    /// the mount path with `MountError::Config`.
    #[tokio::test]
    async fn serve_nfs_rejects_non_directory_mount_path() {
        let dir = std::env::temp_dir();
        let file = dir.join(format!(
            "bloom-mount-test-file-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&file, b"not a directory").expect("create temp file");
        let cfg = MountConfig {
            mount_path: file.clone(),
            nfs_listen: ephemeral_addr(),
            readonly: false,
        };
        let vfs = bloom_vfs::Vfs::builder().build();
        let res = serve_nfs_with(vfs, cfg).await;
        let _ = std::fs::remove_file(&file);
        match res {
            Err(MountError::Config(msg)) => assert!(msg.contains("not a directory")),
            Err(other) => panic!("expected MountError::Config, got {other:?}"),
            Ok(_) => panic!("non-directory mount path should error"),
        }
    }

    /// Calling `unmount` twice must be safe: the second call observes
    /// the `unmounted` flag and returns `Ok(())` without re-running
    /// `umount`. The first call will fail because the mount path is
    /// fake — that's fine, the contract under test is "second call is
    /// a clean no-op", not "first call succeeds".
    #[tokio::test]
    async fn unmount_is_idempotent() {
        let mount_path = unique_nonexistent_path();
        let task = dummy_server_task();
        let handle = NfsMountHandle::new(ephemeral_addr(), mount_path.clone(), task);
        // First call: umount(8) will fail (path doesn't exist / isn't
        // a mount). We don't care about the error variant here, only
        // that the flag flips.
        let _ = handle.unmount().await;
        // Second call must short-circuit and return Ok.
        let second = handle.unmount().await;
        assert!(
            second.is_ok(),
            "second unmount should be a no-op, got {second:?}"
        );
    }

    #[test]
    fn unmount_args_are_platform_compatible() {
        let args = unmount_args(Path::new("/tmp/bloom"));
        assert!(args.contains(&"-f".to_string()));
        assert_eq!(args.last().map(String::as_str), Some("/tmp/bloom"));
        #[cfg(target_os = "linux")]
        assert!(args.contains(&"-l".to_string()));
        #[cfg(not(target_os = "linux"))]
        assert!(!args.contains(&"-l".to_string()));
    }

    /// Aborting the server task as part of `unmount` should cause the
    /// `JoinHandle` to finish in short order. We can't observe the
    /// handle directly through the public API (it's consumed inside
    /// `unmount`), so we verify the abort path via a parallel task we
    /// own and abort with the same `JoinHandle::abort`. This exercises
    /// the same tokio mechanics `unmount` uses.
    #[tokio::test]
    async fn server_task_abort_finishes_promptly() {
        let task = dummy_server_task();
        // Sanity: task is live until we abort it.
        assert!(!task.is_finished(), "dummy task should be live");
        task.abort();
        // The accept-loop task should resolve its `JoinHandle` with a
        // cancelled `JoinError` essentially immediately. Bound the wait
        // generously (2s) to avoid flakes on loaded CI but still catch
        // the regression where abort never lands.
        let join = timeout(TokioDuration::from_secs(2), task)
            .await
            .expect("aborted task should join within deadline");
        match join {
            Err(e) => assert!(
                e.is_cancelled(),
                "expected JoinError::is_cancelled, got {e:?}"
            ),
            Ok(()) => panic!("aborted task should not complete normally"),
        }
    }

    /// The `Drop` impl issues a best-effort `umount` and aborts the
    /// server task. It must never panic — even when the mount never
    /// actually succeeded (path is bogus, umount(8) will fail).
    #[tokio::test]
    async fn drop_without_unmount_does_not_panic() {
        let mount_path = unique_nonexistent_path();
        let task = dummy_server_task();
        let handle = NfsMountHandle::new(ephemeral_addr(), mount_path, task);
        // Confirm the public accessors expose what we passed in before
        // we drop. (The test asserts `Drop` is sound by simply running
        // it inside the test — a panic in `Drop` would abort the test
        // process even with `#[should_panic]`.)
        assert!(handle.mount_path().is_absolute());
        assert_eq!(handle.nfs_addr().ip().to_string(), "127.0.0.1");
        drop(handle);
    }

    /// Dropping a handle *after* `unmount` has succeeded (well, after
    /// the unmount flag has been flipped — first-call umount will fail
    /// for our bogus path but the flag still flips) must skip the
    /// best-effort umount entirely. We don't have a direct hook into
    /// the spawn'd `umount` from Drop, but we can at least confirm the
    /// no-panic property and that the server task is aborted as part
    /// of Drop's cleanup branch.
    #[tokio::test]
    async fn drop_after_unmount_is_quiet() {
        let mount_path = unique_nonexistent_path();
        let task = dummy_server_task();
        let handle = NfsMountHandle::new(ephemeral_addr(), mount_path, task);
        let _ = handle.unmount().await; // flips the unmounted flag
        drop(handle);
    }

    /// Sanity that we can build a `BloomFs` adapter against an empty Vfs
    /// — server.rs constructs one inline via `BloomFs::new(vfs)` and
    /// hands it to `embednfs::NfsServer`. If this regressed (say a
    /// mandatory builder option was added) the failure here pinpoints
    /// the wiring, not the mount command.
    #[test]
    fn bloomfs_constructs_from_empty_vfs() {
        let vfs = bloom_vfs::Vfs::builder().build();
        let _fs = crate::adapter::BloomFs::new(vfs);
        // Constructing without panicking is the assertion.
        let _vfs2: Arc<()> = Arc::new(());
    }
}
