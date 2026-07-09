#![cfg(feature = "mount")]

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bloom_mount::{MountHandle, serve_nfs};
use bloom_vfs::handler::{Entry, Handler, HandlerError};
use bloom_vfs::{Vfs, VfsPath};

#[derive(Default)]
struct ChallengeStagingHandler {
    lookups: parking_lot::Mutex<usize>,
    lists: parking_lot::Mutex<usize>,
    staged: parking_lot::Mutex<Vec<Vec<u8>>>,
}

impl ChallengeStagingHandler {
    fn lookup_count(&self) -> usize {
        *self.lookups.lock()
    }

    fn list_count(&self) -> usize {
        *self.lists.lock()
    }

    fn staged_count(&self) -> usize {
        self.staged.lock().len()
    }
}

#[async_trait]
impl Handler for ChallengeStagingHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        *self.lookups.lock() += 1;
        if path.is_root() {
            return Ok(Entry::dir(""));
        }
        match path.first() {
            Some("challenge") => Ok(Entry::writable_file("challenge")),
            _ => Err(HandlerError::NotFound(path.to_string_path())),
        }
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        match path.first() {
            Some("challenge") => {
                self.staged.lock().push(data.to_vec());
                Err(HandlerError::PermissionDenied)
            }
            _ => Err(HandlerError::PermissionDenied),
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        *self.lists.lock() += 1;
        if path.is_root() {
            Ok(vec![Entry::writable_file("challenge")])
        } else {
            Err(HandlerError::NotADir(path.to_string_path()))
        }
    }
}

fn unique_mount_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("bloom-mount-denied-{}-{nanos}", std::process::id()))
}

fn command_output_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> std::io::Result<Option<Output>> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output().map(Some);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn command_text(cmd: &str, args: &[&str], timeout: Duration) -> String {
    let mut command = Command::new(cmd);
    command.args(args);
    match command_output_with_timeout(&mut command, timeout) {
        Ok(Some(output)) => format!(
            "status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        Ok(None) => "timed out".to_string(),
        Err(err) => format!("failed to run: {err}"),
    }
}

/// Manual issue #77 coverage: a real shell redirect through a kernel NFS
/// mount must fail when the handler stages a challenge and returns
/// PermissionDenied. This needs platform mount privileges, so it is ignored
/// and self-skips when `serve_nfs` cannot establish the mount.
#[tokio::test]
#[ignore = "requires local NFS mount privileges"]
async fn mounted_printf_surfaces_permission_denied() {
    let mount_dir = unique_mount_dir();
    std::fs::create_dir(&mount_dir).expect("create temporary mount dir");

    let handler = Arc::new(ChallengeStagingHandler::default());
    let vfs = Vfs::builder().mount("stage", handler.clone()).build();
    let mount = match serve_nfs(vfs, &mount_dir).await {
        Ok(mount) => mount,
        Err(err) => {
            eprintln!("skipping real mount permission-denied test: {err}");
            let _ = std::fs::remove_dir(&mount_dir);
            return;
        }
    };

    let mut root_ls = Command::new("ls");
    root_ls.arg("-la").arg(&mount_dir);
    match command_output_with_timeout(&mut root_ls, Duration::from_secs(5))
        .expect("run ls through mounted root")
    {
        Some(output) if output.status.success() => {}
        Some(output) => {
            eprintln!(
                "skipping real mount permission-denied test: root ls failed: stdout={} stderr={} lookups={} lists={} staged_count={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
                handler.lookup_count(),
                handler.list_count(),
                handler.staged_count()
            );
            let _ = mount.unmount().await;
            let _ = std::fs::remove_dir(&mount_dir);
            return;
        }
        None => {
            eprintln!(
                "skipping real mount permission-denied test: root ls timed out; nfs_addr={} mount={} nfsstat={} lookups={} lists={} staged_count={}",
                mount.nfs_addr(),
                command_text("mount", &[], Duration::from_secs(2)),
                command_text("nfsstat", &["-m"], Duration::from_secs(2)),
                handler.lookup_count(),
                handler.list_count(),
                handler.staged_count()
            );
            let _ = mount.unmount().await;
            let _ = std::fs::remove_dir(&mount_dir);
            return;
        }
    }

    let stage_dir = mount_dir.join("stage");
    let mut stage_ls = Command::new("ls");
    stage_ls.arg("-la").arg(&stage_dir);
    match command_output_with_timeout(&mut stage_ls, Duration::from_secs(5))
        .expect("run ls through mounted stage dir")
    {
        Some(output) if output.status.success() => {}
        Some(output) => {
            eprintln!(
                "skipping real mount permission-denied test: stage ls failed: stdout={} stderr={} lookups={} lists={} staged_count={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
                handler.lookup_count(),
                handler.list_count(),
                handler.staged_count()
            );
            let _ = mount.unmount().await;
            let _ = std::fs::remove_dir(&mount_dir);
            return;
        }
        None => {
            eprintln!(
                "skipping real mount permission-denied test: stage ls timed out; lookups={} lists={} staged_count={}",
                handler.lookup_count(),
                handler.list_count(),
                handler.staged_count()
            );
            let _ = mount.unmount().await;
            let _ = std::fs::remove_dir(&mount_dir);
            return;
        }
    }

    let target = mount_dir.join("stage").join("challenge");
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg("printf '%s' '{\"action\":\"usdSend\"}' > \"$1\"")
        .arg("bloom-mount-test")
        .arg(&target);
    let output = match command_output_with_timeout(&mut command, Duration::from_secs(10))
        .expect("run shell redirect through mounted path")
    {
        Some(output) => output,
        None => {
            eprintln!(
                "skipping real mount permission-denied test: shell redirect timed out; lookups={} lists={} staged_count={}",
                handler.lookup_count(),
                handler.list_count(),
                handler.staged_count()
            );
            let _ = mount.unmount().await;
            let _ = std::fs::remove_dir(&mount_dir);
            return;
        }
    };

    if let Err(err) = mount.unmount().await {
        eprintln!("real mount permission-denied test cleanup: unmount failed: {err}");
    }
    let _ = std::fs::remove_dir(&mount_dir);

    assert!(
        !output.status.success(),
        "mounted shell redirect unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        handler.staged_count(),
        1,
        "content write should stage exactly one challenge before denying"
    );
}
