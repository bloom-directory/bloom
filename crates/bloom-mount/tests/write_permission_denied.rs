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
    staged: parking_lot::Mutex<Vec<Vec<u8>>>,
}

impl ChallengeStagingHandler {
    fn staged_count(&self) -> usize {
        self.staged.lock().len()
    }
}

#[async_trait]
impl Handler for ChallengeStagingHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
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
            eprintln!("skipping real mount permission-denied test: shell redirect timed out");
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
