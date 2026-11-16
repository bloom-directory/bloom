//! Mount one stub outbox entry whose owner approves a few seconds after the
//! first confirm, and block until SIGTERM/SIGINT.
//!
//! Used by `tests/docker/test_owner_wait.sh` to check, through the Linux
//! kernel's NFS client, what the adapter's unit tests can only check
//! in-process: a first `confirm` is refused at once, a repeat waits for the
//! owner and then succeeds, and the kernel re-sending a refused write does
//! not reach the handler again.
//!
//! Usage:
//!     owner_wait_mount <mount-point> <approve-after-seconds>

#[cfg(not(feature = "mount"))]
fn main() {
    eprintln!("owner_wait_mount: rebuild with --features mount");
    std::process::exit(2);
}

#[cfg(feature = "mount")]
mod stub {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use bloom_vfs::handler::{Entry, Handler, HandlerError};
    use bloom_vfs::VfsPath;

    /// The one entry: `wallets/w/0/chains/c/outbox/pending/e1/`.
    const ENTRY: [&str; 7] = ["w", "0", "chains", "c", "outbox", "pending", "e1"];
    const CHALLENGE: &str = "approval_challenge.json";

    pub struct Outbox {
        pub approve_after: Duration,
        pub first_confirm: parking_lot::Mutex<Option<Instant>>,
        pub writes: AtomicUsize,
        pub sent: AtomicUsize,
    }

    impl Outbox {
        fn active(&self) -> bool {
            (*self.first_confirm.lock()).is_some_and(|at| at.elapsed() >= self.approve_after)
        }
        fn challenge(&self) -> Option<String> {
            if (*self.first_confirm.lock()).is_none() || self.sent.load(Ordering::SeqCst) > 0 {
                return None;
            }
            let state = if self.active() {
                "active"
            } else {
                "awaiting_ceremony"
            };
            Some(format!(
                r#"{{"approval_id":"a1","state":"{state}","ceremony_url":"http://localhost/c/e1"}}"#
            ))
        }
        /// How often a confirm reached the handler, and how often it sent.
        fn counts(&self) -> String {
            format!(
                "writes={} sent={}\n",
                self.writes.load(Ordering::SeqCst),
                self.sent.load(Ordering::SeqCst)
            )
        }
        fn file(&self, leaf: &str) -> Option<Entry> {
            match leaf {
                "confirm" => Some(Entry::writable_file(leaf)),
                "counts" => Some(Entry::file(leaf).with_size(self.counts().len() as u64)),
                CHALLENGE => self
                    .challenge()
                    .map(|body| Entry::file(leaf).with_size(body.len() as u64)),
                _ => None,
            }
        }
    }

    fn within_entry(segments: &[String]) -> bool {
        segments.len() <= ENTRY.len() && segments.iter().zip(ENTRY).all(|(a, b)| a == b)
    }

    #[async_trait::async_trait]
    impl Handler for Outbox {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            let segments = p.segments();
            if within_entry(segments) {
                return Ok(Entry::dir(
                    segments.last().map(String::as_str).unwrap_or("wallets"),
                ));
            }
            match segments.split_last() {
                Some((leaf, dir)) if dir.len() == ENTRY.len() && within_entry(dir) => self
                    .file(leaf)
                    .ok_or_else(|| HandlerError::not_found(p.to_string_path())),
                _ => Err(HandlerError::not_found(p.to_string_path())),
            }
        }

        async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            let segments = p.segments();
            if !within_entry(segments) {
                return Err(HandlerError::not_found(p.to_string_path()));
            }
            Ok(match ENTRY.get(segments.len()) {
                Some(child) => vec![Entry::dir(child)],
                None => ["confirm", "counts", CHALLENGE]
                    .into_iter()
                    .filter_map(|leaf| self.file(leaf))
                    .collect(),
            })
        }

        async fn read(&self, p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            match p.segments().last().map(String::as_str) {
                Some("counts") => Ok(self.counts().into_bytes()),
                Some(CHALLENGE) => self
                    .challenge()
                    .map(String::into_bytes)
                    .ok_or_else(|| HandlerError::not_found(p.to_string_path())),
                _ => Ok(Vec::new()),
            }
        }

        async fn write(&self, p: &VfsPath, _data: &[u8]) -> Result<(), HandlerError> {
            if p.segments().last().map(String::as_str) != Some("confirm") {
                return Err(HandlerError::PermissionDenied);
            }
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.first_confirm.lock().get_or_insert_with(Instant::now);
            if !self.active() {
                return Err(HandlerError::ApprovalPending(format!(
                    "wallets/{}/{CHALLENGE}",
                    ENTRY.join("/")
                )));
            }
            self.sent.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
}

#[cfg(feature = "mount")]
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::time::Duration;

    let mut args = std::env::args().skip(1);
    let (Some(mount_point), Some(approve_after)) = (args.next(), args.next()) else {
        return Err("usage: owner_wait_mount <mount-point> <approve-after-seconds>".into());
    };
    let mount_path = std::path::PathBuf::from(mount_point);
    std::fs::create_dir_all(&mount_path)?;

    let outbox = Arc::new(stub::Outbox {
        approve_after: Duration::from_secs(approve_after.parse()?),
        first_confirm: parking_lot::Mutex::new(None),
        writes: 0.into(),
        sent: 0.into(),
    });
    let vfs = bloom_vfs::Vfs::builder().mount("wallets", outbox).build();
    let handle = bloom_mount::serve_nfs(vfs, &mount_path).await?;
    if let Some(parent) = mount_path.parent() {
        std::fs::write(
            parent.join(".bloom-mounted"),
            mount_path.display().to_string(),
        )?;
    }

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    tokio::select! {
        _ = sigterm.recv() => {},
        _ = sigint.recv() => {},
    }
    bloom_mount::MountHandle::unmount(&handle).await?;
    Ok(())
}
