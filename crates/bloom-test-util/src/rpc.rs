//! Async polling helpers used by integration tests.
//!
//! - [`wait_for_socket`]: poll until a UDS path exists or the deadline
//!   elapses. Dedups two near-identical loops in `bloom/tests/cli.rs` and
//!   `bloom-daemon/src/ipc.rs`.

use std::path::Path;
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::time::{sleep, timeout};

/// Block until the file at `path` exists (typically a UDS socket created
/// by a daemon's listener) or `deadline` elapses.
///
/// Polls every 50ms. Returns `Err` on timeout.
pub async fn wait_for_socket(path: &Path, deadline: Duration) -> Result<()> {
    let path = path.to_path_buf();
    let fut = async {
        loop {
            if path.exists() {
                return Ok::<(), anyhow::Error>(());
            }
            sleep(Duration::from_millis(50)).await;
        }
    };
    timeout(deadline, fut).await.map_err(|_| {
        anyhow!(
            "socket {} did not appear within {:?}",
            path.display(),
            deadline
        )
    })??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::fs;

    #[tokio::test]
    async fn wait_for_socket_returns_when_file_appears() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("sock");
        let p2 = path.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(80)).await;
            fs::write(&p2, b"").await.unwrap();
        });
        wait_for_socket(&path, Duration::from_secs(2))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn wait_for_socket_times_out() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("never");
        let err = wait_for_socket(&path, Duration::from_millis(150))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("did not appear"));
    }
}
