//! Shared helpers for `bloom-it`'s integration tests.
//!
//! The original tests inlined an anvil-spawn helper inside each
//! `tests/*.rs` file; with multiple revert/trace tests landing alongside
//! the existing stage-confirm flow we hoist the spawn / fund / config
//! helpers here so each test only needs the bits specific to its
//! scenario.

use std::net::TcpListener;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;

/// Default funder; anvil's prefunded account #0.
pub const FUNDER_PRIV_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Foundry binaries; rely on `$PATH`. Override with `BLOOM_ANVIL_BIN` /
/// `BLOOM_CAST_BIN` if you need to point at a specific install.
pub fn anvil_bin() -> String {
    std::env::var("BLOOM_ANVIL_BIN").unwrap_or_else(|_| "anvil".to_string())
}

pub fn cast_bin() -> String {
    std::env::var("BLOOM_CAST_BIN").unwrap_or_else(|_| "cast".to_string())
}

/// RAII guard that kills the spawned anvil process on drop.
pub struct AnvilGuard {
    child: Option<Child>,
    port: u16,
}

impl AnvilGuard {
    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Anvil serves WebSocket pubsub on the same TCP port as HTTP, so
    /// we just rewrite the scheme. Used by the `rpc_ws_subscriptions`
    /// integration test (WP-4).
    pub fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}", self.port)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Detach the underlying anvil `Child` so a test can `.kill()` /
    /// `.wait()` it explicitly. Used by the RPC failover test which
    /// needs to take an endpoint down mid-run and observe the
    /// fallback layer route around it.
    pub fn take_child(&mut self) -> Option<Child> {
        self.child.take()
    }
}

impl Drop for AnvilGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            // Best-effort kill. start_kill is sync; the OS will reap.
            let _ = c.start_kill();
        }
    }
}

/// Pick an OS-assigned free TCP port by binding to :0 and releasing it.
pub fn pick_free_port() -> Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

/// Spawn anvil on a free port and wait until its stdout reports it is
/// listening. Returns a guard that kills the child on drop.
pub async fn spawn_anvil() -> Result<AnvilGuard> {
    let port = pick_free_port()?;
    let mut cmd = Command::new(anvil_bin());
    cmd.arg("--port")
        .arg(port.to_string())
        .arg("--host")
        .arg("127.0.0.1")
        // Determinism: chain id 31337, default mnemonic.
        .arg("--chain-id")
        .arg("31337")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd.spawn().context("spawn anvil")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("anvil stdout missing"))?;

    // Read lines until we see "Listening on" or hit a timeout.
    let mut reader = BufReader::new(stdout).lines();
    let wait = async {
        loop {
            match reader.next_line().await? {
                Some(line) => {
                    if line.contains("Listening on") {
                        return Ok::<(), anyhow::Error>(());
                    }
                }
                None => return Err(anyhow!("anvil exited before becoming ready")),
            }
        }
    };
    timeout(Duration::from_secs(15), wait)
        .await
        .map_err(|_| anyhow!("timed out waiting for anvil to start"))??;

    Ok(AnvilGuard {
        child: Some(child),
        port,
    })
}

/// Send a raw transaction with `cast send` from the prefunded funder
/// account; returns stdout as captured.
pub async fn cast_send(rpc_url: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cast_bin())
        .arg("send")
        .arg("--private-key")
        .arg(FUNDER_PRIV_KEY)
        .arg("--rpc-url")
        .arg(rpc_url)
        .args(args)
        .output()
        .await
        .context("invoke cast send")?;
    if !out.status.success() {
        return Err(anyhow!(
            "cast send failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}
