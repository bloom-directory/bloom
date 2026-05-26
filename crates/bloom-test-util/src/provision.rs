//! Multi-validator orchestration: provision a local network by shelling
//! out to `bloom chain testnet`, spawn validator processes, and tear them
//! down on drop.
//!
//! Migrated from `bloom_it::chain_harness`. Lives here so every test
//! consumer — chain-smoke, DEX e2e, docker harness — uses the same
//! bootstrap path.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

/// Resolve the `bloom` binary path.
///
/// Resolution order:
///   1. `$BLOOM_BIN` env var.
///   2. `<workspace_root>/target/debug/bloom`.
pub fn bloom_bin() -> PathBuf {
    if let Ok(p) = std::env::var("BLOOM_BIN") {
        return PathBuf::from(p);
    }
    // CARGO_MANIFEST_DIR points at crates/bloom-test-util. Workspace root is two up.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("../../target/debug/bloom")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(manifest_dir).join("../../target/debug/bloom"))
}

/// Pick an OS-assigned free TCP port (binds to `:0` then releases).
///
/// Race window between this call and the validator binding the port is
/// inherent to OS-assigned-port harnesses; tests should retry on startup
/// failure if it bites.
pub fn pick_free_port() -> Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

/// Per-node spawn configuration.
pub struct ChainNodeConfig {
    pub home: PathBuf,
    pub config: PathBuf,
}

/// RAII guard around a `bloom chain run-validator` child process.
pub struct ChainNodeGuard {
    child: Option<Child>,
    home: PathBuf,
    rpc_sock: PathBuf,
}

impl ChainNodeGuard {
    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn rpc_sock(&self) -> &Path {
        &self.rpc_sock
    }
}

impl Drop for ChainNodeGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.start_kill();
        }
    }
}

/// Spawn a single validator node. The caller is responsible for having
/// already run `bloom chain init` against `home` and written a working
/// `config.toml`.
///
/// Returns once the UDS RPC socket exists, or after `boot_timeout`.
pub async fn spawn_validator(
    cfg: ChainNodeConfig,
    boot_timeout: Duration,
) -> Result<ChainNodeGuard> {
    let bin = bloom_bin();
    let rpc_sock = cfg.home.join("chain/rpc.sock");

    let stdout_log = cfg.home.join("validator.stdout.log");
    let stderr_log = cfg.home.join("validator.stderr.log");
    let stdout_file = std::fs::File::create(&stdout_log)
        .with_context(|| format!("create {}", stdout_log.display()))?;
    let stderr_file = std::fs::File::create(&stderr_log)
        .with_context(|| format!("create {}", stderr_log.display()))?;

    let mut cmd = Command::new(&bin);
    cmd.env(
        "RUST_LOG",
        std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()),
    )
    .arg("--home")
    .arg(&cfg.home)
    .arg("chain")
    .arg("run-validator")
    .arg("--config")
    .arg(&cfg.config)
    .stdout(Stdio::from(stdout_file))
    .stderr(Stdio::from(stderr_file))
    .kill_on_drop(true);

    let child = cmd
        .spawn()
        .with_context(|| format!("spawn {} chain run-validator", bin.display()))?;

    let wait = async {
        loop {
            if rpc_sock.exists() {
                return Ok::<(), anyhow::Error>(());
            }
            sleep(Duration::from_millis(100)).await;
        }
    };
    timeout(boot_timeout, wait).await.map_err(|_| {
        anyhow!(
            "validator at {} did not produce rpc.sock within timeout",
            cfg.home.display()
        )
    })??;

    Ok(ChainNodeGuard {
        child: Some(child),
        home: cfg.home,
        rpc_sock,
    })
}

/// Provision a `count`-validator local network into `parent` by shelling
/// out to `bloom chain testnet`. The CLI writes per-node
/// `home<i>/chain/{keystore,blocks,state_blobs,genesis.toml,config.toml}`
/// and emits a JSON manifest to stdout, which we parse into
/// [`ChainNodeConfig`]s ready for [`spawn_validator`].
///
/// Synchronous: blocks the calling thread on the CLI subprocess. Test code
/// should invoke this from `tokio::task::spawn_blocking` if it cares about
/// async behaviour.
pub fn provision_network(parent: &Path, count: usize) -> Result<Vec<ChainNodeConfig>> {
    use std::process::Command as StdCommand;

    if count == 0 {
        return Err(anyhow!("provision_network: count must be >= 1"));
    }
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create parent dir {}", parent.display()))?;

    let bin = bloom_bin();
    let out = StdCommand::new(&bin)
        .arg("chain")
        .arg("testnet")
        .arg("--validators")
        .arg(count.to_string())
        .arg("--output-dir")
        .arg(parent)
        .output()
        .with_context(|| format!("invoke {} chain testnet", bin.display()))?;
    if !out.status.success() {
        return Err(anyhow!(
            "bloom chain testnet failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let manifest: serde_json::Value =
        serde_json::from_slice(&out.stdout).context("parse testnet manifest JSON")?;
    let arr = manifest
        .get("validators")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("manifest missing `validators` array"))?;

    let mut cfgs = Vec::with_capacity(arr.len());
    for v in arr {
        let home = v
            .get("home")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("manifest entry missing `home`"))?;
        let home = PathBuf::from(home);
        let config = home.join("chain/config.toml");
        cfgs.push(ChainNodeConfig { home, config });
    }
    Ok(cfgs)
}
