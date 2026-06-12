//! `bloom` — bloom daemon and CLI.
//!
//! For v1, the CLI drives the same in-process daemon — there's no
//! separate long-running server. Each invocation builds the daemon,
//! performs the requested VFS operation, and exits. A `serve` subcommand
//! exists as a placeholder for the eventual long-running NFS-mounted
//! daemon.

#![forbid(unsafe_code)]

mod commands {
    pub mod chain;
    pub mod pipe;
}

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bloom_daemon::Daemon;
use bloom_daemon::ipc::{IpcClient, IpcServer, default_socket_path};
use bloom_proto::HomeDir;
use bloom_vfs::{VfsPath, handler::Handler};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};
use tracing::{debug, info, trace};
use tracing_subscriber::EnvFilter;

use commands::chain::ChainCmd;

#[cfg(target_os = "linux")]
const DEFAULT_MOUNT_PATH: &str = "/bloom";
#[cfg(target_os = "macos")]
const DEFAULT_MOUNT_PATH: &str = "/Volumes/bloom";
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const DEFAULT_MOUNT_PATH: &str = "/bloom";

const ALPHA_DISCLOSURE: &str = "⚠️  Bloom is experimental, unaudited alpha software. Do not use with funds you cannot afford to lose. Review every generated transaction plan before signing.";

#[derive(Parser, Debug)]
#[command(
    name = "bloom",
    version,
    about = "Bloom — an agentic Ethereum wallet as a virtual filesystem",
    long_about = "Bloom mounts an agentic Ethereum wallet as a directory for agents. EXPERIMENTAL / UNAUDITED ALPHA: do not use with funds you cannot afford to lose, and review every generated transaction plan before signing. Read balances, contracts, ENS, prices, and status with cat/ls; stage wallet actions by writing intents into an outbox; confirm only after reviewing the generated plan. New agents should read https://bloom.directory/SKILL.md, then run bloom init and bloom serve --mount ~/bloom. Use bloom vfs only as a fallback when mounting is unavailable."
)]
struct Cli {
    /// Override home directory (default: ~/.bloom).
    #[arg(long, env = "BLOOM_HOME")]
    home: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Show daemon status (chains configured, version, home dir).
    Status,
    /// VFS path operations (no NFS mount required).
    #[command(subcommand)]
    Vfs(VfsCmd),
    /// Wallet management.
    #[command(subcommand)]
    Wallet(WalletCmd),
    /// Run the daemon as a long-lived process.
    Serve {
        /// Mount the VFS for the lifetime of the daemon.
        ///
        /// With no PATH, defaults to /bloom on Linux and /Volumes/bloom on macOS.
        #[arg(
            long,
            value_name = "PATH",
            num_args = 0..=1,
            default_missing_value = DEFAULT_MOUNT_PATH
        )]
        mount: Option<PathBuf>,
    },
    /// Talk to a running `bloom serve` over its UDS JSON-RPC socket.
    #[command(subcommand)]
    Ipc(IpcCmd),
    /// Manage wasm petals: install, run, list, name.
    #[command(subcommand)]
    Petals(PetalsCmd),
    /// Initialise ~/.bloom with default config + dirs.
    Init,
    /// Sovereign bloom-chain: init, run-validator, submit, query.
    #[command(subcommand)]
    Chain(ChainCmd),
    /// Lower a pipe expression into a PTB and stream its receipt (spec §3.5).
    ///
    /// `EXPR` is a pipe expression — linear `A | B | C` (each command's
    /// primary output feeds the next) plus named `--a <(<sub-expr>)>`
    /// DAG inputs. It lowers + validates against the chain via the same
    /// `PtbSession` the NFS `tx`-session front door uses, so a plan piped
    /// here commits identically to one staged over the mount.
    Pipe {
        /// The pipe expression to lower, e.g.
        /// `'/bloom/petals/dex/pool/swap amount=100 --in <(/bloom/wallet/coin)>'`.
        expr: String,
        /// Signer pubkey (32-byte hex). Repeat for a multi-signer tx.
        #[arg(long = "signer", value_name = "HEX")]
        signers: Vec<String>,
        /// Gas-payer object id (32-byte hex `Coin<LOOM>`).
        #[arg(long, value_name = "HEX")]
        gas_payer: String,
    },
    /// Print a shell completion script.
    Completions { shell: Shell },
}

#[derive(Subcommand, Debug)]
enum IpcCmd {
    /// Send a raw JSON-RPC call. `params` is a JSON literal (default: null).
    Call {
        method: String,
        #[arg(long)]
        params: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum VfsCmd {
    /// `cat /bloom/<path>` — read a file via the VFS.
    Cat { path: String },
    /// `ls /bloom/<path>` — list a directory via the VFS.
    Ls {
        #[arg(default_value = "/")]
        path: String,
    },
    /// Write data to a writable VFS path. Reads from stdin if `--data` is omitted.
    Write {
        path: String,
        #[arg(long)]
        data: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum PetalsCmd {
    /// Install a wasm (or WAT) module at `<path>`. Accepts `-` for stdin.
    Install {
        /// Path to a `.wasm` or `.wat` file, or `-` for stdin.
        path: String,
        /// Petname to bind to the resulting hash.
        #[arg(long)]
        name: Option<String>,
        /// Capabilities to grant. Repeat to grant multiple, e.g.
        /// `--cap vfs.read --cap vfs.write`.
        #[arg(long = "cap", value_name = "CAP")]
        caps: Vec<String>,
    },
    /// Run a petal by petname or hash.
    Run {
        /// Petname or 64-char hex hash.
        name_or_hash: String,
        /// File to feed to the petal as stdin (default: empty). `-` means
        /// read from this process's stdin.
        #[arg(long)]
        input: Option<String>,
        /// Restrict capabilities for this run to the listed set
        /// (intersected with the petal's declared caps). Without this
        /// flag, the petal runs with all of its declared caps.
        #[arg(long = "cap", value_name = "CAP")]
        cap_mask: Vec<String>,
    },
    /// List installed petals.
    Ls,
    /// Bind `<name>` to `<hash>`. Omit `<hash>` to remove the binding.
    Name { name: String, hash: Option<String> },
    /// Remove an installed petal (and any petname pointing at it).
    Uninstall {
        /// 64-char hex content hash of the petal to remove.
        hash: String,
    },
}

#[derive(Subcommand, Debug)]
enum WalletCmd {
    /// Create a new wallet. Pass `--passkey` for a browser WebAuthn ceremony;
    /// defaults to passphrase-encrypted local wallet.
    New {
        name: String,
        #[arg(long)]
        passkey: bool,
        #[arg(long, env = "BLOOM_PASSPHRASE")]
        passphrase: Option<String>,
    },
    /// Import a wallet from a hex private key.
    Import {
        name: String,
        private_key: String,
        #[arg(long)]
        passkey: bool,
        #[arg(long, env = "BLOOM_PASSPHRASE")]
        passphrase: Option<String>,
    },
    /// List configured wallets.
    List,
    /// Unlock a wallet for the lifetime of the process.
    /// For passkey wallets the passphrase is not needed — a browser
    /// ceremony is opened instead.
    Unlock {
        name: String,
        #[arg(long, env = "BLOOM_PASSPHRASE")]
        passphrase: Option<String>,
    },
    /// Stage a tx by writing an intent file. Convenience for the
    /// outbox flow.
    Stage {
        wallet: String,
        chain: String,
        /// Intent body (JSON, TOML, or shell-style). If omitted, read
        /// from stdin.
        #[arg(long)]
        intent: Option<String>,
    },
    /// Unlock then broadcast a staged tx in one shot. Required because
    /// the v1 CLI rebuilds the daemon per invocation, so a separate
    /// `unlock` doesn't persist.
    Confirm {
        wallet: String,
        chain: String,
        id: String,
        #[arg(long, env = "BLOOM_PASSPHRASE")]
        passphrase: Option<String>,
        /// Confirmation text (default "y"; "override" bypasses soft
        /// policy warnings).
        #[arg(long, default_value = "y")]
        text: String,
    },
    /// Sign the current policy.toml for a passkey-gated wallet.
    /// The wallet must already be unlocked (run `unlock` first).
    SignPolicy { name: String },
    /// Re-bind an existing PRF-based passkey wallet to a new passkey
    /// credential. Unlocks with the current credential first to prove
    /// ownership, then runs a fresh WebAuthn registration ceremony and
    /// re-encrypts the private key under the new PRF output. The wallet
    /// address does not change.
    ///
    /// Use this to rotate authenticators (e.g. new YubiKey or new device)
    /// without moving funds. A recovery key is printed once after rebind.
    RebindPasskey { name: String },
    /// Permanently delete a wallet. All wallet files are removed from disk.
    /// This cannot be undone — make sure you have the recovery key or the
    /// private key stored elsewhere before deleting a passkey wallet.
    Delete { name: String },
}

/// Print the recovery key to stdout and block until the user types "saved".
///
/// All tracing logs go to stderr; this prints to stdout, so it cannot be
/// buried by ceremony log noise. The loop prevents the terminal from
/// scrolling past the key unnoticed.
fn acknowledge_recovery_key(name: &str, key: &str) {
    use std::io::Write as _;
    let line = "═".repeat(60);
    println!("\n{line}");
    println!("  ⚠  RECOVERY KEY — write this down before continuing.");
    println!("  bloom will NEVER show this again.\n");
    println!("  0x{key}\n");
    println!("  To recover:  bloom wallet import {name} 0x<key>");
    println!("{line}");
    loop {
        print!("\n  Type \"saved\" and press Enter to continue: ");
        let _ = std::io::stdout().flush();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap_or(0);
        if input.trim().eq_ignore_ascii_case("saved") {
            break;
        }
    }
    println!();
}

#[tokio::main]
async fn main() -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();

    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

/// Returns `None` when no daemon socket is present (daemon not started),
/// propagating all other errors normally. A stale socket (file exists but
/// connection refused) is removed and surfaced as an error rather than
/// silently falling back to in-process — a stale socket almost always
/// means the daemon crashed and the caller should restart it explicitly.
async fn try_ipc(
    client: &IpcClient,
    method: &str,
    params: serde_json::Value,
) -> std::io::Result<Option<serde_json::Value>> {
    match client.call(method, params).await {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!(error = %e, "ipc.no_daemon_fallback");
            Ok(None)
        }
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            // Only remove if it is actually a socket, not a regular
            // file or symlink placed by another process.
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                let removed = std::fs::symlink_metadata(client.socket())
                    .is_ok_and(|m| m.file_type().is_socket())
                    && std::fs::remove_file(client.socket()).is_ok();
                let detail = if removed {
                    "stale socket removed"
                } else {
                    "socket not responding"
                };
                Err(std::io::Error::other(format!(
                    "daemon socket exists but is not responding ({detail}); \
                     start the daemon with 'bloom serve'",
                )))
            }
            #[cfg(not(unix))]
            {
                let _ = std::fs::remove_file(client.socket());
                return Err(std::io::Error::other(
                    "daemon socket exists but is not responding (stale socket removed); \
                     start the daemon with 'bloom serve'",
                ));
            }
        }
        Err(e) => Err(e),
    }
}

async fn run(cli: Cli) -> Result<()> {
    let home = match cli.home {
        Some(p) => {
            debug!(path = %p.display(), "cli.home.override");
            HomeDir::at(p)
        }
        None => HomeDir::resolve("~/.bloom").context("resolving home dir")?,
    };
    trace!(cmd = ?cli.cmd, home = %home.root().display(), "cli.dispatch");

    match cli.cmd {
        Cmd::Init => {
            eprintln!("{ALPHA_DISCLOSURE}");
            let d = Daemon::from_home(home.clone()).context("init daemon")?;
            println!("home: {}", d.home.root().display());
            println!("config: {}", d.home.config_path().display());
            println!("chains: {:?}", d.chains.list_names());
            println!("next: mkdir -p ~/bloom && bloom serve --mount ~/bloom");
            println!("then: ls ~/bloom && cat ~/bloom/docs/README.md");
            println!("fallback: bloom vfs cat /docs/README.md");
            println!("agent setup: https://bloom.directory/SKILL.md");
            Ok(())
        }
        Cmd::Status => {
            let d = Daemon::from_home(home).context("build daemon")?;
            println!("version: {}", env!("CARGO_PKG_VERSION"));
            println!("home: {}", d.home.root().display());
            println!("chains: {:?}", d.chains.list_names());
            println!("default_chain: {}", d.config.default_chain);
            println!(
                "block_mainnet_broadcast: {}",
                d.config.block_mainnet_broadcast
            );
            println!("try: bloom vfs ls /");
            println!("wallet: bloom wallet new alice --passphrase <passphrase>");
            Ok(())
        }
        Cmd::Vfs(VfsCmd::Cat { path }) => {
            let socket = default_socket_path(home.root());
            let p = VfsPath::parse(&path).context("parse path")?;
            let client = IpcClient::new(&socket);
            let ipc_res = try_ipc(&client, "read", serde_json::json!({ "path": path }))
                .await
                .context("ipc read")?;
            let bytes = if let Some(res) = ipc_res {
                debug!(socket = %socket.display(), "cli.vfs.cat.via_ipc");
                let b64 = res
                    .get("bytes_b64")
                    .and_then(|v| v.as_str())
                    .context("ipc read: missing bytes_b64")?;
                B64.decode(b64).context("ipc read: bad base64")?
            } else {
                debug!("cli.vfs.cat.via_inproc: no daemon socket present");
                let d = Daemon::from_home(home).context("build daemon")?;
                d.vfs.read(&p).await.context("vfs read")?
            };
            std::io::Write::write_all(&mut std::io::stdout(), &bytes)?;
            Ok(())
        }
        Cmd::Vfs(VfsCmd::Ls { path }) => {
            let socket = default_socket_path(home.root());
            let p = VfsPath::parse(&path).context("parse path")?;
            let client = IpcClient::new(&socket);
            let ipc_res = try_ipc(&client, "list", serde_json::json!({ "path": path }))
                .await
                .context("ipc list")?;
            if let Some(res) = ipc_res {
                debug!(socket = %socket.display(), "cli.vfs.ls.via_ipc");
                let arr = res.as_array().context("ipc list: expected array")?;
                for e in arr {
                    let name = e.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                    let kind = match e.get("kind").and_then(|v| v.as_str()).unwrap_or("file") {
                        "dir" => "Dir",
                        "symlink" => "Symlink",
                        _ => "File",
                    };
                    println!("{}\t{}", name, kind);
                }
            } else {
                debug!("cli.vfs.ls.via_inproc: no daemon socket present");
                let d = Daemon::from_home(home).context("build daemon")?;
                let entries = d.vfs.list(&p).await.context("vfs list")?;
                for e in entries {
                    println!("{}\t{:?}", e.name, e.kind);
                }
            }
            Ok(())
        }
        Cmd::Vfs(VfsCmd::Write { path, data }) => {
            let socket = default_socket_path(home.root());
            let p = VfsPath::parse(&path).context("parse path")?;
            let body = match data {
                Some(s) => s.into_bytes(),
                None => {
                    let mut buf = Vec::new();
                    std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)?;
                    buf
                }
            };
            let client = IpcClient::new(&socket);
            let ipc_res = try_ipc(
                &client,
                "write",
                serde_json::json!({ "path": path, "bytes_b64": B64.encode(&body) }),
            )
            .await
            .context("ipc write")?;
            if ipc_res.is_some() {
                debug!(socket = %socket.display(), "cli.vfs.write.via_ipc");
            } else {
                debug!("cli.vfs.write.via_inproc: no daemon socket present");
                let d = Daemon::from_home(home).context("build daemon")?;
                d.vfs.write(&p, &body).await.context("vfs write")?;
            }
            Ok(())
        }
        Cmd::Wallet(WalletCmd::New {
            name,
            passkey,
            passphrase,
        }) => {
            let d = Daemon::from_home(home).context("build daemon")?;
            let info = if passkey {
                d.keystore.create_passkey(&name).await?
            } else {
                let pass = passphrase.as_deref().unwrap_or("");
                if pass.is_empty() {
                    anyhow::bail!("passphrase required (use --passphrase or BLOOM_PASSPHRASE)");
                }
                d.keystore.create_local(&name, pass)?
            };
            println!("created wallet '{}': {}", info.name, info.address);
            if let Some(ref key) = info.recovery_key {
                acknowledge_recovery_key(&info.name, key);
            }
            Ok(())
        }
        Cmd::Wallet(WalletCmd::Import {
            name,
            private_key,
            passkey,
            passphrase,
        }) => {
            let d = Daemon::from_home(home).context("build daemon")?;
            let info = if passkey {
                d.keystore.import_passkey(&name, &private_key).await?
            } else {
                let pass = passphrase.as_deref().unwrap_or("");
                if pass.is_empty() {
                    anyhow::bail!("passphrase required (use --passphrase or BLOOM_PASSPHRASE)");
                }
                d.keystore.import_hex(&name, &private_key, pass)?
            };
            println!("imported wallet '{}': {}", info.name, info.address);
            if let Some(ref key) = info.recovery_key {
                acknowledge_recovery_key(&info.name, key);
            }
            Ok(())
        }
        Cmd::Wallet(WalletCmd::List) => {
            let d = Daemon::from_home(home).context("build daemon")?;
            for info in d.keystore.list()? {
                let kind = match info.kind {
                    bloom_keystore::WalletKind::Local => "local",
                    bloom_keystore::WalletKind::Watch => "watch",
                    bloom_keystore::WalletKind::PasskeyGated => "passkey",
                };
                println!("{}\t{}\t{}", info.name, info.address, kind);
            }
            Ok(())
        }
        Cmd::Wallet(WalletCmd::Unlock { name, passphrase }) => {
            let d = Daemon::from_home(home).context("build daemon")?;
            let info = d.keystore.info(&name)?;
            match info.kind {
                bloom_keystore::WalletKind::PasskeyGated => {
                    d.keystore.unlock_passkey(&name).await?;
                }
                _ => {
                    d.keystore
                        .unlock(&name, passphrase.as_deref().unwrap_or(""))?;
                }
            }
            println!("unlocked '{}' (in-memory; ends with this process)", name);
            Ok(())
        }
        Cmd::Wallet(WalletCmd::SignPolicy { name }) => {
            let d = Daemon::from_home(home).context("build daemon")?;
            // Auto-unlock passkey wallets so this command is self-contained.
            let info = d.keystore.info(&name)?;
            // Show the policy the user is about to sign, in the terminal,
            // before the browser ceremony opens.
            let policy_toml = toml::to_string_pretty(&info.policy)
                .unwrap_or_else(|_| "(could not serialise policy)".into());
            println!("Policy for '{name}':\n\n{policy_toml}");
            if info.kind == bloom_keystore::WalletKind::PasskeyGated
                && !d.keystore.is_unlocked(&name)
            {
                d.keystore.unlock_passkey(&name).await?;
            }
            d.keystore.sign_policy(&name)?;
            println!("policy.toml signed for '{name}'");
            Ok(())
        }
        Cmd::Wallet(WalletCmd::RebindPasskey { name }) => {
            let d = Daemon::from_home(home).context("build daemon")?;
            let info = d.keystore.rebind_passkey(&name).await?;
            println!(
                "✓ '{}' rebound to new passkey credential ({})",
                info.name, info.address
            );
            if let Some(ref key) = info.recovery_key {
                acknowledge_recovery_key(&info.name, key);
            }
            Ok(())
        }
        Cmd::Wallet(WalletCmd::Delete { name }) => {
            let d = Daemon::from_home(home).context("build daemon")?;
            d.keystore.delete(&name)?;
            println!("✓ wallet '{name}' deleted");
            Ok(())
        }
        Cmd::Wallet(WalletCmd::Stage {
            wallet,
            chain,
            intent,
        }) => {
            let d = Daemon::from_home(home).context("build daemon")?;
            let body = match intent {
                Some(s) => s,
                None => {
                    let mut buf = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
                    buf
                }
            };
            let parsed = bloom_tx::intent_parser::parse(&body).context("parse intent")?;
            let info = d.keystore.info(&wallet)?;
            let client = d
                .chains
                .get(&chain)
                .with_context(|| format!("chain '{}'", chain))?;
            let staged = d
                .tx_engine
                .stage(
                    &wallet,
                    info.address,
                    parsed,
                    &client,
                    &info.policy,
                    Some(&d.address_book),
                )
                .await?;
            println!("{}", staged.id);
            Ok(())
        }
        Cmd::Wallet(WalletCmd::Confirm {
            wallet,
            chain,
            id,
            passphrase,
            text,
        }) => {
            let d = Daemon::from_home(home).context("build daemon")?;
            let info = d.keystore.info(&wallet)?;
            match info.kind {
                bloom_keystore::WalletKind::PasskeyGated => {
                    d.keystore.unlock_passkey(&wallet).await?;
                }
                _ => {
                    d.keystore
                        .unlock(&wallet, passphrase.as_deref().unwrap_or(""))?;
                }
            }
            let signer = d.keystore.signer(&wallet)?;
            let info = d.keystore.info(&wallet)?;
            let client = d
                .chains
                .get(&chain)
                .with_context(|| format!("chain '{}'", chain))?;
            let staged = d
                .tx_engine
                .confirm(&wallet, &chain, &id, &client, &signer, &info.policy, &text)
                .await?;
            println!(
                "broadcast {} hash={}",
                staged.id,
                staged.tx_hash.as_deref().unwrap_or("?")
            );
            Ok(())
        }
        Cmd::Serve { mount } => {
            eprintln!("{ALPHA_DISCLOSURE}");
            let d = Daemon::from_home(home).context("build daemon")?;
            // Spawn the outbox expiry sweeper for the lifetime of the
            // serve command (fix #3). The handle is dropped (and the task
            // signalled to stop) right before the function returns.
            let sweeper = d.spawn_background_tasks();
            let mount_handle = mount_bloom(&d, mount.as_deref()).await?;
            let chains: Vec<String> = d.chains.list_names();
            println!(
                "bloom serve: home={} chains={:?}",
                d.home.root().display(),
                chains
            );
            if let Some(mount_path) = mount.as_deref() {
                println!("mount: {}", mount_path.display());
            }
            let socket = default_socket_path(d.home.root());
            println!("ipc socket: {}", socket.display());
            info!(home = %d.home.root().display(), chains = ?chains, socket = %socket.display(), mount = ?mount, "cli.serve.starting");
            let server = IpcServer::new(d.vfs.clone(), env!("CARGO_PKG_VERSION"), chains)
                .with_petals(d.petals.clone());
            let server2 = server.clone();
            // Trigger graceful shutdown on Ctrl-C or SIGTERM.
            let shutdown = tokio::spawn(async move {
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{SignalKind, signal};
                    let mut sigterm = signal(SignalKind::terminate())
                        .expect("SIGTERM handler registration failed");
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => info!("cli.serve.ctrl_c_received"),
                        _ = sigterm.recv() => info!("cli.serve.sigterm_received"),
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = tokio::signal::ctrl_c().await;
                    info!("cli.serve.ctrl_c_received");
                }
                server2.trigger_shutdown();
            });
            let serve_result = server.serve(&socket).await.context("ipc serve");
            shutdown.abort();
            // Stop the outbox expiry sweeper (fix #3) and any other
            // daemon-owned workers (watch executor, etc., fix #6).
            let unmount_result = unmount_bloom(mount_handle).await;
            sweeper.shutdown().await;
            d.shutdown().await;
            serve_result?;
            unmount_result?;
            info!("cli.serve.shutdown_complete");
            println!("shutting down");
            Ok(())
        }
        Cmd::Petals(cmd) => run_petals(home, cmd).await,
        Cmd::Chain(cmd) => commands::chain::run_chain(&home, cmd).await,
        Cmd::Pipe {
            expr,
            signers,
            gas_payer,
        } => {
            let rpc_sock = home.root().join("chain").join("rpc.sock");
            let chain_dir = home.root().join("chain");
            commands::pipe::run(&rpc_sock, &chain_dir, &expr, &signers, &gas_payer).await
        }
        Cmd::Completions { shell } => {
            generate(shell, &mut Cli::command(), "bloom", &mut std::io::stdout());
            Ok(())
        }
        Cmd::Ipc(IpcCmd::Call { method, params }) => {
            let socket = default_socket_path(home.root());
            if !socket.exists() {
                debug!(socket = %socket.display(), "cli.ipc.call.no_socket: daemon may not be running");
            }
            let client = IpcClient::new(&socket);
            let v: serde_json::Value = match params {
                Some(s) => serde_json::from_str(&s).context("parse params JSON")?,
                None => serde_json::Value::Null,
            };
            debug!(%method, socket = %socket.display(), "cli.ipc.call");
            let result = client
                .call(&method, v)
                .await
                .with_context(|| format!("ipc call to {}", socket.display()))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
    }
}

async fn run_petals(home: HomeDir, cmd: PetalsCmd) -> Result<()> {
    use std::collections::BTreeSet;
    use std::io::Read;

    use bloom_petals::{Capability, RunOptions, VfsHost};

    let d = Daemon::from_home(home).context("build daemon")?;
    let vfs_arc = std::sync::Arc::new(d.vfs.clone());

    match cmd {
        PetalsCmd::Install { path, name, caps } => {
            let bytes = if path == "-" {
                let mut buf = Vec::new();
                std::io::stdin()
                    .read_to_end(&mut buf)
                    .context("read stdin")?;
                buf
            } else {
                std::fs::read(&path).with_context(|| format!("read {path}"))?
            };
            let mut cap_set: BTreeSet<Capability> = BTreeSet::new();
            for c in &caps {
                let cap = Capability::parse(c)
                    .ok_or_else(|| anyhow::anyhow!("unknown capability: {c:?}"))?;
                cap_set.insert(cap);
            }
            let (result, meta) = d
                .petals
                .install(
                    &bytes,
                    name.as_deref(),
                    &cap_set,
                    bloom_petals::PetalMode::Local,
                )
                .context("install petal")?;
            println!("hash: {}", result.hash);
            println!("mode: {}", meta.mode.as_str());
            println!("size: {} bytes", result.size);
            if result.already_present {
                println!("note: already installed (caps unioned with existing)");
            }
            if let Some(n) = &meta.name {
                println!("name: {n}");
            }
            if !meta.caps.is_empty() {
                let cs: Vec<&str> = meta.caps.iter().map(|c| c.as_str()).collect();
                println!("caps: {}", cs.join(", "));
            }
            Ok(())
        }
        PetalsCmd::Run {
            name_or_hash,
            input,
            cap_mask,
        } => {
            let stdin = match input.as_deref() {
                Some("-") => {
                    let mut buf = Vec::new();
                    std::io::stdin()
                        .read_to_end(&mut buf)
                        .context("read stdin")?;
                    buf
                }
                Some(p) => std::fs::read(p).with_context(|| format!("read {p}"))?,
                None => Vec::new(),
            };
            let cap_mask = if cap_mask.is_empty() {
                None
            } else {
                let mut s: BTreeSet<Capability> = BTreeSet::new();
                for c in &cap_mask {
                    let cap = Capability::parse(c)
                        .ok_or_else(|| anyhow::anyhow!("unknown capability: {c:?}"))?;
                    s.insert(cap);
                }
                Some(s)
            };
            let host = std::sync::Arc::new(VfsHost::new(vfs_arc.clone()));
            let out = d
                .petals
                .run(&name_or_hash, stdin, host, cap_mask, RunOptions::default())
                .await
                .context("run petal")?;
            use std::io::Write;
            // Stream stdout/stderr to the user verbatim so they can pipe
            // a petal's output. Exit code goes to the parent process.
            std::io::stdout().write_all(&out.stdout).ok();
            std::io::stderr().write_all(&out.stderr).ok();
            if out.exit_code != 0 {
                anyhow::bail!("petal exited with code {}", out.exit_code);
            }
            Ok(())
        }
        PetalsCmd::Ls => {
            let names = d.petals.registry().snapshot();
            let mut name_for_hash: std::collections::BTreeMap<String, String> = Default::default();
            for (n, h) in &names {
                name_for_hash.entry(h.clone()).or_insert(n.clone());
            }
            let hashes = d.petals.store().list_hashes().context("list petals")?;
            if hashes.is_empty() {
                println!("(no petals installed)");
                return Ok(());
            }
            for h in hashes {
                let meta = d.petals.store().load_meta(&h).context("load meta")?;
                let n = name_for_hash.get(&h).map(String::as_str).unwrap_or("-");
                let caps: Vec<&str> = meta.caps.iter().map(|c| c.as_str()).collect();
                println!(
                    "{}  {:<7}  {:>7}  caps=[{}]  name={}",
                    &meta.hash[..12],
                    meta.mode.as_str(),
                    meta.size,
                    caps.join(","),
                    n
                );
            }
            Ok(())
        }
        PetalsCmd::Name { name, hash } => match hash {
            Some(h) => {
                d.petals
                    .registry()
                    .set(&name, &h)
                    .with_context(|| format!("bind name {name} -> {h}"))?;
                println!("bound {name} -> {h}");
                Ok(())
            }
            None => {
                let removed = d
                    .petals
                    .registry()
                    .unset(&name)
                    .with_context(|| format!("unset name {name}"))?;
                if removed {
                    println!("removed name {name}");
                } else {
                    println!("name {name} was not bound");
                }
                Ok(())
            }
        },
        PetalsCmd::Uninstall { hash } => {
            let removed = d.petals.uninstall(&hash).context("uninstall petal")?;
            if removed {
                println!("removed {hash}");
            } else {
                println!("not installed: {hash}");
            }
            Ok(())
        }
    }
}

#[cfg(feature = "mount")]
async fn mount_bloom(
    daemon: &Daemon,
    mount: Option<&std::path::Path>,
) -> Result<Option<bloom_mount::NfsMountHandle>> {
    match mount {
        Some(path) => daemon
            .mount(path)
            .await
            .map(Some)
            .with_context(|| format!("mount bloom vfs at {}", path.display())),
        None => Ok(None),
    }
}

#[cfg(not(feature = "mount"))]
async fn mount_bloom(daemon: &Daemon, mount: Option<&std::path::Path>) -> Result<Option<()>> {
    let _ = daemon;
    match mount {
        Some(path) => anyhow::bail!(
            "mount support is not enabled in this build; rebuild with --features mount (release binaries are built with --all-features): {}",
            path.display()
        ),
        None => Ok(None),
    }
}

#[cfg(feature = "mount")]
async fn unmount_bloom(handle: Option<bloom_mount::NfsMountHandle>) -> Result<()> {
    if let Some(handle) = handle {
        bloom_mount::MountHandle::unmount(&handle)
            .await
            .context("unmount bloom vfs")?;
    }
    Ok(())
}

#[cfg(not(feature = "mount"))]
async fn unmount_bloom(handle: Option<()>) -> Result<()> {
    let _ = handle;
    Ok(())
}
