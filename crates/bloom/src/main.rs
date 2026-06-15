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
    pub mod polymarket;
}

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bloom_daemon::Daemon;
use bloom_daemon::ipc::{IpcClient, IpcServer, default_socket_path};
use bloom_proto::{CeremonyIntent, CeremonyIntentKind, HomeDir, HomeWritePermit};
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum EndpointSource {
    Default,
    Explicit,
}

#[derive(Debug, Clone)]
struct ResolvedEndpoint {
    socket: PathBuf,
    source: EndpointSource,
    display: String,
}

impl ResolvedEndpoint {
    fn default_for_home(home: &HomeDir) -> Self {
        let socket = default_socket_path(home.root());
        Self {
            display: format!("unix:{}", socket.display()),
            socket,
            source: EndpointSource::Default,
        }
    }

    fn explicit(raw: &str) -> Result<Self> {
        let path = parse_unix_endpoint(raw)?;
        Ok(Self {
            display: format!("unix:{}", path.display()),
            socket: path,
            source: EndpointSource::Explicit,
        })
    }

    fn explicit_socket(path: PathBuf) -> Self {
        Self {
            display: format!("unix:{}", path.display()),
            socket: path,
            source: EndpointSource::Explicit,
        }
    }

    fn is_explicit(&self) -> bool {
        matches!(self.source, EndpointSource::Explicit)
    }
}

fn parse_unix_endpoint(raw: &str) -> Result<PathBuf> {
    if let Some(rest) = raw.strip_prefix("unix:") {
        if rest.is_empty() {
            anyhow::bail!("empty unix endpoint path");
        }
        Ok(PathBuf::from(rest))
    } else if raw.starts_with("tcp:") || raw.starts_with("fd:") || raw == "stdio" {
        anyhow::bail!("unsupported Bloom endpoint '{raw}' (only unix:/path is implemented)");
    } else {
        Ok(PathBuf::from(raw))
    }
}

fn resolve_client_endpoint(
    home: &HomeDir,
    connect: Option<&str>,
    ipc_socket: Option<&Path>,
) -> Result<ResolvedEndpoint> {
    if let Some(raw) = connect {
        return ResolvedEndpoint::explicit(raw);
    }
    if let Some(path) = ipc_socket {
        return Ok(ResolvedEndpoint::explicit_socket(path.to_path_buf()));
    }
    Ok(ResolvedEndpoint::default_for_home(home))
}

fn resolve_server_endpoint(home: &HomeDir, endpoint: Option<&str>) -> Result<ResolvedEndpoint> {
    if let Some(raw) = endpoint {
        return ResolvedEndpoint::explicit(raw);
    }
    Ok(ResolvedEndpoint::default_for_home(home))
}

fn build_write_daemon(home: HomeDir) -> Result<(Arc<HomeWritePermit>, Daemon)> {
    let permit = Arc::new(HomeWritePermit::acquire(&home)?);
    let daemon = Daemon::from_home_with_permit(home, permit.clone()).context("build daemon")?;
    Ok((permit, daemon))
}

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

    /// Connect to an explicit Bloom IPC endpoint.
    ///
    /// Currently only Unix socket endpoints are supported:
    /// `unix:/path/to/bloom.sock`. A bare path is accepted as a
    /// compatibility shorthand.
    #[arg(long, value_name = "ENDPOINT")]
    connect: Option<String>,

    /// Compatibility alias for `--connect unix:<path>`.
    #[arg(long, value_name = "PATH")]
    ipc_socket: Option<PathBuf>,

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
        /// IPC endpoint to bind.
        ///
        /// Currently only Unix socket endpoints are supported:
        /// `unix:/path/to/bloom.sock`. A bare path is accepted as a
        /// compatibility shorthand.
        #[arg(long, value_name = "ENDPOINT")]
        endpoint: Option<String>,

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
    /// Polymarket: onboard a wallet.
    #[command(subcommand)]
    Polymarket(PolymarketCmd),
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
        /// Unlock this wallet and run the write in an in-process daemon — the
        /// signing key must be unlocked in the same process that signs.
        /// Required for VFS writes whose handler signs, such as Polymarket
        /// onboarding. NOTE: this BYPASSES any running `bloom serve` daemon and
        /// its IPC; without this flag, writes route over IPC to that daemon.
        /// For passkey wallets it must run in the FOREGROUND — it opens a
        /// WebAuthn ceremony; backgrounding it will hang.
        #[arg(long)]
        unlock_wallet: Option<String>,
        /// Passphrase for `--unlock-wallet` local wallets. Passkey wallets
        /// ignore this and open a WebAuthn ceremony instead.
        #[arg(long, env = "BLOOM_PASSPHRASE")]
        passphrase: Option<String>,
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
enum PolymarketCmd {
    /// Run the Polymarket onboarding state machine for a wallet. Blocks
    /// until completion or a pause point. With --target-pusd the fund stage
    /// is satisfied automatically (one swap, at most once per invocation).
    Onboard {
        wallet: String,
        /// Auto-fund: swap native into pUSD until the funding address holds
        /// this much (decimal). Requires --max-spend.
        #[arg(long)]
        target_pusd: Option<String>,
        /// Input-spend bound for the auto-funding swap, in native units.
        #[arg(long)]
        max_spend: Option<String>,
        /// Route slippage bound in basis points (default 50 = 0.5%).
        #[arg(long, default_value_t = 50)]
        slippage_bps: u16,
        /// Acknowledge EVM policy warnings on the funding transactions.
        #[arg(long)]
        confirm_risk: bool,
        /// Passphrase for local wallets (passkey wallets ignore this).
        #[arg(long, env = "BLOOM_PASSPHRASE", hide = true)]
        passphrase: Option<String>,
    },
    /// Buy into a market. Default is a marketable limit (FAK: fills at or
    /// under --max-price, never rests). Pass --limit-price for an explicit
    /// resting limit order (GTC). Creates a durable, reviewable draft first;
    /// --dry-run stops there.
    Order {
        wallet: String,
        /// Market slug (e.g. "fifwc-arg-alg-2026-06-16-arg").
        slug: String,
        /// YES or NO.
        outcome: String,
        /// pUSD amount to spend, decimal (e.g. "10" = $10).
        amount: String,
        /// Refuse rather than pay more than this per share (decimal).
        #[arg(long)]
        max_price: Option<String>,
        /// Place a resting limit at exactly this price instead of a
        /// marketable order (defaults the order type to GTC).
        #[arg(long)]
        limit_price: Option<String>,
        /// FAK | FOK | GTC (default: FAK marketable, GTC with --limit-price).
        #[arg(long)]
        order_type: Option<String>,
        /// Build and persist the reviewable draft, then exit before any
        /// signature.
        #[arg(long)]
        dry_run: bool,
        /// Acknowledge policy warnings (require_flag_above_usd). Deny-level
        /// policy can never be bypassed from the command line.
        #[arg(long)]
        confirm_risk: bool,
        #[arg(long, env = "BLOOM_PASSPHRASE", hide = true)]
        passphrase: Option<String>,
    },
    /// Revalidate and execute a previously created draft (see --dry-run).
    Confirm {
        wallet: String,
        /// Draft id (e.g. "0001").
        draft_id: String,
        #[arg(long)]
        confirm_risk: bool,
        #[arg(long, env = "BLOOM_PASSPHRASE", hide = true)]
        passphrase: Option<String>,
    },
    /// Sell shares of a position (sell-to-close). Risk-reducing: refused only
    /// on an affirmative geoblock, not on a geoblock outage. Verifies current
    /// holdings cover the sale before signing.
    Sell {
        wallet: String,
        slug: String,
        /// YES or NO.
        outcome: String,
        /// Share count to sell, decimal (e.g. "14.38").
        shares: String,
        /// Refuse rather than receive less than this per share (decimal).
        #[arg(long)]
        min_price: Option<String>,
        /// Place a resting limit at exactly this price (GTC).
        #[arg(long)]
        limit_price: Option<String>,
        #[arg(long)]
        order_type: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        confirm_risk: bool,
        #[arg(long, env = "BLOOM_PASSPHRASE", hide = true)]
        passphrase: Option<String>,
    },
    /// Cancel a resting Polymarket order. Cancellation is risk-reducing and
    /// is never blocked by the geoblock gate (a warning is printed instead).
    /// Needs no wallet unlock — CLOB credentials are enough.
    Cancel {
        wallet: String,
        /// CLOB order id (from the post response or account orders.json).
        order_id: String,
    },
    /// Show open Polymarket positions and required exit actions. Read-only;
    /// useful for cold-start agents and operational reminders.
    Obligations { wallet: String },
    /// Redeem a resolved position back to pUSD through the deposit wallet.
    /// Refuses before the passkey ceremony unless the Data API marks the
    /// matching position redeemable.
    Redeem {
        wallet: String,
        /// Market slug to redeem.
        slug: String,
        /// Preflight the redeem call and print the plan without unlocking or submitting.
        #[arg(long)]
        dry_run: bool,
        #[arg(long, env = "BLOOM_PASSPHRASE", hide = true)]
        passphrase: Option<String>,
    },
    /// Revoke the pUSD/CTF spending approvals onboarding granted to the four V2
    /// contracts (the inverse of onboarding's approve stage). Withdraws the
    /// trading contracts' authority over the deposit wallet's collateral and
    /// positions; trading needs re-onboarding afterward.
    RevokeApprovals {
        wallet: String,
        /// Print the plan without unlocking or submitting.
        #[arg(long)]
        dry_run: bool,
        #[arg(long, env = "BLOOM_PASSPHRASE", hide = true)]
        passphrase: Option<String>,
    },
    /// Transfer pUSD out of the Polymarket deposit wallet to the owner EOA.
    WithdrawPusd {
        wallet: String,
        /// Amount of pUSD to withdraw, or "all".
        amount: String,
        /// Print the plan without unlocking or submitting.
        #[arg(long)]
        dry_run: bool,
        #[arg(long, env = "BLOOM_PASSPHRASE", hide = true)]
        passphrase: Option<String>,
    },
    /// Swap into pUSD until the Polymarket funding address holds the target
    /// amount. Target-denominated: --target-pusd 50 means "end with at least
    /// 50 pUSD", never "spend 50 of the input token". Input spend is bounded
    /// by --max-spend. Goes through the standard tx engine (EVM policy, plan,
    /// outbox audit, allow_broadcast).
    Fund {
        wallet: String,
        /// Desired pUSD balance at the funding address (decimal). Required
        /// unless --request is given.
        #[arg(long, required_unless_present = "request")]
        target_pusd: Option<String>,
        /// Hard cap on input spend, in input-token units (decimal). Required
        /// unless --request is given.
        #[arg(long, required_unless_present = "request")]
        max_spend: Option<String>,
        /// Input token: "native" (default; POL on Polygon) or an 0x… ERC-20
        /// address on the settlement chain.
        #[arg(long)]
        from_token: Option<String>,
        /// Route slippage bound in basis points (default 50 = 0.5%).
        #[arg(long, default_value_t = 50)]
        slippage_bps: u16,
        /// Execute a fund request staged via the VFS (`polymarket/fund/<wallet>/new`):
        /// sources target/max-spend/from-token/slippage from the stored request,
        /// re-reading live balances + quotes at execute time. Conflicts with the
        /// individual flags above.
        #[arg(long, conflicts_with_all = ["target_pusd", "max_spend", "from_token"])]
        request: Option<String>,
        /// Stage the swap into the outbox and stop before any signature.
        #[arg(long)]
        dry_run: bool,
        /// Acknowledge EVM policy warnings on the staged transactions.
        #[arg(long)]
        confirm_risk: bool,
        #[arg(long, env = "BLOOM_PASSPHRASE", hide = true)]
        passphrase: Option<String>,
    },
    /// Manage builder API keys (relayer submission auth, auto-created from
    /// CLOB credentials; never wallet authority).
    #[command(subcommand)]
    BuilderKeys(BuilderKeysCmd),
}

#[derive(Subcommand, Debug)]
enum BuilderKeysCmd {
    /// List builder API keys on the account (key ids only; no secrets).
    List { wallet: String },
    /// Revoke a builder API key. With no KEY, uses the official client's
    /// no-body form. Bloom's stored creds are deleted when they match.
    Revoke { wallet: String, key: Option<String> },
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
    endpoint: &ResolvedEndpoint,
    method: &str,
    params: serde_json::Value,
) -> std::io::Result<Option<serde_json::Value>> {
    match client.call(method, params).await {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if endpoint.is_explicit() {
                return Err(std::io::Error::new(
                    e.kind(),
                    format!(
                        "explicit Bloom endpoint {} is not available: {e}",
                        endpoint.display
                    ),
                ));
            }
            debug!(error = %e, "ipc.no_daemon_fallback");
            Ok(None)
        }
        Err(e) if is_endpoint_permission_denial(&e) => {
            if endpoint.is_explicit() {
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("explicit Bloom endpoint {} failed: {e}", endpoint.display),
                ));
            }
            debug!(endpoint = %endpoint.display, error = %e, "ipc.permission_fallback");
            Ok(None)
        }
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            if endpoint.is_explicit() {
                return Err(std::io::Error::new(
                    e.kind(),
                    format!(
                        "explicit Bloom endpoint {} is not responding: {e}",
                        endpoint.display
                    ),
                ));
            }
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

fn is_endpoint_permission_denial(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1)
}

async fn run(cli: Cli) -> Result<()> {
    let (connect, ipc_socket) = if cli.connect.is_some() {
        (cli.connect, None)
    } else if cli.ipc_socket.is_some() {
        (None, cli.ipc_socket)
    } else if let Ok(endpoint) = std::env::var("BLOOM_RPC_ENDPOINT") {
        (Some(endpoint), None)
    } else {
        (
            None,
            std::env::var_os("BLOOM_IPC_SOCKET").map(PathBuf::from),
        )
    };
    let home = match cli.home {
        Some(p) => {
            debug!(path = %p.display(), "cli.home.override");
            HomeDir::at(p)
        }
        None => HomeDir::resolve("~/.bloom").context("resolving home dir")?,
    };
    let client_endpoint = resolve_client_endpoint(&home, connect.as_deref(), ipc_socket.as_deref())
        .context("resolve Bloom endpoint")?;
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
            let p = VfsPath::parse(&path).context("parse path")?;
            let client = IpcClient::new(&client_endpoint.socket);
            let ipc_res = try_ipc(
                &client,
                &client_endpoint,
                "read",
                serde_json::json!({ "path": path }),
            )
            .await
            .with_context(|| format!("ipc read via {}", client_endpoint.display))?;
            let bytes = if let Some(res) = ipc_res {
                debug!(endpoint = %client_endpoint.display, "cli.vfs.cat.via_ipc");
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
            let p = VfsPath::parse(&path).context("parse path")?;
            let client = IpcClient::new(&client_endpoint.socket);
            let ipc_res = try_ipc(
                &client,
                &client_endpoint,
                "list",
                serde_json::json!({ "path": path }),
            )
            .await
            .with_context(|| format!("ipc list via {}", client_endpoint.display))?;
            if let Some(res) = ipc_res {
                debug!(endpoint = %client_endpoint.display, "cli.vfs.ls.via_ipc");
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
        Cmd::Vfs(VfsCmd::Write {
            path,
            data,
            unlock_wallet,
            passphrase,
        }) => {
            let p = VfsPath::parse(&path).context("parse path")?;
            let mut body = match data {
                Some(s) => s.into_bytes(),
                None => {
                    let mut buf = Vec::new();
                    std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)?;
                    buf
                }
            };
            if let Some(wallet) = unlock_wallet {
                let client = IpcClient::new(&client_endpoint.socket);
                let ipc_res = try_ipc(
                    &client,
                    &client_endpoint,
                    "write_unlocked",
                    serde_json::json!({
                        "path": path,
                        "bytes_b64": B64.encode(&body),
                        "wallet": &wallet,
                        "passphrase": passphrase.as_deref(),
                    }),
                )
                .await
                .with_context(|| format!("ipc unlocked write via {}", client_endpoint.display))?;
                if ipc_res.is_some() {
                    debug!(endpoint = %client_endpoint.display, "cli.vfs.write_unlocked.via_ipc");
                    return Ok(());
                }

                debug!("cli.vfs.write.via_inproc: unlock requested and no daemon socket present");
                let (_home_permit, d) = build_write_daemon(home)?;
                let info = d.keystore.info(&wallet)?;
                match info.kind {
                    bloom_keystore::WalletKind::PasskeyGated => {
                        let intent = vfs_write_unlock_intent(
                            &wallet,
                            &p,
                            &body,
                            Some(bloom_proto::checksum_address(&info.address)),
                            Some(&d.home.outbox_dir()),
                        );
                        let reviewed_intent_hash = intent.intent_hash();
                        persist_outbox_review_intent(&wallet, &p, &d.home.outbox_dir(), &intent)?;
                        let editable_policy = if is_wallet_policy_write(&wallet, &p) {
                            Some(String::from_utf8_lossy(&body).to_string())
                        } else {
                            None
                        };
                        let edited_policy = d
                            .keystore
                            .unlock_passkey_with_intent_and_policy_edit(
                                &wallet,
                                Some(intent),
                                editable_policy,
                            )
                            .await?;
                        if let Some(policy) = edited_policy {
                            body = policy.into_bytes();
                        } else if is_outbox_confirm_write(&wallet, &p) {
                            persist_outbox_review_approved(
                                &wallet,
                                &p,
                                &d.home.outbox_dir(),
                                &reviewed_intent_hash,
                            )?;
                            body.extend_from_slice(
                                format!("\nreview_hash={reviewed_intent_hash}").as_bytes(),
                            );
                        }
                    }
                    _ => {
                        d.keystore
                            .unlock(&wallet, passphrase.as_deref().unwrap_or(""))?;
                    }
                }
                d.vfs.write(&p, &body).await.context("vfs write")?;

                // If this is a polymarket `begin` write, the handler spawned a background
                // task. In in-process mode we must poll until the task reaches a stable
                // stage, else the process exits and kills the task.
                let segs = p.segments();
                if segs.len() == 4
                    && segs[0] == "polymarket"
                    && segs[1] == "onboard"
                    && segs[3] == "begin"
                {
                    let wallet_name = segs[2].clone();
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        let status_path = VfsPath::parse(&format!(
                            "polymarket/onboard/{wallet_name}/status.json"
                        ))
                        .context("parse status path")?;
                        if let Ok(bytes) = d.vfs.read(&status_path).await
                            && let Ok(st) = serde_json::from_slice::<serde_json::Value>(&bytes)
                        {
                            let stage = st["stage"].as_str().unwrap_or("unknown");
                            info!(stage, "polymarket.onboard.stage");
                            if matches!(stage, "complete" | "fund") || st["last_error"].is_string()
                            {
                                if stage == "fund" {
                                    let addr = st["deposit_wallet"].as_str().unwrap_or("?");
                                    println!("fund the EOA: {addr}");
                                    println!(
                                        "send POL (gas) and pUSD to this address on Polygon, then re-run"
                                    );
                                }
                                break;
                            }
                        }
                    }
                }
                return Ok(());
            }
            let client = IpcClient::new(&client_endpoint.socket);
            let ipc_res = try_ipc(
                &client,
                &client_endpoint,
                "write",
                serde_json::json!({ "path": path, "bytes_b64": B64.encode(&body) }),
            )
            .await
            .with_context(|| format!("ipc write via {}", client_endpoint.display))?;
            if ipc_res.is_some() {
                debug!(endpoint = %client_endpoint.display, "cli.vfs.write.via_ipc");
            } else {
                debug!("cli.vfs.write.via_inproc: no daemon socket present");
                let (_home_permit, d) = build_write_daemon(home)?;
                d.vfs.write(&p, &body).await.context("vfs write")?;
            }
            Ok(())
        }
        Cmd::Wallet(WalletCmd::New {
            name,
            passkey,
            passphrase,
        }) => {
            let (_home_permit, d) = build_write_daemon(home)?;
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
            let (_home_permit, d) = build_write_daemon(home)?;
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
            let client = IpcClient::new(&client_endpoint.socket);
            let ipc_res = try_ipc(
                &client,
                &client_endpoint,
                "wallet.sign_policy",
                serde_json::json!({ "wallet": &name }),
            )
            .await
            .with_context(|| format!("ipc sign-policy via {}", client_endpoint.display))?;
            if ipc_res.is_some() {
                println!("policy.toml signed for '{name}'");
                return Ok(());
            }

            let (_home_permit, d) = build_write_daemon(home.clone())?;
            // Read the policy raw — deliberately WITHOUT verifying the old
            // signature: the only time re-signing is needed is when the file
            // is modified-but-unsigned, and `info()` would refuse exactly
            // then. Authorization is the ceremony below, with the exact
            // content shown first.
            let (policy_toml, kind) = d.keystore.raw_policy(&name)?;
            println!("Policy for '{name}' (about to sign exactly this):\n\n{policy_toml}");
            if kind == bloom_keystore::WalletKind::PasskeyGated {
                let policy_path = home.keystore_dir().join(&name).join("policy.toml");
                let address =
                    std::fs::read_to_string(home.keystore_dir().join(&name).join("address"))
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                let policy_digest = blake3::hash(policy_toml.as_bytes()).to_hex().to_string();
                let mut intent = CeremonyIntent::new(
                    &name,
                    "Sign Wallet Policy",
                    CeremonyIntentKind::SignPolicy,
                );
                intent.wallet_address = address;
                intent.summary_lines = vec![
                    format!("Review rules for wallet '{name}'."),
                    "This does not move money or place a trade.".into(),
                    "After approval, Bloom uses these rules to decide what is allowed.".into(),
                ];
                // Show the exact policy body on the review page (the "Policy"
                // section), so the user reviews the contents — not a blind
                // digest. This is a display-only field, excluded from
                // `stable_subject_hash`, so it does not perturb the intent hash;
                // `policy_blake3` in `canonical_subject` stays the anchor.
                intent.policy_lines = policy_toml.lines().map(str::to_string).collect();
                intent.risk_lines = vec![
                    "Approving these rules can change what Bloom allows later.".into(),
                    "The OS passkey prompt only proves your presence; review the details on this page."
                        .into(),
                ];
                intent.artifact_paths = vec![policy_path.display().to_string()];
                intent.canonical_subject = serde_json::json!({
                    "kind": "sign_policy",
                    "wallet": name,
                    "policy_path": policy_path,
                    "policy_blake3": policy_digest,
                });
                // Persist the full reviewed intent next to policy.toml.sig so the
                // approval is re-readable later (the .sig is the cryptographic
                // record; this is the human-readable reviewed context).
                if let Ok(bytes) = serde_json::to_vec_pretty(&intent) {
                    let review_path = home.keystore_dir().join(&name).join("policy.review.json");
                    let _ = std::fs::write(&review_path, bytes);
                }
                d.keystore.lock(&name);
                d.keystore
                    .unlock_passkey_with_intent(&name, Some(intent))
                    .await?;
            }
            d.keystore.sign_policy(&name)?;
            println!("policy.toml signed for '{name}'");
            Ok(())
        }
        Cmd::Wallet(WalletCmd::RebindPasskey { name }) => {
            let (_home_permit, d) = build_write_daemon(home)?;
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
            let (_home_permit, d) = build_write_daemon(home)?;
            d.keystore.delete(&name)?;
            println!("✓ wallet '{name}' deleted");
            Ok(())
        }
        Cmd::Wallet(WalletCmd::Stage {
            wallet,
            chain,
            intent,
        }) => {
            let (home_permit, d) = build_write_daemon(home)?;
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
                    &home_permit,
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
            let (home_permit, d) = build_write_daemon(home)?;
            let info = d.keystore.info(&wallet)?;
            let mut reviewed_intent_hash: Option<String> = None;
            match info.kind {
                bloom_keystore::WalletKind::PasskeyGated => {
                    // Build the review intent from the staged outbox entry. An
                    // EVM staged tx is byte-immutable for the user-risking
                    // fields (chain/to/value/data/nonce fixed at stage time),
                    // so the intent faithfully reflects what will be signed.
                    let intent = d
                        .tx_engine
                        .outbox
                        .read(&wallet, &chain, &id)
                        .ok()
                        .map(|entry| {
                            let s = &entry.staged;
                            let data_hash = blake3::hash(s.data_hex.as_bytes()).to_hex();
                            let mut it = CeremonyIntent::new(
                                &wallet,
                                "Sign Polygon Transaction",
                                CeremonyIntentKind::EvmTransaction,
                            )
                            .with_address(&s.from)
                            .summary(format!("Chain: {} (id {})", s.chain, s.chain_id))
                            .summary(format!("To: {}", s.to))
                            .summary(format!("Value: {} wei", s.value_wei))
                            .summary(format!(
                                "Nonce: {}  data: {}B",
                                s.nonce,
                                s.data_hex.len() / 2
                            ))
                            .summary(format!("Outbox id: {}", s.id))
                            .risk("Broadcasts this exact staged transaction.")
                            .subject(serde_json::json!({
                                "action": "evm_transaction",
                                "chain_id": s.chain_id,
                                "from": s.from,
                                "to": s.to,
                                "value_wei": s.value_wei,
                                "nonce": s.nonce,
                                "data_blake3": data_hash.to_string(),
                            }));
                            for c in &s.policy_checks {
                                it = it
                                    .policy(format!("[{:?}] {}: {}", c.outcome, c.rule, c.message));
                            }
                            // Persist the full reviewed intent into the staged
                            // tx's outbox dir; the pending → sent transition is a
                            // dir rename, so it rides along to the sent record.
                            if let Ok(bytes) = serde_json::to_vec_pretty(&it) {
                                let _ = d.tx_engine.outbox.write_artefact(
                                    &entry.dir,
                                    "review_intent.json",
                                    &bytes,
                                );
                            }
                            reviewed_intent_hash = Some(it.intent_hash());
                            it
                        });
                    d.keystore.lock(&wallet);
                    d.keystore
                        .unlock_passkey_with_intent(&wallet, intent)
                        .await?;
                    if let Some(hash) = &reviewed_intent_hash
                        && let Ok(entry) = d.tx_engine.outbox.read(&wallet, &chain, &id)
                    {
                        let approved = serde_json::json!({
                            "schema": "bloom.review_approved.v1",
                            "intent_hash": hash,
                        });
                        let _ = d.tx_engine.outbox.write_artefact(
                            &entry.dir,
                            "review_approved.json",
                            &serde_json::to_vec_pretty(&approved)?,
                        );
                    }
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
                .confirm(
                    &home_permit,
                    &wallet,
                    &chain,
                    &id,
                    &client,
                    &signer,
                    &info.policy,
                    &text,
                    reviewed_intent_hash.as_deref(),
                )
                .await?;
            println!(
                "broadcast {} hash={}",
                staged.id,
                staged.tx_hash.as_deref().unwrap_or("?")
            );
            Ok(())
        }
        Cmd::Serve { endpoint, mount } => {
            eprintln!("{ALPHA_DISCLOSURE}");
            let (_home_permit, d) = build_write_daemon(home)?;
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
            let endpoint = resolve_server_endpoint(&d.home, endpoint.as_deref())
                .context("resolve serve endpoint")?;
            let socket = endpoint.socket.clone();
            println!("ipc endpoint: {}", endpoint.display);
            println!("ipc socket: {}", socket.display());
            info!(home = %d.home.root().display(), chains = ?chains, endpoint = %endpoint.display, socket = %socket.display(), mount = ?mount, "cli.serve.starting");
            let server = IpcServer::new(d.vfs.clone(), env!("CARGO_PKG_VERSION"), chains)
                .with_keystore(d.keystore.clone())
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
        Cmd::Polymarket(PolymarketCmd::Onboard {
            wallet,
            target_pusd,
            max_spend,
            slippage_bps,
            confirm_risk,
            passphrase,
        }) => {
            let (_home_permit, d) = build_write_daemon(home)?;
            commands::polymarket::onboard(
                &d,
                commands::polymarket::OnboardArgs {
                    wallet,
                    target_pusd,
                    max_spend,
                    slippage_bps,
                    confirm_risk,
                    passphrase,
                },
            )
            .await
        }
        Cmd::Polymarket(PolymarketCmd::Order {
            wallet,
            slug,
            outcome,
            amount,
            max_price,
            limit_price,
            order_type,
            dry_run,
            confirm_risk,
            passphrase,
        }) => {
            let (_home_permit, d) = build_write_daemon(home)?;
            commands::polymarket::place(
                &d,
                commands::polymarket::PlaceArgs {
                    wallet,
                    slug,
                    outcome,
                    side: bloom_polymarket::Side::Buy,
                    amount,
                    price_bound: max_price,
                    limit_price,
                    order_type,
                    dry_run,
                    confirm_risk,
                    passphrase,
                },
            )
            .await
        }
        Cmd::Polymarket(PolymarketCmd::Sell {
            wallet,
            slug,
            outcome,
            shares,
            min_price,
            limit_price,
            order_type,
            dry_run,
            confirm_risk,
            passphrase,
        }) => {
            let (_home_permit, d) = build_write_daemon(home)?;
            commands::polymarket::place(
                &d,
                commands::polymarket::PlaceArgs {
                    wallet,
                    slug,
                    outcome,
                    side: bloom_polymarket::Side::Sell,
                    amount: shares,
                    price_bound: min_price,
                    limit_price,
                    order_type,
                    dry_run,
                    confirm_risk,
                    passphrase,
                },
            )
            .await
        }
        Cmd::Polymarket(PolymarketCmd::Confirm {
            wallet,
            draft_id,
            confirm_risk,
            passphrase,
        }) => {
            let (_home_permit, d) = build_write_daemon(home)?;
            commands::polymarket::confirm(
                &d,
                &wallet,
                &draft_id,
                confirm_risk,
                passphrase.as_deref(),
            )
            .await
        }
        Cmd::Polymarket(PolymarketCmd::Cancel { wallet, order_id }) => {
            let (_home_permit, d) = build_write_daemon(home)?;
            commands::polymarket::cancel(&d, &wallet, &order_id).await
        }
        Cmd::Polymarket(PolymarketCmd::Obligations { wallet }) => {
            let d = Daemon::from_home(home).context("build daemon")?;
            commands::polymarket::obligations(&d, &wallet).await
        }
        Cmd::Polymarket(PolymarketCmd::Redeem {
            wallet,
            slug,
            dry_run,
            passphrase,
        }) => {
            let (_home_permit, d) = build_write_daemon(home)?;
            commands::polymarket::redeem(&d, &wallet, &slug, dry_run, passphrase.as_deref()).await
        }
        Cmd::Polymarket(PolymarketCmd::RevokeApprovals {
            wallet,
            dry_run,
            passphrase,
        }) => {
            let (_home_permit, d) = build_write_daemon(home)?;
            commands::polymarket::revoke_approvals(&d, &wallet, dry_run, passphrase.as_deref())
                .await
        }
        Cmd::Polymarket(PolymarketCmd::WithdrawPusd {
            wallet,
            amount,
            dry_run,
            passphrase,
        }) => {
            let (_home_permit, d) = build_write_daemon(home)?;
            commands::polymarket::withdraw_pusd(
                &d,
                &wallet,
                &amount,
                dry_run,
                passphrase.as_deref(),
            )
            .await
        }
        Cmd::Polymarket(PolymarketCmd::BuilderKeys(BuilderKeysCmd::List { wallet })) => {
            let d = Daemon::from_home(home).context("build daemon")?;
            commands::polymarket::builder_keys_list(&d, &wallet).await
        }
        Cmd::Polymarket(PolymarketCmd::BuilderKeys(BuilderKeysCmd::Revoke { wallet, key })) => {
            let (_home_permit, d) = build_write_daemon(home)?;
            commands::polymarket::builder_keys_revoke(&d, &wallet, key.as_deref()).await
        }
        Cmd::Polymarket(PolymarketCmd::Fund {
            wallet,
            target_pusd,
            max_spend,
            from_token,
            slippage_bps,
            request,
            dry_run,
            confirm_risk,
            passphrase,
        }) => {
            let (_home_permit, d) = build_write_daemon(home)?;
            if let Some(id) = request {
                commands::polymarket::fund_from_request(
                    &d,
                    &wallet,
                    &id,
                    dry_run,
                    confirm_risk,
                    passphrase,
                )
                .await
            } else {
                commands::polymarket::fund(
                    &d,
                    commands::polymarket::FundArgs {
                        wallet,
                        // `required_unless_present = "request"` guarantees these.
                        target_pusd: target_pusd.expect("target_pusd required without --request"),
                        from_token,
                        max_spend: max_spend.expect("max_spend required without --request"),
                        slippage_bps,
                        dry_run,
                        confirm_risk,
                        passphrase,
                    },
                )
                .await
            }
        }
        Cmd::Petals(cmd) => {
            let _home_permit = HomeWritePermit::acquire(&home)?;
            run_petals(home, cmd).await
        }
        Cmd::Chain(cmd) => {
            let _home_permit = if cmd.requires_home_write_lock() {
                Some(HomeWritePermit::acquire(&home)?)
            } else {
                None
            };
            commands::chain::run_chain(&home, cmd).await
        }
        Cmd::Pipe {
            expr,
            signers,
            gas_payer,
        } => {
            let _home_permit = HomeWritePermit::acquire(&home)?;
            let rpc_sock = home.root().join("chain").join("rpc.sock");
            let chain_dir = home.root().join("chain");
            commands::pipe::run(&rpc_sock, &chain_dir, &expr, &signers, &gas_payer).await
        }
        Cmd::Completions { shell } => {
            generate(shell, &mut Cli::command(), "bloom", &mut std::io::stdout());
            Ok(())
        }
        Cmd::Ipc(IpcCmd::Call { method, params }) => {
            let endpoint = client_endpoint;
            if !endpoint.socket.exists() {
                debug!(endpoint = %endpoint.display, "cli.ipc.call.no_socket: daemon may not be running");
            }
            let client = IpcClient::new(&endpoint.socket);
            let v: serde_json::Value = match params {
                Some(s) => serde_json::from_str(&s).context("parse params JSON")?,
                None => serde_json::Value::Null,
            };
            debug!(%method, endpoint = %endpoint.display, "cli.ipc.call");
            let result = client
                .call(&method, v)
                .await
                .with_context(|| format!("ipc call to {}", endpoint.display))?;
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

fn vfs_write_unlock_intent(
    wallet: &str,
    path: &VfsPath,
    body: &[u8],
    wallet_address: Option<String>,
    outbox_root: Option<&std::path::Path>,
) -> CeremonyIntent {
    let path_s = path.to_string_path();
    let segs = path.segments();
    let is_wallet_policy_write = matches!(
        segs,
        [root, w, file] if root == "wallets" && w == wallet && file == "policy.toml"
    );
    if is_wallet_policy_write {
        let policy_text = String::from_utf8_lossy(body);
        let policy_digest = blake3::hash(body).to_hex().to_string();
        let mut intent = CeremonyIntent::new(
            wallet,
            "Approve Wallet Policy Write",
            CeremonyIntentKind::SignPolicy,
        );
        intent.wallet_address = wallet_address;
        intent.summary_lines = vec![
            format!("Review rules for wallet '{wallet}'."),
            "This does not move money or place a trade.".into(),
            "After approval, Bloom uses these rules to decide what is allowed.".into(),
        ];
        intent.policy_lines = policy_text.lines().map(str::to_string).collect();
        intent.risk_lines = vec![
            "Approving these rules can change what Bloom allows later.".into(),
            "The OS passkey prompt only proves your presence; review the details on this page."
                .into(),
        ];
        intent.artifact_paths = vec![path_s.clone()];
        intent.canonical_subject = serde_json::json!({
            "kind": "vfs_policy_write",
            "wallet": wallet,
            "path": path_s,
            "policy_blake3": policy_digest,
        });
        return intent;
    }

    if let Some(intent) =
        outbox_confirm_unlock_intent(wallet, &path_s, segs, wallet_address.clone(), outbox_root)
    {
        return intent;
    }

    CeremonyIntent::new(
        wallet,
        "Approve VFS Wallet Write",
        CeremonyIntentKind::WalletUnlock,
    )
    .summary(format!("Approve one VFS write for wallet '{wallet}'."))
    .summary(format!("Path: {path_s}"))
    .risk("This unlock is scoped to the foreground write request.")
    .risk("The OS passkey prompt will show bloom/localhost, not the VFS path.")
    .artifact(path_s.clone())
    .subject(serde_json::json!({
        "kind": "vfs_write_unlocked",
        "wallet": wallet,
        "path": path_s,
    }))
}

fn outbox_confirm_unlock_intent(
    wallet: &str,
    path_s: &str,
    segs: &[String],
    wallet_address: Option<String>,
    outbox_root: Option<&std::path::Path>,
) -> Option<CeremonyIntent> {
    let [root, w, chains, chain, outbox, pending, id, confirm] = segs else {
        return None;
    };
    if root != "wallets"
        || w != wallet
        || chains != "chains"
        || outbox != "outbox"
        || pending != "pending"
        || confirm != "confirm"
    {
        return None;
    }
    let plan_path = outbox_root?
        .join(wallet)
        .join(chain)
        .join("pending")
        .join(id)
        .join("plan.md");
    let plan = std::fs::read_to_string(&plan_path).ok()?;
    let plan_hash = blake3::hash(plan.as_bytes()).to_hex().to_string();
    let defi_review = find_defi_review_for_outbox(outbox_root?, wallet, id);
    let mut intent = CeremonyIntent::new(
        wallet,
        format!("Approve {} Transaction", chain),
        CeremonyIntentKind::EvmTransaction,
    );
    intent.wallet_address = wallet_address;
    intent.summary_lines = defi_review
        .as_ref()
        .map(|review| review.summary_lines.clone())
        .unwrap_or_default();
    if !intent.summary_lines.is_empty() {
        intent.summary_lines.push("Transaction to sign:".into());
    }
    intent.summary_lines.extend(
        plan.lines()
            .filter(|line| {
                line.starts_with("Wallet:")
                    || line.starts_with("From:")
                    || line.starts_with("To:")
                    || line.starts_with("Chain:")
                    || line.starts_with("Value:")
                    || line.starts_with("Nonce:")
                    || line.starts_with("Gas:")
                    || line.starts_with("Data:")
            })
            .map(|line| line.trim().to_string()),
    );
    if intent.summary_lines.is_empty() {
        intent
            .summary_lines
            .push(format!("Broadcast staged transaction {id} on {chain}."));
    }
    intent.risk_lines = defi_review
        .as_ref()
        .map(|review| review.risk_lines.clone())
        .unwrap_or_default();
    intent.risk_lines.extend(vec![
        "Approving will sign and broadcast this transaction.".into(),
        "For cross-chain routes, source-chain confirmation is not destination settlement.".into(),
        "The OS passkey prompt only proves your presence; review the transaction on this page."
            .into(),
    ]);
    intent.policy_lines = defi_review
        .as_ref()
        .map(|review| {
            let mut lines: Vec<String> = review.plan_md.lines().map(str::to_string).collect();
            lines.extend(["".into(), "---".into(), "".into()]);
            lines.extend(plan.lines().map(str::to_string));
            lines
        })
        .unwrap_or_else(|| plan.lines().map(str::to_string).collect());
    intent.artifact_paths = vec![path_s.to_string(), plan_path.display().to_string()];
    if let Some(review) = &defi_review {
        intent
            .artifact_paths
            .push(format!("defi session {}", review.id));
    }
    intent.canonical_subject = serde_json::json!({
        "kind": "outbox_confirm",
        "wallet": wallet,
        "chain": chain,
        "outbox_id": id,
        "path": path_s,
        "plan_blake3": plan_hash,
        "defi_session_id": defi_review.as_ref().map(|review| review.id.as_str()),
        "defi_plan_blake3": defi_review.as_ref().map(|review| review.plan_hash.as_str()),
    });
    Some(intent)
}

#[derive(Debug, Clone)]
struct DefiReview {
    id: String,
    plan_md: String,
    plan_hash: String,
    summary_lines: Vec<String>,
    risk_lines: Vec<String>,
}

fn find_defi_review_for_outbox(
    outbox_root: &std::path::Path,
    wallet: &str,
    outbox_id: &str,
) -> Option<DefiReview> {
    let home = if outbox_root.file_name().is_some_and(|name| name == "outbox") {
        outbox_root.parent().unwrap_or(outbox_root)
    } else {
        outbox_root
    };
    let sessions = home.join("defi").join(wallet).join("sessions");
    for entry in std::fs::read_dir(sessions).ok()? {
        let path = entry.ok()?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let raw = std::fs::read_to_string(&path).ok()?;
        let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
        let staged = value
            .get("staged_ids")
            .and_then(|v| v.as_array())
            .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(outbox_id)));
        if !staged {
            continue;
        }
        let id = value
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let plan_md = value
            .get("plan_md")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let plan_hash = blake3::hash(plan_md.as_bytes()).to_hex().to_string();
        let mut summary_lines = vec![format!("DeFi route intent {id}:")];
        summary_lines.extend(plan_md.lines().filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("Intent:")
                || trimmed.starts_with("Chain:")
                || trimmed.starts_with("Dest chain:")
                || trimmed.starts_with("Receiver:")
                || trimmed.starts_with("Token in:")
                || trimmed.starts_with("Token out:")
                || trimmed.starts_with("Slippage:")
                || trimmed.starts_with("Router:")
                || trimmed.starts_with("Protocols:")
                || trimmed.starts_with("Tx value:")
            {
                Some(trimmed.to_string())
            } else {
                None
            }
        }));
        let risk_lines = value
            .get("policy_checks")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter(|check| check.get("outcome").and_then(|v| v.as_str()) == Some("warn"))
            .filter_map(|check| {
                let rule = check.get("rule").and_then(|v| v.as_str()).unwrap_or("defi");
                let message = check.get("message").and_then(|v| v.as_str())?;
                Some(format!("{rule}: {message}"))
            })
            .collect();
        return Some(DefiReview {
            id,
            plan_md,
            plan_hash,
            summary_lines,
            risk_lines,
        });
    }
    None
}

fn is_wallet_policy_write(wallet: &str, path: &VfsPath) -> bool {
    matches!(
        path.segments(),
        [root, w, file] if root == "wallets" && w == wallet && file == "policy.toml"
    )
}

fn is_outbox_confirm_write(wallet: &str, path: &VfsPath) -> bool {
    matches!(
        path.segments(),
        [root, w, chains, _chain, outbox, pending, _id, confirm]
            if root == "wallets"
                && w == wallet
                && chains == "chains"
                && outbox == "outbox"
                && pending == "pending"
                && confirm == "confirm"
    )
}

fn outbox_confirm_dir(wallet: &str, path: &VfsPath, outbox_root: &Path) -> Option<PathBuf> {
    let [root, w, chains, chain, outbox, pending, id, confirm] = path.segments() else {
        return None;
    };
    if root == "wallets"
        && w == wallet
        && chains == "chains"
        && outbox == "outbox"
        && pending == "pending"
        && confirm == "confirm"
    {
        Some(
            outbox_root
                .join(wallet)
                .join(chain)
                .join("pending")
                .join(id),
        )
    } else {
        None
    }
}

fn persist_outbox_review_intent(
    wallet: &str,
    path: &VfsPath,
    outbox_root: &Path,
    intent: &CeremonyIntent,
) -> Result<()> {
    let Some(dir) = outbox_confirm_dir(wallet, path, outbox_root) else {
        return Ok(());
    };
    std::fs::write(
        dir.join("review_intent.json"),
        serde_json::to_vec_pretty(intent)?,
    )?;
    Ok(())
}

fn persist_outbox_review_approved(
    wallet: &str,
    path: &VfsPath,
    outbox_root: &Path,
    intent_hash: &str,
) -> Result<()> {
    let Some(dir) = outbox_confirm_dir(wallet, path, outbox_root) else {
        return Ok(());
    };
    let approved = serde_json::json!({
        "schema": "bloom.review_approved.v1",
        "intent_hash": intent_hash,
    });
    std::fs::write(
        dir.join("review_approved.json"),
        serde_json::to_vec_pretty(&approved)?,
    )?;
    Ok(())
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
