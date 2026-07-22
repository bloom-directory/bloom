//! `bloom` — bloom daemon and CLI.
//!
//! For v1, the CLI drives the same in-process daemon — there's no
//! separate long-running server. Each invocation builds the daemon,
//! performs the requested VFS operation, and exits. A `serve` subcommand
//! exists as a placeholder for the eventual long-running NFS-mounted
//! daemon.

#![forbid(unsafe_code)]

mod commands {
    pub mod qr;
}
mod github_source;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::time::{SystemTime, UNIX_EPOCH};

static UPDATE_EXIT_CODE: AtomicI32 = AtomicI32::new(0);

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bloom_auth_api::{ApprovalChallenge, AssuranceLevel, SignerTransport, UnsignedApproval};
use bloom_daemon::Daemon;
use bloom_daemon::ipc::{IpcClient, IpcServer, default_socket_path};
use bloom_hyperliquid::{HyperliquidClient, HyperliquidNetwork, UsdSendRequest, pretty_json};
use bloom_proto::{AuditRecord, CeremonyIntent, CeremonyIntentKind, HomeDir, HomeWritePermit};
use bloom_tx::TxEngineError;
use bloom_vfs::{
    VfsPath,
    handler::{Entry, EntryKind, Handler, HandlerError},
};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};
use tracing::{debug, info, trace};
use tracing_subscriber::EnvFilter;

#[cfg(target_os = "linux")]
const DEFAULT_MOUNT_PATH: &str = "/bloom";
#[cfg(target_os = "macos")]
const DEFAULT_MOUNT_PATH: &str = "/Volumes/bloom";
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const DEFAULT_MOUNT_PATH: &str = "/bloom";

const ALPHA_DISCLOSURE: &str = "⚠️  Bloom is experimental, unaudited alpha software. Do not use with funds you cannot afford to lose. Review every generated transaction plan before signing.";
const PASSKEY_WRITE_UNLOCKED_DISABLED: &str = "write_unlocked is disabled for passkey wallets; \
stage a Sealed Approval action and sign through PetalHost::sign_hash";

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

fn set_default_wallet_if_empty(home: &HomeDir, wallet: &str) -> Result<bool> {
    let path = home.config_path();
    let mut cfg = bloom_proto::Config::load_or_init(&path)
        .with_context(|| format!("load config {}", path.display()))?;
    if cfg
        .default_wallet
        .as_deref()
        .is_none_or(|w| w.trim().is_empty())
    {
        cfg.default_wallet = Some(wallet.to_string());
        cfg.save(&path)
            .with_context(|| format!("save config {}", path.display()))?;
        Ok(true)
    } else {
        Ok(false)
    }
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

    /// Suppress daemon/diagnostic logs on stderr (values still print on
    /// stdout). `RUST_LOG` overrides this when set.
    #[arg(long, short, global = true)]
    quiet: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Show daemon status (chains configured, version, uptime).
    Status,
    /// VFS path operations (no NFS mount required).
    #[command(subcommand)]
    Vfs(VfsCmd),
    /// Wallet management.
    #[command(subcommand)]
    Wallet(WalletCmd),
    /// Paid/free HTTP requests via the `/requests` VFS surface.
    #[command(subcommand)]
    Request(RequestCmd),
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
    /// Manage wasm petals: install, app, list, uninstall.
    #[command(subcommand, visible_alias = "petal")]
    Petals(PetalsCmd),
    /// Hyperliquid HyperCore reads and tightly scoped test actions.
    #[command(subcommand)]
    Hyperliquid(HyperliquidCmd),
    /// Check for newer bloom releases on GitHub and inspect the
    /// current update-checker state.
    #[command(subcommand)]
    Update(UpdateCmd),
    /// Initialise ~/.bloom with default config + dirs.
    Init,

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
    /// `stat /bloom/<path>` — inspect VFS metadata without a kernel mount.
    Stat { path: String },
    /// Write data to a writable VFS path. Reads from stdin if `--data` is omitted.
    Write {
        path: String,
        #[arg(long)]
        data: Option<String>,
        /// Unlock this wallet and run the write in an in-process daemon — the
        /// signing key must be unlocked in the same process that signs.
        /// Required for VFS writes whose handler signs. NOTE: this BYPASSES any
        /// running `bloom serve` daemon and
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
    /// Install a Petal package directory, `.petal.tar`, or trusted GitHub source repository.
    Install {
        /// Path to a package directory, `.petal.tar`, or trusted GitHub source repository URL.
        path: String,
        /// Git tag, branch, or commit SHA to install from a GitHub source repository.
        #[arg(long = "ref", value_name = "TAG_OR_SHA")]
        ref_: Option<String>,
    },
    /// Validate a Petal package directory and optionally emit a deterministic `.petal.tar`.
    Build {
        /// Package directory containing petal.toml, README.md, AGENTS.md, and petal/<name>/.
        package_dir: String,
        /// Write a deterministic `.petal.tar` archive.
        #[arg(long, value_name = "ARCHIVE")]
        out: Option<String>,
    },
    /// List installed petals.
    Ls,
    /// Remove an installed petal (and any petname pointing at it).
    Uninstall {
        /// Content hash of the petal to remove: full 64-char hex, a
        /// unique prefix of at least 12 chars (as printed by `ls`),
        /// a Petal name, or a petname.
        target: String,
    },
}

#[derive(Subcommand, Debug)]
enum PetalAppCmd {
    /// Validate a v2 package directory and optionally emit a deterministic `.petal.tar`.
    Build {
        /// Package directory containing petal.toml, README.md, AGENTS.md, and app/<name>/.
        package_dir: String,
        /// Write a deterministic `.petal.tar` archive.
        #[arg(long, value_name = "ARCHIVE")]
        out: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum RequestCmd {
    /// Create a request from one-line, TOML, or HTTP-message-like input.
    New {
        /// Request text, e.g. `GET https://example.com/data`.
        request: String,
        /// Paying wallet. If omitted, config.default_wallet or the only wallet is used.
        #[arg(long)]
        wallet: Option<String>,
        /// Stage/probe only; never spends or signs.
        #[arg(long)]
        dry_run: bool,
    },
    /// Show the staged payment plan for an id or `latest`.
    Plan { id: String },
    /// Confirm a pending paid request.
    Confirm {
        id: String,
        /// Confirmation text: `y`/`yes`/`confirm`, or the wallet's policy override
        /// sentinel to bypass soft limits. Defaults to `confirm`.
        #[arg(long, default_value = "confirm")]
        text: String,
        /// Paying wallet to unlock for signing. If omitted, it is read from the
        /// staged request.
        #[arg(long)]
        wallet: Option<String>,
        /// Alias for `--wallet`, kept for parity with `bloom vfs write`.
        #[arg(long)]
        unlock_wallet: Option<String>,
        /// Passphrase for a local/imported paying wallet (passkey wallets prompt).
        #[arg(long, env = "BLOOM_PASSPHRASE")]
        passphrase: Option<String>,
    },
    /// Print response body for an id or `latest`.
    Body { id: String },
    /// Print receipt JSON for an id or `latest`.
    Receipt { id: String },
}

/// Subcommands for `bloom update`.
#[derive(Subcommand, Debug)]
enum UpdateCmd {
    /// Force a refresh against GitHub and print the result as JSON.
    /// Exits 0 if up to date, 1 if behind, 2 if unknown/error.
    Check,
    /// Print the cached snapshot without making a network call.
    Status,
}

#[derive(Subcommand, Debug)]
enum HyperliquidCmd {
    /// Print account clearinghouse state.
    Account {
        user: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Print spot/unified clearinghouse state.
    SpotState {
        user: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Print open orders.
    OpenOrders {
        user: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Print user fills.
    Fills {
        user: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Print user funding history for a coin.
    Funding {
        user: String,
        coin: String,
        #[arg(long)]
        start_time: Option<u64>,
        #[arg(long)]
        end_time: Option<u64>,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Print an L2 order book snapshot.
    Book {
        coin: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Print candle snapshots for a time range.
    Candles {
        coin: String,
        interval: String,
        start_time: u64,
        end_time: u64,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Print market metadata.
    Metadata {
        #[arg(long, default_value = "perp")]
        kind: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Manage daemon-held ephemeral API-wallet sessions.
    Session {
        #[command(subcommand)]
        command: HyperliquidSessionCmd,
    },
    /// Run the read-only smoke suite for an account.
    TestReads {
        user: String,
        #[arg(long, default_value = "BTC")]
        coin: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Transfer USDC internally between Hyperliquid accounts (usdSend, Sealed Approval).
    /// Requires transfer_cap_usd in the wallet [hyperliquid] policy.
    SendAsset {
        wallet: String,
        destination: String,
        amount: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
        #[arg(long, env = "BLOOM_PASSPHRASE", hide = true)]
        passphrase: Option<String>,
    },
    /// Unlock once, place a far-away post-only perp order, then cancel it if it rests.
    TestPostOnlyCancel {
        wallet: String,
        #[arg(long, default_value = "BTC")]
        coin: String,
        /// Perp asset id. BTC is normally 0 on mainnet.
        #[arg(long, default_value_t = 0)]
        asset: u32,
        /// Explicit limit price. Defaults to roughly 50% of current mid.
        #[arg(long)]
        price: Option<String>,
        /// Explicit size. Defaults to a size whose limit notional is just above $10.
        #[arg(long)]
        size: Option<String>,
        /// Refuse if price * size is above this USD cap.
        #[arg(long, default_value_t = 15.0)]
        max_notional_usd: f64,
        /// Make the one passkey policy-session ceremony explicit.
        #[arg(long)]
        policy_session: bool,
        /// Required acknowledgement for a live-order test command.
        #[arg(long)]
        danger_accept_live_orders: bool,
        #[arg(long, env = "BLOOM_PASSPHRASE", hide = true)]
        passphrase: Option<String>,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
}

#[derive(Subcommand, Debug)]
enum HyperliquidSessionCmd {
    /// Create an approved ephemeral API-wallet session in the running daemon.
    Create {
        wallet: String,
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        agent_name: Option<String>,
        /// Vault/subaccount address this session trades on. When set, risk
        /// monitoring and cleanup target this account and every submit must
        /// carry a matching vaultAddress.
        #[arg(long)]
        vault_address: Option<String>,
        #[arg(long, default_value = "mainnet")]
        network: String,
        #[arg(long, env = "BLOOM_PASSPHRASE")]
        passphrase: Option<String>,
    },
    /// Print session status.
    Status {
        wallet: String,
        id: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Print session audit records.
    Audit {
        wallet: String,
        id: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Stop a session without submitting cleanup orders.
    Stop {
        wallet: String,
        id: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Cancel all open orders for the session account.
    CancelAll {
        wallet: String,
        id: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Cancel orders and submit reduce-only IOC closes for open positions.
    CloseAll {
        wallet: String,
        id: String,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
}

#[derive(Subcommand, Debug)]
enum WalletCmd {
    /// Create a new wallet. Defaults to a passkey (WebAuthn) ceremony; pass
    /// `--local` for a passphrase-encrypted wallet. Passphrase wallets created
    /// non-interactively require `--allow-passphrase-wallet` and
    /// `--passphrase-file`, and a recovery file is written to the keystore.
    New {
        name: String,
        /// Create a passphrase-encrypted local wallet (default is passkey).
        #[arg(long)]
        local: bool,
        /// Acknowledge creating a passphrase wallet non-interactively (no tty).
        /// Required for `--local` when stdin is not a terminal. Writes a
        /// recovery file containing the passphrase next to the key.
        #[arg(long)]
        allow_passphrase_wallet: bool,
        /// Read the passphrase from this file instead of an interactive
        /// prompt. Avoids leaking the passphrase via /proc/<pid>/cmdline.
        /// Only used with `--local` for non-interactive creation.
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<PathBuf>,
    },
    /// Import a wallet from a hex private key. Defaults to passkey; pass
    /// `--local` for passphrase-encrypted (same passphrase rules as `new`).
    Import {
        name: String,
        private_key: String,
        #[arg(long)]
        local: bool,
        #[arg(long)]
        allow_passphrase_wallet: bool,
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<PathBuf>,
    },
    /// List configured wallets.
    List,
    /// Print a table of all wallets with their total portfolio value across
    /// all connected chains. Queries Hyperliquid clearinghouse state for each
    /// wallet. Use `--network` to select mainnet (default) or testnet.
    Portfolio {
        /// Hyperliquid network to query. Defaults to mainnet.
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Print a wallet's deposit address. Default output is the bare checksummed
    /// address (one line, scriptable); `--qr` adds a scannable QR block above it,
    /// and `--qr-out <path>` writes a scannable SVG of the address to a file.
    Address {
        name: String,
        #[arg(long)]
        qr: bool,
        /// Write a scannable SVG QR of the deposit address to this path.
        #[arg(long, value_name = "PATH")]
        qr_out: Option<PathBuf>,
    },
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
    /// Unlock then submit a same-nonce self-send replacement to cancel a staged tx.
    Cancel {
        wallet: String,
        chain: String,
        id: String,
        #[arg(long, env = "BLOOM_PASSPHRASE")]
        passphrase: Option<String>,
        /// Confirmation text. Must be non-empty.
        #[arg(long, default_value = "y")]
        text: String,
    },
    /// Unlock then submit a same-nonce replacement tx from a new intent body.
    Replace {
        wallet: String,
        chain: String,
        id: String,
        /// Replacement intent body (JSON, TOML, or shell-style). If omitted, read stdin.
        #[arg(long)]
        intent: Option<String>,
        #[arg(long, env = "BLOOM_PASSPHRASE")]
        passphrase: Option<String>,
    },
    /// Unlock once, review a batch of staged txs, then broadcast them in order.
    ///
    /// Each TX is `chain:id`, for example `base:0001-abc`.
    ConfirmBatch {
        wallet: String,
        /// Staged tx references in the exact order to broadcast.
        txs: Vec<String>,
        #[arg(long, env = "BLOOM_PASSPHRASE")]
        passphrase: Option<String>,
        /// Confirmation text for each tx. Defaults to `override`, which
        /// acknowledges soft policy warnings after the aggregate passkey review.
        #[arg(long, default_value = "override")]
        text: String,
        /// Require an aggregate passkey policy-session review for passkey wallets.
        #[arg(long)]
        policy_session: bool,
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

/// Resolve the passphrase for a new/imported local wallet.
///
/// Interactive (tty): prompts twice via `rpassword` and requires a match.
/// Non-interactive: requires `--allow-passphrase-wallet` + `--passphrase-file`
/// so an agent cannot silently mint a passphrase wallet with a machine-chosen
/// secret — passkey is the default, and passphrase creation must be explicit.
fn resolve_new_wallet_passphrase(
    allow_passphrase_wallet: bool,
    passphrase_file: Option<&Path>,
) -> Result<String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        let p1 = rpassword::prompt_password("Enter passphrase: ")?;
        if p1.is_empty() {
            bail!("passphrase must not be empty");
        }
        let p2 = rpassword::prompt_password("Confirm passphrase: ")?;
        if p1 != p2 {
            bail!("passphrases do not match");
        }
        Ok(p1)
    } else {
        if !allow_passphrase_wallet {
            bail!(
                "creating a passphrase wallet non-interactively requires --allow-passphrase-wallet \
                 and --passphrase-file <PATH>; passkey is the default — run without --local for a \
                 WebAuthn ceremony"
            );
        }
        let path = passphrase_file.ok_or_else(|| {
            anyhow::anyhow!("--passphrase-file <PATH> is required with --allow-passphrase-wallet")
        })?;
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read passphrase file {}", path.display()))?;
        // Strip a single trailing newline pair only — never interior whitespace,
        // which may be a legitimate part of the passphrase.
        let pass = raw.trim_end_matches(['\n', '\r']).to_string();
        if pass.is_empty() {
            bail!("passphrase file is empty");
        }
        Ok(pass)
    }
}

/// Write `bytes` to `path` with mode 0600 via a temp file + atomic rename.
fn write_secret_file_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path).with_context(|| format!("rename {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)?;
    }
    Ok(())
}

/// Record the passphrase for a newly-created local wallet to a 0600
/// `RECOVERY.txt` next to the key. Surfacing the secret the caller chose is
/// the last line of defense against silent agent-created passphrase wallets.
fn write_wallet_recovery(home: &HomeDir, name: &str, passphrase: &str) -> Result<PathBuf> {
    let path = home.wallet_dir(name).join("RECOVERY.txt");
    let body = format!(
        "Bloom passphrase-wallet recovery\n\
         wallet: {name}\n\
         \n\
         passphrase: {passphrase}\n\
         \n\
         This wallet was created with a passphrase. Store this file securely or\n\
         migrate to a passkey wallet (`bloom wallet new {name}` without --local)\n\
         and then remove this file.\n"
    );
    write_secret_file_0600(&path, body.as_bytes())?;
    Ok(path)
}

/// Append a first-class `wallet.created` audit entry (kind + source). The CLI
/// path does not flow through the VFS router, so without this a wallet created
/// via `bloom wallet new` leaves no audit trail at all.
fn audit_wallet_created(audit: &bloom_proto::AuditLog, name: &str, kind: &str) {
    let _ = audit.append(AuditRecord {
        ts_ms: 0,
        kind: "wallet.created".into(),
        wallet: Some(name.into()),
        chain: None,
        data: serde_json::json!({"kind": kind, "source": "cli"}),
        prev: String::new(),
        digest: String::new(),
    });
}

struct WalletPortfolioRow {
    name: String,
    address: String,
    account_value: f64,
    withdrawable: f64,
    positions: Vec<String>,
}

fn print_portfolio_table(rows: &[WalletPortfolioRow], network: &str) {
    if rows.is_empty() {
        println!("no wallets found");
        return;
    }
    println!("\n  Bloom Wallet Portfolio — Hyperliquid {network}\n");
    println!(
        "  {:<18} {:<44} {:>12} {:>12} POSITIONS",
        "WALLET", "ADDRESS", "ACCT VALUE", "WITHDRAWABLE"
    );
    println!("  {}", "-".repeat(120));
    for row in rows {
        let pos_str = if row.positions.is_empty() {
            "—".to_string()
        } else {
            row.positions.join(", ")
        };
        println!(
            "  {:<18} {:<44} ${:>11} ${:>11} {}",
            row.name.chars().take(18).collect::<String>(),
            &row.address[..row.address.len().min(44)],
            format!("{:.4}", row.account_value),
            format!("{:.4}", row.withdrawable),
            pos_str
        );
    }
    println!("  {}", "-".repeat(120));
    let total_value: f64 = rows.iter().map(|r| r.account_value).sum();
    let total_wd: f64 = rows.iter().map(|r| r.withdrawable).sum();
    let total_pos: usize = rows.iter().map(|r| r.positions.len()).sum();
    println!(
        "  {:<18} {:<44} ${:>11} ${:>11} {} position(s)\n",
        "TOTAL",
        "",
        format!("{:.4}", total_value),
        format!("{:.4}", total_wd),
        total_pos
    );
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // RUST_LOG wins when set; otherwise default to `info`, or `error`
    // under `--quiet` so `vfs cat`/`ls` output stays clean.
    let default_level = if cli.quiet { "error" } else { "info" };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level)),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();

    match run(cli).await {
        Ok(()) => {
            let code = UPDATE_EXIT_CODE.load(std::sync::atomic::Ordering::SeqCst);
            if code != 0 {
                return ExitCode::from(code as u8);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

fn reject_archive_output_inside_package(package_dir: &str, out: &str) -> Result<()> {
    let package_dir = std::fs::canonicalize(package_dir)
        .with_context(|| format!("canonicalize package dir {package_dir}"))?;
    let out_path = std::path::Path::new(out);
    let out_parent = out_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let out_parent = std::fs::canonicalize(out_parent)
        .with_context(|| format!("canonicalize archive parent {out}"))?;
    let out_abs = out_parent.join(out_path.file_name().unwrap_or_default());
    if out_abs.starts_with(&package_dir) {
        bail!(
            "--out must be outside the package directory so archives are not packaged into future builds"
        );
    }
    Ok(())
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

/// True when a daemon IPC call failed because the VFS *handler* returned
/// `PermissionDenied` (JSON-RPC code `-32007`) — i.e. a Sealed Approval
/// challenge was staged — rather than a transport/socket-level denial.
/// [`try_ipc`] only surfaces this as a propagated `Err`, so it is safe to
/// distinguish it here by the JSON-RPC error payload.
fn is_ipc_handler_permission_denied(e: &std::io::Error) -> bool {
    let s = e.to_string();
    s.contains("-32007") || s.contains("permission denied")
}

fn system_time_to_unix_ms(time: SystemTime) -> u128 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn unix_ms_to_system_time(ms: u128) -> SystemTime {
    let ms = ms.min(u64::MAX as u128) as u64;
    UNIX_EPOCH + std::time::Duration::from_millis(ms)
}

fn entry_kind_label(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Dir => "dir",
        EntryKind::File => "file",
        EntryKind::Symlink => "symlink",
    }
}

fn print_vfs_stat(
    path: &str,
    name: &str,
    kind: &str,
    mode: u32,
    size: u64,
    link_target: Option<&str>,
    modified: Option<SystemTime>,
) {
    let (modified, modified_source) = match modified {
        Some(t) => (t, "artifact"),
        None => (SystemTime::now(), "synthetic_now"),
    };
    let modified_ms = system_time_to_unix_ms(modified);
    println!("path: {path}");
    println!("name: {name}");
    println!("kind: {kind}");
    println!("mode: {:04o}", mode & 0o7777);
    println!("size: {size}");
    println!("modified_ms: {modified_ms}");
    println!("modified: {}", humantime::format_rfc3339(modified));
    println!("modified_source: {modified_source}");
    if let Some(target) = link_target {
        println!("link_target: {target}");
    }
}

fn print_vfs_stat_entry(path: &str, entry: &Entry) {
    print_vfs_stat(
        path,
        &entry.name,
        entry_kind_label(entry.kind),
        entry.mode,
        entry.size,
        entry.link_target.as_deref(),
        entry.modified,
    )
}

fn print_vfs_stat_json(path: &str, entry: &serde_json::Value) -> Result<()> {
    let name = entry
        .get("name")
        .and_then(|v| v.as_str())
        .context("ipc lookup: missing name")?;
    let kind = entry
        .get("kind")
        .and_then(|v| v.as_str())
        .context("ipc lookup: missing kind")?;
    let mode = entry
        .get("mode")
        .and_then(|v| v.as_u64())
        .context("ipc lookup: missing mode")? as u32;
    let size = entry
        .get("size")
        .and_then(|v| v.as_u64())
        .context("ipc lookup: missing size")?;
    let link_target = entry.get("link_target").and_then(|v| v.as_str());
    let modified = entry
        .get("modified_ms")
        .and_then(|v| v.as_u64())
        .map(|ms| unix_ms_to_system_time(ms as u128));
    print_vfs_stat(path, name, kind, mode, size, link_target, modified);
    Ok(())
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
            let (_home_permit, d) = build_write_daemon(home.clone()).context("init daemon")?;
            let preinstalled = github_source::ensure_preinstalled_petals(&home, &d)
                .context("provision configured pre-installed Petals")?;
            println!("home: {}", d.home.root().display());
            println!("config: {}", d.home.config_path().display());
            println!("chains: {:?}", d.chains.list_names());
            println!("preinstalled_petals: {preinstalled:?}");
            println!("next: bloom wallet new main");
            println!("then: bloom wallet address main --qr");
            println!("mount: mkdir -p ~/bloom && bloom serve --mount ~/bloom");
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
                "default_wallet: {}",
                d.config.default_wallet.as_deref().unwrap_or("<none>")
            );
            if d.config.hyperliquid.is_some() {
                println!("hyperliquid_vfs: enabled (/hyperliquid)");
                // Which wallets have an actual trading boundary in force.
                let policed: Vec<String> = d
                    .keystore
                    .list()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|w| w.policy.hyperliquid.is_configured())
                    .map(|w| w.name)
                    .collect();
                if policed.is_empty() {
                    println!(
                        "hyperliquid_policy: none configured (any wallet can trade unconstrained \
                         once unlocked — add [hyperliquid] to a wallet policy)"
                    );
                } else {
                    println!("hyperliquid_policy: configured for {}", policed.join(", "));
                }
            } else {
                println!("hyperliquid_vfs: disabled (add [hyperliquid] to config.toml)");
            }
            println!("try: bloom vfs ls /");
            if d.keystore.list()?.is_empty() {
                println!("no wallets yet — create one with bloom wallet new main");
            } else {
                println!("deposit: bloom wallet address <wallet> --qr");
                println!("agent workflow: browse the mounted VFS or use bloom vfs cat/ls/write");
            }
            if let Some(snap) = d.update_checker.quick_check_cached() {
                let latest = snap.latest.as_deref().unwrap_or("?");
                let latest_display = latest.strip_prefix('v').unwrap_or(latest);
                let available = match snap.available() {
                    bloom_update::UpdateAvailable::OutOfDate => "out_of_date",
                    bloom_update::UpdateAvailable::UpToDate => "up_to_date",
                    bloom_update::UpdateAvailable::Unknown => "unknown",
                };
                println!("latest_release: {}", latest);
                println!("update_available: {}", available);
                if matches!(snap.available(), bloom_update::UpdateAvailable::OutOfDate) {
                    eprintln!(
                        "hint: bloom v{} is available (you have v{}); see /status/update",
                        latest_display,
                        env!("CARGO_PKG_VERSION")
                    );
                }
            }
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
        Cmd::Vfs(VfsCmd::Stat { path }) => {
            let p = VfsPath::parse(&path).context("parse path")?;
            let client = IpcClient::new(&client_endpoint.socket);
            let ipc_res = try_ipc(
                &client,
                &client_endpoint,
                "lookup",
                serde_json::json!({ "path": path }),
            )
            .await
            .with_context(|| format!("ipc lookup via {}", client_endpoint.display))?;
            if let Some(res) = ipc_res {
                debug!(endpoint = %client_endpoint.display, "cli.vfs.stat.via_ipc");
                print_vfs_stat_json(&path, &res)?;
            } else {
                debug!("cli.vfs.stat.via_inproc: no daemon socket present");
                let d = Daemon::from_home(home).context("build daemon")?;
                let entry = d.vfs.lookup(&p).await.context("vfs lookup")?;
                print_vfs_stat_entry(&path, &entry);
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
            let body = match data {
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
                        bail!(PASSKEY_WRITE_UNLOCKED_DISABLED);
                    }
                    _ => {
                        d.keystore
                            .unlock(&wallet, passphrase.as_deref().unwrap_or(""))?;
                    }
                }
                d.vfs.write(&p, &body).await.context("vfs write")?;
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
        Cmd::Request(RequestCmd::New {
            request,
            wallet,
            dry_run,
        }) => {
            let body = request_body_with_wallet(request, wallet.as_deref());
            let path = if dry_run {
                "/requests/new.dry-run"
            } else {
                "/requests/new"
            };
            let client = IpcClient::new(&client_endpoint.socket);
            let ipc_res = try_ipc(
                &client,
                &client_endpoint,
                "write",
                serde_json::json!({ "path": path, "bytes_b64": B64.encode(body.as_bytes()) }),
            )
            .await
            .with_context(|| format!("ipc request new via {}", client_endpoint.display))?;
            if ipc_res.is_some() {
                debug!(endpoint = %client_endpoint.display, "cli.request.new.via_ipc");
                if dry_run {
                    println!("dry_run: true (unpaid probe/staging only; no spend/signing)");
                }
                return Ok(());
            }
            debug!("cli.request.new.via_inproc: no daemon socket present");
            let (_home_permit, d) = build_write_daemon(home)?;
            d.vfs
                .write(&VfsPath::parse(path)?, body.as_bytes())
                .await
                .context("request new")?;
            let latest = d
                .vfs
                .read(&VfsPath::parse("/requests/latest")?)
                .await
                .context("read latest request")?;
            let latest = String::from_utf8_lossy(&latest);
            println!("request: {}", latest.trim());
            if dry_run {
                println!("dry_run: true (unpaid probe/staging only; no spend/signing)");
            }
            Ok(())
        }
        Cmd::Request(RequestCmd::Plan { id }) => {
            let d = Daemon::from_home(home).context("build daemon")?;
            let path = VfsPath::parse(&format!("/requests/{id}/plan.md"))?;
            let bytes = d.vfs.read(&path).await.context("request plan")?;
            std::io::Write::write_all(&mut std::io::stdout(), &bytes)?;
            Ok(())
        }
        Cmd::Request(RequestCmd::Confirm {
            id,
            text,
            wallet,
            unlock_wallet,
            passphrase,
        }) => {
            let path = format!("/requests/{id}/confirm");
            let p = VfsPath::parse(&path)?;
            let body = text.into_bytes();
            let client = IpcClient::new(&client_endpoint.socket);
            let wallet = unlock_wallet.or(wallet);
            let wallet = match wallet {
                Some(w) => Some(w),
                None => read_request_wallet(&client, &client_endpoint, &home, &id).await?,
            };
            let wallet = wallet.context(
                "could not determine paying wallet for this request; pass --wallet or --unlock-wallet",
            )?;
            // Daemon-backed confirm reaches the VFS handler through a *plain*
            // `write`, not `write_unlocked`: the requests handler stages a
            // Sealed Approval challenge and signs the x402/Tempo MPP credential
            // only under a grant-gated PetalHost signature. `write_unlocked` is
            // not a passkey signing lane. On a staged-challenge PermissionDenied
            // we run the request ceremony (writes approval.json to the shared
            // home) and retry the same plain write so the daemon consumes it.
            let confirm_params = serde_json::json!({
                "path": path,
                "bytes_b64": B64.encode(&body),
            });
            match try_ipc(&client, &client_endpoint, "write", confirm_params.clone()).await {
                Ok(Some(_)) => {
                    debug!(endpoint = %client_endpoint.display, "cli.request.confirm.via_ipc");
                    return Ok(());
                }
                Ok(None) => {
                    debug!("cli.request.confirm.via_inproc: no daemon socket present");
                    // Fall through to the in-process fallback below.
                }
                Err(e) if is_ipc_handler_permission_denied(&e) => {
                    // The daemon staged a Sealed Approval challenge on the first
                    // plain write. Build a read-only daemon (the serving daemon
                    // holds the home write lock) to run the request ceremony,
                    // which writes approval.json onto the shared home, then retry
                    // the same plain write so the daemon verifies and consumes it.
                    let ceremony_daemon = Daemon::from_home(home.clone())
                        .context("build daemon for request confirm ceremony")?;
                    let approved = sign_request_sealed_approval_if_challenged(
                        &ceremony_daemon,
                        &wallet,
                        &id,
                        None,
                    )
                    .await
                    .context("request confirm Sealed Approval ceremony")?;
                    if !approved {
                        return Err(anyhow::Error::new(e)).context(
                            "request confirm denied but no approval challenge was staged",
                        );
                    }
                    let retry = try_ipc(&client, &client_endpoint, "write", confirm_params)
                        .await
                        .with_context(|| {
                            format!("ipc request confirm retry via {}", client_endpoint.display)
                        })?;
                    if retry.is_some() {
                        debug!(endpoint = %client_endpoint.display, "cli.request.confirm.via_ipc.after_ceremony");
                        return Ok(());
                    }
                    bail!("request confirm retry did not reach the daemon after Sealed Approval");
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e)).with_context(|| {
                        format!("ipc request confirm via {}", client_endpoint.display)
                    });
                }
            }
            let (_home_permit, d) = build_write_daemon(home)?;
            let info = d.keystore.info(&wallet)?;
            let passkey_wallet = matches!(info.kind, bloom_keystore::WalletKind::PasskeyGated);
            match info.kind {
                bloom_keystore::WalletKind::PasskeyGated => {}
                _ => {
                    d.keystore
                        .unlock(&wallet, passphrase.as_deref().unwrap_or(""))?;
                }
            }
            match d.vfs.write(&p, &body).await {
                Ok(()) => {}
                Err(first_err)
                    if passkey_wallet && matches!(first_err, HandlerError::PermissionDenied) =>
                {
                    let intent = vfs_write_unlock_intent(
                        &wallet,
                        &p,
                        &body,
                        Some(bloom_proto::checksum_address(&info.address)),
                        Some(&d.home.outbox_dir()),
                        d.keystore
                            .raw_policy(&wallet)
                            .ok()
                            .map(|(p, _)| p)
                            .as_deref(),
                    );
                    if sign_request_sealed_approval_if_challenged(&d, &wallet, &id, Some(intent))
                        .await?
                    {
                        d.vfs
                            .write(&p, &body)
                            .await
                            .context("request confirm after Sealed Approval")?;
                    } else {
                        return Err(first_err).context("request confirm");
                    }
                }
                Err(e) => return Err(e).context("request confirm"),
            }
            Ok(())
        }
        Cmd::Request(RequestCmd::Body { id }) => {
            let d = Daemon::from_home(home).context("build daemon")?;
            let path = VfsPath::parse(&format!("/requests/{id}/response/body"))?;
            let bytes = d.vfs.read(&path).await.context("request body")?;
            std::io::Write::write_all(&mut std::io::stdout(), &bytes)?;
            Ok(())
        }
        Cmd::Request(RequestCmd::Receipt { id }) => {
            let d = Daemon::from_home(home).context("build daemon")?;
            let path = VfsPath::parse(&format!("/requests/{id}/receipt.json"))?;
            let bytes = d.vfs.read(&path).await.context("request receipt")?;
            std::io::Write::write_all(&mut std::io::stdout(), &bytes)?;
            Ok(())
        }
        Cmd::Wallet(WalletCmd::New {
            name,
            local,
            allow_passphrase_wallet,
            passphrase_file,
        }) => {
            let (_home_permit, d) = build_write_daemon(home)?;
            let info = if local {
                let pass = resolve_new_wallet_passphrase(
                    allow_passphrase_wallet,
                    passphrase_file.as_deref(),
                )?;
                let info = d.keystore.create_local(&name, &pass)?;
                let recovery = write_wallet_recovery(&d.home, &info.name, &pass)?;
                eprintln!(
                    "passphrase recovery file: {} (mode 0600) — store or delete after migrating to passkey",
                    recovery.display()
                );
                info
            } else {
                d.keystore.create_passkey(&name).await?
            };
            audit_wallet_created(
                &d.audit,
                &info.name,
                if local { "local" } else { "passkey" },
            );
            println!("created wallet '{}': {}", info.name, info.address);
            if set_default_wallet_if_empty(&d.home, &info.name)? {
                println!(
                    "default_wallet: {} (set in {})",
                    info.name,
                    d.home.config_path().display()
                );
            }
            if let Some(ref key) = info.recovery_key {
                acknowledge_recovery_key(&info.name, key);
            }
            // Show the deposit QR + address right away — a fresh wallet's first
            // need is to receive funds.
            println!("\n── deposit ──");
            commands::qr::print_deposit(&bloom_proto::checksum_address(&info.address));
            Ok(())
        }
        Cmd::Wallet(WalletCmd::Import {
            name,
            private_key,
            local,
            allow_passphrase_wallet,
            passphrase_file,
        }) => {
            let (_home_permit, d) = build_write_daemon(home)?;
            let info = if local {
                let pass = resolve_new_wallet_passphrase(
                    allow_passphrase_wallet,
                    passphrase_file.as_deref(),
                )?;
                let info = d.keystore.import_hex(&name, &private_key, &pass)?;
                let recovery = write_wallet_recovery(&d.home, &info.name, &pass)?;
                eprintln!(
                    "passphrase recovery file: {} (mode 0600) — store or delete after migrating to passkey",
                    recovery.display()
                );
                info
            } else {
                d.keystore.import_passkey(&name, &private_key).await?
            };
            audit_wallet_created(
                &d.audit,
                &info.name,
                if local { "local" } else { "passkey" },
            );
            println!("imported wallet '{}': {}", info.name, info.address);
            if set_default_wallet_if_empty(&d.home, &info.name)? {
                println!(
                    "default_wallet: {} (set in {})",
                    info.name,
                    d.home.config_path().display()
                );
            }
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
        Cmd::Wallet(WalletCmd::Portfolio { network }) => {
            let d = Daemon::from_home(home).context("build daemon")?;
            let client = hl_client(&d.home, &network)?;
            let wallets = d.keystore.list()?;
            let mut set = tokio::task::JoinSet::new();
            for (idx, info) in wallets.into_iter().enumerate() {
                let client = client.clone();
                set.spawn(async move {
                    let address = format!("{:?}", info.address).to_ascii_lowercase();
                    let res = client
                        .info(serde_json::json!({
                            "type": "clearinghouseState",
                            "user": address,
                        }))
                        .await;
                    (idx, info, address, res)
                });
            }
            let mut rows: Vec<(usize, WalletPortfolioRow)> = Vec::new();
            while let Some(joined) = set.join_next().await {
                let (idx, info, address, ch_result) = joined?;
                let (account_value, withdrawable, positions) = match ch_result {
                    Ok(v) => {
                        let av = v
                            .get("marginSummary")
                            .and_then(|m| m.get("accountValue"))
                            .and_then(|a| a.as_str())
                            .and_then(|s| s.parse::<f64>().ok())
                            .unwrap_or(0.0);
                        let wd = v
                            .get("withdrawable")
                            .and_then(|w| w.as_str())
                            .and_then(|s| s.parse::<f64>().ok())
                            .unwrap_or(0.0);
                        let positions: Vec<String> = v
                            .get("assetPositions")
                            .and_then(|a| a.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|ap| {
                                        ap.get("position")
                                            .and_then(|p| p.get("coin"))
                                            .and_then(|c| c.as_str())
                                            .map(|s| s.to_string())
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        (av, wd, positions)
                    }
                    Err(_) => (0.0, 0.0, Vec::new()),
                };
                rows.push((
                    idx,
                    WalletPortfolioRow {
                        name: info.name,
                        address,
                        account_value,
                        withdrawable,
                        positions,
                    },
                ));
            }
            rows.sort_by_key(|(i, _)| *i);
            let table: Vec<WalletPortfolioRow> = rows.into_iter().map(|(_, r)| r).collect();
            print_portfolio_table(&table, &network);
            Ok(())
        }
        Cmd::Wallet(WalletCmd::Address { name, qr, qr_out }) => {
            let d = Daemon::from_home(home).context("build daemon")?;
            // Read-only: an unsigned/stale passkey policy must not block this.
            let info = d.keystore.info_unverified(&name)?;
            let address = bloom_proto::checksum_address(&info.address);
            if let Some(path) = qr_out {
                match commands::qr::render_qr_svg(&address) {
                    Some(svg) => {
                        std::fs::write(&path, svg)
                            .with_context(|| format!("write QR SVG to {}", path.display()))?;
                        eprintln!("wrote deposit QR SVG: {}", path.display());
                    }
                    None => anyhow::bail!("address too large to encode as a QR code"),
                }
            }
            if qr && let Some(code) = commands::qr::render_qr(&address) {
                println!("{code}");
            }
            println!("{address}");
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
                intent.wallet_address = address.clone();
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
                d.keystore.lock(&name);
                let reviewed_policy = d
                    .keystore
                    .unlock_passkey_with_intent_and_policy_edit(
                        &name,
                        Some(intent),
                        Some(policy_toml.clone()),
                    )
                    .await?;
                let final_policy = reviewed_policy.unwrap_or(policy_toml);
                toml::from_str::<bloom_proto::Policy>(&final_policy)
                    .context("reviewed policy.toml is invalid")?;
                if final_policy != std::fs::read_to_string(&policy_path).unwrap_or_default() {
                    std::fs::write(&policy_path, final_policy.as_bytes())
                        .with_context(|| format!("write {}", policy_path.display()))?;
                }
                let final_digest = blake3::hash(final_policy.as_bytes()).to_hex().to_string();
                let mut reviewed_intent = CeremonyIntent::new(
                    &name,
                    "Sign Wallet Policy",
                    CeremonyIntentKind::SignPolicy,
                );
                reviewed_intent.wallet_address = address;
                reviewed_intent.summary_lines = vec![
                    format!("Review rules for wallet '{name}'."),
                    "This does not move money or place a trade.".into(),
                    "After approval, Bloom uses these rules to decide what is allowed.".into(),
                    format!("Policy digest: {final_digest}"),
                ];
                reviewed_intent.policy_lines = final_policy.lines().map(str::to_string).collect();
                reviewed_intent.risk_lines = vec![
                    "Approving these rules can change what Bloom allows later.".into(),
                    "The OS passkey prompt only proves your presence; review the details on this page."
                        .into(),
                ];
                reviewed_intent.artifact_paths = vec![policy_path.display().to_string()];
                reviewed_intent.canonical_subject = serde_json::json!({
                    "kind": "sign_policy",
                    "wallet": name,
                    "policy_path": policy_path,
                    "policy_blake3": final_digest,
                });
                if let Ok(bytes) = serde_json::to_vec_pretty(&reviewed_intent) {
                    let review_path = home.keystore_dir().join(&name).join("policy.review.json");
                    let _ = std::fs::write(&review_path, bytes);
                }
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
            let body = match intent {
                Some(s) => s,
                None => {
                    let mut buf = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
                    buf
                }
            };
            let path = format!("/wallets/{wallet}/chains/{chain}/outbox/new.tx");
            let client = IpcClient::new(&client_endpoint.socket);
            let ipc_res = try_ipc(
                &client,
                &client_endpoint,
                "write",
                serde_json::json!({ "path": path, "bytes_b64": B64.encode(body.as_bytes()) }),
            )
            .await
            .with_context(|| format!("ipc wallet stage via {}", client_endpoint.display))?;
            if ipc_res.is_some() {
                debug!(endpoint = %client_endpoint.display, "cli.wallet.stage.via_ipc");
                return Ok(());
            }
            debug!("cli.wallet.stage.via_inproc: no daemon socket present");
            let (home_permit, d) = build_write_daemon(home)?;
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
            passphrase: _,
            text,
        }) => {
            let path = format!("/wallets/{wallet}/chains/{chain}/outbox/pending/{id}/confirm");
            let body = text.into_bytes();
            let client = IpcClient::new(&client_endpoint.socket);
            // Daemon-backed confirm must use the plain VFS write lane. The
            // wallets handler/tx engine stages Sealed Approval challenges and
            // later consumes approval.json; `write_unlocked` is intentionally
            // not a passkey signing lane.
            let confirm_params = serde_json::json!({
                "path": path,
                "bytes_b64": B64.encode(&body),
            });
            match try_ipc(&client, &client_endpoint, "write", confirm_params.clone()).await {
                Ok(Some(_)) => {
                    debug!(endpoint = %client_endpoint.display, "cli.wallet.confirm.via_ipc");
                    return Ok(());
                }
                Ok(None) => {
                    debug!("cli.wallet.confirm.via_inproc: no daemon socket present");
                    // Fall through to the in-process fallback below.
                }
                Err(e) if is_ipc_handler_permission_denied(&e) => {
                    // The serving daemon staged approval_challenge.json on the
                    // first plain write. Build a read-only daemon in this
                    // process to run the foreground ceremony against the shared
                    // home, write approval.json, then retry the same write so
                    // the serving daemon verifies and broadcasts.
                    let ceremony_daemon = Daemon::from_home(home.clone())
                        .context("build daemon for wallet confirm ceremony")?;
                    let approved = sign_outbox_sealed_approval_if_challenged(
                        &ceremony_daemon,
                        &wallet,
                        &chain,
                        &id,
                        None,
                    )
                    .await
                    .context("wallet confirm Sealed Approval ceremony")?;
                    if !approved {
                        return Err(anyhow::Error::new(e))
                            .context("wallet confirm denied but no approval challenge was staged");
                    }
                    let retry = try_ipc(&client, &client_endpoint, "write", confirm_params)
                        .await
                        .with_context(|| {
                            format!("ipc wallet confirm retry via {}", client_endpoint.display)
                        })?;
                    if retry.is_some() {
                        debug!(endpoint = %client_endpoint.display, "cli.wallet.confirm.via_ipc.after_ceremony");
                        return Ok(());
                    }
                    bail!("wallet confirm retry did not reach the daemon after Sealed Approval");
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e)).with_context(|| {
                        format!("ipc wallet confirm via {}", client_endpoint.display)
                    });
                }
            }
            let text = String::from_utf8(body).expect("wallet confirm text originated as UTF-8");
            let (home_permit, d) = build_write_daemon(home)?;
            let info = d.keystore.info(&wallet)?;
            let passkey_wallet = info.kind == bloom_keystore::WalletKind::PasskeyGated;
            let mut approval_intent: Option<CeremonyIntent> = None;
            if passkey_wallet {
                // Build the review intent from the staged outbox entry. An
                // EVM staged tx is byte-immutable for the user-risking fields
                // (chain/to/value/data/nonce fixed at stage time), so the
                // intent faithfully reflects what will be signed.
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
                            format!("Sign {} Transaction", s.chain),
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
                            it = it.policy(format!("[{:?}] {}: {}", c.outcome, c.rule, c.message));
                        }
                        if let Ok(bytes) = serde_json::to_vec_pretty(&it) {
                            let _ = d.tx_engine.outbox.write_artefact(
                                &entry.dir,
                                "review_intent.json",
                                &bytes,
                            );
                        }
                        approval_intent = Some(it.clone());
                        it
                    });
                let _ = intent;
            }
            let info = d.keystore.info(&wallet)?;
            let client = d
                .chains
                .get(&chain)
                .with_context(|| format!("chain '{}'", chain))?;
            let confirm_once = || {
                d.tx_engine.confirm(
                    &home_permit,
                    &wallet,
                    &chain,
                    &id,
                    &client,
                    &info.policy,
                    &text,
                )
            };
            let staged = match confirm_once().await {
                Ok(staged) => staged,
                Err(TxEngineError::ApprovalRequired(requirement)) if passkey_wallet => {
                    if sign_outbox_sealed_approval_if_challenged(
                        &d,
                        &wallet,
                        &chain,
                        &id,
                        approval_intent.clone(),
                    )
                    .await?
                    {
                        confirm_once().await?
                    } else {
                        return Err(TxEngineError::ApprovalRequired(requirement).into());
                    }
                }
                Err(e) => return Err(e.into()),
            };
            println!(
                "broadcast {} hash={}",
                staged.id,
                staged.tx_hash.as_deref().unwrap_or("?")
            );
            Ok(())
        }
        Cmd::Wallet(WalletCmd::Cancel {
            wallet,
            chain,
            id,
            passphrase,
            text,
        }) => {
            wallet_outbox_action_vfs_write(WalletOutboxActionWrite {
                home,
                client_endpoint: &client_endpoint,
                wallet: wallet.clone(),
                chain,
                id: id.clone(),
                action: "cancel",
                body: text.into_bytes(),
                passphrase,
            })
            .await?;
            println!("cancel submitted for {id}");
            Ok(())
        }
        Cmd::Wallet(WalletCmd::Replace {
            wallet,
            chain,
            id,
            intent,
            passphrase,
        }) => {
            let body = match intent {
                Some(s) => s,
                None => {
                    let mut buf = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
                    buf
                }
            };
            wallet_outbox_action_vfs_write(WalletOutboxActionWrite {
                home,
                client_endpoint: &client_endpoint,
                wallet,
                chain,
                id: id.clone(),
                action: "replace",
                body: body.into_bytes(),
                passphrase,
            })
            .await?;
            println!("replacement submitted for {id}");
            Ok(())
        }
        Cmd::Wallet(WalletCmd::ConfirmBatch {
            wallet,
            txs,
            passphrase: _,
            text,
            policy_session,
        }) => {
            if txs.is_empty() {
                bail!("confirm-batch needs at least one tx ref like base:0001-abc");
            }
            let refs: Vec<(String, String)> = txs
                .iter()
                .map(|s| parse_batch_tx_ref(s))
                .collect::<Result<Vec<_>>>()?;
            let (home_permit, d) = build_write_daemon(home)?;
            let info = d.keystore.info(&wallet)?;

            let mut entries = Vec::new();
            for (chain, id) in &refs {
                let entry = d
                    .tx_engine
                    .outbox
                    .read(&wallet, chain, id)
                    .with_context(|| format!("read pending tx {chain}:{id}"))?;
                if entry.staged.status != bloom_proto::TxStatus::Pending {
                    bail!(
                        "tx {}:{} is {}, not pending",
                        chain,
                        id,
                        entry.staged.status
                    );
                }
                entries.push(entry);
            }

            let mut approval_intent: Option<CeremonyIntent> = None;
            let passkey_wallet = info.kind == bloom_keystore::WalletKind::PasskeyGated;
            if info.kind == bloom_keystore::WalletKind::PasskeyGated {
                if !policy_session {
                    bail!(
                        "passkey confirm-batch requires --policy-session so the one ceremony is explicit"
                    );
                }
                let mut intent = CeremonyIntent::new(
                    &wallet,
                    "Authorize Batch Transaction Session",
                    CeremonyIntentKind::EvmTransaction,
                )
                .with_address(bloom_proto::checksum_address(&info.address))
                .summary(format!(
                    "Broadcast {} staged transaction(s).",
                    entries.len()
                ))
                .summary("Policy is rechecked for every transaction before broadcast.")
                .risk("One passkey approval unlocks this process to sign this exact batch.")
                .risk("If a transaction fails, later transactions are not attempted.");

                let mut subjects = Vec::new();
                for entry in &entries {
                    let s = &entry.staged;
                    let data_hash = blake3::hash(s.data_hex.as_bytes()).to_hex().to_string();
                    intent = intent
                        .summary(format!(
                            "{}:{} chain={} nonce={} to={} value={} wei data={}B",
                            s.chain,
                            s.id,
                            s.chain_id,
                            s.nonce,
                            s.to,
                            s.value_wei,
                            s.data_hex.len() / 2
                        ))
                        .artifact(entry.dir.display().to_string());
                    for c in &s.policy_checks {
                        intent = intent.policy(format!(
                            "{}:{} [{:?}] {}: {}",
                            s.chain, s.id, c.outcome, c.rule, c.message
                        ));
                    }
                    subjects.push(serde_json::json!({
                        "id": s.id,
                        "chain": s.chain,
                        "chain_id": s.chain_id,
                        "from": s.from,
                        "to": s.to,
                        "value_wei": s.value_wei,
                        "nonce": s.nonce,
                        "data_blake3": data_hash,
                    }));
                }
                intent = intent.subject(serde_json::json!({
                    "action": "evm_transaction_batch",
                    "wallet": wallet,
                    "txs": subjects,
                    "confirm_text": text,
                }));

                let review_bytes = serde_json::to_vec_pretty(&intent)?;
                for entry in &entries {
                    let _ = d.tx_engine.outbox.write_artefact(
                        &entry.dir,
                        "review_intent.json",
                        &review_bytes,
                    );
                }
                approval_intent = Some(intent);
            }

            let info = d.keystore.info(&wallet)?;
            for (chain, id) in refs {
                let client = d
                    .chains
                    .get(&chain)
                    .with_context(|| format!("chain '{}'", chain))?;
                let confirm_once = || {
                    d.tx_engine.confirm(
                        &home_permit,
                        &wallet,
                        &chain,
                        &id,
                        &client,
                        &info.policy,
                        &text,
                    )
                };
                let staged = match confirm_once().await {
                    Ok(staged) => staged,
                    Err(TxEngineError::ApprovalRequired(requirement)) if passkey_wallet => {
                        if sign_outbox_sealed_approval_if_challenged(
                            &d,
                            &wallet,
                            &chain,
                            &id,
                            approval_intent.clone(),
                        )
                        .await
                        .with_context(|| format!("sign Sealed Approval for {chain}:{id}"))?
                        {
                            confirm_once()
                                .await
                                .with_context(|| format!("confirm {chain}:{id}"))?
                        } else {
                            return Err(TxEngineError::ApprovalRequired(requirement).into());
                        }
                    }
                    Err(e) => {
                        return Err(anyhow::Error::from(e))
                            .with_context(|| format!("confirm {chain}:{id}"));
                    }
                };
                println!(
                    "broadcast {}:{} hash={}",
                    chain,
                    staged.id,
                    staged.tx_hash.as_deref().unwrap_or("?")
                );
            }
            Ok(())
        }
        Cmd::Serve { endpoint, mount } => {
            eprintln!("{ALPHA_DISCLOSURE}");
            let (_home_permit, d) = build_write_daemon(home.clone())?;
            github_source::ensure_preinstalled_petals(&home, &d)
                .context("provision configured pre-installed Petals before serving")?;
            // Spawn the outbox expiry sweeper for the lifetime of the
            // serve command (fix #3). The handle is dropped (and the task
            // signalled to stop) right before the function returns.
            let sweeper = d.spawn_background_tasks();
            // Interaction Mode 3: own and serve the mounted-VFS Sealed Approval
            // ceremony endpoint (`ceremony_url` in approval_challenge.json).
            // The daemon never opens a browser; it only serves the URL a
            // deliberate client opens.
            let ceremony = bloom_daemon::ceremony_server::spawn(&d)
                .await
                .context("bind sealed approval ceremony server")?;
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
                .with_petals(d.petals.clone())
                .with_auth_services(d.auth_services.clone())
                .with_signer_cache(d.signer_cache.clone());
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
            ceremony.shutdown().await;
            sweeper.shutdown().await;
            d.shutdown().await;
            serve_result?;
            unmount_result?;
            info!("cli.serve.shutdown_complete");
            println!("shutting down");
            Ok(())
        }
        Cmd::Hyperliquid(cmd) => handle_hyperliquid(home, &client_endpoint, cmd).await,
        Cmd::Update(cmd) => handle_update(&home, cmd).await,
        Cmd::Petals(cmd) => {
            let _home_permit = HomeWritePermit::acquire(&home)?;
            run_petals(home, cmd).await
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
    let cmd = match cmd {
        PetalsCmd::Build { package_dir, out } => {
            if let Some(out) = out.as_deref() {
                reject_archive_output_inside_package(&package_dir, out)?;
            }
            let package = bloom_petals::package::build_petal_package_dir(&package_dir)
                .with_context(|| format!("build Petal package {package_dir}"))?;
            let consent = bloom_petals::package::petal_consent_summary(&package)
                .context("build Petal consent summary")?;
            println!("hash: {}", package.hash);
            println!("contract: {}", bloom_petals::package::ROUTE_PACKAGE);
            println!(
                "wit_digest: {}",
                bloom_petals::package::contract_wit_digest()
            );
            println!("petal_mount: petals/{}/", package.name);
            println!("routes: {}", package.route_index.routes.len());
            println!("artifacts: {package_dir}/artifacts");
            print_petal_consent(&consent);
            if let Some(out) = out {
                let file =
                    std::fs::File::create(&out).with_context(|| format!("create archive {out}"))?;
                package
                    .write_petal_tar(file)
                    .with_context(|| format!("write archive {out}"))?;
                println!("archive: {out}");
            }
            return Ok(());
        }
        other => other,
    };

    let d = Daemon::from_home(home.clone()).context("build daemon")?;
    match cmd {
        PetalsCmd::Install { path, ref_ } => {
            if let Some(repo) = github_source::parse_github_install_url(&path)? {
                let installed =
                    github_source::install_github_source(&home, &d, &repo, ref_.as_deref())?;
                println!();
                println!("hash: {}", installed.result.hash);
                println!("mode: petal");
                println!("size: {} bytes", installed.result.size);
                if installed.result.already_present {
                    println!("note: already installed");
                }
                if let Some(app) = &installed.meta.petal {
                    println!("petal_mount: petals/{}/", app.name);
                }
                println!("routes: {}", installed.index.routes.len());
                println!(
                    "source: {}/{}@{}",
                    installed.provenance.owner,
                    installed.provenance.repo,
                    installed
                        .provenance
                        .selected_tag
                        .as_deref()
                        .unwrap_or(&installed.provenance.requested_ref)
                );
                println!("resolved_commit: {}", installed.provenance.resolved_commit);
                print_petal_consent(&installed.consent);
                return Ok(());
            }

            if ref_.is_some() {
                bail!("--ref is only supported for trusted GitHub source installs");
            }
            let path_meta = std::fs::metadata(&path).with_context(|| format!("stat {path}"))?;
            let is_petal_dir = path_meta.is_dir();
            if !is_petal_dir && !path.ends_with(".petal.tar") {
                bail!(
                    "petals install only accepts Petal package directories, .petal.tar archives, or trusted GitHub source repositories"
                );
            }
            let consent_package = if is_petal_dir {
                bloom_petals::package::PreparedPetalPackage::from_dir(&path)
                    .with_context(|| format!("read Petal package dir {path}"))?
            } else {
                bloom_petals::package::PreparedPetalPackage::from_petal_tar(&path)
                    .with_context(|| format!("read Petal package archive {path}"))?
            };
            let mut consent = bloom_petals::package::petal_consent_summary(&consent_package)
                .context("build app consent summary")?;
            apply_configured_petal_endpoints(&d, &mut consent)?;
            let (result, meta, index) = if is_petal_dir {
                d.petals
                    .store()
                    .install_petal_package_dir(&path)
                    .with_context(|| format!("install Petal package dir {path}"))?
            } else {
                d.petals
                    .store()
                    .install_petal_package_tar(&path)
                    .with_context(|| format!("install Petal package archive {path}"))?
            };
            println!("hash: {}", result.hash);
            println!("mode: petal");
            println!("size: {} bytes", result.size);
            if result.already_present {
                println!("note: already installed");
            }
            if let Some(app) = &meta.petal {
                println!("petal_mount: petals/{}/", app.name);
            }
            println!("routes: {}", index.routes.len());
            print_petal_consent(&consent);
            Ok(())
        }
        PetalsCmd::Build { .. } => {
            unreachable!("Petal build commands are handled before daemon startup")
        }
        PetalsCmd::Ls => {
            let package_hashes = d
                .petals
                .store()
                .list_package_hashes()
                .context("list Petal packages")?;
            if package_hashes.is_empty() {
                println!("(no petals installed)");
                return Ok(());
            }
            for h in package_hashes {
                let meta = d.petals.store().load_meta(&h).context("load meta")?;
                let app = meta
                    .petal
                    .as_ref()
                    .map(|app| format!("  app=petals/{}/", app.name))
                    .unwrap_or_default();
                let source = meta.source.as_ref().map_or_else(String::new, |source| {
                    let selected = source
                        .selected_tag
                        .as_deref()
                        .unwrap_or(&source.requested_ref);
                    format!("  source={}/{}@{}", source.owner, source.repo, selected)
                });
                println!(
                    "{}  {:<7}  {:>7}  caps=[]  name=-{}{}",
                    &meta.hash[..bloom_petals::store::HASH_PREFIX_LEN],
                    "app",
                    meta.size,
                    app,
                    source
                );
            }
            Ok(())
        }
        PetalsCmd::Uninstall { target } => {
            let removed = d.petals.uninstall(&target).context("uninstall petal")?;
            if removed {
                println!("removed {target}");
            } else {
                println!("not installed: {target}");
            }
            Ok(())
        }
    }
}

fn print_petal_consent(summary: &bloom_petals::package::PetalConsentSummary) {
    println!("consent:");
    if let Some(package_summary) = &summary.package_summary {
        println!("  summary: {package_summary}");
    }
    println!("  docs: {}", summary.docs.join(", "));
    if !summary.capabilities.is_empty() {
        println!("  capabilities: {}", summary.capabilities.join(", "));
    }
    if !summary.network.is_empty() {
        println!("  network:");
        for rule in &summary.network {
            println!("{}", format_petal_consent_net_rule(rule));
        }
    }
    if !summary.sign_intents.is_empty() {
        println!("  signing_intents: {}", summary.sign_intents.join(", "));
    }
    if !summary.store_namespaces.is_empty() {
        println!("  private_store:");
        for ns in &summary.store_namespaces {
            let visibility = if ns.secret { "secret" } else { "private" };
            println!("    - {} {}", ns.namespace, visibility);
        }
    }
    if !summary.routes.is_empty() {
        println!("  routes:");
        for route in &summary.routes {
            let ops = route
                .ops
                .iter()
                .map(|op| format!("{op:?}").to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join(",");
            let mut flags = Vec::new();
            if route.side_effecting_read {
                flags.push("side_effecting_read".to_string());
            }
            if route.write_async {
                flags.push("write_async".to_string());
            }
            if let Some(ttl) = route.cache_ttl_ms {
                flags.push(format!("cache_ttl_ms={ttl}"));
            }
            let caps = if route.required_caps.is_empty() {
                "-".to_string()
            } else {
                route.required_caps.join(",")
            };
            if flags.is_empty() {
                println!("    - {} ops=[{}] caps=[{}]", route.path, ops, caps);
            } else {
                println!(
                    "    - {} ops=[{}] caps=[{}] flags=[{}]",
                    route.path,
                    ops,
                    caps,
                    flags.join(",")
                );
            }
        }
    }
}

fn apply_configured_petal_endpoints(
    daemon: &Daemon,
    summary: &mut bloom_petals::package::PetalConsentSummary,
) -> Result<()> {
    let bindings = daemon
        .config
        .petals
        .runtime
        .get(&summary.name)
        .map(|app| &app.endpoints)
        .cloned()
        .unwrap_or_default();
    bloom_petals::package::apply_petal_consent_endpoint_bindings(summary, &bindings)
        .context("apply configured Petal endpoint bindings")
}

fn format_petal_consent_net_rule(rule: &bloom_petals::package::PetalConsentNetRule) -> String {
    let binding = rule
        .binding
        .as_deref()
        .map(|binding| format!(" binding={binding}"))
        .unwrap_or_default();
    let effective = rule
        .effective_origin
        .as_deref()
        .map(|origin| format!(" effective_origin={origin}"))
        .unwrap_or_default();
    format!(
        "    - declared_host={}{}{} methods=[{}] paths=[{}]",
        rule.host,
        binding,
        effective,
        rule.methods.join(","),
        rule.paths.join(",")
    )
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
    wallet_policy_toml: Option<&str>,
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

    if is_policy_session_new(wallet, path) {
        let mut intent = bloom_proto::policy_session_mint_intent(wallet, &path_s, body);
        intent.wallet_address = wallet_address;
        return intent;
    }

    if let Some(intent) =
        outbox_confirm_unlock_intent(wallet, &path_s, segs, wallet_address.clone(), outbox_root)
    {
        return intent;
    }

    if let Some(intent) = bloom_proto::hyperliquid_write_unlock_intent(
        wallet,
        &path_s,
        segs,
        body,
        wallet_address.clone(),
        wallet_policy_toml,
    ) {
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
    let defi_review = find_defi_review_for_outbox(outbox_root?, wallet, chain, id);
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

pub(crate) async fn sign_outbox_sealed_approval_if_challenged(
    d: &Daemon,
    wallet: &str,
    chain: &str,
    id: &str,
    intent: Option<CeremonyIntent>,
) -> Result<bool> {
    let entry = d
        .tx_engine
        .outbox
        .read(wallet, chain, id)
        .with_context(|| format!("read pending outbox entry {wallet}/{chain}/{id}"))?;
    let challenge_path = entry.dir.join("approval_challenge.json");
    if !challenge_path.exists() {
        return Ok(false);
    }

    let challenge: ApprovalChallenge = serde_json::from_slice(
        &std::fs::read(&challenge_path)
            .with_context(|| format!("read {}", challenge_path.display()))?,
    )
    .with_context(|| format!("parse {}", challenge_path.display()))?;
    // Fail fast if the challenge does not refer to a real sealed action for
    // this wallet; full binding is re-verified daemon-side at consume time.
    let sealed = d
        .auth_services
        .require_store()
        .context("Sealed Approval auth store is not wired")?
        .sealed_intent(&challenge.intent_hash)
        .await
        .context("read sealed intent for approval challenge")?;
    anyhow::ensure!(
        sealed.envelope.header.wallet == wallet,
        "approval challenge wallet mismatch: sealed action belongs to '{}'",
        sealed.envelope.header.wallet
    );

    let review_session_id = if challenge.assurance == AssuranceLevel::Hardened {
        let review_session_id = sealed_review_session_id(&challenge);
        d.auth_services
            .require_writer()
            .context("Sealed Approval auth store writer is not wired")?
            .issue_review_session(
                &review_session_id,
                &challenge.surface,
                &challenge.action_id,
                challenge.expiry_ms,
                cli_now_ms(),
            )
            .await
            .context("issue hardened review session")?;
        Some(review_session_id)
    } else {
        None
    };

    // Echo every daemon-issued challenge field faithfully (§5.7 step 10);
    // any drift is rejected at consume time.
    let unsigned = UnsignedApproval::for_challenge(
        &challenge,
        SignerTransport::BrowserWebauthn,
        None,
        review_session_id,
    );
    let (_grant, approval) = bloom_daemon::sealed_ceremony::run_sealed_approval_ceremony(
        &d.keystore,
        &d.auth_services,
        unsigned,
        intent,
        cli_now_ms(),
        d.signer_cache.as_ref(),
    )
    .await
    .context("run sealed approval browser ceremony")?;
    let approval_path = entry.dir.join("approval.json");
    std::fs::write(
        &approval_path,
        serde_json::to_vec_pretty(&approval).context("encode Sealed Approval")?,
    )
    .with_context(|| format!("write {}", approval_path.display()))?;
    Ok(true)
}

async fn sign_request_sealed_approval_if_challenged(
    d: &Daemon,
    wallet: &str,
    id: &str,
    intent: Option<CeremonyIntent>,
) -> Result<bool> {
    let id = resolve_pending_request_id(d.home.root(), id)
        .with_context(|| format!("resolve pending request id {id}"))?;
    let dir = d.home.root().join("requests").join("pending").join(&id);
    let challenge_path = dir.join("approval_challenge.json");
    if !challenge_path.exists() {
        return Ok(false);
    }

    let challenge: ApprovalChallenge = serde_json::from_slice(
        &std::fs::read(&challenge_path)
            .with_context(|| format!("read {}", challenge_path.display()))?,
    )
    .with_context(|| format!("parse {}", challenge_path.display()))?;
    let sealed = d
        .auth_services
        .require_store()
        .context("Sealed Approval auth store is not wired")?
        .sealed_intent(&challenge.intent_hash)
        .await
        .context("read sealed intent for request approval challenge")?;
    anyhow::ensure!(
        sealed.envelope.header.wallet == wallet,
        "approval challenge wallet mismatch: sealed action belongs to '{}'",
        sealed.envelope.header.wallet
    );

    let review_session_id = if challenge.assurance == AssuranceLevel::Hardened {
        let review_session_id = sealed_review_session_id(&challenge);
        d.auth_services
            .require_writer()
            .context("Sealed Approval auth store writer is not wired")?
            .issue_review_session(
                &review_session_id,
                &challenge.surface,
                &challenge.action_id,
                challenge.expiry_ms,
                cli_now_ms(),
            )
            .await
            .context("issue hardened request review session")?;
        Some(review_session_id)
    } else {
        None
    };

    let unsigned = UnsignedApproval::for_challenge(
        &challenge,
        SignerTransport::BrowserWebauthn,
        None,
        review_session_id,
    );
    let (_grant, approval) = bloom_daemon::sealed_ceremony::run_sealed_approval_ceremony(
        &d.keystore,
        &d.auth_services,
        unsigned,
        intent,
        cli_now_ms(),
        d.signer_cache.as_ref(),
    )
    .await
    .context("run request sealed approval browser ceremony")?;
    let approval_path = dir.join("approval.json");
    std::fs::write(
        &approval_path,
        serde_json::to_vec_pretty(&approval).context("encode request Sealed Approval")?,
    )
    .with_context(|| format!("write {}", approval_path.display()))?;
    Ok(true)
}

fn resolve_pending_request_id(home: &Path, id: &str) -> Result<String> {
    if id != "latest" {
        return Ok(id.to_string());
    }
    let latest_path = home.join("requests").join("latest");
    let latest = std::fs::read_to_string(&latest_path)
        .with_context(|| format!("read {}", latest_path.display()))?;
    let (state, id) = latest
        .trim()
        .split_once('/')
        .context("requests/latest should be formatted as state/id")?;
    if state != "pending" {
        bail!("latest request is {state}/{id}, not pending");
    }
    Ok(id.to_string())
}

pub(crate) fn sealed_review_session_id(challenge: &ApprovalChallenge) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.review_session.v1");
    hasher.update(challenge.surface.as_bytes());
    hasher.update(&[0]);
    hasher.update(challenge.action_id.as_bytes());
    hasher.update(&[0]);
    hasher.update(challenge.intent_hash.as_bytes());
    hasher.update(&[0]);
    hasher.update(challenge.server_nonce.as_bytes());
    format!("review-{}", hasher.finalize().to_hex())
}

fn cli_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
    chain: &str,
    outbox_id: &str,
) -> Option<DefiReview> {
    let home = if outbox_root.file_name().is_some_and(|name| name == "outbox") {
        outbox_root.parent().unwrap_or(outbox_root)
    } else {
        outbox_root
    };
    let sessions = home.join("defi").join(wallet).join("sessions");
    for entry in std::fs::read_dir(sessions).ok()? {
        // Skip an unreadable/corrupt sibling rather than aborting the whole scan.
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        // Outbox ids are scoped per chain, so bind the review to the chain
        // being confirmed — a different chain's session must not shadow it.
        let chain_matches = value.get("chain").and_then(|v| v.as_str()) == Some(chain);
        let staged = value
            .get("staged_ids")
            .and_then(|v| v.as_array())
            .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(outbox_id)));
        if !chain_matches || !staged {
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

fn is_policy_session_new(wallet: &str, path: &VfsPath) -> bool {
    matches!(
        path.segments(),
        [root, w, ps, leaf]
            if root == "wallets" && w == wallet && ps == "policy-session" && leaf == "new"
    )
}

struct WalletOutboxActionWrite<'a> {
    home: HomeDir,
    client_endpoint: &'a ResolvedEndpoint,
    wallet: String,
    chain: String,
    id: String,
    action: &'a str,
    body: Vec<u8>,
    passphrase: Option<String>,
}

async fn wallet_outbox_action_vfs_write(input: WalletOutboxActionWrite<'_>) -> Result<()> {
    let WalletOutboxActionWrite {
        home,
        client_endpoint,
        wallet,
        chain,
        id,
        action,
        body,
        passphrase,
    } = input;
    if !matches!(action, "cancel" | "replace") {
        bail!("unsupported wallet outbox action '{action}'");
    }
    let path = format!("/wallets/{wallet}/chains/{chain}/outbox/pending/{id}/{action}");
    let client = IpcClient::new(&client_endpoint.socket);
    let ipc_res = try_ipc(
        &client,
        client_endpoint,
        "write_unlocked",
        serde_json::json!({
            "path": path,
            "bytes_b64": B64.encode(&body),
            "wallet": &wallet,
            "passphrase": passphrase.as_deref(),
        }),
    )
    .await
    .with_context(|| format!("ipc wallet outbox {action} via {}", client_endpoint.display))?;
    if ipc_res.is_some() {
        debug!(endpoint = %client_endpoint.display, action, "cli.wallet.outbox_action.via_ipc");
        return Ok(());
    }

    debug!(
        action,
        "cli.wallet.outbox_action.via_inproc: no daemon socket present"
    );
    let p = VfsPath::parse(&path)?;
    let (_home_permit, d) = build_write_daemon(home)?;
    let info = d.keystore.info(&wallet)?;
    match info.kind {
        bloom_keystore::WalletKind::PasskeyGated => {
            bail!(PASSKEY_WRITE_UNLOCKED_DISABLED);
        }
        _ => {
            d.keystore
                .unlock(&wallet, passphrase.as_deref().unwrap_or(""))?;
        }
    }
    d.vfs
        .write(&p, &body)
        .await
        .with_context(|| format!("wallet outbox {action}"))?;
    Ok(())
}

fn request_body_with_wallet(mut request: String, wallet: Option<&str>) -> String {
    let Some(wallet) = wallet else {
        return request;
    };
    if let Ok(mut value) = request.parse::<toml::Value>()
        && value.get("url").is_some()
        && let Some(table) = value.as_table_mut()
    {
        table.insert("wallet".into(), toml::Value::String(wallet.to_string()));
        return toml::to_string_pretty(&value).unwrap_or_else(|_| {
            let mut fallback = request.clone();
            fallback.push('\n');
            fallback.push_str(&format!("wallet = \"{wallet}\""));
            fallback
        });
    }
    let Some(first_newline) = request.find('\n') else {
        request.push(' ');
        request.push_str(&format!("wallet={wallet}"));
        return request;
    };
    request.insert_str(first_newline, &format!(" wallet={wallet}"));
    request
}

fn parse_batch_tx_ref(s: &str) -> Result<(String, String)> {
    let (chain, id) = s
        .split_once(':')
        .with_context(|| format!("tx ref '{s}' must be chain:id"))?;
    let chain = chain.trim();
    let id = id.trim();
    if chain.is_empty() || id.is_empty() {
        bail!("tx ref '{s}' must include non-empty chain and id");
    }
    Ok((chain.to_string(), id.to_string()))
}

async fn handle_hyperliquid(
    home: HomeDir,
    endpoint: &ResolvedEndpoint,
    cmd: HyperliquidCmd,
) -> Result<()> {
    match cmd {
        HyperliquidCmd::Account { user, network } => {
            print_hl_info(&home, &network, hl_user_req("clearinghouseState", &user)).await
        }
        HyperliquidCmd::SpotState { user, network } => {
            print_hl_info(
                &home,
                &network,
                hl_user_req("spotClearinghouseState", &user),
            )
            .await
        }
        HyperliquidCmd::OpenOrders { user, network } => {
            print_hl_info(&home, &network, hl_user_req("openOrders", &user)).await
        }
        HyperliquidCmd::Fills { user, network } => {
            print_hl_info(&home, &network, hl_user_req("userFills", &user)).await
        }
        HyperliquidCmd::Funding {
            user,
            coin,
            start_time,
            end_time,
            network,
        } => {
            let mut req = serde_json::json!({
                "type": "userFunding",
                "user": user.to_ascii_lowercase(),
                "coin": coin,
            });
            let obj = req.as_object_mut().expect("json object");
            if let Some(start) = start_time {
                obj.insert("startTime".into(), serde_json::json!(start));
            }
            if let Some(end) = end_time {
                obj.insert("endTime".into(), serde_json::json!(end));
            }
            print_hl_info(&home, &network, req).await
        }
        HyperliquidCmd::Book { coin, network } => {
            print_hl_info(
                &home,
                &network,
                serde_json::json!({"type": "l2Book", "coin": coin}),
            )
            .await
        }
        HyperliquidCmd::Candles {
            coin,
            interval,
            start_time,
            end_time,
            network,
        } => {
            print_hl_info(
                &home,
                &network,
                serde_json::json!({
                    "type": "candleSnapshot",
                    "req": {
                        "coin": coin,
                        "interval": interval,
                        "startTime": start_time,
                        "endTime": end_time,
                    }
                }),
            )
            .await
        }
        HyperliquidCmd::Metadata { kind, network } => {
            let body = match kind.as_str() {
                "perp" => serde_json::json!({"type": "meta"}),
                "perp-contexts" => serde_json::json!({"type": "metaAndAssetCtxs"}),
                "spot" => serde_json::json!({"type": "spotMeta"}),
                "spot-contexts" => serde_json::json!({"type": "spotMetaAndAssetCtxs"}),
                "mids" => serde_json::json!({"type": "allMids"}),
                other => bail!(
                    "unknown metadata kind '{other}' (use perp, perp-contexts, spot, spot-contexts, mids)"
                ),
            };
            print_hl_info(&home, &network, body).await
        }
        HyperliquidCmd::Session { command } => handle_hl_session(endpoint, command).await,
        HyperliquidCmd::SendAsset {
            wallet,
            destination,
            amount,
            network,
            passphrase,
        } => {
            let path = format!("/hyperliquid/{network}/exchange/{wallet}/send_asset.json");
            let body = serde_json::to_vec(&UsdSendRequest {
                destination,
                amount,
                nonce: None,
            })?;
            if passphrase.is_some() {
                eprintln!(
                    "warning: --passphrase is ignored for Hyperliquid Sealed Approval; use the browser ceremony"
                );
            }
            hl_session_ipc_write_with_sealed_approval(endpoint, &path, body, &wallet).await?;
            let last_response =
                format!("/hyperliquid/{network}/exchange/{wallet}/last_response.json");
            match hl_session_ipc_read(endpoint, &last_response).await {
                Ok(bytes) => std::io::Write::write_all(&mut std::io::stdout(), &bytes)?,
                Err(_) => println!("usdSend submitted"),
            }
            Ok(())
        }
        HyperliquidCmd::TestReads {
            user,
            coin,
            network,
        } => test_hl_reads(&home, &network, &user, &coin).await,
        HyperliquidCmd::TestPostOnlyCancel {
            wallet,
            coin,
            asset,
            price,
            size,
            max_notional_usd,
            policy_session,
            danger_accept_live_orders,
            passphrase,
            network,
        } => {
            test_hl_post_only_cancel(
                home,
                TestPostOnlyCancelArgs {
                    wallet,
                    coin,
                    asset,
                    price,
                    size,
                    max_notional_usd,
                    policy_session,
                    danger_accept_live_orders,
                    passphrase,
                    network,
                },
            )
            .await
        }
    }
}

async fn handle_update(home: &HomeDir, cmd: UpdateCmd) -> Result<()> {
    match cmd {
        UpdateCmd::Status => {
            let installed = env!("CARGO_PKG_VERSION");
            let snap = bloom_update::read_cache_only(installed, &home.cache_dir());
            let json = serde_json::to_string_pretty(&snap).context("serialise update snapshot")?;
            println!("{json}");
            Ok(())
        }
        UpdateCmd::Check => {
            // An explicit check needs only a checker; avoid constructing
            // the full daemon and its unrelated VFS/transaction services.
            let checker =
                bloom_update::UpdateChecker::new(env!("CARGO_PKG_VERSION"), home.cache_dir())
                    .context("build update checker")?;
            let snap = checker.refresh().await;
            let json = serde_json::to_string_pretty(&snap).context("serialise update snapshot")?;
            println!("{json}");
            let code = match snap.available() {
                bloom_update::UpdateAvailable::OutOfDate => 1,
                bloom_update::UpdateAvailable::UpToDate => 0,
                bloom_update::UpdateAvailable::Unknown => 2,
            };
            if code != 0 {
                UPDATE_EXIT_CODE.store(code, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(())
        }
    }
}

async fn handle_hl_session(endpoint: &ResolvedEndpoint, cmd: HyperliquidSessionCmd) -> Result<()> {
    match cmd {
        HyperliquidSessionCmd::Create {
            wallet,
            id,
            agent_name,
            vault_address,
            network,
            passphrase,
        } => {
            let path = hl_session_wallet_path(&network, &wallet, "new.json");
            let body = serde_json::json!({
                "id": id,
                "agent_name": agent_name,
                "vault_address": vault_address,
            });
            if passphrase.is_some() {
                eprintln!(
                    "warning: --passphrase is ignored for Hyperliquid Sealed Approval; use the browser ceremony"
                );
            }
            hl_session_ipc_write_with_sealed_approval(
                endpoint,
                &path,
                serde_json::to_vec(&body)?,
                &wallet,
            )
            .await?;
            let last_response =
                format!("/hyperliquid/{network}/exchange/{wallet}/last_response.json");
            match hl_session_ipc_read(endpoint, &last_response).await {
                Ok(bytes) => std::io::Write::write_all(&mut std::io::stdout(), &bytes)?,
                Err(_) => println!("created Hyperliquid agent session"),
            }
            Ok(())
        }
        HyperliquidSessionCmd::Status {
            wallet,
            id,
            network,
        } => {
            let path = hl_session_path(&network, &wallet, &id, "status.json");
            let bytes = hl_session_ipc_read(endpoint, &path).await?;
            std::io::Write::write_all(&mut std::io::stdout(), &bytes)?;
            Ok(())
        }
        HyperliquidSessionCmd::Audit {
            wallet,
            id,
            network,
        } => {
            let path = hl_session_path(&network, &wallet, &id, "audit.jsonl");
            let bytes = hl_session_ipc_read(endpoint, &path).await?;
            std::io::Write::write_all(&mut std::io::stdout(), &bytes)?;
            Ok(())
        }
        HyperliquidSessionCmd::Stop {
            wallet,
            id,
            network,
        } => {
            hl_session_ipc_write(
                endpoint,
                &hl_session_path(&network, &wallet, &id, "stop"),
                Vec::new(),
            )
            .await
        }
        HyperliquidSessionCmd::CancelAll {
            wallet,
            id,
            network,
        } => {
            hl_session_ipc_write(
                endpoint,
                &hl_session_path(&network, &wallet, &id, "cancel_all"),
                Vec::new(),
            )
            .await
        }
        HyperliquidSessionCmd::CloseAll {
            wallet,
            id,
            network,
        } => {
            hl_session_ipc_write(
                endpoint,
                &hl_session_path(&network, &wallet, &id, "close_all"),
                Vec::new(),
            )
            .await
        }
    }
}

fn hl_session_wallet_path(network: &str, wallet: &str, file: &str) -> String {
    format!("/hyperliquid/{network}/agent_sessions/{wallet}/{file}")
}

fn hl_session_path(network: &str, wallet: &str, id: &str, file: &str) -> String {
    format!("/hyperliquid/{network}/agent_sessions/{wallet}/{id}/{file}")
}

/// Resolve a staged request's paying wallet from its `request.toml`, IPC-first
/// with an in-process read fallback. Returns `None` if the field is absent.
async fn read_request_wallet(
    client: &IpcClient,
    endpoint: &ResolvedEndpoint,
    home: &HomeDir,
    id: &str,
) -> Result<Option<String>> {
    let path = format!("/requests/{id}/request.toml");
    let bytes = match try_ipc(
        client,
        endpoint,
        "read",
        serde_json::json!({ "path": path }),
    )
    .await
    .with_context(|| format!("ipc read via {}", endpoint.display))?
    {
        Some(res) => {
            let b64 = res
                .get("bytes_b64")
                .and_then(|v| v.as_str())
                .context("ipc read: missing bytes_b64")?;
            B64.decode(b64).context("ipc read: bad base64")?
        }
        None => {
            let d = Daemon::from_home(home.clone()).context("build daemon")?;
            let p = VfsPath::parse(&path)?;
            d.vfs.read(&p).await.context("read request.toml")?
        }
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes).context("parse request.toml")?;
    Ok(value
        .get("wallet")
        .and_then(|v| v.as_str())
        .map(str::to_string))
}

async fn hl_session_ipc_read(endpoint: &ResolvedEndpoint, path: &str) -> Result<Vec<u8>> {
    let client = IpcClient::new(&endpoint.socket);
    let Some(res) = try_ipc(
        &client,
        endpoint,
        "read",
        serde_json::json!({ "path": path }),
    )
    .await
    .with_context(|| format!("ipc read via {}", endpoint.display))?
    else {
        bail!("Hyperliquid agent sessions require a running bloom serve daemon");
    };
    let b64 = res
        .get("bytes_b64")
        .and_then(|v| v.as_str())
        .context("ipc read: missing bytes_b64")?;
    B64.decode(b64).context("ipc read: bad base64")
}

async fn hl_session_ipc_write(
    endpoint: &ResolvedEndpoint,
    path: &str,
    body: Vec<u8>,
) -> Result<()> {
    let client = IpcClient::new(&endpoint.socket);
    let res = try_ipc(
        &client,
        endpoint,
        "write",
        serde_json::json!({
            "path": path,
            "bytes_b64": B64.encode(&body),
        }),
    )
    .await
    .with_context(|| format!("ipc write via {}", endpoint.display))?;
    if res.is_none() {
        bail!("Hyperliquid agent sessions require a running bloom serve daemon");
    }
    Ok(())
}

async fn hl_session_ipc_write_with_sealed_approval(
    endpoint: &ResolvedEndpoint,
    path: &str,
    body: Vec<u8>,
    wallet: &str,
) -> Result<()> {
    match hl_session_ipc_write_once(endpoint, path, &body).await {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("Hyperliquid Sealed Approval requires a running bloom serve daemon");
        }
        Err(e) if is_ipc_permission_denied(&e) => {
            let challenge_path = hyperliquid_challenge_vfs_path(path, &body)
                .with_context(|| format!("locate Hyperliquid approval challenge for {path}"))?;
            let challenge = read_hyperliquid_approval_challenge(endpoint, &challenge_path).await?;
            ensure_hyperliquid_challenge_matches(&challenge, wallet)?;
            let url = challenge
                .ceremony_url
                .clone()
                .context("Hyperliquid approval challenge is missing ceremony_url")?;
            eprintln!("Hyperliquid Sealed Approval required.");
            eprintln!("Opening ceremony URL: {url}");
            open_ceremony_url(&url);
            wait_for_hyperliquid_grant(&url)?;
        }
        Err(e) => return Err(e).with_context(|| format!("ipc write via {}", endpoint.display)),
    }

    match hl_session_ipc_write_once(endpoint, path, &body).await {
        Ok(()) => Ok(()),
        Err(e) if is_ipc_permission_denied(&e) => {
            bail!(
                "Hyperliquid Sealed Approval grant is not active yet; complete the grant ceremony and rerun the command"
            )
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("Hyperliquid Sealed Approval requires a running bloom serve daemon")
        }
        Err(e) => Err(e).with_context(|| format!("ipc write via {}", endpoint.display)),
    }
}

async fn hl_session_ipc_write_once(
    endpoint: &ResolvedEndpoint,
    path: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let client = IpcClient::new(&endpoint.socket);
    client
        .call(
            "write",
            serde_json::json!({
                "path": path,
                "bytes_b64": B64.encode(body),
            }),
        )
        .await
        .map(|_| ())
}

fn is_ipc_permission_denied(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::PermissionDenied
        || e.to_string().contains("\"code\":-32007")
        || e.to_string()
            .to_ascii_lowercase()
            .contains("permission denied")
}

fn hyperliquid_challenge_vfs_path(path: &str, body: &[u8]) -> Result<String> {
    let vfs_path = VfsPath::parse(path)?;
    let segments = vfs_path.segments();
    if segments.len() == 5
        && segments[0] == "hyperliquid"
        && segments[2] == "exchange"
        && segments[4] == "send_asset.json"
    {
        return Ok(format!(
            "/hyperliquid/{}/exchange/{}/approval_challenge.json",
            segments[1], segments[3]
        ));
    }
    if segments.len() == 5
        && segments[0] == "hyperliquid"
        && segments[2] == "agent_sessions"
        && segments[4] == "new.json"
    {
        let request: serde_json::Value =
            serde_json::from_slice(body).context("parse Hyperliquid session create body")?;
        let id = request
            .get("id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .context("Hyperliquid session create requires an explicit stable id")?;
        return Ok(format!(
            "/hyperliquid/{}/agent_sessions/{}/{id}/approval_challenge.json",
            segments[1], segments[3]
        ));
    }
    bail!("unsupported Hyperliquid Sealed Approval path {path}");
}

async fn read_hyperliquid_approval_challenge(
    endpoint: &ResolvedEndpoint,
    path: &str,
) -> Result<ApprovalChallenge> {
    let bytes = hl_session_ipc_read(endpoint, path)
        .await
        .with_context(|| format!("ipc read Hyperliquid approval challenge {path}"))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse Hyperliquid approval challenge {path}"))
}

fn ensure_hyperliquid_challenge_matches(challenge: &ApprovalChallenge, wallet: &str) -> Result<()> {
    if challenge.surface != "hyperliquid" {
        bail!(
            "approval challenge surface is {}, expected hyperliquid",
            challenge.surface
        );
    }
    if challenge.wallet != wallet {
        bail!(
            "approval challenge wallet is {}, expected {}",
            challenge.wallet,
            wallet
        );
    }
    if challenge.expiry_ms <= cli_now_ms() {
        bail!("Hyperliquid approval challenge expired; rerun the command to issue a new challenge");
    }
    Ok(())
}

fn open_ceremony_url(url: &str) {
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut cmd = Command::new("open");
        cmd.arg(url);
        cmd
    };
    #[cfg(target_os = "linux")]
    let mut cmd = {
        let mut cmd = Command::new("xdg-open");
        cmd.arg(url);
        cmd
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut cmd = Command::new("cmd");
        cmd.args(["/C", "start", "", url]);
        cmd
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let mut cmd = { Command::new("true") };
    let _ = cmd.status();
}

fn wait_for_hyperliquid_grant(url: &str) -> Result<()> {
    if std::io::stdin().is_terminal() {
        eprintln!("Complete the ceremony in grant mode, then press Enter to retry the write.");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
    } else {
        eprintln!(
            "Complete the ceremony in grant mode, then rerun the command if the automatic retry happens before approval."
        );
        eprintln!("Ceremony URL: {url}");
    }
    Ok(())
}

fn hl_network(raw: &str) -> Result<HyperliquidNetwork> {
    match raw {
        "mainnet" => Ok(HyperliquidNetwork::Mainnet),
        "testnet" => Ok(HyperliquidNetwork::Testnet),
        other => bail!("unknown Hyperliquid network '{other}' (use mainnet or testnet)"),
    }
}

fn hl_client(home: &HomeDir, raw: &str) -> Result<HyperliquidClient> {
    let network = hl_network(raw)?;
    let mut client = HyperliquidClient::new(network);
    // Honor [hyperliquid] mainnet_url/testnet_url overrides, same as the daemon
    // (so local/staging/proxy deployments work from the CLI too).
    if let Ok(config) = bloom_proto::Config::load_or_init(&home.config_path())
        && let Some(hl) = config.hyperliquid
    {
        let raw_url = match network {
            HyperliquidNetwork::Mainnet => hl.mainnet_url,
            HyperliquidNetwork::Testnet => hl.testnet_url,
        };
        if let Ok(url) = raw_url.parse::<url::Url>() {
            client = client.with_base_url(url);
        }
    }
    Ok(client)
}

fn hl_user_req(kind: &str, user: &str) -> serde_json::Value {
    serde_json::json!({
        "type": kind,
        "user": user.to_ascii_lowercase(),
    })
}

async fn print_hl_info(home: &HomeDir, network: &str, body: serde_json::Value) -> Result<()> {
    let client = hl_client(home, network)?;
    let value = client.info(body).await?;
    std::io::Write::write_all(&mut std::io::stdout(), &pretty_json(&value))?;
    Ok(())
}

async fn test_hl_reads(home: &HomeDir, network: &str, user: &str, coin: &str) -> Result<()> {
    let client = hl_client(home, network)?;
    let now = bloom_hyperliquid::now_ms();
    let start = now.saturating_sub(60 * 60 * 1000);
    let calls = [
        ("account", hl_user_req("clearinghouseState", user)),
        ("spot_state", hl_user_req("spotClearinghouseState", user)),
        ("open_orders", hl_user_req("openOrders", user)),
        (
            "frontend_open_orders",
            hl_user_req("frontendOpenOrders", user),
        ),
        ("fills", hl_user_req("userFills", user)),
        (
            "funding",
            serde_json::json!({
                "type": "userFunding",
                "user": user.to_ascii_lowercase(),
                "coin": coin,
                "startTime": start,
                "endTime": now,
            }),
        ),
        ("portfolio", hl_user_req("portfolio", user)),
        ("rate_limit", hl_user_req("userRateLimit", user)),
        ("mids", serde_json::json!({"type": "allMids"})),
        ("perp_meta", serde_json::json!({"type": "meta"})),
        (
            "perp_contexts",
            serde_json::json!({"type": "metaAndAssetCtxs"}),
        ),
        ("spot_meta", serde_json::json!({"type": "spotMeta"})),
        (
            "spot_contexts",
            serde_json::json!({"type": "spotMetaAndAssetCtxs"}),
        ),
        ("book", serde_json::json!({"type": "l2Book", "coin": coin})),
        (
            "candles",
            serde_json::json!({
                "type": "candleSnapshot",
                "req": {
                    "coin": coin,
                    "interval": "1m",
                    "startTime": start,
                    "endTime": now,
                }
            }),
        ),
    ];

    let mut out = serde_json::Map::new();
    for (name, body) in calls {
        match client.info(body).await {
            Ok(value) => {
                out.insert(name.to_string(), value);
            }
            Err(e) => {
                out.insert(
                    name.to_string(),
                    serde_json::json!({"error": e.to_string()}),
                );
            }
        }
    }
    std::io::Write::write_all(
        &mut std::io::stdout(),
        &pretty_json(&serde_json::Value::Object(out)),
    )?;
    Ok(())
}

struct TestPostOnlyCancelArgs {
    wallet: String,
    coin: String,
    asset: u32,
    price: Option<String>,
    size: Option<String>,
    max_notional_usd: f64,
    policy_session: bool,
    danger_accept_live_orders: bool,
    passphrase: Option<String>,
    network: String,
}

async fn test_hl_post_only_cancel(_home: HomeDir, args: TestPostOnlyCancelArgs) -> Result<()> {
    let TestPostOnlyCancelArgs {
        wallet: _wallet,
        coin: _coin,
        asset: _asset,
        price: _price,
        size: _size,
        max_notional_usd,
        policy_session: _policy_session,
        danger_accept_live_orders,
        passphrase: _passphrase,
        network: _network,
    } = args;
    if !danger_accept_live_orders {
        bail!("refusing live Hyperliquid test order without --danger-accept-live-orders");
    }
    if max_notional_usd <= 0.0 {
        bail!("--max-notional-usd must be positive");
    }
    bail!(
        "direct owner-key Hyperliquid test orders are disabled; create a Sealed Approval agent session and submit through /hyperliquid/<network>/agent_sessions/<wallet>/<session>/order.json"
    )
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

#[cfg(test)]
mod tests {
    use super::{format_petal_consent_net_rule, request_body_with_wallet};

    #[test]
    fn petal_consent_network_line_includes_named_binding() {
        let line = format_petal_consent_net_rule(&bloom_petals::package::PetalConsentNetRule {
            binding: Some("clob".into()),
            host: "clob.polymarket.com".into(),
            effective_origin: Some("https://clob.internal.example".into()),
            methods: vec!["POST".into()],
            paths: vec!["/order".into()],
        });
        assert_eq!(
            line,
            "    - declared_host=clob.polymarket.com binding=clob effective_origin=https://clob.internal.example methods=[POST] paths=[/order]"
        );
    }

    #[test]
    fn request_wallet_injection_preserves_http_message_body() {
        let input = concat!(
            "POST https://api.example.com/data\n",
            "content-type: application/json\n",
            "\n",
            "{\"ok\":true}"
        )
        .to_string();
        let output = request_body_with_wallet(input, Some("gavin"));
        assert!(output.starts_with("POST https://api.example.com/data wallet=gavin\n"));
        assert!(output.ends_with("\n\n{\"ok\":true}"));
    }
}

#[cfg(test)]
mod hl_cli_tests {
    use super::*;

    #[test]
    fn post_only_cancel_test_requires_danger_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(test_hl_post_only_cancel(
                HomeDir::at(tmp.path()),
                TestPostOnlyCancelArgs {
                    wallet: "minnow".into(),
                    coin: "BTC".into(),
                    asset: 0,
                    price: None,
                    size: None,
                    max_notional_usd: 15.0,
                    policy_session: false,
                    danger_accept_live_orders: false,
                    passphrase: None,
                    network: "mainnet".into(),
                },
            ))
            .unwrap_err();
        assert!(err.to_string().contains("--danger-accept-live-orders"));
    }

    #[test]
    fn hl_client_honors_config_endpoint_override() {
        let tmp = tempfile::tempdir().unwrap();
        let home = HomeDir::at(tmp.path());
        let mut cfg = bloom_proto::Config::local_default();
        cfg.hyperliquid = Some(bloom_proto::config::HyperliquidConfig {
            mainnet_url: "http://localhost:9999/".into(),
            ..Default::default()
        });
        std::fs::write(home.config_path(), toml::to_string(&cfg).unwrap()).unwrap();
        // Mainnet uses the configured override.
        let client = hl_client(&home, "mainnet").unwrap();
        assert_eq!(client.base_url().as_str(), "http://localhost:9999/");
        // Testnet wasn't overridden → default public endpoint.
        let tclient = hl_client(&home, "testnet").unwrap();
        assert!(tclient.base_url().as_str().contains("hyperliquid-testnet"));
    }
}
