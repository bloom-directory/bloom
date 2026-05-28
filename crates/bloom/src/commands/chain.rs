//! `bloom chain ...` — sovereign chain subcommand tree (spec §12).
//!
//! All subcommands that talk to a running node do so via the UDS JSON-RPC
//! socket at `<bloom_home>/chain/rpc.sock`.
//!
//! Subcommands that build/sign txs use the xDSA wallet stored in
//! `<bloom_home>/chain/keystore/<validator>.xdsa`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use bloom_chain_node::rpc::RpcClient;
use clap::Subcommand;
use serde_json::json;

// ---------------------------------------------------------------------------
// Top-level `chain` subcommand
// ---------------------------------------------------------------------------

/// Subcommand group for `bloom chain`.
#[derive(Subcommand, Debug)]
pub enum ChainCmd {
    /// Create a fresh node home: genesis.toml skeleton, config.toml, keystore/.
    Init {
        /// Path to an existing genesis file to copy (default: generate skeleton).
        #[arg(long, value_name = "FILE")]
        genesis: Option<PathBuf>,
        /// Overwrite an existing `keystore/validator.xdsa` if present.
        ///
        /// Without this flag, `chain init` refuses to clobber an existing
        /// validator key — accidental re-init on a populated node home would
        /// otherwise replace the operator's secret material in place.
        #[arg(long)]
        force: bool,
    },
    /// Run a validator node (long-running).
    RunValidator {
        /// Path to `config.toml` (default: `<bloom_home>/chain/config.toml`).
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
    /// Submit a signed tx (SSZ-encoded, from file or stdin).
    Submit {
        /// Path to SSZ-encoded `Tx` file, or `-` for stdin.
        tx_file_or_dash: String,
    },
    /// Wrap an already-signed inner PTB in a signed outer tx and submit it.
    ///
    /// The `--ptb-file` bytes are the output of `bloom_script::encode_ptb`
    /// for an inner `PtbTx` that is ALREADY xDSA-signed against its
    /// `signers`. The CLI treats those bytes as opaque — it does not sign
    /// the inner PTB — and only builds + signs the OUTER xDSA tx envelope
    /// (which is what block-apply verifies).
    SubmitPtb {
        /// Path to a file holding the `encode_ptb` bytes of a signed `PtbTx`.
        #[arg(long, value_name = "PATH")]
        ptb_file: PathBuf,
        /// Poll for the tx receipt after submitting and print it.
        #[arg(long)]
        wait: bool,
        /// Receipt-poll timeout in seconds (only with `--wait`; default 30).
        #[arg(long, value_name = "N", default_value_t = 30u64)]
        wait_timeout_secs: u64,
    },
    /// Deploy a Bloom-native petal wasm module.
    Deploy {
        /// Path to a `.wasm` file carrying a bloom_petal_manifest_v0 section.
        #[arg(value_name = "WASM")]
        wasm: PathBuf,
        /// Poll for the tx receipt after submitting and print it.
        #[arg(long)]
        wait: bool,
        /// Receipt-poll timeout in seconds (only with `--wait`; default 30).
        #[arg(long, value_name = "N", default_value_t = 30u64)]
        wait_timeout_secs: u64,
    },
    /// Query chain state.
    #[command(subcommand)]
    Query(QueryCmd),
    /// List the current validator set (JSON).
    LsValidators,
    /// Probe validator readiness via `chain_health`.
    Health,
    /// Provision a local multi-validator testnet under `--output-dir`.
    ///
    /// Generates `N` xDSA keypairs, writes per-node `home<i>/chain/`
    /// directories with a shared genesis.toml and distinct config.toml,
    /// and emits a JSON manifest with the validator addresses and ports.
    /// Used by `bloom-it`'s `chain_smoke` / `chain_dex_demo` harness.
    Testnet {
        /// Number of validators (default 4).
        #[arg(long, default_value_t = 4u8)]
        validators: u8,
        /// Output parent directory (created if missing).
        #[arg(long, value_name = "DIR")]
        output_dir: PathBuf,
        /// Base TCP port; nodes get `base..base+N-1`. Defaults to OS-picked.
        #[arg(long, value_name = "PORT")]
        base_port: Option<u16>,
        /// Genesis chain_id.
        #[arg(long, default_value = "bloomchain.local")]
        chain_id: String,
        /// Per-validator pre-funded LOOM allocation, in bloomweis.
        #[arg(long, default_value = "1000000000000000000000000")]
        allocation: String,
        /// Override per-validator `listen_addr` in config.toml. Useful for
        /// docker-compose where every container should bind the same internal
        /// `0.0.0.0:port` regardless of host. When set, the port is also used
        /// for genesis peer-host rewriting (see `--peer-hosts`).
        #[arg(long, value_name = "ADDR")]
        listen_addr: Option<String>,
        /// Set per-validator `rpc_tcp_addr` in config.toml, enabling the
        /// JSON-RPC TCP listener alongside the UDS socket. Same value is
        /// written for every node (intended for matching docker port mappings).
        #[arg(long, value_name = "ADDR")]
        rpc_tcp_addr: Option<String>,
        /// Permit a non-loopback/wildcard RPC TCP bind in generated configs.
        /// Required with `--rpc-tcp-addr 0.0.0.0:...` for docker-only testnets.
        #[arg(long)]
        unsafe_rpc_public_bind: bool,
        /// Comma-separated hostnames (one per validator). When set, the i-th
        /// `[[validators]]` entry in genesis.toml gets its `host` rewritten
        /// to `peer_hosts[i]:<listen_port>` so peers reach each other by
        /// container/DNS name rather than 127.0.0.1.
        #[arg(long, value_name = "CSV")]
        peer_hosts: Option<String>,
    },
}

/// `bloom chain query ...` subcommands.
#[derive(Subcommand, Debug)]
pub enum QueryCmd {
    /// JSON: nonce, code_hash, storage_root.
    Account {
        /// Address (hex or b1-prefixed).
        addr: String,
    },
    /// JSON: block header + tx hashes.
    Block {
        /// Block height (integer) or block hash (64-char hex).
        height_or_hash: String,
    },
    /// JSON: tx + receipt.
    Tx {
        /// Tx hash (64-char hex).
        hash: String,
    },
    /// Raw hex of storage value at `<addr>/<key_hex>`.
    State {
        /// Contract address.
        addr: String,
        /// 32-byte storage key as hex.
        key_hex: String,
    },
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/// Run a `chain` subcommand.
///
/// `home`: the resolved bloom home directory (`~/.bloom` by default).
pub async fn run_chain(home: &bloom_proto::HomeDir, cmd: ChainCmd) -> Result<()> {
    let chain_dir = home.root().join("chain");
    let rpc_sock = chain_dir.join("rpc.sock");

    // CLI consumers honor `BLOOM_RPC_TCP=host:port` to switch the RpcClient
    // from UDS to TCP. The docker-compose harness sets this so that user-side
    // commands (`bloom chain submit/query/...`) talk to a validator over the
    // network rather than via a Unix socket that doesn't exist on the host.
    let make_client = || -> RpcClient {
        match std::env::var("BLOOM_RPC_TCP") {
            Ok(addr) if !addr.is_empty() => RpcClient::tcp(addr),
            _ => RpcClient::new(&rpc_sock),
        }
    };

    match cmd {
        // ── init ──────────────────────────────────────────────────────────────
        ChainCmd::Init { genesis, force } => {
            std::fs::create_dir_all(chain_dir.join("keystore"))
                .context("create chain keystore dir")?;
            std::fs::create_dir_all(chain_dir.join("blocks")).context("create chain blocks dir")?;
            std::fs::create_dir_all(chain_dir.join("state_blobs"))
                .context("create chain state_blobs dir")?;

            // Write genesis.toml skeleton.
            let genesis_dest = chain_dir.join("genesis.toml");
            if let Some(src) = genesis {
                std::fs::copy(&src, &genesis_dest)
                    .with_context(|| format!("copy genesis from {}", src.display()))?;
                println!("copied genesis: {}", genesis_dest.display());
            } else {
                let skeleton = genesis_skeleton();
                std::fs::write(&genesis_dest, skeleton).context("write genesis.toml skeleton")?;
                println!("wrote genesis skeleton: {}", genesis_dest.display());
            }

            // Write config.toml skeleton.
            let config_dest = chain_dir.join("config.toml");
            if !config_dest.exists() {
                let config = config_skeleton();
                std::fs::write(&config_dest, config).context("write config.toml")?;
                println!("wrote config: {}", config_dest.display());
            }

            // Generate a fresh xDSA keypair for this validator.
            let (sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
            let sk_bytes = sk.to_bytes();
            let pk_bytes = pk.0.clone();

            // Derive address (spec §4.3 — canonical helper).
            let addr_bytes = bloom_chain_types::types::Address::from_pubkey_bytes(&pk_bytes).0;
            let addr_hex = hex::encode(addr_bytes);

            // Write key file (unencrypted seed for v0 — v1 should use passphrase).
            //
            // Refuses to overwrite an existing key unless `--force` is set
            // (review 2026-05-19 #9). Mode 0o600 is set on Unix so the secret
            // is never world- or group-readable.
            let key_path = chain_dir.join("keystore").join("validator.xdsa");
            write_secret_key_file(&key_path, sk_bytes.as_slice(), force)
                .with_context(|| format!("write validator key: {}", key_path.display()))?;

            println!("validator address : {addr_hex}");
            println!("validator key     : {}", key_path.display());
            println!(
                "\nEdit {} to add validators and allocations, then share genesis.toml with all validators.",
                genesis_dest.display()
            );
            Ok(())
        }

        // ── run-validator ─────────────────────────────────────────────────────
        ChainCmd::RunValidator { config } => {
            let config_path = config.unwrap_or_else(|| chain_dir.join("config.toml"));
            let (node_cfg, run_config) =
                load_validator_run_config(home.root(), &chain_dir, &config_path)?;
            let node = bloom_chain_node::Node::new(run_config);
            println!("starting bloom chain validator at {}", node_cfg.listen_addr);
            node.run().await
        }

        // ── submit ────────────────────────────────────────────────────────────
        ChainCmd::Submit { tx_file_or_dash } => {
            let bytes = if tx_file_or_dash == "-" {
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)?;
                buf
            } else {
                std::fs::read(&tx_file_or_dash)
                    .with_context(|| format!("read {}", tx_file_or_dash))?
            };

            let client = make_client();
            let result = client
                .call("chain_submit_tx", json!({ "tx_hex": hex::encode(&bytes) }))
                .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }

        // ── submit-ptb ──────────────────────────────────────────────────────────
        ChainCmd::SubmitPtb {
            ptb_file,
            wait,
            wait_timeout_secs,
        } => {
            use bloom_chain_types::ssz::Encode;

            // The inner PTB is opaque to the CLI: read the `encode_ptb` bytes
            // verbatim and wrap them in `TxKind::SubmitPtb`. Only the outer
            // envelope is signed here.
            let ptb_bytes = std::fs::read(&ptb_file)
                .with_context(|| format!("read ptb file: {}", ptb_file.display()))?;

            let (sk, pk, sender) = load_wallet_key(&chain_dir)?;
            let chain_id = load_chain_id(&chain_dir)?;
            let client = make_client();
            let nonce = fetch_nonce(&client, &sender).await? + 1;
            let tx = build_and_sign_tx(
                &sk,
                &pk,
                sender,
                &chain_id,
                nonce,
                build_submit_ptb_kind(ptb_bytes),
                10_000_000,
                1,
            )?;
            let tx_hash = tx.tx_hash();
            client
                .call(
                    "chain_submit_tx",
                    json!({ "tx_hex": hex::encode(tx.as_ssz_bytes()) }),
                )
                .await?;

            if wait {
                // Poll until a receipt is indexed (or timeout) and print it.
                let timeout = std::time::Duration::from_secs(wait_timeout_secs);
                let receipt = poll_tx_receipt(&client, &tx_hash, timeout).await?;
                println!("{}", serde_json::to_string_pretty(&receipt)?);
            }
            // Always emit the tx_hash as the LAST line so a driver can capture
            // it regardless of whether `--wait` was set.
            println!("{}", json!({ "tx_hash": hex::encode(tx_hash.0) }));
            Ok(())
        }

        // ── query account ─────────────────────────────────────────────────────
        ChainCmd::Query(QueryCmd::Account { addr }) => {
            let client = make_client();
            let result = client
                .call("chain_query_account", json!({ "address": addr }))
                .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }

        // ── query block ───────────────────────────────────────────────────────
        ChainCmd::Query(QueryCmd::Block { height_or_hash }) => {
            let client = make_client();
            let params = if let Ok(h) = height_or_hash.parse::<u64>() {
                json!({ "height": h })
            } else {
                json!({ "hash": height_or_hash })
            };
            let result = client.call("chain_query_block", params).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }

        // ── query tx ──────────────────────────────────────────────────────────
        ChainCmd::Query(QueryCmd::Tx { hash }) => {
            let client = make_client();
            let result = client
                .call("chain_query_tx", json!({ "tx_hash": hash }))
                .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }

        // ── query state ───────────────────────────────────────────────────────
        ChainCmd::Query(QueryCmd::State { addr, key_hex }) => {
            let client = make_client();
            let result = client
                .call(
                    "chain_query_state",
                    json!({ "address": addr, "key": key_hex }),
                )
                .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }

        // ── ls-validators ─────────────────────────────────────────────────────
        ChainCmd::LsValidators => {
            let client = make_client();
            let result = client.call("chain_ls_validators", json!(null)).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }

        ChainCmd::Health => {
            let client = make_client();
            let result = client.call("chain_health", json!({})).await?;
            if result.get("ok").and_then(|v| v.as_bool()) != Some(true) {
                anyhow::bail!("chain_health returned not ok: {result}");
            }
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }

        // ── deploy petal ─────────────────────────────────────────────────────
        ChainCmd::Deploy {
            wasm,
            wait,
            wait_timeout_secs,
        } => {
            use bloom_chain_types::ssz::Encode;
            use bloom_chain_types::tx::TxKind;

            let wasm_bytes =
                std::fs::read(&wasm).with_context(|| format!("read wasm: {}", wasm.display()))?;
            let (sk, pk, sender) = load_wallet_key(&chain_dir)?;
            let chain_id = load_chain_id(&chain_dir)?;
            let client = make_client();
            let nonce = fetch_nonce(&client, &sender).await? + 1;
            let tx = build_and_sign_tx(
                &sk,
                &pk,
                sender,
                &chain_id,
                nonce,
                TxKind::DeployPetal { wasm_bytes },
                10_000_000,
                1,
            )?;
            let tx_hash = tx.tx_hash();
            let result = client
                .call(
                    "chain_submit_tx",
                    json!({ "tx_hex": hex::encode(tx.as_ssz_bytes()) }),
                )
                .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            if wait {
                let receipt = poll_tx_receipt(
                    &client,
                    &tx_hash,
                    std::time::Duration::from_secs(wait_timeout_secs),
                )
                .await?;
                println!("{}", serde_json::to_string_pretty(&receipt)?);
            }
            println!("{}", json!({ "tx_hash": hex::encode(tx_hash.0) }));
            Ok(())
        }

        // ── testnet ───────────────────────────────────────────────────────────
        ChainCmd::Testnet {
            validators,
            output_dir,
            base_port,
            chain_id,
            allocation,
            listen_addr,
            rpc_tcp_addr,
            unsafe_rpc_public_bind,
            peer_hosts,
        } => provision_testnet(
            validators,
            &output_dir,
            base_port,
            &chain_id,
            &allocation,
            listen_addr.as_deref(),
            rpc_tcp_addr.as_deref(),
            unsafe_rpc_public_bind,
            peer_hosts.as_deref(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn genesis_skeleton() -> &'static str {
    r#"# bloom-chain v0 genesis (edit before sharing with validators)
chain_id = "bloomchain.v0"
genesis_time_ms = 0  # set to Unix epoch ms at launch

[[validators]]
address = ""           # hex or b1-prefixed address
pubkey  = ""           # base64-encoded composite xDSA public key (1984 bytes)
voting_power = 100
host = "127.0.0.1:26656"

[[allocations]]
address = ""           # hex or b1-prefixed address
amount  = "1000000000000000000000"  # 1000 LOOM in bloomweis
"#
}

fn config_skeleton() -> &'static str {
    r#"# bloom-chain node config
validator_address = ""     # hex or b1-prefixed address of this node's key
listen_addr = "0.0.0.0:26656"
log_level = "info"
fuel_limit = 30000000
wasmtime_version = "26"
"#
}

/// Write a validator secret-key file with strict permissions and an explicit
/// no-overwrite rule (review 2026-05-19 #9).
///
/// - Refuses to overwrite an existing file unless `force` is set; the error
///   message names the path and points the caller at `--force`.
/// - On Unix, creates the file with mode 0o600 atomically (the mode is
///   passed to `open(2)` before the secret is written, so the file never
///   exists on disk with a wider mode). If the file already exists and
///   `force` is set, we re-set the mode explicitly after writing because
///   `truncate(2)` doesn't change the existing mode.
/// - On non-Unix platforms the chmod is skipped; we still honor the no-
///   overwrite check.
fn write_secret_key_file(path: &std::path::Path, bytes: &[u8], force: bool) -> Result<()> {
    use std::io::Write;

    if path.exists() && !force {
        anyhow::bail!(
            "refusing to overwrite existing key at {}; pass --force to replace",
            path.display()
        );
    }

    // Ensure the parent directory exists; callers usually create it earlier,
    // but be defensive so we don't silently fail on a malformed home.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create key parent dir: {}", parent.display()))?;
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut f = opts
        .open(path)
        .with_context(|| format!("open key for write: {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("write key bytes: {}", path.display()))?;
    f.sync_all()
        .with_context(|| format!("fsync key: {}", path.display()))?;
    drop(f);

    // If the file pre-existed (force-replace path), `OpenOptions::mode` only
    // applies on create; tighten permissions explicitly so a previously
    // 0644-permission file becomes 0600 after re-init.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("chmod 0600 key: {}", path.display()))?;
    }

    Ok(())
}

/// Load `config.toml` + genesis + the home keystore secret, derive the
/// validator address from the keystore pubkey, and verify it matches
/// `config.validator_address` (review 2026-05-19 #15).
///
/// A drift between the declared `validator_address` in `config.toml` and
/// the key actually on disk would otherwise let a node sign votes with a
/// key that doesn't match the address it announces to peers — wallets,
/// validators, and the validator set hash would all disagree.
///
/// Returns `(NodeConfig, NodeRunConfig)` so the caller can spawn the
/// long-running validator runtime, and so this function is callable from
/// tests without needing the tokio runtime.
pub(crate) fn load_validator_run_config(
    bloom_home: &std::path::Path,
    chain_dir: &std::path::Path,
    config_path: &std::path::Path,
) -> Result<(
    bloom_chain_node::NodeConfig,
    bloom_chain_node::NodeRunConfig,
)> {
    let config_text = std::fs::read_to_string(config_path)
        .with_context(|| format!("read config: {}", config_path.display()))?;
    let node_cfg: bloom_chain_node::NodeConfig =
        toml::from_str(&config_text).context("parse config.toml")?;

    // Load validator key from `<chain_dir>/keystore/validator.xdsa` BEFORE
    // loading genesis: the address-mismatch check is the cheaper failure
    // mode, and surfacing it before genesis validation gives a clearer error
    // (and makes the test seam viable without a fully-populated genesis).
    let key_path = chain_dir.join("keystore").join("validator.xdsa");
    let key_bytes =
        std::fs::read(&key_path).with_context(|| format!("read key: {}", key_path.display()))?;
    let sk = bloom_keystore::xdsa::XdsaSecretKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow::anyhow!("decode validator key: {e}"))?;
    let pk = sk.public_key();
    let derived = bloom_chain_types::types::Address::from_pubkey_bytes(&pk.0);

    // Reconcile config.validator_address with derive(keystore_pubkey).
    //
    // We accept the same string formats `parse_b1_address` accepts (b1-prefixed
    // OR raw 64-char hex) so the config can use either form.
    let declared = bloom_chain_node::genesis::parse_b1_address(&node_cfg.validator_address)
        .with_context(|| {
            format!(
                "parse config.validator_address {:?}",
                node_cfg.validator_address
            )
        })?;
    if declared != derived {
        anyhow::bail!(
            "validator_address mismatch: config declares {} but keystore at {} \
             derives {} — refusing to run with a key that doesn't match the \
             declared identity",
            hex::encode(declared.0),
            key_path.display(),
            hex::encode(derived.0),
        );
    }

    let genesis_path = node_cfg
        .genesis_path
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| chain_dir.join("genesis.toml"));
    let genesis = bloom_chain_node::Genesis::from_file(&genesis_path)?;
    let local_validator = genesis
        .validator_set
        .get_by_address(&derived)
        .with_context(|| {
            format!(
                "local validator {} is not present in genesis validator set",
                hex::encode(derived.0)
            )
        })?;
    if local_validator.pubkey.0 != pk.0 {
        anyhow::bail!(
            "local validator pubkey mismatch: genesis entry for {} does not match keystore at {}",
            hex::encode(derived.0),
            key_path.display()
        );
    }
    validate_rpc_tcp_bind_policy(
        node_cfg.rpc_tcp_addr.as_deref(),
        node_cfg.unsafe_rpc_public_bind,
    )?;

    let run_config = bloom_chain_node::NodeRunConfig {
        chain_id: genesis.chain_id.clone(),
        validator_address: derived,
        validator_secret_key: std::sync::Arc::new(sk),
        genesis,
        listen_addr: node_cfg.listen_addr.clone(),
        rpc_tcp_addr: node_cfg.rpc_tcp_addr.clone(),
        unsafe_rpc_public_bind: node_cfg.unsafe_rpc_public_bind,
        bloom_home: bloom_home.to_path_buf(),
        fuel_limit: node_cfg.fuel_limit.unwrap_or(30_000_000),
    };
    Ok((node_cfg, run_config))
}

fn validate_rpc_tcp_bind_policy(addr: Option<&str>, unsafe_public_bind: bool) -> Result<()> {
    let Some(addr) = addr else {
        return Ok(());
    };
    if is_loopback_rpc_bind(addr)? {
        return Ok(());
    }
    if unsafe_public_bind {
        return Ok(());
    }
    anyhow::bail!(
        "rpc_tcp_addr {addr:?} is not loopback-only; set unsafe_rpc_public_bind = true only for controlled docker/private networks"
    );
}

fn is_loopback_rpc_bind(addr: &str) -> Result<bool> {
    use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

    if let Ok(socket) = addr.parse::<SocketAddr>() {
        return Ok(match socket.ip() {
            IpAddr::V4(ip) => ip.is_loopback(),
            IpAddr::V6(ip) => ip.is_loopback(),
        });
    }

    let host = addr
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches(['[', ']']))
        .ok_or_else(|| anyhow::anyhow!("rpc_tcp_addr must be host:port, got {addr:?}"))?;
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(true);
    }
    // Avoid DNS lookups for public-bind policy except localhost: a hostname may
    // resolve differently inside containers or operator environments.
    if host.parse::<IpAddr>().is_err() {
        return Ok(false);
    }
    let mut addrs = addr
        .to_socket_addrs()
        .with_context(|| format!("resolve rpc_tcp_addr {addr:?}"))?;
    Ok(addrs.all(|a| a.ip().is_loopback()))
}

/// Load the local validator xDSA key from `<chain_dir>/keystore/validator.xdsa`.
fn load_wallet_key(
    chain_dir: &std::path::Path,
) -> Result<(
    bloom_keystore::xdsa::XdsaSecretKey,
    bloom_keystore::xdsa::XdsaPublicKey,
    bloom_chain_types::types::Address,
)> {
    let key_path = chain_dir.join("keystore").join("validator.xdsa");
    let key_bytes =
        std::fs::read(&key_path).with_context(|| format!("read key: {}", key_path.display()))?;
    let sk = bloom_keystore::xdsa::XdsaSecretKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow::anyhow!("decode validator key: {e}"))?;
    let pk = sk.public_key();
    let addr = bloom_chain_types::types::Address::from_pubkey_bytes(&pk.0);
    Ok((sk, pk, addr))
}

/// Build and sign a Tx with an explicit `chain_id` and `nonce`. Callers are
/// responsible for fetching the next-valid nonce from the chain via
/// [`fetch_nonce`] and reading `chain_id` from the local genesis with
/// [`load_chain_id`]; baking either of those in would produce txs that get
/// silently rejected by the mempool.
#[allow(clippy::too_many_arguments)]
fn build_and_sign_tx(
    sk: &bloom_keystore::xdsa::XdsaSecretKey,
    pk: &bloom_keystore::xdsa::XdsaPublicKey,
    sender: bloom_chain_types::types::Address,
    chain_id: &str,
    nonce: u64,
    kind: bloom_chain_types::tx::TxKind,
    max_fuel: u64,
    fee_per_unit: u64,
) -> Result<bloom_chain_types::tx::Tx> {
    use bloom_chain_types::tx::Tx;
    use bloom_chain_types::types::{PubKeyBytes, SigBytes};

    let mut tx = Tx {
        chain_id: chain_id.to_string(),
        sender,
        nonce,
        max_fuel,
        fee_per_unit,
        kind,
        pubkey: PubKeyBytes(pk.to_bytes()),
        sig: SigBytes(vec![]),
    };
    let digest = tx.signing_digest();
    let sig = sk.sign(&digest.0);
    tx.sig = SigBytes(sig.to_bytes());
    Ok(tx)
}

/// Read `chain_id` from `<chain_dir>/genesis.toml` so signed txs use the same
/// signing domain as the running validators.
fn load_chain_id(chain_dir: &std::path::Path) -> Result<String> {
    let path = chain_dir.join("genesis.toml");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read genesis: {}", path.display()))?;
    let parsed: bloom_chain_node::genesis::GenesisFile =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(parsed.chain_id)
}

/// Fetch the on-chain account nonce for `sender`. Returns 0 for an unknown
/// account so the caller can compute `next_nonce = current + 1`.
async fn fetch_nonce(
    client: &RpcClient,
    sender: &bloom_chain_types::types::Address,
) -> Result<u64> {
    let res = client
        .call(
            "chain_query_account",
            json!({ "address": hex::encode(sender.0) }),
        )
        .await
        .context("rpc chain_query_account")?;
    Ok(res.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0))
}

/// Build the `TxKind::SubmitPtb` envelope kind from the opaque `encode_ptb`
/// bytes of an already-signed inner PTB. The CLI never inspects or signs the
/// inner PTB — the node decodes it and xDSA-verifies it against registered
/// signer addresses during execution — so this is a thin, pure wrapper kept
/// separate for unit testing.
fn build_submit_ptb_kind(ptb_bytes: Vec<u8>) -> bloom_chain_types::tx::TxKind {
    bloom_chain_types::tx::TxKind::SubmitPtb { ptb_bytes }
}

/// Poll `chain_query_tx` until a receipt for `tx_hash` is indexed, returning
/// the full receipt JSON (success or revert alike). `submit-ptb` callers want
/// to see whatever receipt landed, so the decision is left to them. Bails only
/// if the timeout elapses with no receipt.
async fn poll_tx_receipt(
    client: &RpcClient,
    tx_hash: &bloom_chain_types::types::Hash32,
    timeout: std::time::Duration,
) -> Result<serde_json::Value> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let res = client
            .call(
                "chain_query_tx",
                json!({ "tx_hash": hex::encode(tx_hash.0) }),
            )
            .await
            .context("rpc chain_query_tx")?;
        if !res.is_null() {
            return Ok(res);
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for receipt of tx {}",
                hex::encode(tx_hash.0)
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
}

// ---------------------------------------------------------------------------
// `bloom chain testnet`
// ---------------------------------------------------------------------------

/// Provision an N-validator local network under `output_dir`.
///
/// For each `i in 0..validators`:
///   - Creates `output_dir/home<i>/chain/{keystore, blocks, state_blobs}`
///   - Generates a fresh xDSA keypair, writes it to
///     `home<i>/chain/keystore/validator.xdsa`.
///   - Derives the validator address via
///     `blake3("bloom-chain.v0.addr:" || pubkey)`.
///
/// Builds one shared `GenesisFile` carrying all N validators (with
/// `host = 127.0.0.1:base+i`) and per-validator pre-funded allocations,
/// then writes it to every `home<i>/chain/genesis.toml`.
/// Writes a per-node `config.toml` with distinct `listen_addr` and
/// `validator_address`. Finally prints a JSON manifest to stdout that the
/// test harness consumes.
#[allow(clippy::too_many_arguments)]
fn provision_testnet(
    validators: u8,
    output_dir: &std::path::Path,
    base_port: Option<u16>,
    chain_id: &str,
    allocation: &str,
    listen_addr_override: Option<&str>,
    rpc_tcp_addr_override: Option<&str>,
    unsafe_rpc_public_bind: bool,
    peer_hosts_csv: Option<&str>,
) -> Result<()> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use bloom_chain_node::genesis::{GenesisAllocation, GenesisFile, NodeConfig, ValidatorConfig};

    if validators == 0 {
        anyhow::bail!("--validators must be >= 1");
    }
    let alloc_amount: u128 = allocation
        .parse()
        .with_context(|| format!("parse --allocation as u128: {allocation:?}"))?;

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("create output dir {}", output_dir.display()))?;

    // Resolve base TCP port; if unspecified, pick a contiguous N-port window.
    let base = match base_port {
        Some(p) => p,
        None => pick_free_port_window(validators as u16)?,
    };

    // If `--listen-addr` is set, derive the listen port from it so peer-host
    // rewriting (below) uses the same port across all validators.
    let listen_addr_port: Option<u16> = match listen_addr_override {
        Some(s) => Some(
            parse_port_from_host_port(s)
                .with_context(|| format!("parse port from --listen-addr {s:?}"))?,
        ),
        None => None,
    };

    // Parse --peer-hosts CSV; must match the validator count when set.
    let peer_hosts: Option<Vec<String>> = match peer_hosts_csv {
        Some(csv) => {
            let v: Vec<String> = csv
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if v.len() != validators as usize {
                anyhow::bail!(
                    "--peer-hosts expected {} entries, got {}",
                    validators,
                    v.len()
                );
            }
            Some(v)
        }
        None => None,
    };

    // First pass: generate keys + derive addresses; persist keystore files.
    struct NodeProv {
        home: PathBuf,
        address_hex: String,
        pubkey_b64: String,
        /// Per-validator local listen address written into config.toml.
        listen_addr: String,
        /// Externally-reachable host:port that goes into genesis `[[validators]].host`.
        peer_host: String,
    }
    let mut nodes: Vec<NodeProv> = Vec::with_capacity(validators as usize);

    for i in 0..validators {
        let home = output_dir.join(format!("home{i}"));
        let chain_dir = home.join("chain");
        std::fs::create_dir_all(chain_dir.join("keystore"))
            .with_context(|| format!("mkdir keystore for home{i}"))?;
        std::fs::create_dir_all(chain_dir.join("blocks"))
            .with_context(|| format!("mkdir blocks for home{i}"))?;
        std::fs::create_dir_all(chain_dir.join("state_blobs"))
            .with_context(|| format!("mkdir state_blobs for home{i}"))?;

        let (sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
        let sk_bytes = sk.to_bytes();

        // Address = blake3("bloom-chain.v0.addr:" || pubkey) — canonical helper.
        let addr_bytes = bloom_chain_types::types::Address::from_pubkey_bytes(&pk.0).0;

        let key_path = chain_dir.join("keystore").join("validator.xdsa");
        // Testnet provisioning creates fresh per-validator home dirs, so the
        // path should never already exist — but write with mode 0o600 so the
        // secret never lands on disk with the umask-default 0644.
        write_secret_key_file(&key_path, sk_bytes.as_slice(), false)
            .with_context(|| format!("write key for home{i}"))?;

        // Default per-validator port window: 127.0.0.1:{base+i}.
        let default_host = format!("127.0.0.1:{}", base + i as u16);

        // `listen_addr`: override if --listen-addr is set (same for every node).
        let listen_addr = listen_addr_override
            .map(|s| s.to_string())
            .unwrap_or_else(|| default_host.clone());

        // `peer_host` (genesis): if --peer-hosts is given, use peer_hosts[i]
        // and the listen port; otherwise fall back to the per-validator
        // 127.0.0.1:base+i host.
        let peer_host = match (&peer_hosts, listen_addr_port) {
            (Some(hosts), Some(port)) => format!("{}:{}", hosts[i as usize], port),
            (Some(hosts), None) => format!("{}:{}", hosts[i as usize], base + i as u16),
            (None, _) => default_host.clone(),
        };

        nodes.push(NodeProv {
            home,
            address_hex: hex::encode(addr_bytes),
            pubkey_b64: B64.encode(&pk.0),
            listen_addr,
            peer_host,
        });
    }

    // Build the shared GenesisFile.
    let genesis_time_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let genesis = GenesisFile {
        chain_id: chain_id.to_string(),
        genesis_time_ms,
        validators: nodes
            .iter()
            .map(|n| ValidatorConfig {
                address: n.address_hex.clone(),
                pubkey: n.pubkey_b64.clone(),
                voting_power: 100,
                host: Some(n.peer_host.clone()),
            })
            .collect(),
        allocations: nodes
            .iter()
            .map(|n| GenesisAllocation {
                address: n.address_hex.clone(),
                amount: alloc_amount.to_string(),
            })
            .collect(),
        petals: vec![],
        key_registry: vec![],
    };
    let genesis_toml = toml::to_string_pretty(&genesis).context("serialize shared genesis.toml")?;

    // Second pass: write shared genesis + per-node config + collect manifest.
    let mut manifest = Vec::with_capacity(nodes.len());
    for n in &nodes {
        let chain_dir = n.home.join("chain");
        std::fs::write(chain_dir.join("genesis.toml"), &genesis_toml)
            .with_context(|| format!("write genesis for {}", n.home.display()))?;

        let node_cfg = NodeConfig {
            validator_address: n.address_hex.clone(),
            listen_addr: n.listen_addr.clone(),
            rpc_tcp_addr: rpc_tcp_addr_override.map(|s| s.to_string()),
            unsafe_rpc_public_bind,
            genesis_path: None,
            log_level: Some("info".into()),
            fuel_limit: Some(30_000_000),
            wasmtime_version: Some(env!("CARGO_PKG_VERSION").into()),
        };
        let cfg_toml =
            toml::to_string_pretty(&node_cfg).context("serialize per-node config.toml")?;
        std::fs::write(chain_dir.join("config.toml"), &cfg_toml)
            .with_context(|| format!("write config for {}", n.home.display()))?;

        manifest.push(json!({
            "home": n.home,
            "address": n.address_hex,
            "listen_addr": n.listen_addr,
            "peer_host": n.peer_host,
            "rpc_sock": chain_dir.join("rpc.sock"),
            "rpc_tcp_addr": rpc_tcp_addr_override,
            "unsafe_rpc_public_bind": unsafe_rpc_public_bind,
        }));
    }

    let out = json!({
        "chain_id": chain_id,
        "genesis_time_ms": genesis_time_ms,
        "validators": manifest,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

/// Parse the port out of a `host:port` (or `[::]:port`) string.
fn parse_port_from_host_port(s: &str) -> Result<u16> {
    let port_str = s
        .rsplit_once(':')
        .map(|(_, p)| p)
        .ok_or_else(|| anyhow::anyhow!("expected host:port, got {s:?}"))?;
    port_str
        .parse::<u16>()
        .with_context(|| format!("parse port {port_str:?}"))
}

/// Bind `count` consecutive TCP listeners starting at an OS-assigned port,
/// then release them — best-effort window for a multi-node testnet.
///
/// Returns the first port in the contiguous window. There is an inherent
/// race between releasing the listeners and the validators rebinding; tests
/// using this harness must tolerate occasional bind failures.
fn pick_free_port_window(count: u16) -> Result<u16> {
    use std::net::TcpListener;

    // Try a few times to find a free contiguous window.
    'outer: for _ in 0..16 {
        let first_listener = TcpListener::bind("127.0.0.1:0").context("bind probe port")?;
        let first_port = first_listener.local_addr()?.port();
        drop(first_listener);

        let mut listeners = Vec::with_capacity(count as usize);
        for i in 0..count {
            match TcpListener::bind(format!("127.0.0.1:{}", first_port + i)) {
                Ok(l) => listeners.push(l),
                Err(_) => continue 'outer,
            }
        }
        drop(listeners);
        return Ok(first_port);
    }
    anyhow::bail!("could not find a free TCP port window of size {count}")
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a minimal valid genesis.toml for the unit tests.
    fn write_minimal_genesis(path: &std::path::Path, chain_id: &str) {
        let g = format!(
            r#"chain_id = "{chain_id}"
genesis_time_ms = 1747526400000
validators = []
allocations = []
"#
        );
        std::fs::write(path, g).unwrap();
    }

    /// `build_submit_ptb_kind` wraps opaque PTB bytes verbatim into a
    /// `TxKind::SubmitPtb` without touching them — the CLI does not sign or
    /// decode the inner PTB.
    #[test]
    fn build_submit_ptb_kind_wraps_bytes_verbatim() {
        use bloom_chain_types::tx::TxKind;
        let bytes = vec![0x01u8, 0x02, 0x03, 0xFF];
        match build_submit_ptb_kind(bytes.clone()) {
            TxKind::SubmitPtb { ptb_bytes } => assert_eq!(ptb_bytes, bytes),
            other => panic!("expected SubmitPtb, got {other:?}"),
        }
    }

    /// review 2026-05-19 #9 — `write_secret_key_file` refuses to overwrite
    /// an existing path unless `force` is set.
    #[test]
    fn write_secret_key_file_refuses_overwrite_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("k");
        write_secret_key_file(&path, b"first", false).expect("initial write");
        let err =
            write_secret_key_file(&path, b"second", false).expect_err("second write must error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("refusing to overwrite") && msg.contains("--force"),
            "unexpected error: {msg}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"first");

        write_secret_key_file(&path, b"second", true).expect("force write");
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
    }

    /// review 2026-05-19 #9 — freshly written secrets must be mode 0o600
    /// on Unix.
    #[cfg(unix)]
    #[test]
    fn write_secret_key_file_uses_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("k");
        write_secret_key_file(&path, b"data", false).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got 0o{mode:o}");
    }

    /// review 2026-05-19 #9 — `--force` re-write must restore mode 0o600
    /// even when the pre-existing file was wider.
    #[cfg(unix)]
    #[test]
    fn write_secret_key_file_force_resets_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("k");
        // Pre-seed the file with deliberately wide perms (0o644).
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        write_secret_key_file(&path, b"new", true).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "expected force-write to chmod 0600, got 0o{mode:o}"
        );
    }

    /// review 2026-05-19 #15 — `run-validator` must reject a config whose
    /// declared `validator_address` doesn't match the keystore-derived
    /// address, with an error message naming both addresses.
    #[test]
    fn load_validator_run_config_rejects_address_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let chain_dir = home.join("chain");
        let keystore = chain_dir.join("keystore");
        std::fs::create_dir_all(&keystore).unwrap();

        // Real key — derive its address (the "truthful" one).
        let (sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
        let derived = bloom_chain_types::types::Address::from_pubkey_bytes(&pk.0);
        let key_path = keystore.join("validator.xdsa");
        std::fs::write(&key_path, sk.to_bytes().as_slice()).unwrap();

        // Declare a *different* validator_address (all-0x11) in config.toml.
        let bogus = bloom_chain_types::types::Address([0x11u8; 32]);
        let config = bloom_chain_node::NodeConfig {
            validator_address: hex::encode(bogus.0),
            listen_addr: "127.0.0.1:0".into(),
            rpc_tcp_addr: None,
            unsafe_rpc_public_bind: false,
            genesis_path: None,
            log_level: Some("warn".into()),
            fuel_limit: Some(30_000_000),
            wasmtime_version: Some("test".into()),
        };
        let config_path = chain_dir.join("config.toml");
        std::fs::write(&config_path, toml::to_string_pretty(&config).unwrap()).unwrap();
        write_minimal_genesis(&chain_dir.join("genesis.toml"), "bloomchain.test");

        let err = match load_validator_run_config(home, &chain_dir, &config_path) {
            Ok(_) => panic!("mismatch must be rejected"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("validator_address mismatch"),
            "expected mismatch error, got: {msg}"
        );
        assert!(
            msg.contains(&hex::encode(bogus.0)),
            "error must name declared address: {msg}"
        );
        assert!(
            msg.contains(&hex::encode(derived.0)),
            "error must name derived address: {msg}"
        );
        assert!(
            msg.contains(&key_path.display().to_string()),
            "error must name keystore path: {msg}"
        );
    }

    /// review 2026-05-19 #15 — a config that *does* match the keystore
    /// derivation passes the reconciliation check.
    #[test]
    fn load_validator_run_config_accepts_matching_address() {
        use base64::Engine as _;
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let chain_dir = home.join("chain");
        let keystore = chain_dir.join("keystore");
        std::fs::create_dir_all(&keystore).unwrap();

        let (sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
        let derived = bloom_chain_types::types::Address::from_pubkey_bytes(&pk.0);
        let key_path = keystore.join("validator.xdsa");
        std::fs::write(&key_path, sk.to_bytes().as_slice()).unwrap();

        let config = bloom_chain_node::NodeConfig {
            validator_address: hex::encode(derived.0),
            listen_addr: "127.0.0.1:0".into(),
            rpc_tcp_addr: None,
            unsafe_rpc_public_bind: false,
            genesis_path: None,
            log_level: Some("warn".into()),
            fuel_limit: Some(30_000_000),
            wasmtime_version: Some("test".into()),
        };
        let config_path = chain_dir.join("config.toml");
        std::fs::write(&config_path, toml::to_string_pretty(&config).unwrap()).unwrap();
        // Genesis must list the local validator so `Genesis::from_file`
        // doesn't reject "empty validator set".
        let pk_b64 = base64::engine::general_purpose::STANDARD.encode(&pk.0);
        let genesis = format!(
            r#"chain_id = "bloomchain.test"
genesis_time_ms = 1747526400000
allocations = []

[[validators]]
address = "{}"
pubkey = "{}"
voting_power = 100
host = "127.0.0.1:26656"
"#,
            hex::encode(derived.0),
            pk_b64
        );
        std::fs::write(chain_dir.join("genesis.toml"), genesis).unwrap();

        let (loaded_cfg, run_cfg) = load_validator_run_config(home, &chain_dir, &config_path)
            .expect("matching config should load");
        assert_eq!(loaded_cfg.validator_address, hex::encode(derived.0));
        assert_eq!(run_cfg.validator_address, derived);
    }

    #[test]
    fn rpc_tcp_bind_policy_rejects_public_without_flag() {
        let err = validate_rpc_tcp_bind_policy(Some("0.0.0.0:8545"), false)
            .expect_err("wildcard RPC bind must require explicit unsafe flag");
        assert!(
            err.to_string().contains("unsafe_rpc_public_bind"),
            "unexpected error: {err}"
        );
        validate_rpc_tcp_bind_policy(Some("127.0.0.1:8545"), false).unwrap();
        validate_rpc_tcp_bind_policy(Some("0.0.0.0:8545"), true).unwrap();
    }
}
