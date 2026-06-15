//! `bloom chain ...` — sovereign chain subcommand tree (spec §12).
//!
//! All subcommands that talk to a running node do so via the UDS JSON-RPC
//! socket at `<bloom_home>/chain/rpc.sock`.
//!
//! Subcommands that build/sign txs use the xDSA wallet stored in
//! `<bloom_home>/chain/keystore/<validator>.xdsa`.

use std::io::{IsTerminal, Read};
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
    /// Generate a client xDSA wallet, write it to the chain keystore, and print its address.
    Keygen {
        /// Overwrite the address-named key file if it already exists.
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
        /// Path to a `.wasm` file carrying a bloom_petal_manifest section.
        #[arg(value_name = "WASM")]
        wasm: PathBuf,
        /// Poll for the tx receipt after submitting and print it.
        #[arg(long)]
        wait: bool,
        /// Receipt-poll timeout in seconds (only with `--wait`; default 30).
        #[arg(long, value_name = "N", default_value_t = 30u64)]
        wait_timeout_secs: u64,
    },
    /// Execute one read-only petal call against the latest committed snapshot.
    #[command(name = "view-call", alias = "view")]
    ViewCall {
        /// Composed view command array as JSON. When set, --path/--function/--arg are ignored.
        #[arg(long, value_name = "JSON")]
        commands: Option<String>,
        /// Deployed petal path, e.g. `/bloom/apps/bloombook`.
        #[arg(long)]
        path: Option<String>,
        /// Petal function name, e.g. `counts`.
        #[arg(long)]
        function: Option<String>,
        /// Optional pinned petal hash. If omitted, the node resolves `--path`.
        #[arg(long)]
        hash: Option<String>,
        /// JSON argument descriptor. Repeat for each argument.
        ///
        /// Examples:
        /// `--arg '{"kind":"object","id":"<object-id>"}'`
        /// `--arg '{"kind":"const","value":"42"}'`
        #[arg(long = "arg", value_name = "JSON")]
        args: Vec<String>,
        /// Canonical TypeTag bytes as hex. Repeat for generic functions.
        #[arg(long = "type-arg", value_name = "HEX")]
        type_args: Vec<String>,
        /// Signer address to expose to `&Signer` args. Repeat as needed.
        #[arg(long = "signer", value_name = "ADDR")]
        signers: Vec<String>,
        /// Evaluate against a retained historical block height.
        #[arg(long, value_name = "HEIGHT")]
        at_block: Option<u64>,
        /// Fuel cap for the non-committing execution.
        #[arg(long, value_name = "N", default_value_t = 1_000_000u64)]
        fuel_limit: u64,
    },
    /// Execute one mutating petal call by lowering it through the PTB builder.
    #[command(name = "call")]
    Call {
        /// Deployed petal path, e.g. `/bloom/apps/bloombook`.
        #[arg(long)]
        path: Option<String>,
        /// Petal function name, e.g. `swap`.
        #[arg(long)]
        function: Option<String>,
        /// JSON argument descriptor. Repeat for each argument.
        #[arg(long = "arg", value_name = "JSON")]
        args: Vec<String>,
        /// Canonical TypeTag bytes as hex. Repeat for generic functions.
        #[arg(long = "type-arg", value_name = "HEX")]
        type_args: Vec<String>,
        /// Signer address/pubkey for the inner PTB. Defaults to the local validator key.
        #[arg(long = "signer", value_name = "ADDR")]
        signers: Vec<String>,
        /// Explicit gas-payer object id. If omitted, selects signer-owned Coin<LOOM>.
        #[arg(long = "gas-payer", value_name = "OBJECT_ID")]
        gas_payer: Option<String>,
        /// Gas budget for the inner PTB.
        #[arg(long = "gas-budget", value_name = "N", default_value_t = 1_000_000u64)]
        gas_budget: u64,
        /// Outer transaction fuel cap.
        #[arg(long = "fuel-limit", value_name = "N", default_value_t = 10_000_000u64)]
        fuel_limit: u64,
        /// Lower and validate the PTB without submitting it.
        #[arg(long)]
        dry_run: bool,
        /// Submit without waiting for the committed receipt.
        #[arg(long = "no-wait")]
        no_wait: bool,
    },
    /// Transfer LOOM fuel to an address by splitting the signer's Coin<LOOM>.
    Transfer {
        /// Recipient address (0x/raw-hex or b1-prefixed).
        #[arg(long, value_name = "ADDR")]
        to: String,
        /// LOOM amount in bloomweis.
        #[arg(long, value_name = "N")]
        amount: String,
        /// Signer address. Defaults to validator.xdsa or the only .xdsa key in the keystore.
        #[arg(long = "signer", value_name = "ADDR")]
        signer: Option<String>,
        /// Explicit Coin<LOOM> object id to split. If omitted, selects signer-owned Coin<LOOM>.
        #[arg(long = "gas-payer", value_name = "OBJECT_ID")]
        gas_payer: Option<String>,
        /// Gas budget for the inner PTB.
        #[arg(long = "gas-budget", value_name = "N", default_value_t = 1_000_000u64)]
        gas_budget: u64,
        /// Outer transaction fuel cap.
        #[arg(long = "fuel-limit", value_name = "N", default_value_t = 10_000_000u64)]
        fuel_limit: u64,
        /// Build and validate the transfer PTB without submitting it.
        #[arg(long)]
        dry_run: bool,
        /// Submit without waiting for the committed receipt.
        #[arg(long = "no-wait")]
        no_wait: bool,
    },
    /// Execute one atomic multi-endpoint petal plan through the PTB builder.
    #[command(name = "pipe")]
    Pipe {
        /// Pipe expression over `/bloom/petals/...` endpoint paths. If omitted, read from stdin.
        #[arg(value_name = "EXPR")]
        expr: Option<String>,
        /// Signer address/pubkey for the inner PTB. Defaults to the local validator key.
        #[arg(long = "signer", value_name = "ADDR")]
        signers: Vec<String>,
        /// Explicit gas-payer object id. If omitted, selects signer-owned Coin<LOOM>.
        #[arg(long = "gas-payer", value_name = "OBJECT_ID")]
        gas_payer: Option<String>,
        /// Gas budget for the inner PTB.
        #[arg(long = "gas-budget", value_name = "N", default_value_t = 1_000_000u64)]
        gas_budget: u64,
        /// Outer transaction fuel cap.
        #[arg(long = "fuel-limit", value_name = "N", default_value_t = 10_000_000u64)]
        fuel_limit: u64,
        /// Lower and validate the PTB without submitting it.
        #[arg(long)]
        dry_run: bool,
        /// Submit without waiting for the committed receipt.
        #[arg(long = "no-wait")]
        no_wait: bool,
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
        /// Treasury LOOM allocation, in bloomweis.
        #[arg(long, default_value = "1000000000000000000000000000")]
        treasury_allocation: String,
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

impl ChainCmd {
    pub fn requires_home_write_lock(&self) -> bool {
        matches!(
            self,
            ChainCmd::Init { .. }
                | ChainCmd::Keygen { .. }
                | ChainCmd::RunValidator { .. }
                | ChainCmd::Testnet { .. }
        )
    }
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
            let (sk_bytes, pk) = generate_xdsa_key_material()?;
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
            write_secret_key_file(&key_path, &sk_bytes, force)
                .with_context(|| format!("write validator key: {}", key_path.display()))?;

            println!("validator address : {addr_hex}");
            println!("validator key     : {}", key_path.display());
            println!(
                "\nEdit {} to add validators and allocations, then share genesis.toml with all validators.",
                genesis_dest.display()
            );
            Ok(())
        }

        // ── keygen ────────────────────────────────────────────────────────────
        ChainCmd::Keygen { force } => {
            let keystore_dir = chain_dir.join("keystore");
            std::fs::create_dir_all(&keystore_dir).context("create chain keystore dir")?;
            let (sk_bytes, pk) = generate_xdsa_key_material()?;
            let addr = bloom_chain_types::types::Address::from_pubkey_bytes(&pk.0);
            let addr_hex = hex::encode(addr.0);
            let key_path = keystore_dir.join(format!("{addr_hex}.xdsa"));
            write_secret_key_file(&key_path, &sk_bytes, force)
                .with_context(|| format!("write client key: {}", key_path.display()))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "address": format!("0x{addr_hex}"),
                    "key_path": key_path,
                }))?
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

            let client = make_client();
            let (sk, pk, sender) = load_wallet_key(&chain_dir)?;
            let chain_id = fetch_chain_id(&client).await?;
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

        // ── view petal call ──────────────────────────────────────────────────
        ChainCmd::ViewCall {
            commands,
            path,
            function,
            hash,
            args,
            type_args,
            signers,
            at_block,
            fuel_limit,
        } => {
            let parsed_args = args
                .iter()
                .map(|arg| {
                    serde_json::from_str::<serde_json::Value>(arg)
                        .with_context(|| format!("parse --arg JSON: {arg}"))
                })
                .collect::<Result<Vec<_>>>()?;
            let parsed_commands = commands
                .as_deref()
                .map(|commands| {
                    serde_json::from_str::<serde_json::Value>(commands)
                        .with_context(|| format!("parse --commands JSON: {commands}"))
                })
                .transpose()?;
            let mut stdin_params = read_view_call_stdin_json()?;
            let client = make_client();
            let endpoint_mode = parsed_commands.is_none();
            let mut params = if let Some(commands) = parsed_commands {
                json!({
                    "commands": commands,
                    "signers": signers,
                    "at_block": at_block,
                    "fuel_limit": fuel_limit,
                })
            } else {
                let path = path.context("--path is required unless --commands is set")?;
                let function =
                    function.context("--function is required unless --commands is set")?;
                json!({
                    "path": path,
                    "function": function,
                    "hash": hash,
                    "args": parsed_args,
                    "type_args": type_args,
                    "signers": signers,
                    "at_block": at_block,
                    "fuel_limit": fuel_limit,
                })
            };
            merge_view_stdin_params(&mut params, &mut stdin_params, endpoint_mode)?;
            let result = client.call("chain_view_call", params).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }

        // ── mutating petal call ─────────────────────────────────────────────
        ChainCmd::Call {
            path,
            function,
            args,
            type_args,
            signers,
            gas_payer,
            gas_budget,
            fuel_limit,
            dry_run,
            no_wait,
        } => {
            use bloom_chain_node::rpc::RpcChainAdapter;
            use bloom_chain_types::ssz::Encode;
            use bloom_script::PqSignature;

            let parsed_args = args
                .iter()
                .map(|arg| {
                    serde_json::from_str::<serde_json::Value>(arg)
                        .with_context(|| format!("parse --arg JSON: {arg}"))
                })
                .collect::<Result<Vec<_>>>()?;
            let mut stdin_params = read_call_stdin_json("call")?;
            let mut params = json!({
                "path": path,
                "function": function,
                "args": parsed_args,
                "type_args": type_args,
                "signers": signers,
                "gas_payer": gas_payer,
                "gas_budget": gas_budget,
                "fuel_limit": fuel_limit,
            });
            merge_stdin_params(&mut params, &mut stdin_params);

            let request = chain_call_request_from_params(&params, gas_budget, fuel_limit)?;
            let signer_override = chain_call_signer_override(&request)?;
            let (sk, pk, sender) = load_wallet_key_for_signer(&chain_dir, signer_override)?;

            let client = make_client();
            let gas_payer = match request.gas_payer.as_deref() {
                Some(s) if !s.is_empty() => parse_object_id_32(s).context("parse --gas-payer")?,
                _ => {
                    bloom_chain_node::gas_select::select_loom_gas_payer_rpc(
                        &client,
                        sender.0,
                        request.gas_budget as u128,
                    )
                    .await?
                }
            };
            let chain = RpcChainAdapter::from_env_or_socket(&rpc_sock);
            let mut plan = prepare_chain_call_plan(&chain, &request, sender, gas_payer)?;

            if dry_run {
                let value = dry_run_plan_json(&plan, &request.endpoint())?;
                println!("{}", serde_json::to_string_pretty(&value)?);
                return Ok(());
            }

            let ptb_digest = plan.tx.signing_digest();
            plan.tx.signatures = vec![PqSignature(sk.sign(&ptb_digest).to_bytes())];
            let ptb_bytes = bloom_script::encode_ptb(&plan.tx).context("encode signed PTB")?;
            let nonce = fetch_nonce(&client, &sender).await? + 1;
            let chain_id = fetch_chain_id(&client).await?;
            let tx = build_and_sign_tx(
                &sk,
                &pk,
                sender,
                &chain_id,
                nonce,
                build_submit_ptb_kind(ptb_bytes),
                request.fuel_limit,
                1,
            )?;
            let tx_hash = tx.tx_hash();
            client
                .call(
                    "chain_submit_tx",
                    json!({ "tx_hex": hex::encode(tx.as_ssz_bytes()) }),
                )
                .await?;
            if no_wait {
                let value = chain_call_submission_output(true, &tx_hash, None)?;
                println!("{}", value);
                return Ok(());
            }
            let receipt =
                poll_tx_receipt(&client, &tx_hash, std::time::Duration::from_secs(30)).await?;
            let value = chain_call_submission_output(false, &tx_hash, Some(&receipt))?;
            println!("{}", serde_json::to_string_pretty(&value)?);
            ensure_success_receipt(&value)?;
            Ok(())
        }

        // ── transfer ────────────────────────────────────────────────────────
        ChainCmd::Transfer {
            to,
            amount,
            signer,
            gas_payer,
            gas_budget,
            fuel_limit,
            dry_run,
            no_wait,
        } => {
            use bloom_chain_node::rpc::RpcChainAdapter;
            use bloom_chain_types::ssz::Encode;
            use bloom_script::PqSignature;

            let recipient = parse_addr(&to).with_context(|| format!("parse --to {to:?}"))?;
            let amount: u128 = amount
                .parse()
                .with_context(|| format!("parse --amount as u128: {amount:?}"))?;
            if amount == 0 {
                anyhow::bail!("--amount must be > 0");
            }
            let signer_override = signer
                .as_deref()
                .map(|s| parse_addr(s).with_context(|| format!("parse --signer {s:?}")))
                .transpose()?;
            let (sk, pk, sender) = load_wallet_key_for_signer(&chain_dir, signer_override)?;
            let client = make_client();
            let needed = amount
                .checked_add(gas_budget as u128)
                .context("transfer amount plus gas budget overflows u128")?;
            let gas_payer = match gas_payer.as_deref() {
                Some(s) if !s.is_empty() => parse_object_id_32(s).context("parse --gas-payer")?,
                _ => {
                    bloom_chain_node::gas_select::select_loom_gas_payer_rpc(
                        &client, sender.0, needed,
                    )
                    .await?
                }
            };
            let chain = RpcChainAdapter::from_env_or_socket(&rpc_sock);
            let mut plan =
                prepare_transfer_plan(&chain, sender, recipient, amount, gas_payer, gas_budget)?;

            if dry_run {
                let value = transfer_dry_run_json(&plan, recipient, amount)?;
                println!("{}", serde_json::to_string_pretty(&value)?);
                return Ok(());
            }

            let ptb_digest = plan.signing_digest();
            plan.signatures = vec![PqSignature(sk.sign(&ptb_digest).to_bytes())];
            let ptb_bytes =
                bloom_script::encode_ptb(&plan).context("encode signed transfer PTB")?;
            let nonce = fetch_nonce(&client, &sender).await? + 1;
            let chain_id = fetch_chain_id(&client).await?;
            let tx = build_and_sign_tx(
                &sk,
                &pk,
                sender,
                &chain_id,
                nonce,
                build_submit_ptb_kind(ptb_bytes),
                fuel_limit,
                1,
            )?;
            let tx_hash = tx.tx_hash();
            client
                .call(
                    "chain_submit_tx",
                    json!({ "tx_hex": hex::encode(tx.as_ssz_bytes()) }),
                )
                .await?;
            if no_wait {
                println!("{}", tx_hash_json(&tx_hash));
                return Ok(());
            }
            let receipt =
                poll_tx_receipt(&client, &tx_hash, std::time::Duration::from_secs(30)).await?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
            ensure_success_receipt(&receipt)?;
            Ok(())
        }

        // ── mutating petal pipe ─────────────────────────────────────────────
        ChainCmd::Pipe {
            expr,
            signers,
            gas_payer,
            gas_budget,
            fuel_limit,
            dry_run,
            no_wait,
        } => {
            use bloom_chain_node::rpc::RpcChainAdapter;
            use bloom_chain_types::ssz::Encode;
            use bloom_script::PqSignature;

            let expr = read_pipe_expr(expr)?;
            let signer_override = single_signer_override(&signers, "bloom chain pipe")?;
            let (sk, pk, sender) = load_wallet_key_for_signer(&chain_dir, signer_override)?;

            let client = make_client();
            let gas_payer = match gas_payer.as_deref() {
                Some(s) if !s.is_empty() => parse_object_id_32(s).context("parse --gas-payer")?,
                _ => {
                    bloom_chain_node::gas_select::select_loom_gas_payer_rpc(
                        &client,
                        sender.0,
                        gas_budget as u128,
                    )
                    .await?
                }
            };
            let chain = RpcChainAdapter::from_env_or_socket(&rpc_sock);
            let mut plan =
                prepare_chain_pipe_plan(&chain, &expr, &signers, sender, gas_payer, gas_budget)?;

            let plan_receipt = crate::commands::pipe::receipt_ndjson(&plan);
            if dry_run {
                print!("{plan_receipt}");
                return Ok(());
            }

            let ptb_digest = plan.tx.signing_digest();
            plan.tx.signatures = vec![PqSignature(sk.sign(&ptb_digest).to_bytes())];
            let ptb_bytes = bloom_script::encode_ptb(&plan.tx).context("encode signed PTB")?;
            let nonce = fetch_nonce(&client, &sender).await? + 1;
            let chain_id = fetch_chain_id(&client).await?;
            let tx = build_and_sign_tx(
                &sk,
                &pk,
                sender,
                &chain_id,
                nonce,
                build_submit_ptb_kind(ptb_bytes),
                fuel_limit,
                1,
            )?;
            let tx_hash = tx.tx_hash();
            client
                .call(
                    "chain_submit_tx",
                    json!({ "tx_hex": hex::encode(tx.as_ssz_bytes()) }),
                )
                .await?;
            if no_wait {
                println!("{}", tx_hash_json(&tx_hash));
                return Ok(());
            }
            let receipt =
                poll_tx_receipt(&client, &tx_hash, std::time::Duration::from_secs(30)).await?;
            let out = chain_pipe_submission_ndjson(&plan_receipt, &tx_hash, &receipt);
            print!("{out}");
            ensure_success_receipt(&receipt)?;
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
            let client = make_client();
            let chain_id = fetch_chain_id(&client).await?;
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
            treasury_allocation,
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
            &treasury_allocation,
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

fn read_view_call_stdin_json() -> Result<serde_json::Value> {
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Ok(serde_json::Value::Null);
    }

    let mut body = String::new();
    stdin
        .read_to_string(&mut body)
        .context("read view-call stdin")?;
    let body = body.trim();
    if body.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_str(body).context("parse view-call stdin JSON")
}

fn read_call_stdin_json(label: &str) -> Result<serde_json::Value> {
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Ok(serde_json::Value::Null);
    }

    let mut body = String::new();
    stdin
        .read_to_string(&mut body)
        .with_context(|| format!("read {label} stdin"))?;
    let body = body.trim();
    if body.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_str(body).with_context(|| format!("parse {label} stdin JSON"))
}

fn read_pipe_expr(expr: Option<String>) -> Result<String> {
    if let Some(expr) = expr {
        let expr = expr.trim();
        if expr.is_empty() {
            anyhow::bail!("pipe expression cannot be empty");
        }
        return Ok(expr.to_string());
    }

    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        anyhow::bail!("pipe expression is required as EXPR or stdin");
    }
    let mut body = String::new();
    stdin
        .read_to_string(&mut body)
        .context("read chain pipe stdin")?;
    let body = body.trim();
    if body.is_empty() {
        anyhow::bail!("pipe expression cannot be empty");
    }
    Ok(body.to_string())
}

fn merge_stdin_params(params: &mut serde_json::Value, stdin_params: &mut serde_json::Value) {
    if let Some(stdin_params) = stdin_params.as_object_mut()
        && let Some(params) = params.as_object_mut()
    {
        for (key, value) in std::mem::take(stdin_params) {
            match key.as_str() {
                "path" | "function" => {}
                _ => {
                    params.insert(key, value);
                }
            }
        }
    }
}

fn merge_view_stdin_params(
    params: &mut serde_json::Value,
    stdin_params: &mut serde_json::Value,
    endpoint_mode: bool,
) -> Result<()> {
    if endpoint_mode
        && stdin_params
            .get("commands")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|commands| !commands.is_empty())
    {
        anyhow::bail!("view-call endpoint mode does not accept stdin 'commands'");
    }
    if let Some(stdin_params) = stdin_params.as_object_mut()
        && let Some(params) = params.as_object_mut()
    {
        for (key, value) in std::mem::take(stdin_params) {
            match key.as_str() {
                "path" | "function" => {}
                _ => {
                    params.insert(key, value);
                }
            }
        }
    }
    Ok(())
}

fn parse_addr(s: &str) -> Result<bloom_chain_types::types::Address> {
    bloom_chain_node::genesis::parse_b1_address(s)
}

fn parse_object_id_32(s: &str) -> Result<bloom_objects::ObjectId> {
    let bytes = hex::decode(s.trim().trim_start_matches("0x")).context("decode object id hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("object id must be 32 bytes"))?;
    Ok(bloom_objects::ObjectId(arr))
}

#[derive(Debug, Clone)]
struct ChainCallRequest {
    path: String,
    function: String,
    args: Vec<serde_json::Value>,
    type_args: Vec<serde_json::Value>,
    signers: Vec<String>,
    gas_payer: Option<String>,
    gas_budget: u64,
    fuel_limit: u64,
}

impl ChainCallRequest {
    fn endpoint(&self) -> String {
        format!("{}/{}", self.path.trim_end_matches('/'), self.function)
    }
}

fn chain_call_request_from_params(
    params: &serde_json::Value,
    default_gas_budget: u64,
    default_fuel_limit: u64,
) -> Result<ChainCallRequest> {
    Ok(ChainCallRequest {
        path: params
            .get("path")
            .and_then(|v| v.as_str())
            .context("--path is required")?
            .to_string(),
        function: params
            .get("function")
            .and_then(|v| v.as_str())
            .context("--function is required")?
            .to_string(),
        args: params
            .get("args")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
        type_args: params
            .get("type_args")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
        signers: params
            .get("signers")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .map(|v| {
                        v.as_str()
                            .map(str::to_string)
                            .context("signers entries must be strings")
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default(),
        gas_payer: params
            .get("gas_payer")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        gas_budget: params
            .get("gas_budget")
            .and_then(|v| v.as_u64())
            .unwrap_or(default_gas_budget),
        fuel_limit: params
            .get("fuel_limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(default_fuel_limit),
    })
}

fn chain_call_signer_override(
    request: &ChainCallRequest,
) -> Result<Option<bloom_chain_types::types::Address>> {
    single_signer_override(&request.signers, "bloom chain call")
}

fn chain_call_signers_for_sender(
    request: &ChainCallRequest,
    sender: bloom_chain_types::types::Address,
) -> Result<Vec<[u8; 32]>> {
    single_signers_for_sender(&request.signers, sender, "bloom chain call")
}

fn single_signer_override(
    signers: &[String],
    command: &str,
) -> Result<Option<bloom_chain_types::types::Address>> {
    if signers.len() > 1 {
        anyhow::bail!("{command} supports exactly one --signer");
    }
    signers
        .first()
        .map(|s| parse_addr(s).with_context(|| format!("parse --signer {s:?}")))
        .transpose()
}

fn single_signers_for_sender(
    signers_raw: &[String],
    sender: bloom_chain_types::types::Address,
    command: &str,
) -> Result<Vec<[u8; 32]>> {
    let signers = if signers_raw.is_empty() {
        vec![sender.0]
    } else {
        signers_raw
            .iter()
            .map(|s| parse_addr(s).with_context(|| format!("parse --signer {s:?}")))
            .map(|r| r.map(|a| a.0))
            .collect::<Result<Vec<_>>>()?
    };

    if signers != vec![sender.0] {
        anyhow::bail!(
            "{command} can sign exactly one signer: the local key address {}",
            hex::encode(sender.0)
        );
    }
    Ok(signers)
}

fn prepare_chain_call_plan(
    chain: &dyn bloom_script::ChainStateIface,
    request: &ChainCallRequest,
    sender: bloom_chain_types::types::Address,
    gas_payer: bloom_objects::ObjectId,
) -> Result<crate::commands::pipe::LoweredPlan> {
    let signers = chain_call_signers_for_sender(request, sender)?;
    let command = single_call_command(
        chain,
        &request.path,
        &request.function,
        &request.type_args,
        &request.args,
    )?;
    crate::commands::pipe::lower_and_build_with_gas(
        chain,
        &command,
        signers,
        gas_payer,
        request.gas_budget,
        1,
    )
}

fn prepare_chain_pipe_plan(
    chain: &dyn bloom_script::ChainStateIface,
    expr: &str,
    signers_raw: &[String],
    sender: bloom_chain_types::types::Address,
    gas_payer: bloom_objects::ObjectId,
    gas_budget: u64,
) -> Result<crate::commands::pipe::LoweredPlan> {
    let signers = single_signers_for_sender(signers_raw, sender, "bloom chain pipe")?;
    crate::commands::pipe::lower_and_build_with_gas(chain, expr, signers, gas_payer, gas_budget, 1)
}

fn prepare_transfer_plan(
    chain: &dyn bloom_script::ChainStateIface,
    sender: bloom_chain_types::types::Address,
    recipient: bloom_chain_types::types::Address,
    amount: u128,
    gas_payer: bloom_objects::ObjectId,
    gas_budget: u64,
) -> Result<bloom_script::PtbTx> {
    use bloom_objects::{AccessMode, Owner};
    use bloom_script::{
        AlwaysOkVerifier, Arg, Command, ExpectedVersion, MoveCmd, PetalRef, PqSignature, UseRef,
        ValidationContext, ValidationMode, loom_coin_type_tag, loom_marker_type_tag, validate_ptb,
    };

    let fungible_hash = bloom_script::resolve_fungible_petal_hash(chain).ok_or_else(|| {
        anyhow::anyhow!(
            "missing required VFS binding for {}",
            bloom_script::CORE_FUNGIBLE_PATH
        )
    })?;
    let source = chain
        .load_object(&gas_payer)
        .with_context(|| format!("load source Coin<LOOM> {}", hex::encode(gas_payer.0)))?;
    let loom_coin_type = loom_coin_type_tag(fungible_hash);
    if source.type_tag != loom_coin_type {
        anyhow::bail!("selected gas payer is not a Coin<LOOM>");
    }
    if source.owner != Owner::Address(sender.0) {
        anyhow::bail!("selected Coin<LOOM> is not owned by signer");
    }

    let mut tx = bloom_script::PtbTx {
        signers: vec![sender.0],
        commands: vec![
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: bloom_script::CORE_FUNGIBLE_PATH.to_string(),
                    hash: Some(fungible_hash),
                },
                function: "identity".to_string(),
                type_args: vec![loom_marker_type_tag(fungible_hash)],
                args: vec![Arg::Object {
                    id: gas_payer,
                    expected_version: ExpectedVersion(source.version),
                    access_mode: AccessMode::Mutable,
                }],
            }),
            Command::SplitCoins {
                src: UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                },
                amounts: vec![amount],
            },
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 1,
                    ret_idx: 0,
                }],
                owner: Owner::Address(recipient.0),
            },
        ],
        gas_payer,
        gas_budget,
        gas_price: 1,
        expiry_block: u64::MAX,
        signatures: vec![],
    };

    let verifier = AlwaysOkVerifier;
    tx.signatures = vec![PqSignature(vec![0u8; 1])];
    validate_ptb(
        &tx,
        &ValidationContext {
            mode: ValidationMode::Commit,
            current_block: chain.current_block(),
            chain,
            verifier: &verifier,
            loom_coin_type,
        },
    )
    .context("validate transfer PTB")?;
    tx.signatures.clear();
    Ok(tx)
}

fn transfer_dry_run_json(
    tx: &bloom_script::PtbTx,
    recipient: bloom_chain_types::types::Address,
    amount: u128,
) -> Result<serde_json::Value> {
    Ok(json!({
        "dry_run": true,
        "kind": "transfer",
        "to": format!("0x{}", hex::encode(recipient.0)),
        "amount": amount.to_string(),
        "ptb_hash": format!("0x{}", hex::encode(tx.signing_digest())),
        "signers": tx.signers.len(),
        "gas_payer": format!("0x{}", hex::encode(tx.gas_payer.0)),
        "gas_budget": tx.gas_budget,
        "gas_price": tx.gas_price.to_string(),
        "commands": tx.commands.len(),
    }))
}

fn single_call_command(
    chain: &dyn bloom_script::ChainStateIface,
    path: &str,
    function: &str,
    type_args: &[serde_json::Value],
    args: &[serde_json::Value],
) -> Result<String> {
    let hash = chain
        .resolve_path(path)
        .with_context(|| format!("resolve petal path {path}"))?;
    let manifest = chain
        .load_manifest(&hash)
        .with_context(|| format!("load manifest for petal path {path}"))?;
    let function_decl = manifest
        .function(function)
        .with_context(|| format!("function {function} not found in {path}"))?;
    let ctx = SingleCallFunctionCtx {
        chain,
        path,
        function,
        manifest: &manifest,
        self_hash: hash.0,
        function_decl,
    };
    single_call_command_for_function(&ctx, type_args, args)
}

struct SingleCallFunctionCtx<'a> {
    chain: &'a dyn bloom_script::ChainStateIface,
    path: &'a str,
    function: &'a str,
    manifest: &'a bloom_script::PetalManifestStub,
    self_hash: [u8; 32],
    function_decl: &'a bloom_script::FunctionDeclStub,
}

fn single_call_command_for_function(
    ctx: &SingleCallFunctionCtx<'_>,
    type_args: &[serde_json::Value],
    args: &[serde_json::Value],
) -> Result<String> {
    let mut tokens = vec![format!(
        "{}/{}",
        ctx.path.trim_end_matches('/'),
        ctx.function
    )];
    let decoded_type_args = type_args
        .iter()
        .map(|ty| {
            bloom_script::decode_json_type_tag(ty)
                .with_context(|| format!("decode --type-arg {ty}"))
        })
        .collect::<Result<Vec<_>>>()?;
    for ty in type_args {
        tokens.push(format!("type:{}", call_type_arg_token(ty)?));
    }
    if args.len() != ctx.function_decl.args.len() {
        anyhow::bail!(
            "arg count mismatch: function declares {} arg(s), got {}",
            ctx.function_decl.args.len(),
            args.len()
        );
    }
    for (arg, decl) in args.iter().zip(&ctx.function_decl.args) {
        tokens.push(call_arg_token_for_decl(
            ctx.chain,
            arg,
            decl,
            ctx.manifest,
            ctx.self_hash,
            &decoded_type_args,
        )?);
    }
    Ok(tokens.join(" "))
}

fn call_type_arg_token(value: &serde_json::Value) -> Result<String> {
    let tag = bloom_script::decode_json_type_tag(value)
        .with_context(|| format!("decode --type-arg {value}"))?;
    Ok(bloom_value::type_tag_label(&tag))
}

#[cfg(test)]
fn call_arg_token(arg: &serde_json::Value) -> Result<String> {
    if let Some((id, version)) = call_object_id_version(arg)? {
        let id = id.trim().trim_start_matches("0x");
        return if let Some(version) = version {
            Ok(format!("obj:{id}@{version}"))
        } else {
            Ok(format!("obj:{id}"))
        };
    }
    if let Some(idx) = call_signer_index(arg)? {
        return Ok(format!("signer:{idx}"));
    }
    let kind = arg
        .get("kind")
        .and_then(|v| v.as_str())
        .context("call arg missing string field 'kind'")?;
    match kind {
        "signer" => {
            let idx = arg
                .get("index")
                .and_then(|v| v.as_u64())
                .context("signer arg missing numeric field 'index'")?;
            Ok(format!("signer:{idx}"))
        }
        "const" => {
            if let Some(hex) = arg.get("hex").and_then(|v| v.as_str()) {
                anyhow::bail!("raw const hex is not accepted for typed JSON args: {hex}");
            } else if let Some(value) = arg.get("value") {
                match value {
                    serde_json::Value::String(s) => Ok(s.clone()),
                    serde_json::Value::Number(n) => Ok(n.to_string()),
                    serde_json::Value::Bool(b) => Ok(b.to_string()),
                    _ => anyhow::bail!("const arg 'value' must be string, number, or bool"),
                }
            } else {
                anyhow::bail!("const arg requires 'hex' or 'value'")
            }
        }
        other => anyhow::bail!("unsupported call arg kind {other:?}"),
    }
}

fn call_arg_token_for_decl(
    chain: &dyn bloom_script::ChainStateIface,
    arg: &serde_json::Value,
    decl: &bloom_script::ArgDeclStub,
    manifest: &bloom_script::PetalManifestStub,
    self_hash: [u8; 32],
    type_args: &[bloom_objects::TypeTag],
) -> Result<String> {
    match decl {
        bloom_script::ArgDeclStub::Object { .. } => call_object_token(chain, arg),
        bloom_script::ArgDeclStub::Signer => {
            let idx = call_signer_index(arg)?.context("expected signer arg")?;
            Ok(format!("signer:{idx}"))
        }
        bloom_script::ArgDeclStub::Const(tag) => {
            call_const_token(chain, arg, tag, manifest, self_hash, type_args)
        }
        bloom_script::ArgDeclStub::TypeArg(_) => Ok(format!("type:{}", call_type_arg_token(arg)?)),
    }
}

fn call_object_token(
    chain: &dyn bloom_script::ChainStateIface,
    arg: &serde_json::Value,
) -> Result<String> {
    let (id, version) = call_object_id_version(arg)?.context("expected object arg")?;
    let id = id.trim().trim_start_matches("0x");
    let version = match version {
        Some(version) => version,
        None => {
            let id_obj = parse_object_id_32(id)?;
            chain
                .load_object(&id_obj)
                .with_context(|| format!("object {id} not found"))?
                .version
        }
    };
    Ok(format!("obj:{id}@{version}"))
}

fn call_const_token(
    chain: &dyn bloom_script::ChainStateIface,
    arg: &serde_json::Value,
    tag: &bloom_objects::TypeTag,
    manifest: &bloom_script::PetalManifestStub,
    self_hash: [u8; 32],
    type_args: &[bloom_objects::TypeTag],
) -> Result<String> {
    let value = if arg.get("kind").and_then(|v| v.as_str()) == Some("const") {
        if let Some(hex) = arg.get("hex").and_then(|v| v.as_str()) {
            anyhow::bail!("raw const hex is not accepted for typed JSON args: {hex}");
        }
        arg.get("value").unwrap_or(arg)
    } else {
        arg
    };
    let resolved = substitute_call_type_args(tag, type_args);
    let load_manifest =
        |petal_hash: &bloom_chain_types::types::Hash32| chain.load_manifest(petal_hash);
    let bytes = bloom_script::decode_json_const_with_manifest_loader(
        manifest,
        self_hash,
        &resolved,
        value,
        Some(&load_manifest),
    )
    .with_context(|| {
        format!(
            "decode const arg for {}",
            bloom_value::type_tag_label(&resolved)
        )
    })?;
    Ok(format!("const:0x{}", hex::encode(bytes)))
}

fn substitute_call_type_args(
    tag: &bloom_objects::TypeTag,
    type_args: &[bloom_objects::TypeTag],
) -> bloom_objects::TypeTag {
    match tag {
        bloom_objects::TypeTag::Generic { idx } => type_args
            .get(*idx as usize)
            .cloned()
            .unwrap_or_else(|| tag.clone()),
        bloom_objects::TypeTag::Concrete {
            petal_hash,
            type_name,
            type_args: inner,
        } => bloom_objects::TypeTag::Concrete {
            petal_hash: *petal_hash,
            type_name: type_name.clone(),
            type_args: inner
                .iter()
                .map(|t| substitute_call_type_args(t, type_args))
                .collect(),
        },
        bloom_objects::TypeTag::External { .. } => tag.clone(),
    }
}

fn call_object_id_version(arg: &serde_json::Value) -> Result<Option<(&str, Option<u64>)>> {
    if let Some(id) = arg.as_str() {
        return Ok(Some((id, None)));
    }
    let obj = if arg.get("kind").and_then(|v| v.as_str()) == Some("object") {
        arg
    } else if let Some(obj) = arg.get("object") {
        if let Some(id) = obj.as_str() {
            return Ok(Some((id, None)));
        }
        obj
    } else {
        return Ok(None);
    };
    let id = obj
        .get("id")
        .and_then(|v| v.as_str())
        .context("object arg missing string field 'id'")?;
    Ok(Some((id, obj.get("version").and_then(|v| v.as_u64()))))
}

fn call_signer_index(arg: &serde_json::Value) -> Result<Option<u64>> {
    if let Some(index) = arg.as_u64() {
        return Ok(Some(index));
    }
    if let Some(index) = arg.get("signer").and_then(|v| v.as_u64()) {
        return Ok(Some(index));
    }
    if arg.get("kind").and_then(|v| v.as_str()) == Some("signer") {
        return arg
            .get("index")
            .and_then(|v| v.as_u64())
            .map(Some)
            .context("signer arg missing numeric field 'index'");
    }
    Ok(None)
}

fn dry_run_plan_json(
    plan: &crate::commands::pipe::LoweredPlan,
    endpoint: &str,
) -> Result<serde_json::Value> {
    let mut value: serde_json::Value = serde_json::from_str(
        crate::commands::pipe::receipt_ndjson(plan)
            .lines()
            .next()
            .unwrap_or("{}"),
    )
    .context("render dry-run plan")?;
    value["dry_run"] = serde_json::Value::Bool(true);
    value["endpoint"] = serde_json::Value::String(endpoint.to_string());
    Ok(value)
}

fn chain_pipe_submission_ndjson(
    plan_receipt: &str,
    tx_hash: &bloom_chain_types::types::Hash32,
    receipt: &serde_json::Value,
) -> String {
    let tx_hash_hex = format!("0x{}", hex::encode(tx_hash.0));
    let mut out = plan_receipt.to_string();
    out.push_str(
        &json!({
            "kind": "submit",
            "tx_hash": tx_hash_hex,
        })
        .to_string(),
    );
    out.push('\n');
    out.push_str(
        &json!({
            "kind": "receipt",
            "tx_hash": tx_hash_hex,
            "receipt": receipt,
        })
        .to_string(),
    );
    out.push('\n');
    out
}

fn tx_hash_json(tx_hash: &bloom_chain_types::types::Hash32) -> serde_json::Value {
    json!({ "tx_hash": hex::encode(tx_hash.0) })
}

fn chain_call_submission_output(
    no_wait: bool,
    tx_hash: &bloom_chain_types::types::Hash32,
    receipt: Option<&serde_json::Value>,
) -> Result<serde_json::Value> {
    if no_wait {
        return Ok(tx_hash_json(tx_hash));
    }
    let receipt = receipt.context("missing call receipt after submit")?;
    Ok(receipt.clone())
}

fn ensure_success_receipt(receipt: &serde_json::Value) -> Result<()> {
    if receipt.get("success").and_then(|v| v.as_bool()) == Some(true) {
        Ok(())
    } else {
        anyhow::bail!("petal call reverted: {}", receipt_revert_reason(receipt))
    }
}

fn receipt_revert_reason(receipt: &serde_json::Value) -> &str {
    receipt
        .get("return_text")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| receipt.get("return_data").and_then(|v| v.as_str()))
        .unwrap_or("unknown revert")
}

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

fn generate_xdsa_key_material() -> Result<(Vec<u8>, bloom_keystore::xdsa::XdsaPublicKey)> {
    std::thread::Builder::new()
        .name("bloom-xdsa-keygen".to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let (sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
            let bytes = sk.to_bytes().as_slice().to_vec();
            (bytes, pk)
        })
        .context("spawn xDSA keygen thread")?
        .join()
        .map_err(|_| anyhow::anyhow!("xDSA keygen thread panicked"))
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
    load_wallet_key_for_signer(chain_dir, None)
}

/// Load an xDSA chain key, optionally selecting by bloom-chain address.
///
/// Stage 2 keeps the zero-config validator-key default but lets callers pass
/// `--signer <addr>` to choose another raw `.xdsa` key under
/// `<chain_dir>/keystore`.
fn load_wallet_key_for_signer(
    chain_dir: &std::path::Path,
    signer: Option<bloom_chain_types::types::Address>,
) -> Result<(
    bloom_keystore::xdsa::XdsaSecretKey,
    bloom_keystore::xdsa::XdsaPublicKey,
    bloom_chain_types::types::Address,
)> {
    let key_path = chain_dir.join("keystore").join("validator.xdsa");
    if signer.is_none() {
        if key_path.exists() {
            return load_xdsa_key_at(&key_path);
        }
        return load_single_xdsa_key(&chain_dir.join("keystore"));
    }
    let signer = signer.expect("checked above");
    let keystore_dir = chain_dir.join("keystore");
    let entries = std::fs::read_dir(&keystore_dir)
        .with_context(|| format!("read chain keystore dir: {}", keystore_dir.display()))?;
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("xdsa") {
            continue;
        }
        let loaded = load_xdsa_key_at(&path)
            .with_context(|| format!("load signer candidate {}", path.display()))?;
        if loaded.2 == signer {
            return Ok(loaded);
        }
    }
    anyhow::bail!(
        "no xDSA key for signer {} found under {}",
        hex::encode(signer.0),
        keystore_dir.display()
    )
}

fn load_single_xdsa_key(
    keystore_dir: &std::path::Path,
) -> Result<(
    bloom_keystore::xdsa::XdsaSecretKey,
    bloom_keystore::xdsa::XdsaPublicKey,
    bloom_chain_types::types::Address,
)> {
    let mut keys = std::fs::read_dir(keystore_dir)
        .with_context(|| format!("read chain keystore dir: {}", keystore_dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("xdsa"))
        .collect::<Vec<_>>();
    keys.sort();
    match keys.as_slice() {
        [path] => load_xdsa_key_at(path),
        [] => anyhow::bail!("no xDSA keys found under {}", keystore_dir.display()),
        _ => anyhow::bail!(
            "multiple xDSA keys found under {}; pass --signer to select one",
            keystore_dir.display()
        ),
    }
}

fn load_xdsa_key_at(
    key_path: &std::path::Path,
) -> Result<(
    bloom_keystore::xdsa::XdsaSecretKey,
    bloom_keystore::xdsa::XdsaPublicKey,
    bloom_chain_types::types::Address,
)> {
    let key_bytes =
        std::fs::read(key_path).with_context(|| format!("read key: {}", key_path.display()))?;
    let sk = bloom_keystore::xdsa::XdsaSecretKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow::anyhow!("decode xDSA key {}: {e}", key_path.display()))?;
    let pk = sk.public_key();
    let addr = bloom_chain_types::types::Address::from_pubkey_bytes(&pk.0);
    Ok((sk, pk, addr))
}

/// Build and sign a Tx with an explicit `chain_id` and `nonce`. Callers are
/// responsible for fetching the next-valid nonce from the chain via
/// [`fetch_nonce`] and resolving `chain_id` from the connected node via
/// [`fetch_chain_id`]; baking either of those in would produce txs that get
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

/// Fetch `chain_id` from the connected validator so public clients only need a
/// local signer key, not a copied genesis file.
async fn fetch_chain_id(client: &RpcClient) -> Result<String> {
    let res = client
        .call("chain_health", json!({}))
        .await
        .context("rpc chain_health")?;
    res.get("chain_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow::anyhow!("chain_health missing chain_id: {res}"))
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
    treasury_allocation: &str,
    listen_addr_override: Option<&str>,
    rpc_tcp_addr_override: Option<&str>,
    unsafe_rpc_public_bind: bool,
    peer_hosts_csv: Option<&str>,
) -> Result<()> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use bloom_chain_node::genesis::{
        GenesisAllocation, GenesisFile, GenesisKeyRegistryEntry, GenesisPetal, NodeConfig,
        ValidatorConfig,
    };

    if validators == 0 {
        anyhow::bail!("--validators must be >= 1");
    }
    let alloc_amount: u128 = allocation
        .parse()
        .with_context(|| format!("parse --allocation as u128: {allocation:?}"))?;
    let treasury_amount: u128 = treasury_allocation
        .parse()
        .with_context(|| format!("parse --treasury-allocation as u128: {treasury_allocation:?}"))?;

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

        let (sk_bytes, pk) = generate_xdsa_key_material()?;

        // Address = blake3("bloom-chain.v0.addr:" || pubkey) — canonical helper.
        let addr_bytes = bloom_chain_types::types::Address::from_pubkey_bytes(&pk.0).0;

        let key_path = chain_dir.join("keystore").join("validator.xdsa");
        // Testnet provisioning creates fresh per-validator home dirs, so the
        // path should never already exist — but write with mode 0o600 so the
        // secret never lands on disk with the umask-default 0644.
        write_secret_key_file(&key_path, &sk_bytes, false)
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

    let treasury_home = output_dir.join("treasury");
    let treasury_chain_dir = treasury_home.join("chain");
    std::fs::create_dir_all(treasury_chain_dir.join("keystore"))
        .context("mkdir treasury keystore")?;
    let (treasury_sk_bytes, treasury_pk) = generate_xdsa_key_material()?;
    let treasury_addr = bloom_chain_types::types::Address::from_pubkey_bytes(&treasury_pk.0);
    let treasury_addr_hex = hex::encode(treasury_addr.0);
    let treasury_key_path = treasury_chain_dir
        .join("keystore")
        .join(format!("{treasury_addr_hex}.xdsa"));
    write_secret_key_file(&treasury_key_path, &treasury_sk_bytes, false)
        .context("write treasury key")?;

    // Build the shared GenesisFile.
    let genesis_time_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let core_fungible_wasm =
        genesis_manifest_wasm(bloom_petal_fungible::fungible::__bloom_manifest_bytes())
            .context("build core fungible genesis petal wasm")?;
    let mut allocations = nodes
        .iter()
        .map(|n| GenesisAllocation {
            address: n.address_hex.clone(),
            amount: alloc_amount.to_string(),
        })
        .collect::<Vec<_>>();
    allocations.push(GenesisAllocation {
        address: treasury_addr_hex.clone(),
        amount: treasury_amount.to_string(),
    });
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
        allocations,
        petals: vec![GenesisPetal {
            path: bloom_script::CORE_FUNGIBLE_PATH.to_string(),
            wasm_hex: hex::encode(core_fungible_wasm),
        }],
        key_registry: vec![GenesisKeyRegistryEntry {
            address: treasury_addr_hex.clone(),
            pubkey: B64.encode(&treasury_pk.0),
        }],
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
    std::fs::create_dir_all(treasury_chain_dir.join("blocks")).context("mkdir treasury blocks")?;
    std::fs::create_dir_all(treasury_chain_dir.join("state_blobs"))
        .context("mkdir treasury state_blobs")?;
    std::fs::write(treasury_chain_dir.join("genesis.toml"), &genesis_toml)
        .context("write treasury genesis")?;

    let out = json!({
        "chain_id": chain_id,
        "genesis_time_ms": genesis_time_ms,
        "validators": manifest,
        "treasury": {
            "home": treasury_home,
            "address": format!("0x{treasury_addr_hex}"),
            "key_path": treasury_key_path,
            "allocation": treasury_amount.to_string(),
        },
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

fn genesis_manifest_wasm(manifest_bytes: &[u8]) -> Result<Vec<u8>> {
    let manifest = bloom_petal_manifest::codec::decode(manifest_bytes)
        .context("decode genesis petal manifest")?;
    let mut wasm = Vec::new();
    wasm.extend_from_slice(b"\0asm");
    wasm.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

    // type 0: (i32, i32) -> i32, the PTB petal export ABI.
    wasm_section(&mut wasm, 1, &[0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f]);

    let mut export_names: Vec<String> = manifest
        .functions
        .iter()
        .map(|function| format!("__petal_{}", function.name))
        .collect();
    export_names.extend(
        manifest
            .invariants
            .iter()
            .map(|invariant| invariant.wasm_export.clone()),
    );

    let mut functions = Vec::new();
    write_uleb128(&mut functions, export_names.len() as u64);
    functions.extend(std::iter::repeat_n(0x00, export_names.len()));
    wasm_section(&mut wasm, 3, &functions);

    let mut exports = Vec::new();
    write_uleb128(&mut exports, export_names.len() as u64);
    for (idx, export_name) in export_names.iter().enumerate() {
        write_uleb128(&mut exports, export_name.len() as u64);
        exports.extend_from_slice(export_name.as_bytes());
        exports.push(0x00);
        write_uleb128(&mut exports, idx as u64);
    }
    wasm_section(&mut wasm, 7, &exports);

    let mut code = Vec::new();
    write_uleb128(&mut code, export_names.len() as u64);
    for _ in &export_names {
        // no locals; i32.const -3; end. This manifest-only bootstrap wasm
        // exists to bind the path and schema at genesis, but it must fail
        // closed if someone calls it before replacing it with real wasm.
        code.extend_from_slice(&[0x04, 0x00, 0x41, 0x7d, 0x0b]);
    }
    wasm_section(&mut wasm, 10, &code);

    Ok(append_manifest_section(wasm, manifest_bytes))
}

fn wasm_section(out: &mut Vec<u8>, id: u8, body: &[u8]) {
    out.push(id);
    write_uleb128(out, body.len() as u64);
    out.extend_from_slice(body);
}

fn append_manifest_section(mut wasm: Vec<u8>, manifest_bytes: &[u8]) -> Vec<u8> {
    let name = bloom_petal_manifest::MANIFEST_CUSTOM_SECTION;
    let mut body = Vec::new();
    write_uleb128(&mut body, name.len() as u64);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(manifest_bytes);
    wasm.push(0x00);
    write_uleb128(&mut wasm, body.len() as u64);
    wasm.extend_from_slice(&body);
    wasm
}

fn write_uleb128(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
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
    use std::collections::HashMap;
    use std::sync::Mutex;

    use bloom_chain_types::Hash32;
    use bloom_objects::{AccessMode, Object, ObjectId, Owner, TypeTag};
    use bloom_petal_fungible::ops::coin_payload;
    use bloom_script::{Arg, ArgDeclStub, Command, FunctionDeclStub, PetalManifestStub};

    #[derive(Default)]
    struct MockChain {
        objects: Mutex<HashMap<[u8; 32], Object>>,
        petals: Mutex<HashMap<[u8; 32], Vec<u8>>>,
        manifests: Mutex<HashMap<[u8; 32], PetalManifestStub>>,
        paths: Mutex<HashMap<String, Hash32>>,
    }

    impl MockChain {
        fn put_object(&self, obj: Object) {
            self.objects.lock().unwrap().insert(obj.id.0, obj);
        }

        fn put_petal(&self, path: &str, hash: Hash32, manifest: PetalManifestStub) {
            self.paths.lock().unwrap().insert(path.to_string(), hash);
            self.petals.lock().unwrap().insert(hash.0, vec![0]);
            self.manifests.lock().unwrap().insert(hash.0, manifest);
        }
    }

    impl bloom_script::ChainStateIface for MockChain {
        fn load_object(&self, id: &ObjectId) -> Option<Object> {
            self.objects.lock().unwrap().get(&id.0).cloned()
        }

        fn load_petal(&self, _hash: &Hash32) -> Option<Vec<u8>> {
            self.petals.lock().unwrap().get(&_hash.0).cloned()
        }

        fn load_manifest(&self, hash: &Hash32) -> Option<PetalManifestStub> {
            self.manifests.lock().unwrap().get(&hash.0).cloned()
        }

        fn resolve_path(&self, path: &str) -> Option<Hash32> {
            self.paths.lock().unwrap().get(path).copied()
        }

        fn current_block(&self) -> u64 {
            1
        }
    }

    fn concrete(name: &str) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: name.to_string(),
            type_args: vec![],
        }
    }

    #[test]
    fn genesis_manifest_wasm_exports_fail_closed() {
        let wasm = genesis_manifest_wasm(bloom_petal_fungible::fungible::__bloom_manifest_bytes())
            .expect("genesis manifest wasm builds");

        assert!(
            wasm.windows(5)
                .any(|window| window == [0x04, 0x00, 0x41, 0x7d, 0x0b]),
            "bootstrap petal exports must return the Invalid host code, not success"
        );
        assert!(
            !wasm
                .windows(5)
                .any(|window| window == [0x04, 0x00, 0x41, 0x00, 0x0b]),
            "bootstrap petal exports must not be successful no-ops"
        );
    }

    fn command_test_chain() -> MockChain {
        let chain = MockChain::default();
        let object_id = ObjectId([0x11; 32]);
        let gas_id = ObjectId([0xFE; 32]);
        chain.put_object(Object {
            id: object_id,
            type_tag: concrete("Counter"),
            owner: Owner::Shared,
            version: 7,
            payload: vec![],
        });
        chain.put_object(Object {
            id: gas_id,
            type_tag: bloom_script::loom_coin_type_tag(bloom_script::DEFAULT_FUNGIBLE_PETAL_HASH),
            owner: Owner::Address([0x22; 32]),
            version: 0,
            payload: coin_payload(3_000_000),
        });
        chain.paths.lock().unwrap().insert(
            bloom_script::CORE_FUNGIBLE_PATH.to_string(),
            bloom_script::DEFAULT_FUNGIBLE_PETAL_HASH,
        );
        let fungible_manifest = bloom_petal_manifest::codec::decode(
            bloom_petal_fungible::fungible::__bloom_manifest_bytes(),
        )
        .unwrap();
        chain.put_petal(
            bloom_script::CORE_FUNGIBLE_PATH,
            bloom_script::DEFAULT_FUNGIBLE_PETAL_HASH,
            bloom_petal_manifest::stub::to_petal_manifest_stub(&fungible_manifest),
        );
        chain.put_petal(
            "/bloom/petals/dex/probe",
            Hash32([0xAB; 32]),
            PetalManifestStub {
                module_path: "/bloom/petals/dex/probe".to_string(),
                functions: vec![
                    FunctionDeclStub {
                        name: "set_counter".to_string(),
                        type_params: vec![],
                        args: vec![
                            ArgDeclStub::Object {
                                ty: concrete("Counter"),
                                mode: AccessMode::Mutable,
                            },
                            ArgDeclStub::Signer,
                            ArgDeclStub::Const(concrete("u64")),
                        ],
                        returns: vec![],
                        ..Default::default()
                    },
                    FunctionDeclStub {
                        name: "spend".to_string(),
                        args: vec![],
                        returns: vec![concrete("Packet")],
                        ..Default::default()
                    },
                    FunctionDeclStub {
                        name: "swap".to_string(),
                        args: vec![ArgDeclStub::Object {
                            ty: concrete("Packet"),
                            mode: AccessMode::Consume,
                        }],
                        returns: vec![concrete("Packet")],
                        ..Default::default()
                    },
                    FunctionDeclStub {
                        name: "receive".to_string(),
                        args: vec![ArgDeclStub::Object {
                            ty: concrete("Packet"),
                            mode: AccessMode::Consume,
                        }],
                        returns: vec![],
                        ..Default::default()
                    },
                    FunctionDeclStub {
                        name: "spend_eth".to_string(),
                        args: vec![],
                        returns: vec![concrete("ETH")],
                        ..Default::default()
                    },
                    FunctionDeclStub {
                        name: "spend_usdc".to_string(),
                        args: vec![],
                        returns: vec![concrete("USDC")],
                        ..Default::default()
                    },
                    FunctionDeclStub {
                        name: "add_liquidity".to_string(),
                        args: vec![
                            ArgDeclStub::Const(concrete("u64")),
                            ArgDeclStub::Object {
                                ty: concrete("ETH"),
                                mode: AccessMode::Consume,
                            },
                            ArgDeclStub::Object {
                                ty: concrete("USDC"),
                                mode: AccessMode::Consume,
                            },
                        ],
                        returns: vec![concrete("LP")],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        );
        chain
    }

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

    #[test]
    fn call_command_builds_ptb_builder_line_from_json_args() {
        let u64_tag = bloom_objects::TypeTag::Concrete {
            petal_hash: bloom_objects::BUILTIN_TYPE_HASH,
            type_name: "u64".to_string(),
            type_args: vec![],
        };
        let u64_tag_hex = hex::encode(u64_tag.encode_canonical().unwrap());
        let chain = command_test_chain();
        let line = single_call_command(
            &chain,
            "/bloom/petals/dex/probe",
            "set_counter",
            &[serde_json::Value::String(u64_tag_hex)],
            &[
                serde_json::json!(
                    "0x1111111111111111111111111111111111111111111111111111111111111111"
                ),
                serde_json::json!({ "kind": "signer", "index": 0 }),
                serde_json::json!({ "kind": "const", "value": 77u64 }),
            ],
        )
        .unwrap();
        assert_eq!(
            line,
            "/bloom/petals/dex/probe/set_counter type:u64 obj:1111111111111111111111111111111111111111111111111111111111111111@7 signer:0 const:0x000000000000004d"
        );
    }

    #[test]
    fn call_request_parsing_preserves_submit_overrides() {
        let params = serde_json::json!({
            "path": "/bloom/petals/dex/probe",
            "function": "set_counter",
            "args": [{ "kind": "const", "value": 77 }],
            "type_args": ["u64"],
            "signers": ["0x2222222222222222222222222222222222222222222222222222222222222222"],
            "gas_payer": "0xfefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe",
            "gas_budget": 2_000_000u64,
            "fuel_limit": 3_000_000u64,
        });
        let request = chain_call_request_from_params(&params, 1_000_000, 10_000_000).unwrap();
        assert_eq!(request.path, "/bloom/petals/dex/probe");
        assert_eq!(request.function, "set_counter");
        assert_eq!(request.args.len(), 1);
        assert_eq!(request.type_args, vec![serde_json::json!("u64")]);
        assert_eq!(
            request.signers,
            vec!["0x2222222222222222222222222222222222222222222222222222222222222222"]
        );
        assert_eq!(
            request.gas_payer.as_deref(),
            Some("0xfefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe")
        );
        assert_eq!(request.gas_budget, 2_000_000);
        assert_eq!(request.fuel_limit, 3_000_000);
    }

    #[test]
    fn call_prepare_plan_uses_command_path_signer_and_gas_override() {
        let chain = command_test_chain();
        let sender = bloom_chain_types::types::Address([0x22; 32]);
        let gas_payer = ObjectId([0xFE; 32]);
        let signer = hex::encode(sender.0);
        let request = ChainCallRequest {
            path: "/bloom/petals/dex/probe".to_string(),
            function: "set_counter".to_string(),
            args: vec![
                serde_json::json!({
                    "object": "0x1111111111111111111111111111111111111111111111111111111111111111"
                }),
                serde_json::json!({ "kind": "signer", "index": 0 }),
                serde_json::json!({ "kind": "const", "value": 77u64 }),
            ],
            type_args: vec![],
            signers: vec![signer],
            gas_payer: Some(
                "0xfefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe".to_string(),
            ),
            gas_budget: 2_000_000,
            fuel_limit: 3_000_000,
        };

        let plan = prepare_chain_call_plan(&chain, &request, sender, gas_payer).unwrap();
        assert_eq!(plan.tx.commands.len(), 1);
        assert_eq!(plan.tx.signers, vec![[0x22; 32]]);
        assert_eq!(plan.tx.gas_payer, gas_payer);
        assert_eq!(plan.tx.gas_budget, 2_000_000);

        let value = dry_run_plan_json(&plan, &request.endpoint()).unwrap();
        assert_eq!(
            value["endpoint"],
            serde_json::json!("/bloom/petals/dex/probe/set_counter")
        );
        assert_eq!(value["dry_run"], true);
        assert_eq!(value["gas_budget"], 2_000_000);
        assert_eq!(value["commands"], 1);
    }

    #[test]
    fn call_prepare_plan_rejects_signer_that_does_not_match_local_key() {
        let chain = command_test_chain();
        let other = hex::encode([0x33; 32]);
        let request = ChainCallRequest {
            path: "/bloom/petals/dex/probe".to_string(),
            function: "set_counter".to_string(),
            args: vec![],
            type_args: vec![],
            signers: vec![other],
            gas_payer: None,
            gas_budget: 1_000_000,
            fuel_limit: 10_000_000,
        };
        let err = prepare_chain_call_plan(
            &chain,
            &request,
            bloom_chain_types::types::Address([0x22; 32]),
            ObjectId([0xFE; 32]),
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains("can sign exactly one signer"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn chain_pipe_prepare_plan_uses_multi_command_expr_signer_and_gas_override() {
        let chain = command_test_chain();
        let sender = bloom_chain_types::types::Address([0x22; 32]);
        let gas_payer = ObjectId([0xFE; 32]);
        let signer = hex::encode(sender.0);
        let expr = "/bloom/petals/dex/probe/spend \
            | /bloom/petals/dex/probe/swap \
            | /bloom/petals/dex/probe/receive";

        let plan =
            prepare_chain_pipe_plan(&chain, expr, &[signer], sender, gas_payer, 2_000_000).unwrap();
        assert_eq!(plan.tx.commands.len(), 3);
        assert_eq!(plan.tx.signers, vec![[0x22; 32]]);
        assert_eq!(plan.tx.gas_payer, gas_payer);
        assert_eq!(plan.tx.gas_budget, 2_000_000);

        match &plan.tx.commands[1] {
            Command::Move(m) => assert_eq!(
                m.args,
                vec![Arg::Use {
                    cmd_idx: 0,
                    ret_idx: 0
                }]
            ),
            other => panic!("expected Move command, got {other:?}"),
        }
        match &plan.tx.commands[2] {
            Command::Move(m) => assert_eq!(
                m.args,
                vec![Arg::Use {
                    cmd_idx: 1,
                    ret_idx: 0
                }]
            ),
            other => panic!("expected Move command, got {other:?}"),
        }

        let receipt = crate::commands::pipe::receipt_ndjson(&plan);
        assert_eq!(receipt.lines().count(), 4);
    }

    #[test]
    fn chain_pipe_submission_output_appends_submit_and_receipt_lines() {
        let plan_receipt = "{\"kind\":\"ptb\"}\n{\"kind\":\"command\"}\n";
        let tx_hash = bloom_chain_types::types::Hash32([0xAB; 32]);
        let receipt = serde_json::json!({ "success": false, "return_text": "nope" });
        let out = chain_pipe_submission_ndjson(plan_receipt, &tx_hash, &receipt);
        let lines = out
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(lines.len(), 4);
        assert_eq!(lines[2]["kind"], "submit");
        assert_eq!(lines[2]["tx_hash"], format!("0x{}", hex::encode(tx_hash.0)));
        assert_eq!(lines[3]["kind"], "receipt");
        assert_eq!(lines[3]["receipt"], receipt);
    }

    #[test]
    fn chain_pipe_prepare_plan_rejects_signer_that_does_not_match_local_key() {
        let chain = command_test_chain();
        let other = hex::encode([0x33; 32]);
        let err = prepare_chain_pipe_plan(
            &chain,
            "/bloom/petals/dex/probe/spend",
            &[other],
            bloom_chain_types::types::Address([0x22; 32]),
            ObjectId([0xFE; 32]),
            1_000_000,
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains("can sign exactly one signer"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn chain_pipe_prepare_plan_supports_named_dag_expr() {
        let chain = command_test_chain();
        let sender = bloom_chain_types::types::Address([0x22; 32]);
        let gas_payer = ObjectId([0xFE; 32]);
        let signer = hex::encode(sender.0);
        let expr = "/bloom/petals/dex/probe/add_liquidity --min-lp 10 \
            --a <(/bloom/petals/dex/probe/spend_eth)> \
            --b <(/bloom/petals/dex/probe/spend_usdc)>";

        let plan =
            prepare_chain_pipe_plan(&chain, expr, &[signer], sender, gas_payer, 3_000_000).unwrap();
        assert_eq!(plan.tx.commands.len(), 3);
        assert_eq!(plan.tx.signers, vec![[0x22; 32]]);
        assert_eq!(plan.tx.gas_payer, gas_payer);
        assert_eq!(plan.tx.gas_budget, 3_000_000);

        match &plan.tx.commands[2] {
            Command::Move(m) => assert_eq!(
                &m.args[1..],
                [
                    Arg::Use {
                        cmd_idx: 0,
                        ret_idx: 0,
                    },
                    Arg::Use {
                        cmd_idx: 1,
                        ret_idx: 0,
                    },
                ]
            ),
            other => panic!("expected Move command, got {other:?}"),
        }
    }

    #[test]
    fn call_stdin_merge_keeps_baked_path_and_function_authoritative() {
        let mut params = serde_json::json!({
            "path": "/bloom/petals/dex/probe",
            "function": "set_counter",
            "args": [],
            "gas_budget": 1_000_000u64,
        });
        let mut stdin = serde_json::json!({
            "path": "/evil",
            "function": "other",
            "args": [{ "kind": "const", "value": 77 }],
            "gas_budget": 2_000_000u64,
        });
        merge_stdin_params(&mut params, &mut stdin);
        assert_eq!(params["path"], "/bloom/petals/dex/probe");
        assert_eq!(params["function"], "set_counter");
        assert_eq!(params["gas_budget"], 2_000_000u64);
        assert_eq!(params["args"][0]["value"], 77);
    }

    #[test]
    fn view_endpoint_stdin_merge_rejects_commands_override() {
        let mut params = serde_json::json!({
            "path": "/bloom/petals/dex/probe",
            "function": "get_counter",
            "args": [],
        });
        let mut stdin = serde_json::json!({
            "commands": [{
                "path": "/bloom/petals/other",
                "function": "get_other"
            }]
        });
        let err = merge_view_stdin_params(&mut params, &mut stdin, true).unwrap_err();
        assert!(
            format!("{err}").contains("does not accept stdin 'commands'"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn view_commands_mode_accepts_stdin_commands() {
        let mut params = serde_json::json!({
            "commands": [],
        });
        let mut stdin = serde_json::json!({
            "commands": [{
                "path": "/bloom/petals/other",
                "function": "get_other"
            }]
        });
        merge_view_stdin_params(&mut params, &mut stdin, false).unwrap();
        assert_eq!(params["commands"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn call_type_arg_accepts_view_call_json_type_tag_form() {
        let token = call_type_arg_token(&serde_json::json!({
            "concrete": {
                "type_name": "vector",
                "petal_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                "type_args": ["u64"]
            }
        }))
        .unwrap();
        assert_eq!(token, "vector<u64>");
    }

    #[test]
    fn call_const_value_encodes_typed_abi_bytes() {
        let chain = command_test_chain();
        let manifest = bloom_script::PetalManifestStub::default();
        let tag = bloom_objects::TypeTag::Concrete {
            petal_hash: bloom_objects::BUILTIN_TYPE_HASH,
            type_name: "u64".to_string(),
            type_args: vec![],
        };
        let token = call_const_token(
            &chain,
            &serde_json::json!({ "kind": "const", "value": "980" }),
            &tag,
            &manifest,
            [0xAB; 32],
            &[],
        )
        .unwrap();
        assert_eq!(token, "const:0x00000000000003d4");
    }

    #[test]
    fn call_arg_accepts_view_call_object_and_signer_forms() {
        let raw = call_arg_token(&serde_json::json!(
            "0x2222222222222222222222222222222222222222222222222222222222222222"
        ))
        .unwrap();
        assert_eq!(
            raw,
            "obj:2222222222222222222222222222222222222222222222222222222222222222"
        );
        let shorthand = call_arg_token(&serde_json::json!({
            "object": "0x3333333333333333333333333333333333333333333333333333333333333333"
        }))
        .unwrap();
        assert_eq!(
            shorthand,
            "obj:3333333333333333333333333333333333333333333333333333333333333333"
        );
        let object = call_arg_token(&serde_json::json!({
            "object": {
                "id": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "version": 9
            }
        }))
        .unwrap();
        assert_eq!(
            object,
            "obj:1111111111111111111111111111111111111111111111111111111111111111@9"
        );
        assert_eq!(call_arg_token(&serde_json::json!(2)).unwrap(), "signer:2");
        assert_eq!(
            call_arg_token(&serde_json::json!({ "signer": 3 })).unwrap(),
            "signer:3"
        );
    }

    #[test]
    fn call_receipt_contract_maps_success_and_revert_reason() {
        ensure_success_receipt(&serde_json::json!({ "success": true })).unwrap();
        let err =
            ensure_success_receipt(&serde_json::json!({ "success": false, "return_text": "nope" }))
                .unwrap_err();
        assert_eq!(format!("{err}"), "petal call reverted: nope");
    }

    #[test]
    fn call_no_wait_tx_hash_json_matches_submit_contract() {
        let hash = bloom_chain_types::types::Hash32([0xAB; 32]);
        assert_eq!(
            tx_hash_json(&hash),
            serde_json::json!({ "tx_hash": "abababababababababababababababababababababababababababababababab" })
        );
    }

    #[test]
    fn call_submission_output_no_wait_skips_receipt_contract() {
        let hash = bloom_chain_types::types::Hash32([0xAB; 32]);
        let output = chain_call_submission_output(
            true,
            &hash,
            Some(&serde_json::json!({ "success": false, "return_text": "ignored" })),
        )
        .unwrap();
        assert_eq!(
            output,
            serde_json::json!({ "tx_hash": "abababababababababababababababababababababababababababababababab" })
        );
    }

    #[test]
    fn call_submission_output_wait_returns_success_or_revert_receipt() {
        let hash = bloom_chain_types::types::Hash32([0xAB; 32]);
        let ok = serde_json::json!({ "success": true, "height": 9 });
        assert_eq!(
            chain_call_submission_output(false, &hash, Some(&ok)).unwrap(),
            ok
        );
        let revert = serde_json::json!({ "success": false, "return_text": "nope" });
        assert_eq!(
            chain_call_submission_output(false, &hash, Some(&revert)).unwrap(),
            revert
        );
        let err = ensure_success_receipt(
            &chain_call_submission_output(
                false,
                &hash,
                Some(&serde_json::json!({ "success": false, "return_text": "nope" })),
            )
            .unwrap(),
        )
        .unwrap_err();
        assert_eq!(format!("{err}"), "petal call reverted: nope");
        let err = chain_call_submission_output(false, &hash, None).unwrap_err();
        assert_eq!(format!("{err}"), "missing call receipt after submit");
    }

    #[test]
    fn call_dry_run_projection_marks_plan_without_submit_fields() {
        let plan = crate::commands::pipe::LoweredPlan {
            tx: bloom_script::PtbTx {
                signers: vec![[0x11; 32]],
                commands: vec![],
                gas_payer: bloom_objects::ObjectId([0xFE; 32]),
                gas_budget: 123,
                gas_price: 1,
                expiry_block: u64::MAX,
                signatures: vec![],
            },
            status: bloom_ptb_builder::SessionStatus {
                id: bloom_ptb_builder::SessionId(1),
                commands: vec![],
                labels: vec![],
                gas_payer_set: true,
                signer_count: 1,
                estimated_gas: 123,
            },
        };
        let value = dry_run_plan_json(&plan, "/bloom/petals/dex/probe/set_counter").unwrap();
        assert_eq!(value["dry_run"], true);
        assert_eq!(value["endpoint"], "/bloom/petals/dex/probe/set_counter");
        assert_eq!(value["gas_budget"], 123);
        assert_eq!(value["commands"], 0);
    }

    #[test]
    fn transfer_plan_splits_selected_loom_coin_and_transfers_output() {
        let chain = command_test_chain();
        let sender = bloom_chain_types::types::Address([0x22; 32]);
        let recipient = bloom_chain_types::types::Address([0x44; 32]);
        let gas_payer = ObjectId([0xFE; 32]);

        let tx = prepare_transfer_plan(&chain, sender, recipient, 500, gas_payer, 1_000).unwrap();
        assert_eq!(tx.signers, vec![[0x22; 32]]);
        assert_eq!(tx.gas_payer, gas_payer);
        assert_eq!(tx.gas_budget, 1_000);
        assert!(tx.signatures.is_empty());
        assert_eq!(tx.commands.len(), 3);

        match &tx.commands[0] {
            Command::Move(m) => {
                assert_eq!(m.petal.path, bloom_script::CORE_FUNGIBLE_PATH);
                assert_eq!(m.function, "identity");
                assert_eq!(
                    m.type_args,
                    vec![bloom_script::loom_marker_type_tag(
                        bloom_script::DEFAULT_FUNGIBLE_PETAL_HASH
                    )]
                );
                assert_eq!(m.args.len(), 1);
            }
            other => panic!("expected core fungible identity move, got {other:?}"),
        }
        match &tx.commands[1] {
            Command::SplitCoins { src, amounts } => {
                assert_eq!(src.cmd_idx, 0);
                assert_eq!(src.ret_idx, 0);
                assert_eq!(amounts, &vec![500]);
            }
            other => panic!("expected SplitCoins, got {other:?}"),
        }
        match &tx.commands[2] {
            Command::TransferObjects { uses, owner } => {
                assert_eq!(uses.len(), 1);
                assert_eq!(uses[0].cmd_idx, 1);
                assert_eq!(uses[0].ret_idx, 0);
                assert_eq!(owner, &bloom_objects::Owner::Address(recipient.0));
            }
            other => panic!("expected TransferObjects, got {other:?}"),
        }

        let dry = transfer_dry_run_json(&tx, recipient, 500).unwrap();
        assert_eq!(dry["dry_run"], true);
        assert_eq!(dry["kind"], "transfer");
        assert_eq!(dry["amount"], "500");
        assert_eq!(dry["commands"], 3);
    }

    #[test]
    fn load_wallet_key_for_signer_selects_matching_xdsa_file() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let tmp = tempfile::tempdir().unwrap();
                let chain_dir = tmp.path().join("chain");
                let keystore = chain_dir.join("keystore");
                std::fs::create_dir_all(&keystore).unwrap();

                let validator_bytes = [1u8; 64];
                let validator_sk =
                    bloom_keystore::xdsa::XdsaSecretKey::from_bytes(&validator_bytes).unwrap();
                std::fs::write(
                    keystore.join("validator.xdsa"),
                    validator_sk.to_bytes().as_slice(),
                )
                .unwrap();

                let other_bytes = [2u8; 64];
                let other_sk =
                    bloom_keystore::xdsa::XdsaSecretKey::from_bytes(&other_bytes).unwrap();
                let other_pk = other_sk.public_key();
                let other_addr = bloom_chain_types::types::Address::from_pubkey_bytes(&other_pk.0);
                std::fs::write(keystore.join("alice.xdsa"), other_sk.to_bytes().as_slice())
                    .unwrap();

                let (_sk, _pk, addr) =
                    load_wallet_key_for_signer(&chain_dir, Some(other_addr)).unwrap();
                assert_eq!(addr, other_addr);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn load_wallet_key_without_signer_uses_only_client_key_when_no_validator_key() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let tmp = tempfile::tempdir().unwrap();
                let chain_dir = tmp.path().join("chain");
                let keystore = chain_dir.join("keystore");
                std::fs::create_dir_all(&keystore).unwrap();

                let bytes = [7u8; 64];
                let sk = bloom_keystore::xdsa::XdsaSecretKey::from_bytes(&bytes).unwrap();
                let expected =
                    bloom_chain_types::types::Address::from_pubkey_bytes(&sk.public_key().0);
                std::fs::write(keystore.join("client.xdsa"), sk.to_bytes().as_slice()).unwrap();

                let (_sk, _pk, addr) = load_wallet_key_for_signer(&chain_dir, None).unwrap();
                assert_eq!(addr, expected);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn load_wallet_key_without_signer_rejects_ambiguous_client_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let chain_dir = tmp.path().join("chain");
        let keystore = chain_dir.join("keystore");
        std::fs::create_dir_all(&keystore).unwrap();
        std::fs::write(keystore.join("a.xdsa"), [1u8; 64]).unwrap();
        std::fs::write(keystore.join("b.xdsa"), [2u8; 64]).unwrap();
        let err = match load_wallet_key_for_signer(&chain_dir, None) {
            Ok(_) => panic!("ambiguous signer key should error"),
            Err(err) => err,
        };
        assert!(
            format!("{err:#}").contains("multiple xDSA keys"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn load_wallet_key_for_signer_errors_when_key_missing() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let tmp = tempfile::tempdir().unwrap();
                let chain_dir = tmp.path().join("chain");
                let keystore = chain_dir.join("keystore");
                std::fs::create_dir_all(&keystore).unwrap();
                let validator_bytes = [1u8; 64];
                let validator_sk =
                    bloom_keystore::xdsa::XdsaSecretKey::from_bytes(&validator_bytes).unwrap();
                std::fs::write(
                    keystore.join("validator.xdsa"),
                    validator_sk.to_bytes().as_slice(),
                )
                .unwrap();

                let missing = bloom_chain_types::types::Address([0x42; 32]);
                let err = match load_wallet_key_for_signer(&chain_dir, Some(missing)) {
                    Ok(_) => panic!("missing signer key should error"),
                    Err(err) => err,
                };
                assert!(
                    format!("{err:#}").contains("no xDSA key for signer"),
                    "unexpected error: {err:#}"
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn testnet_provisioning_allocates_and_registers_treasury_key() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let tmp = tempfile::tempdir().unwrap();
                provision_testnet(
                    1,
                    tmp.path(),
                    Some(39871),
                    "bloomchain.test",
                    "10",
                    "99",
                    None,
                    None,
                    false,
                    None,
                )
                .unwrap();

                let treasury_keystore = tmp.path().join("treasury/chain/keystore");
                let mut keys = std::fs::read_dir(&treasury_keystore)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("xdsa"))
                    .collect::<Vec<_>>();
                keys.sort();
                assert_eq!(keys.len(), 1);
                let treasury = load_xdsa_key_at(&keys[0]).unwrap();
                let treasury_hex = hex::encode(treasury.2.0);

                let genesis_text =
                    std::fs::read_to_string(tmp.path().join("home0/chain/genesis.toml")).unwrap();
                let genesis: bloom_chain_node::genesis::GenesisFile =
                    toml::from_str(&genesis_text).unwrap();
                assert!(
                    genesis
                        .allocations
                        .iter()
                        .any(|alloc| { alloc.address == treasury_hex && alloc.amount == "99" })
                );
                assert!(
                    genesis
                        .key_registry
                        .iter()
                        .any(|entry| { entry.address == treasury_hex && !entry.pubkey.is_empty() })
                );
                assert!(tmp.path().join("treasury/chain/genesis.toml").exists());
            })
            .unwrap()
            .join()
            .unwrap();
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
