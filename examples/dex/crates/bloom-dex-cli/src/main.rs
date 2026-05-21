//! `bloom-dex` — reference DEX driver binary.
//!
//! Example dapp for bloom-chain. Not part of the protocol — talks to a running
//! validator over its standard JSON-RPC socket, exactly like any external
//! dapp would.
//!
//! Mirrors the historical `bloom dex …` subcommand tree.

#![forbid(unsafe_code)]
#![allow(deprecated)]

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use bloom_proto::HomeDir;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use bloom_dex_cli::DexCmd;

#[derive(Parser, Debug)]
#[command(
    name = "bloom-dex",
    version,
    about = "Reference DEX driver (example dapp; not part of the bloom-chain protocol)"
)]
struct Cli {
    /// Override home directory (default: ~/.bloom).
    #[arg(long, env = "BLOOM_HOME")]
    home: Option<PathBuf>,

    #[command(subcommand)]
    cmd: DexCmd,
}

#[tokio::main]
async fn main() -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .try_init();

    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let home = match cli.home {
        Some(p) => HomeDir::at(p),
        None => HomeDir::resolve("~/.bloom").context("resolving home dir")?,
    };
    bloom_dex_cli::run_dex(&home, cli.cmd).await
}
