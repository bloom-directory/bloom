//! `bloom contract ...` — build and verify Bloom Rust smart contracts.
//!
//! Two subcommands today:
//!
//! - `bloom contract build <crate>` runs `cargo build --target
//!   wasm32-unknown-unknown` inside the crate, validates the resulting
//!   wasm against the deterministic-execution profile, extracts the
//!   `bloom_manifest` custom section the macro emitted, fills in
//!   `wasm_hash` / `source_hash` / `imports`, and writes a paired
//!   `<name>.wasm` + `<name>.manifest.json` into `--out-dir`.
//!
//! - `bloom contract verify <manifest> <wasm>` re-runs the validation
//!   checks against a published artefact pair: hashes match, imports
//!   are subset of policy.
//!
//! Everything heavy lives in `bloom-contract-build`; this module is just
//! the CLI surface.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use bloom_contract_build::{Profile, emit_artifacts, manifest_hash, verify_manifest_against_wasm};
use bloom_contract_metadata::Manifest;
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum ContractCmd {
    /// Build a contract crate to `(wasm, manifest.json)`.
    Build {
        /// Path to the contract crate (the directory containing
        /// `Cargo.toml`).
        crate_dir: PathBuf,
        /// Output directory (default: `<crate>/target/bloom`).
        #[arg(long, value_name = "DIR")]
        out_dir: Option<PathBuf>,
        /// Compile in dev profile (default: release).
        #[arg(long)]
        dev: bool,
    },
    /// Verify a published `(manifest, wasm)` pair: hashes match and the
    /// wasm's imports are a subset of the manifest's declared imports.
    Verify {
        /// Path to `<name>.manifest.json`.
        manifest: PathBuf,
        /// Path to `<name>.wasm`.
        wasm: PathBuf,
        /// Optional expected on-chain `manifest_hash` anchor (lowercase
        /// hex, 64 chars). When supplied, the locally-computed hash of
        /// the manifest is compared byte-for-byte and verification fails
        /// on any mismatch.
        #[arg(long, value_name = "HEX")]
        expected_manifest_hash: Option<String>,
    },
}

pub fn run(cmd: ContractCmd) -> Result<()> {
    match cmd {
        ContractCmd::Build {
            crate_dir,
            out_dir,
            dev,
        } => {
            let profile = if dev { Profile::Dev } else { Profile::Release };
            let out_dir = out_dir
                .unwrap_or_else(|| crate_dir.join("target").join("bloom"));
            let artifacts = emit_artifacts(&crate_dir, &out_dir, profile)
                .with_context(|| format!("build contract {}", crate_dir.display()))?;
            println!("contract: {}", artifacts.manifest.contract.name);
            println!("wasm:     {}", artifacts.wasm_path.display());
            println!("manifest: {}", artifacts.manifest_path.display());
            println!("wasm_hash:     {}", artifacts.wasm_hash);
            println!("source_hash:   {}", artifacts.source_hash);
            println!("manifest_hash: {}", artifacts.manifest_hash);
            println!("size: {} bytes", artifacts.wasm.len());
            println!("imports: {}", artifacts.manifest.imports.len());
            println!();
            println!(
                "next: bloom chain deploy --wasm {} --manifest-hash {}",
                artifacts.wasm_path.display(),
                artifacts.manifest_hash,
            );
            Ok(())
        }
        ContractCmd::Verify {
            manifest,
            wasm,
            expected_manifest_hash,
        } => {
            let manifest_bytes = std::fs::read(&manifest)
                .with_context(|| format!("read manifest {}", manifest.display()))?;
            let manifest_obj: Manifest = serde_json::from_slice(&manifest_bytes)
                .with_context(|| format!("decode manifest {}", manifest.display()))?;
            let wasm_bytes = std::fs::read(&wasm)
                .with_context(|| format!("read wasm {}", wasm.display()))?;
            verify_manifest_against_wasm(&manifest_obj, &wasm_bytes)
                .context("manifest does not match wasm")?;

            let actual_manifest_hash = hex_encode(&manifest_hash(&manifest_obj));
            if let Some(expected) = expected_manifest_hash {
                let expected = expected.trim().to_ascii_lowercase();
                if expected != actual_manifest_hash {
                    return Err(anyhow!(
                        "manifest_hash mismatch:\n  expected: {expected}\n  actual:   {actual_manifest_hash}",
                    ));
                }
            }

            println!("ok: manifest matches wasm");
            println!("contract: {}", manifest_obj.contract.name);
            println!("wasm_hash:     {}", manifest_obj.wasm_hash);
            println!("manifest_hash: {}", actual_manifest_hash);
            Ok(())
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const NIBBLE: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        s.push(NIBBLE[(*byte >> 4) as usize] as char);
        s.push(NIBBLE[(*byte & 0x0f) as usize] as char);
    }
    s
}
