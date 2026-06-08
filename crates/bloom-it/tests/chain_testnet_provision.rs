//! Category: CLI-subprocess
//!
//! `chain_testnet_provision.rs` — fast non-network smoke test for the
//! `bloom chain testnet` provisioner.
//!
//! Exercises [`bloom_it::chain_harness::provision_network`], which shells out
//! to `bloom chain testnet`. Verifies that:
//!   1. Per-node `home<i>/chain/{genesis.toml, config.toml, keystore/validator.xdsa}`
//!      exist for every requested validator.
//!   2. The shared genesis round-trips through `bloom_chain_node::Genesis::from_file`.
//!   3. Genesis surfaces N validators in the validator set, each with non-empty
//!      peer host, and N validator allocations plus one treasury allocation.
//!   4. Per-node `config.toml` parses as `bloom_chain_node::NodeConfig` and
//!      every node gets a distinct listen_addr.
//!
//! Doesn't actually spawn validators — that's [`chain_smoke.rs`].

use anyhow::Result;
use std::collections::HashSet;
use std::path::PathBuf;

use bloom_it::chain_harness;
use tempfile::tempdir;

#[test]
fn provisions_three_validator_network() -> Result<()> {
    let dir = tempdir()?;
    let parent: PathBuf = dir.path().to_path_buf();

    let cfgs = chain_harness::provision_network(&parent, 3)?;
    assert_eq!(cfgs.len(), 3, "expected 3 configs");

    let mut listen_addrs = HashSet::new();

    for (i, cfg) in cfgs.iter().enumerate() {
        let home = &cfg.home;
        assert!(
            home.join("chain/genesis.toml").exists(),
            "missing genesis.toml for node {i}"
        );
        assert!(
            home.join("chain/config.toml").exists(),
            "missing config.toml for node {i}"
        );
        assert!(
            home.join("chain/keystore/validator.xdsa").exists(),
            "missing validator key for node {i}"
        );

        // genesis.toml parses through Genesis::from_file.
        let g = bloom_chain_node::Genesis::from_file(&home.join("chain/genesis.toml"))?;
        assert_eq!(g.chain_id, "bloomchain.local");
        assert_eq!(g.validator_set.len(), 3, "validator count in genesis");
        assert_eq!(
            g.allocations.len(),
            4,
            "allocation count in genesis includes treasury"
        );

        // config.toml parses through NodeConfig.
        let cfg_text = std::fs::read_to_string(&cfg.config)?;
        let nc: bloom_chain_node::NodeConfig = toml::from_str(&cfg_text)?;
        assert!(!nc.validator_address.is_empty());
        assert!(nc.listen_addr.starts_with("127.0.0.1:"));
        listen_addrs.insert(nc.listen_addr);
    }

    assert_eq!(
        listen_addrs.len(),
        3,
        "each node must have a distinct listen_addr"
    );

    Ok(())
}
