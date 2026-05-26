//! Category: integration
//!
//! Test: parse a minimal genesis.toml with one validator.
//!
//! Writes a tmpdir genesis, parses it, and asserts ValidatorSet.len() == 1.

use std::io::Write;

use bloom_chain_node::Genesis;
use tempfile::NamedTempFile;

#[test]
fn genesis_load_one_validator() {
    // Construct a minimal 1984-byte composite pubkey in base64.
    // (All zeros — not a valid real key, but sufficient for parse testing.)
    let pk_bytes = vec![0u8; 1984];
    let addr_hex = hex::encode(bloom_chain_types::Address::from_pubkey_bytes(&pk_bytes).0);
    let pk_b64 = {
        // Minimal base64 encoding (standard alphabet).

        let mut out = String::new();
        let enc_table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i + 2 < pk_bytes.len() {
            let b0 = pk_bytes[i] as usize;
            let b1 = pk_bytes[i + 1] as usize;
            let b2 = pk_bytes[i + 2] as usize;
            out.push(enc_table[b0 >> 2] as char);
            out.push(enc_table[((b0 & 3) << 4) | (b1 >> 4)] as char);
            out.push(enc_table[((b1 & 0xf) << 2) | (b2 >> 6)] as char);
            out.push(enc_table[b2 & 0x3f] as char);
            i += 3;
        }
        if i < pk_bytes.len() {
            let b0 = pk_bytes[i] as usize;
            out.push(enc_table[b0 >> 2] as char);
            if i + 1 < pk_bytes.len() {
                let b1 = pk_bytes[i + 1] as usize;
                out.push(enc_table[((b0 & 3) << 4) | (b1 >> 4)] as char);
                out.push(enc_table[(b1 & 0xf) << 2] as char);
                out.push('=');
            } else {
                out.push(enc_table[(b0 & 3) << 4] as char);
                out.push('=');
                out.push('=');
            }
        }
        out
    };

    let alloc_addr = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

    let toml_content = format!(
        r#"
chain_id = "bloomchain.v0"
genesis_time_ms = 1747526400000

[[validators]]
address = "{addr_hex}"
pubkey  = "{pk_b64}"
voting_power = 100
host = "127.0.0.1:26656"

[[allocations]]
address = "{alloc_addr}"
amount  = "1000000000000000000000"
"#
    );

    let mut tmpfile = NamedTempFile::new().expect("tmpfile");
    tmpfile
        .write_all(toml_content.as_bytes())
        .expect("write genesis");
    tmpfile.flush().expect("flush");

    let genesis = Genesis::from_file(tmpfile.path()).expect("parse genesis");

    // Core assertions.
    assert_eq!(genesis.validator_set.len(), 1, "should have one validator");
    assert_eq!(genesis.chain_id, "bloomchain.v0");
    assert_eq!(genesis.genesis_time_ms, 1747526400000);
    assert_eq!(genesis.allocations.len(), 1);
    assert_eq!(genesis.peer_addrs, vec!["127.0.0.1:26656"]);

    // Genesis hash should be deterministic.
    let genesis2 = Genesis::from_file(tmpfile.path()).expect("re-parse genesis");
    assert_eq!(genesis.genesis_hash, genesis2.genesis_hash);
}
