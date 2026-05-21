/// Integration tests for the xDSA keystore path.
///
/// These are in a separate file to keep xdsa.rs focused on the implementation.
/// They are only compiled in `#[cfg(test)]` and accessed via `mod xdsa_tests`
/// declared in lib.rs.
#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use crate::{
        Keystore, WalletAddress, WalletKind, create_xdsa_wallet, load_xdsa_wallet,
        xdsa::{
            XDSA_PK_LEN, XDSA_SIG_LEN, XdsaPublicKey, XdsaSecretKey, XdsaSignature, derive_address,
        },
    };

    fn temp_dir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    // ── generate → sign → verify round-trip ─────────────────────────────────

    #[test]
    fn sign_verify_round_trip() {
        let (sk, pk) = XdsaSecretKey::generate();
        let msg = b"round-trip message";
        let sig = sk.sign(msg);
        pk.verify(msg, &sig).expect("valid sig must verify");
    }

    // ── verify fails on flipped sig byte ────────────────────────────────────

    #[test]
    fn verify_fails_on_flipped_sig_byte() {
        let (sk, pk) = XdsaSecretKey::generate();
        let msg = b"tamper me";
        let mut sig = sk.sign(msg);
        sig.0[100] ^= 0xFF;
        assert!(pk.verify(msg, &sig).is_err(), "tampered sig must fail");
    }

    // ── verify fails on flipped message byte ────────────────────────────────

    #[test]
    fn verify_fails_on_flipped_message_byte() {
        let (sk, pk) = XdsaSecretKey::generate();
        let sig = sk.sign(b"original");
        assert!(
            pk.verify(b"origXnal", &sig).is_err(),
            "modified message must fail"
        );
    }

    // ── encrypt → write → load → decrypt → sign → verify ───────────────────

    #[test]
    fn keystore_encrypt_write_load_decrypt_sign_verify() {
        let td = temp_dir();
        let root = td.path();

        // Create wallet on disk.
        let (addr, pk) = create_xdsa_wallet(root, "alice", "hunter2").unwrap();
        assert!(matches!(addr, WalletAddress::BloomChain(_)));
        assert_eq!(pk.0.len(), XDSA_PK_LEN);

        // Verify on-disk files exist.
        assert!(root.join("alice").join("encrypted.key").exists());
        assert!(root.join("alice").join("pubkey").exists());
        assert!(root.join("alice").join("address").exists());
        assert!(root.join("alice").join("algorithm").exists());
        assert!(root.join("alice").join("kind").exists());

        // Load and decrypt.
        let wallet = load_xdsa_wallet(root, "alice", "hunter2").unwrap();
        assert_eq!(wallet.public_key, pk);
        assert_eq!(wallet.name, "alice");

        // Sign with loaded key and verify with stored pubkey.
        let msg = b"hello bloom-chain";
        let sig = wallet.sign(msg);
        pk.verify(msg, &sig)
            .expect("loaded wallet must produce valid sig");
    }

    // ── wrong passphrase is rejected ────────────────────────────────────────

    #[test]
    fn wrong_passphrase_rejected() {
        let td = temp_dir();
        create_xdsa_wallet(td.path(), "bob", "correct").unwrap();
        assert!(
            load_xdsa_wallet(td.path(), "bob", "wrong").is_err(),
            "wrong passphrase must fail"
        );
    }

    // ── loading an old secp256k1 keystore still works ───────────────────────

    #[test]
    fn old_secp256k1_keystore_still_loads() {
        let td = temp_dir();
        let ks = Keystore::new(td.path()).unwrap();

        // Create a classic secp256k1 wallet.
        let info = ks.create_local("legacy", "pass").unwrap();
        assert_eq!(info.kind, WalletKind::Local);

        // Unlock it — must succeed.
        ks.unlock("legacy", "pass")
            .expect("secp256k1 wallet must unlock");
        assert!(ks.is_unlocked("legacy"));

        // The signer is available.
        let signer = ks.signer("legacy").unwrap();
        assert_eq!(signer.address(), info.address);
    }

    // ── round-trip JSON (de)serialisation of EncryptedFileV2 ────────────────

    #[test]
    fn encrypted_file_v2_json_round_trip() {
        // Encode an xDSA key and check the JSON contains algorithm = "xdsa".
        let td = temp_dir();
        create_xdsa_wallet(td.path(), "carol", "pass2").unwrap();

        let blob = std::fs::read(td.path().join("carol").join("encrypted.key")).unwrap();
        let json_str = std::str::from_utf8(&blob).unwrap();

        // v=2 and algorithm=xdsa must be present.
        assert!(
            json_str.contains("\"v\":2"),
            "version must be 2: {json_str}"
        );
        assert!(
            json_str.contains("\"algorithm\":\"xdsa\""),
            "algorithm must be xdsa: {json_str}"
        );

        // Can parse it back.
        let enc: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(enc["v"], 2);
        assert_eq!(enc["algorithm"], "xdsa");
    }

    // ── secp256k1 JSON envelope does NOT contain algorithm field (compat) ────

    #[test]
    fn secp256k1_envelope_has_no_algorithm_field() {
        let td = temp_dir();
        let ks = Keystore::new(td.path()).unwrap();
        ks.create_local("dave", "pass").unwrap();

        let blob = std::fs::read(td.path().join("dave").join("encrypted.key")).unwrap();
        let json_str = std::str::from_utf8(&blob).unwrap();

        // The old format should not include an algorithm field.
        // (It uses EncryptedFile v1, not EncryptedFileV2 — no "xdsa" string.)
        assert!(
            !json_str.contains("\"algorithm\""),
            "secp256k1 envelope must not have algorithm field: {json_str}"
        );
    }

    // ── address derivation is deterministic ─────────────────────────────────

    #[test]
    fn address_deterministic() {
        let (_, pk) = XdsaSecretKey::generate();
        let a1 = derive_address(&pk);
        let a2 = derive_address(&pk);
        assert_eq!(a1, a2, "address must be deterministic");
        assert_eq!(a1.len(), 32);
    }

    // ── pubkey / sig from_bytes reject bad lengths ───────────────────────────

    #[test]
    fn from_bytes_length_validation() {
        assert!(XdsaPublicKey::from_bytes(&[0u8; 10]).is_err());
        assert!(XdsaPublicKey::from_bytes(&vec![0u8; XDSA_PK_LEN]).is_ok());
        assert!(XdsaSignature::from_bytes(&[0u8; 10]).is_err());
        assert!(XdsaSignature::from_bytes(&vec![0u8; XDSA_SIG_LEN]).is_ok());
    }

    // ── secret key from_bytes / to_bytes round-trip ──────────────────────────

    #[test]
    fn secret_key_bytes_round_trip() {
        let (sk, pk) = XdsaSecretKey::generate();
        let bytes = sk.to_bytes();
        let sk2 = XdsaSecretKey::from_bytes(bytes.as_slice()).unwrap();
        let msg = b"bytes round-trip";
        let sig = sk2.sign(msg);
        pk.verify(msg, &sig).unwrap();
    }
}
