//! The non-custodial signing seam + CLOB auth header construction.
//!
//! [`KeystoreSigner`] is a thin wrapper over a pure-alloy `Arc<PrivateKeySigner>`
//! supplied by the caller (in the daemon, that `Arc` comes from
//! `Keystore::signer(wallet)?`). This crate never owns key hex and never
//! serializes the key.
//!
//! - **L1** (`clob_auth_headers`): EIP-712-sign `ClobAuth` → the headers needed
//!   to mint/derive CLOB API credentials.
//! - **L2** (`l2_headers` / [`l2_message`] / [`l2_hmac`]): HMAC-SHA256 over
//!   `{timestamp}{METHOD}{path}{body}` with the API `secret` — no private key
//!   involved. Byte-exact reference: `rs-clob-client-v2` `src/auth.rs`.

use std::sync::Arc;

use alloy::primitives::Address;
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use base64::prelude::{BASE64_URL_SAFE, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{PolymarketError, Result, eip712};

// CLOB auth header names (shared L1/L2 where applicable).
pub const POLY_ADDRESS: &str = "POLY_ADDRESS";
pub const POLY_NONCE: &str = "POLY_NONCE";
pub const POLY_SIGNATURE: &str = "POLY_SIGNATURE";
pub const POLY_TIMESTAMP: &str = "POLY_TIMESTAMP";
pub const POLY_API_KEY: &str = "POLY_API_KEY";
pub const POLY_PASSPHRASE: &str = "POLY_PASSPHRASE";

/// Abstraction over the owner-signing operations the onboarding flow needs.
///
/// Direct path: [`KeystoreSigner`] signs with the local private key.
/// Sealed path (bloom-vfs): routes through `PetalHost::sign_hash` under a
/// live Sealed Approval grant.
#[async_trait::async_trait]
pub trait OnboardSigner: Send + Sync {
    /// The owner EOA address that signs.
    fn address(&self) -> Address;

    /// Sign a precomputed EIP-712 signing hash (plain 65-byte ECDSA).
    async fn sign_eip712_hash(
        &self,
        hash: &alloy::primitives::B256,
    ) -> Result<alloy::primitives::Signature>;

    /// Build the L1 (`POLY_*`) headers for credential mint/derive.
    async fn clob_auth_headers(
        &self,
        chain_id: u64,
        timestamp: u64,
        nonce: u32,
    ) -> Result<Vec<(String, String)>>;
}

/// A non-custodial signer: holds only a pure-alloy `PrivateKeySigner` handed in
/// by the caller. Knows nothing about the bloom keystore.
#[derive(Clone)]
pub struct KeystoreSigner {
    signer: Arc<PrivateKeySigner>,
    address: Address,
}

impl KeystoreSigner {
    /// Wrap a signer obtained elsewhere (e.g. `keystore.signer(wallet)?`).
    pub fn new(signer: Arc<PrivateKeySigner>) -> Self {
        let address = signer.address();
        Self { signer, address }
    }

    /// The owner EOA address.
    pub fn address(&self) -> Address {
        self.address
    }

    /// The wrapped secp256k1 signer. Already non-custodial: the same `Arc` was
    /// handed in from the keystore.
    pub fn private_key_signer(&self) -> Arc<PrivateKeySigner> {
        self.signer.clone()
    }
}

#[async_trait::async_trait]
impl OnboardSigner for KeystoreSigner {
    fn address(&self) -> Address {
        self.address
    }

    async fn sign_eip712_hash(
        &self,
        hash: &alloy::primitives::B256,
    ) -> Result<alloy::primitives::Signature> {
        self.signer
            .sign_hash(hash)
            .await
            .map_err(|e| PolymarketError::signing(e.to_string()))
    }

    async fn clob_auth_headers(
        &self,
        chain_id: u64,
        timestamp: u64,
        nonce: u32,
    ) -> Result<Vec<(String, String)>> {
        let hash = eip712::clob_auth_signing_hash(self.address, timestamp, nonce, chain_id);
        let sig = self.sign_eip712_hash(&hash).await?;
        Ok(vec![
            // L1 uses the lowercase 0x-address form (SDK: encode_hex_with_prefix).
            (POLY_ADDRESS.to_string(), format!("{:#x}", self.address)),
            (POLY_NONCE.to_string(), nonce.to_string()),
            (POLY_SIGNATURE.to_string(), sig.to_string()),
            (POLY_TIMESTAMP.to_string(), timestamp.to_string()),
        ])
    }
}

/// The L2 HMAC preimage: `{timestamp}{METHOD}{path}{body}`. The SDK normalizes
/// single quotes in the body to double quotes (JSON serializers may emit `'`).
pub fn l2_message(timestamp: u64, method: &str, path: &str, body: &str) -> String {
    let body = body.replace('\'', "\"");
    format!("{timestamp}{method}{path}{body}")
}

/// HMAC-SHA256 of `message` keyed by the base64url-decoded `secret`, re-encoded
/// base64url. This is the L2 `POLY_SIGNATURE`.
pub fn l2_hmac(secret: &str, message: &str) -> Result<String> {
    let key = BASE64_URL_SAFE
        .decode(secret)
        .map_err(|e| PolymarketError::signing(format!("secret base64: {e}")))?;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&key)
        .map_err(|e| PolymarketError::signing(format!("hmac key: {e}")))?;
    mac.update(message.as_bytes());
    Ok(BASE64_URL_SAFE.encode(mac.finalize().into_bytes()))
}

/// Build the L2 (`POLY_*`) headers for an authenticated request.
#[allow(clippy::too_many_arguments)]
pub fn l2_headers(
    address: Address,
    api_key: &str,
    passphrase: &str,
    secret: &str,
    timestamp: u64,
    method: &str,
    path: &str,
    body: &str,
) -> Result<Vec<(&'static str, String)>> {
    let signature = l2_hmac(secret, &l2_message(timestamp, method, path, body))?;
    Ok(vec![
        // L2 uses the checksummed address form (SDK: to_checksum).
        (POLY_ADDRESS, address.to_checksum(None)),
        (POLY_API_KEY, api_key.to_string()),
        (POLY_PASSPHRASE, passphrase.to_string()),
        (POLY_SIGNATURE, signature),
        (POLY_TIMESTAMP, timestamp.to_string()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AMOY;
    use std::str::FromStr;

    // Publicly-known dev key (anvil account 0), from the SDK test vectors.
    const PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const SECRET: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn test_signer() -> KeystoreSigner {
        let pk = PrivateKeySigner::from_str(PRIVATE_KEY).unwrap();
        KeystoreSigner::new(Arc::new(pk))
    }

    /// Reproduces `rs-clob-client-v2` `l1_headers_should_succeed` byte-for-byte.
    #[tokio::test]
    async fn l1_headers_match_sdk_vector() {
        let signer = test_signer();
        assert_eq!(
            signer.address(),
            Address::from_str("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap()
        );
        let headers = signer
            .clob_auth_headers(AMOY, 10_000_000, 23)
            .await
            .unwrap();
        let get = |k: &str| {
            headers
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(
            get(POLY_ADDRESS),
            Some("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
        );
        assert_eq!(get(POLY_NONCE), Some("23"));
        assert_eq!(
            get(POLY_SIGNATURE),
            Some(
                "0xf62319a987514da40e57e2f4d7529f7bac38f0355bd88bb5adbb3768d80de6c1682518e0af677d5260366425f4361e7b70c25ae232aff0ab2331e2b164a1aedc1b"
            )
        );
        assert_eq!(get(POLY_TIMESTAMP), Some("10000000"));
    }

    /// Reproduces `rs-clob-client-v2` `l2_headers_should_succeed`: GET `/`, ts 1.
    #[test]
    fn l2_headers_match_sdk_vector() {
        let address = Address::from_str("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
        let nil_key = "00000000-0000-0000-0000-000000000000";
        let passphrase = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let headers = l2_headers(address, nil_key, passphrase, SECRET, 1, "GET", "/", "").unwrap();
        let get = |k: &str| {
            headers
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(
            get(POLY_ADDRESS),
            Some("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
        );
        assert_eq!(get(POLY_PASSPHRASE), Some(passphrase));
        assert_eq!(get(POLY_API_KEY), Some(nil_key));
        assert_eq!(
            get(POLY_SIGNATURE),
            Some("eHaylCwqRSOa2LFD77Nt_SaTpbsxzN8eTEI3LryhEj4=")
        );
        assert_eq!(get(POLY_TIMESTAMP), Some("1"));
    }

    /// Reproduces the SDK `to_message` + `hmac` vectors exactly.
    #[test]
    fn l2_message_and_hmac_match_sdk_vectors() {
        assert_eq!(
            l2_message(1, "POST", "/path", r#"{"foo":"bar"}"#),
            r#"1POST/path{"foo":"bar"}"#
        );
        let msg = l2_message(1_000_000, "test-sign", "/orders", r#"{"hash":"0x123"}"#);
        assert_eq!(msg, r#"1000000test-sign/orders{"hash":"0x123"}"#);
        assert_eq!(
            l2_hmac(SECRET, &msg).unwrap(),
            "4gJVbox-R6XlDK4nlaicig0_ANVL1qdcahiL8CXfXLM="
        );
    }
}
