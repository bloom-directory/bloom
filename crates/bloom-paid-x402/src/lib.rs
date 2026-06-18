//! x402 protocol adapter for Bloom paid HTTP requests.

use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::dyn_abi::Eip712Domain;
use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::signers::SignerSync;
use alloy::sol;
use alloy::sol_types::SolStruct;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bloom_keystore::{Keystore, KeystoreError, WalletKind};
use bloom_paid_http::{NormalizedChallenge, ParsedRequest, PaymentRequirement};
use serde_json::json;

pub trait X402PaymentSigner: Send + Sync {
    fn sign_x402_payment(&self, ctx: &X402SignContext<'_>)
    -> Result<X402PaymentCredential, String>;
}

pub struct X402SignContext<'a> {
    pub wallet: &'a str,
    /// Stable id of the staged pending request. The nonce in
    /// `TransferWithAuthorization` is derived from this so it is bound to the
    /// request the user actually confirmed, not a fresh id generated at sign
    /// time.
    pub request_id: &'a str,
    pub request: &'a ParsedRequest,
    pub challenge: &'a NormalizedChallenge,
    pub requirement: &'a PaymentRequirement,
}

pub struct X402PaymentCredential {
    /// The secret-bearing value sent as the `X-PAYMENT` retry header. This is
    /// intentionally never persisted to credential.json.
    pub header_value: String,
    /// Redacted/public metadata safe to expose in the VFS.
    pub public_metadata: serde_json::Value,
}

sol! {
    #[allow(missing_docs)]
    struct TransferWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }
}

pub struct KeystoreX402PaymentSigner {
    keystore: Keystore,
}

impl KeystoreX402PaymentSigner {
    pub fn new(keystore: Keystore) -> Self {
        Self { keystore }
    }
}

impl X402PaymentSigner for KeystoreX402PaymentSigner {
    fn sign_x402_payment(
        &self,
        ctx: &X402SignContext<'_>,
    ) -> Result<X402PaymentCredential, String> {
        let signer = self
            .keystore
            .signer(ctx.wallet)
            .map_err(|e| x402_keystore_signer_error(ctx.wallet, &self.keystore, e))?;
        let info = self
            .keystore
            .info(ctx.wallet)
            .map_err(|e| format!("x402 signer wallet metadata unavailable: {e}"))?;
        let scheme = ctx.requirement.scheme.as_deref().unwrap_or("exact");
        if scheme != "exact" {
            return Err(format!(
                "x402 keystore signer supports exact EVM requirements, got scheme '{scheme}'"
            ));
        }
        let network = ctx
            .requirement
            .network
            .as_deref()
            .ok_or_else(|| "x402 requirement missing network".to_string())?;
        let chain_id = x402_evm_chain_id(network)?;
        let asset = parse_x402_address(ctx.requirement.asset.as_deref(), "asset")?;
        let pay_to = parse_x402_address(ctx.requirement.pay_to.as_deref(), "payTo")?;
        let now = unix_seconds();
        let valid_after = U256::from(now.saturating_sub(600));
        let valid_before = U256::from(now + x402_max_timeout_seconds(ctx.requirement));
        let nonce = x402_nonce(ctx, now);
        let value = U256::from_str_radix(ctx.requirement.amount.as_deref().unwrap_or("0"), 10)
            .map_err(|e| format!("x402 amount is not uint256: {e}"))?;
        let authorization = json!({
            "from": info.address.to_string(),
            "to": pay_to.to_string(),
            "value": value.to_string(),
            "validAfter": valid_after.to_string(),
            "validBefore": valid_before.to_string(),
            "nonce": nonce.to_string(),
        });
        let auth = TransferWithAuthorization {
            from: info.address,
            to: pay_to,
            value,
            validAfter: valid_after,
            validBefore: valid_before,
            nonce,
        };
        let domain = Eip712Domain {
            name: x402_requirement_extra_str(ctx.requirement, "name").map(Cow::Owned),
            version: x402_requirement_extra_str(ctx.requirement, "version").map(Cow::Owned),
            chain_id: Some(U256::from(chain_id)),
            verifying_contract: Some(asset),
            ..Eip712Domain::default()
        };
        let digest = auth.eip712_signing_hash(&domain);
        let signature = signer
            .sign_hash_sync(&digest)
            .map_err(|e| format!("x402 keystore signing failed: {e}"))?
            .to_string();
        let header = json!({
            "x402Version": 1,
            "scheme": scheme,
            "network": network,
            "payload": {
                "signature": signature,
                "authorization": authorization,
            },
        });
        let header_bytes =
            serde_json::to_vec(&header).map_err(|e| format!("serialize x402 header: {e}"))?;
        Ok(X402PaymentCredential {
            header_value: STANDARD.encode(header_bytes),
            public_metadata: json!({
                "signer_backend": "bloom-keystore",
                "wallet": ctx.wallet,
                "wallet_kind": wallet_kind_label(info.kind),
                "address": info.address.to_string(),
                "scheme": scheme,
                "network": network,
                "asset": asset.to_string(),
                "pay_to": pay_to.to_string(),
                "resource": ctx.requirement.resource.as_deref().unwrap_or(ctx.request.url.as_str()),
                "authorization": authorization,
                "signature": "redacted",
            }),
        })
    }
}

fn parse_x402_address(value: Option<&str>, field: &str) -> Result<Address, String> {
    value
        .ok_or_else(|| format!("x402 requirement missing {field}"))?
        .parse::<Address>()
        .map_err(|e| format!("x402 requirement {field} is not an EVM address: {e}"))
}

fn x402_evm_chain_id(network: &str) -> Result<u64, String> {
    match network {
        "abstract" => Ok(2741),
        "abstract-testnet" => Ok(11124),
        "base-sepolia" => Ok(84532),
        "base" => Ok(8453),
        "avalanche-fuji" => Ok(43113),
        "avalanche" => Ok(43114),
        "iotex" => Ok(4689),
        "sei" => Ok(1329),
        "sei-testnet" => Ok(1328),
        "polygon" => Ok(137),
        "polygon-amoy" => Ok(80002),
        "peaq" => Ok(3338),
        "story" => Ok(1514),
        "educhain" => Ok(41923),
        "skale-base-sepolia" => Ok(324705682),
        other => Err(format!(
            "x402 keystore signer supports EVM networks only; unsupported network '{other}'"
        )),
    }
}

fn x402_requirement_extra_str(req: &PaymentRequirement, key: &str) -> Option<String> {
    req.raw
        .get("extra")
        .and_then(|v| v.get(key))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn x402_max_timeout_seconds(req: &PaymentRequirement) -> u64 {
    req.raw
        .get("maxTimeoutSeconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(60)
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn x402_nonce(ctx: &X402SignContext<'_>, now: u64) -> B256 {
    keccak256(
        format!(
            "{}:{}:{}:{now}",
            ctx.wallet, ctx.request.url, ctx.request_id
        )
        .as_bytes(),
    )
}

fn wallet_kind_label(kind: WalletKind) -> &'static str {
    match kind {
        WalletKind::Local => "local",
        WalletKind::Watch => "watch",
        WalletKind::PasskeyGated => "passkey",
    }
}

fn x402_keystore_signer_error(wallet: &str, keystore: &Keystore, err: KeystoreError) -> String {
    match err {
        KeystoreError::Locked(_) => match keystore.info(wallet).map(|i| i.kind) {
            Ok(WalletKind::PasskeyGated) => format!(
                "wallet '{wallet}' is locked; passkey wallets must be foreground-unlocked with unlock_passkey before confirming this paid request"
            ),
            _ => format!(
                "wallet '{wallet}' is locked; unlock the wallet before confirming this paid request"
            ),
        },
        other => format!("x402 keystore signer unavailable for wallet '{wallet}': {other}"),
    }
}
