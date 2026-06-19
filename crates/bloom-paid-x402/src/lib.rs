//! x402 protocol adapter for Bloom paid HTTP requests.

use async_trait::async_trait;
use bloom_keystore::{Keystore, KeystoreError, WalletKind};
use bloom_paid_http::{
    NormalizedChallenge, PaidHttpChainRpcResolver, ParsedRequest, PaymentRequirement,
};
use serde_json::json;
use x402_chain_eip155::{V1Eip155ExactClient, V2Eip155ExactClient};
use x402_types::proto::{self, OriginalJson};
use x402_types::scheme::client::X402SchemeClient;
use x402_types::util::Base64Bytes;

#[async_trait]
pub trait X402PaymentSigner: Send + Sync {
    async fn sign_x402_payment(
        &self,
        ctx: &X402SignContext<'_>,
    ) -> Result<X402PaymentCredential, String>;
}

pub struct X402SignContext<'a> {
    pub wallet: &'a str,
    pub request_id: &'a str,
    pub request: &'a ParsedRequest,
    pub challenge: &'a NormalizedChallenge,
    pub requirement: &'a PaymentRequirement,
    pub rpc_resolver: &'a dyn PaidHttpChainRpcResolver,
}

pub struct X402PaymentCredential {
    /// Header name/value to send on the paid retry. x402 V1 uses `X-Payment`;
    /// V2 uses `Payment-Signature`.
    pub header_name: &'static str,
    pub header_value: String,
    /// Redacted/public metadata safe to expose in the VFS.
    pub public_metadata: serde_json::Value,
}

pub struct KeystoreX402PaymentSigner {
    keystore: Keystore,
}

impl KeystoreX402PaymentSigner {
    pub fn new(keystore: Keystore) -> Self {
        Self { keystore }
    }
}

#[async_trait]
impl X402PaymentSigner for KeystoreX402PaymentSigner {
    async fn sign_x402_payment(
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
        let payment_required = parse_payment_required(ctx.challenge)?;
        let candidate = select_candidate(&payment_required, signer).ok_or_else(|| {
            "x402 upstream signer found no matching EIP-155 exact payment option".to_string()
        })?;
        if let Some(network) = ctx.requirement.network.as_deref() {
            let candidate_network = candidate.chain_id.to_string();
            if candidate_network != network {
                return Err(format!(
                    "x402 selected network {candidate_network}, expected staged network {network}"
                ));
            }
        }
        if let Some(asset) = ctx.requirement.asset.as_deref()
            && !candidate.asset.eq_ignore_ascii_case(asset)
        {
            return Err(format!(
                "x402 selected asset {}, expected staged asset {asset}",
                candidate.asset
            ));
        }
        if let Some(pay_to) = ctx.requirement.pay_to.as_deref()
            && !candidate.pay_to.eq_ignore_ascii_case(pay_to)
        {
            return Err(format!(
                "x402 selected pay_to {}, expected staged pay_to {pay_to}",
                candidate.pay_to
            ));
        }
        let header_value = candidate
            .sign()
            .await
            .map_err(|e| format!("x402 upstream signing failed: {e}"))?;
        let header_name = match payment_required {
            proto::PaymentRequired::V1(_) => "X-Payment",
            proto::PaymentRequired::V2(_) => "Payment-Signature",
        };
        let configured_rpc_urls = ctx
            .rpc_resolver
            .http_rpc_urls_for_chain_id_opt(eip155_chain_id_u64(&candidate.chain_id));
        Ok(X402PaymentCredential {
            header_name,
            header_value,
            public_metadata: json!({
                "signer_backend": "x402-chain-eip155",
                "wallet": ctx.wallet,
                "wallet_kind": wallet_kind_label(info.kind),
                "address": info.address.to_string(),
                "scheme": candidate.scheme,
                "x402_version": candidate.x402_version,
                "network": candidate.chain_id.to_string(),
                "asset": candidate.asset,
                "amount": candidate.amount.to_string(),
                "pay_to": candidate.pay_to,
                "rpc_urls_configured": configured_rpc_urls.len(),
                "resource": ctx.requirement.resource.as_deref().unwrap_or(ctx.request.url.as_str()),
                "request_id": ctx.request_id,
                "signature": "redacted",
            }),
        })
    }
}

fn parse_payment_required(
    challenge: &NormalizedChallenge,
) -> Result<proto::PaymentRequired, String> {
    if let Some(header) = challenge.headers.get("payment-required") {
        let bytes = Base64Bytes::from(header.as_bytes())
            .decode()
            .map_err(|e| format!("decode x402 Payment-Required header: {e}"))?;
        let parsed = serde_json::from_slice::<proto::v2::PaymentRequired<OriginalJson>>(&bytes)
            .map_err(|e| format!("parse x402 v2 Payment-Required header: {e}"))?;
        return Ok(proto::PaymentRequired::V2(parsed));
    }
    let value = json!({
        "x402Version": 1,
        "accepts": challenge.accepts.iter().map(|req| req.raw.clone()).collect::<Vec<_>>(),
        "error": null,
    });
    let parsed = serde_json::from_value::<proto::v1::PaymentRequired<OriginalJson>>(value)
        .map_err(|e| format!("parse x402 v1 challenge: {e}"))?;
    Ok(proto::PaymentRequired::V1(parsed))
}

fn select_candidate(
    payment_required: &proto::PaymentRequired,
    signer: std::sync::Arc<alloy::signers::local::PrivateKeySigner>,
) -> Option<x402_types::scheme::client::PaymentCandidate> {
    let mut candidates = V2Eip155ExactClient::new(signer.clone()).accept(payment_required);
    candidates.extend(V1Eip155ExactClient::new(signer).accept(payment_required));
    candidates.into_iter().next()
}

fn eip155_chain_id_u64(chain_id: &x402_types::chain::ChainId) -> Option<u64> {
    (chain_id.namespace() == "eip155")
        .then(|| chain_id.reference().parse().ok())
        .flatten()
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

#[cfg(test)]
mod tests {
    use super::parse_payment_required;
    use bloom_paid_http::normalize_challenge;
    use reqwest::header::{HeaderMap, HeaderValue};
    use url::Url;

    #[test]
    fn parses_nansen_v2_payment_required_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "payment-required",
            HeaderValue::from_static(
                "eyJ4NDAyVmVyc2lvbiI6MiwiZXJyb3IiOiJQYXltZW50IHJlcXVpcmVkIiwicmVzb3VyY2UiOnsidXJsIjoiaHR0cHM6Ly9hcGkubmFuc2VuLmFpL2FwaS92MS90b2tlbi1zY3JlZW5lciIsImRlc2NyaXB0aW9uIjoiUmV0cmlldmUgdG9rZW4gc2NyZWVuZXIgZGF0YSIsIm1pbWVUeXBlIjoiIn0sImFjY2VwdHMiOlt7InNjaGVtZSI6ImV4YWN0IiwibmV0d29yayI6ImVpcDE1NTo4NDUzIiwiYXNzZXQiOiIweDgzMzU4OWZDRDZlRGI2RTA4ZjRjN0MzMkQ0ZjcxYjU0YmRBMDI5MTMiLCJhbW91bnQiOiIxMDAwMCIsInBheVRvIjoiMHg5MzA1M2YxZTdBNWVGRURhNTMyRmU2OUNiYkU0M2NCRWMzQTBGMTNmIiwibWF4VGltZW91dFNlY29uZHMiOjMwMCwiZXh0cmEiOnsibmFtZSI6IlVTRCBDb2luIiwidmVyc2lvbiI6IjIifX1dfQ==",
            ),
        );
        let challenge = normalize_challenge(
            &headers,
            br#"{"x402Version":2,"accepts":[]}"#,
            &Url::parse("https://api.nansen.ai/api/v1/token-screener").unwrap(),
        );
        let parsed = parse_payment_required(&challenge).unwrap();
        match parsed {
            x402_types::proto::PaymentRequired::V2(v2) => {
                assert_eq!(v2.accepts.len(), 1);
            }
            _ => panic!("expected v2 payment required"),
        }
    }
}
