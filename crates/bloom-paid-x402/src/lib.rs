//! x402 protocol adapter for Bloom paid HTTP requests.
//!
//! This adapter never touches wallet key material. It selects the matching
//! x402 payment candidate and asks the Bloom runtime's host signing seam
//! ([`PaidHttpHostSigner`]) to sign the exact EIP-712 digest under a live
//! Sealed Approval grant. The upstream x402 clients are generic over
//! [`SignerLike`], so injecting a host-backed signer reuses all of the
//! crate's EIP-712 construction and header assembly without a
//! `PrivateKeySigner` ever entering this crate.

use std::sync::Arc;

use alloy::primitives::{Address, FixedBytes, Signature, U256};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bloom_paid_http::{
    NormalizedChallenge, PaidHttpChainRpcResolver, PaidHttpHostSigner, PaidHttpSigningFacts,
    ParsedRequest, PaymentRequirement, networks_equivalent,
};
use serde_json::json;
use x402_chain_eip155::v1_eip155_exact::SignerLike;
use x402_chain_eip155::{V1Eip155ExactClient, V2Eip155ExactClient};
use x402_types::proto::{self, OriginalJson};
use x402_types::scheme::client::X402SchemeClient;
use x402_types::util::Base64Bytes;

/// The `sign-hash` intent string every x402 host signature is authorized under.
pub const X402_SIGN_INTENT: &str = "x402.sign";

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
    /// EVM owner address of `wallet` (public; fills the x402 `from` field).
    pub wallet_address: Address,
    /// Host signing seam. Signing is gated on a live paid-HTTP Sealed Approval
    /// grant and never exposes key material to this crate.
    pub host_signer: &'a Arc<dyn PaidHttpHostSigner>,
    /// Secret-free facts recorded in the host `SigningAttestation`.
    pub facts: &'a PaidHttpSigningFacts,
}

pub struct X402PaymentCredential {
    /// Header name/value to send on the paid retry. x402 V1 uses `X-Payment`;
    /// V2 uses `Payment-Signature`.
    pub header_name: &'static str,
    pub header_value: String,
    /// Redacted/public metadata safe to expose in the VFS.
    pub public_metadata: serde_json::Value,
}

/// Adapter that satisfies the upstream x402 [`SignerLike`] contract by routing
/// the EIP-712 digest through the Bloom host signing seam. Cloneable (the x402
/// clients require `Clone`); the clone is a cheap `Arc` bump.
#[derive(Clone)]
struct HostSignerAdapter {
    host: Arc<dyn PaidHttpHostSigner>,
    address: Address,
    facts: Arc<PaidHttpSigningFacts>,
}

#[async_trait]
impl SignerLike for HostSignerAdapter {
    fn address(&self) -> Address {
        self.address
    }

    async fn sign_hash(&self, hash: &FixedBytes<32>) -> Result<Signature, alloy::signers::Error> {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(hash.as_slice());
        let sig65 = self
            .host
            .sign_paid_http_hash(X402_SIGN_INTENT, digest, &self.facts)
            .await
            .map_err(alloy::signers::Error::message)?;
        Signature::from_raw(&sig65).map_err(alloy::signers::Error::message)
    }
}

/// x402 payment signer backed by the Bloom host signing seam.
///
/// Stateless: the per-request host signer, wallet address, and attestation
/// facts arrive on the [`X402SignContext`], so the same instance serves every
/// request without holding a keystore or any key material.
#[derive(Default)]
pub struct HostX402PaymentSigner;

impl HostX402PaymentSigner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl X402PaymentSigner for HostX402PaymentSigner {
    async fn sign_x402_payment(
        &self,
        ctx: &X402SignContext<'_>,
    ) -> Result<X402PaymentCredential, String> {
        let payment_required = parse_payment_required(ctx.challenge)?;
        let adapter = HostSignerAdapter {
            host: ctx.host_signer.clone(),
            address: ctx.wallet_address,
            facts: Arc::new(ctx.facts.clone()),
        };
        let candidate =
            select_candidate(&payment_required, adapter, ctx.requirement)?.ok_or_else(|| {
                "x402 upstream signer found no matching selected payment option".to_string()
            })?;
        // `candidate.sign()` computes the EIP-712 digest and calls back into the
        // host seam (which enforces the grant and consumes exactly one signature
        // allowance), then assembles the header value from the returned
        // signature.
        let header_value = candidate
            .sign()
            .await
            .map_err(|e| format!("x402 host signing failed: {e}"))?;
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
                "signer_backend": "x402-chain-eip155/host-signing",
                "wallet": ctx.wallet,
                "address": ctx.wallet_address.to_string(),
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

/// Decode a base64 secp256k1 signature returned by the host into 65 raw bytes.
pub fn decode_host_signature_b64(signature_b64: &str) -> Result<[u8; 65], String> {
    let bytes = B64
        .decode(signature_b64)
        .map_err(|e| format!("decode host signature: {e}"))?;
    <[u8; 65]>::try_from(bytes.as_slice())
        .map_err(|_| format!("host signature is {} bytes, expected 65", bytes.len()))
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

fn select_candidate<S>(
    payment_required: &proto::PaymentRequired,
    signer: S,
    requirement: &PaymentRequirement,
) -> Result<Option<x402_types::scheme::client::PaymentCandidate>, String>
where
    S: SignerLike + Clone + Send + Sync + 'static,
{
    let mut candidates = V2Eip155ExactClient::new(signer.clone()).accept(payment_required);
    candidates.extend(V1Eip155ExactClient::new(signer).accept(payment_required));
    for candidate in candidates {
        if candidate_matches_requirement(&candidate, requirement)? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn candidate_matches_requirement(
    candidate: &x402_types::scheme::client::PaymentCandidate,
    requirement: &PaymentRequirement,
) -> Result<bool, String> {
    if let Some(scheme) = requirement.scheme.as_deref()
        && !candidate.scheme.eq_ignore_ascii_case(scheme)
    {
        return Ok(false);
    }
    if let Some(network) = requirement.network.as_deref() {
        let candidate_network = candidate.chain_id.to_string();
        if !networks_equivalent(&candidate_network, network) {
            return Ok(false);
        }
    }
    if let Some(asset) = requirement.asset.as_deref()
        && !candidate.asset.eq_ignore_ascii_case(asset)
    {
        return Ok(false);
    }
    if let Some(pay_to) = requirement.pay_to.as_deref()
        && !candidate.pay_to.eq_ignore_ascii_case(pay_to)
    {
        return Ok(false);
    }
    if let Some(amount) = requirement.amount.as_deref() {
        let expected = amount
            .parse::<U256>()
            .map_err(|e| format!("selected x402 requirement amount is not a valid integer: {e}"))?;
        if candidate.amount != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

fn eip155_chain_id_u64(chain_id: &x402_types::chain::ChainId) -> Option<u64> {
    (chain_id.namespace() == "eip155")
        .then(|| chain_id.reference().parse().ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::{candidate_matches_requirement, parse_payment_required};
    use alloy::primitives::U256;
    use async_trait::async_trait;
    use bloom_paid_http::normalize_challenge;
    use reqwest::header::{HeaderMap, HeaderValue};
    use url::Url;
    use x402_types::chain::ChainId;
    use x402_types::scheme::client::{PaymentCandidate, PaymentCandidateSigner, X402Error};

    struct DummyPaymentSigner;

    #[async_trait]
    impl PaymentCandidateSigner for DummyPaymentSigner {
        async fn sign_payment(&self) -> Result<String, X402Error> {
            Ok("signed".into())
        }
    }

    fn candidate(amount: u64) -> PaymentCandidate {
        PaymentCandidate {
            chain_id: "eip155:8453".parse::<ChainId>().unwrap(),
            asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
            amount: U256::from(amount),
            scheme: "exact".into(),
            x402_version: 1,
            pay_to: "0x93053f1e7A5eFEDa532Fe69CbbE43cBEc3A0F13f".into(),
            signer: Box::new(DummyPaymentSigner),
        }
    }

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

    #[test]
    fn candidate_match_requires_selected_atomic_amount() {
        let requirement = bloom_paid_http::PaymentRequirement {
            scheme: Some("exact".into()),
            network: Some("base".into()),
            asset: Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into()),
            amount: Some("10000".into()),
            pay_to: Some("0x93053f1e7A5eFEDa532Fe69CbbE43cBEc3A0F13f".into()),
            resource: None,
            raw: serde_json::json!({}),
        };

        assert!(candidate_matches_requirement(&candidate(10_000), &requirement).unwrap());
        assert!(!candidate_matches_requirement(&candidate(5_000_000), &requirement).unwrap());
    }
}
