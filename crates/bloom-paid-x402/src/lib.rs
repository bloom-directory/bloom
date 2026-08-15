//! x402 protocol adapter for Bloom paid HTTP requests.
//!
//! This adapter never touches wallet key material. It selects the matching
//! x402 payment candidate and asks the Bloom runtime's host signing seam
//! ([`PaidHttpHostSigner`]) to sign the exact EIP-712 digest under a live
//! Sealed Approval grant. The upstream x402 clients are generic over
//! [`SignerLike`], so injecting a host-backed signer reuses all of the
//! crate's EIP-712 construction and header assembly without a
//! concrete local private signer ever entering this crate.

use std::io::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex};

use alloy::primitives::{Address, FixedBytes, Signature, U256};
use alloy::sol_types::{Eip712Domain, SolStruct, eip712_domain};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bloom_paid_http::{
    NormalizedChallenge, PaidHttpChainRpcResolver, PaidHttpHostSigner, PaidHttpSigningFacts,
    ParsedRequest, PaymentRequirement, networks_equivalent,
};
use serde_json::json;
use x402_chain_eip155::chain::Eip155ChainReference;
use x402_chain_eip155::chain::permit2::{EXACT_PERMIT2_PROXY_ADDRESS, PERMIT2_ADDRESS};
use x402_chain_eip155::v1_eip155_exact::SignerLike;
use x402_chain_eip155::v1_eip155_exact::{self as v1_exact, TransferWithAuthorization};
use x402_chain_eip155::v2_eip155_exact::{
    self as v2_exact, ISignatureTransfer, PermitWitnessTransferFrom, x402ExactPermit2Proxy,
};
use x402_chain_eip155::{V1Eip155ExactClient, V2Eip155ExactClient};
use x402_types::chain::ChainId;
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
    /// Machine-private durable unsigned draft. It freezes the upstream
    /// timestamp/nonce before the Broker ceremony so retries sign identical bytes.
    pub draft_path: &'a Path,
}

pub struct X402PaymentCredential {
    /// Header name/value to send on the paid retry. x402 V1 uses `X-Payment`;
    /// V2 uses `Payment-Signature`.
    pub header_name: &'static str,
    pub header_value: String,
    /// Redacted/public metadata safe to expose in the VFS.
    pub public_metadata: serde_json::Value,
}

#[derive(Clone)]
struct DraftSigner {
    address: Address,
    observed_hash: Arc<Mutex<Option<[u8; 32]>>>,
}

#[async_trait]
impl SignerLike for DraftSigner {
    fn address(&self) -> Address {
        self.address
    }

    async fn sign_hash(&self, hash: &FixedBytes<32>) -> Result<Signature, alloy::signers::Error> {
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(hash.as_slice());
        *self.observed_hash.lock().expect("draft hash lock") = Some(bytes);
        Signature::from_raw(&[1_u8; 65]).map_err(alloy::signers::Error::message)
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

fn persist_draft_atomically(path: &Path, value: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "x402 draft path has no parent".to_string())?;
    std::fs::create_dir_all(parent).map_err(|e| format!("create x402 draft directory: {e}"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("create temporary x402 draft: {e}"))?;
    temporary
        .write_all(value.as_bytes())
        .map_err(|e| format!("write temporary x402 draft: {e}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|e| format!("sync temporary x402 draft: {e}"))?;
    temporary
        .persist(path)
        .map_err(|e| format!("persist x402 unsigned draft: {}", e.error))?;
    Ok(())
}

#[async_trait]
impl X402PaymentSigner for HostX402PaymentSigner {
    async fn sign_x402_payment(
        &self,
        ctx: &X402SignContext<'_>,
    ) -> Result<X402PaymentCredential, String> {
        let payment_required = parse_payment_required(ctx.challenge)?;
        let observed_hash = Arc::new(Mutex::new(None));
        let adapter = DraftSigner {
            address: ctx.wallet_address,
            observed_hash: observed_hash.clone(),
        };
        let candidate =
            select_candidate(&payment_required, adapter, ctx.requirement)?.ok_or_else(|| {
                "x402 upstream signer found no matching selected payment option".to_string()
            })?;
        // `candidate.sign()` computes the EIP-712 digest and calls back into the
        // host seam (which enforces the grant and consumes exactly one signature
        // allowance), then assembles the header value from the returned
        // signature.
        let unsigned_header = match std::fs::read_to_string(ctx.draft_path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let value = candidate
                    .sign()
                    .await
                    .map_err(|e| format!("x402 unsigned draft assembly failed: {e}"))?;
                persist_draft_atomically(ctx.draft_path, &value)?;
                value
            }
            Err(error) => return Err(format!("read x402 unsigned draft: {error}")),
        };
        validate_unsigned_draft(
            &unsigned_header,
            &payment_required,
            &candidate,
            ctx.wallet_address,
        )?;
        let (preimage, signing_hash) =
            exact_signing_payload(&unsigned_header, &payment_required, &candidate)?;
        if let Some(observed) = *observed_hash.lock().expect("draft hash lock")
            && observed != signing_hash
        {
            return Err("x402 reconstructed preimage differs from upstream signing hash".into());
        }
        let signature = ctx
            .host_signer
            .sign_paid_http_payload(
                X402_SIGN_INTENT,
                "credential",
                &preimage,
                signing_hash,
                ctx.facts,
            )
            .await?;
        let header_value = replace_payload_signature(&unsigned_header, &signature)?;
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

fn validate_unsigned_draft(
    header: &str,
    required: &proto::PaymentRequired,
    candidate: &x402_types::scheme::client::PaymentCandidate,
    wallet_address: Address,
) -> Result<(), String> {
    let decoded = Base64Bytes::from(header.as_bytes())
        .decode()
        .map_err(|error| format!("decode x402 unsigned payload: {error}"))?;
    match required {
        proto::PaymentRequired::V1(required) => {
            let payload: v1_exact::types::PaymentPayload = serde_json::from_slice(&decoded)
                .map_err(|error| format!("parse x402 v1 unsigned payload: {error}"))?;
            let expected = required
                .accepts
                .iter()
                .filter_map(|raw| v1_exact::types::PaymentRequirements::try_from(raw).ok())
                .find(|entry| {
                    networks_equivalent(&entry.network, &candidate.chain_id.to_string())
                        && entry
                            .asset
                            .to_string()
                            .eq_ignore_ascii_case(&candidate.asset)
                        && entry
                            .pay_to
                            .to_string()
                            .eq_ignore_ascii_case(&candidate.pay_to)
                        && entry.max_amount_required == candidate.amount
                })
                .ok_or_else(|| "x402 v1 draft has no selected accepted requirement".to_string())?;
            let authorization = payload.payload.authorization;
            if !networks_equivalent(&payload.network, &expected.network)
                || authorization.from != wallet_address
                || authorization.to != expected.pay_to
                || authorization.value != expected.max_amount_required
            {
                return Err("x402 v1 unsigned draft differs from selected payment terms".into());
            }
        }
        proto::PaymentRequired::V2(required) => {
            let payload: v2_exact::types::PaymentPayload = serde_json::from_slice(&decoded)
                .map_err(|error| format!("parse x402 v2 unsigned payload: {error}"))?;
            let expected = required
                .accepts
                .iter()
                .filter_map(|raw| v2_exact::types::PaymentRequirements::try_from(raw).ok())
                .find(|entry| {
                    entry.network == candidate.chain_id
                        && entry
                            .asset
                            .to_string()
                            .eq_ignore_ascii_case(&candidate.asset)
                        && entry
                            .pay_to
                            .to_string()
                            .eq_ignore_ascii_case(&candidate.pay_to)
                        && entry.amount.0 == candidate.amount
                })
                .ok_or_else(|| "x402 v2 draft has no selected accepted requirement".to_string())?;
            if payload.accepted != expected
                || serde_json::to_value(&payload.resource).map_err(|e| e.to_string())?
                    != serde_json::to_value(&required.resource).map_err(|e| e.to_string())?
            {
                return Err("x402 v2 unsigned draft differs from selected payment terms".into());
            }
            match &payload.payload {
                v2_exact::ExactEvmPayload::Eip3009(value) => {
                    if value.authorization.from != wallet_address
                        || value.authorization.to != expected.pay_to.0
                        || value.authorization.value != expected.amount.0
                    {
                        return Err(
                            "x402 v2 EIP-3009 draft differs from selected payment terms".into()
                        );
                    }
                }
                v2_exact::ExactEvmPayload::Permit2(value) => {
                    let authorization = &value.permit_2_authorization;
                    if authorization.from.0 != wallet_address
                        || authorization.permitted.token.0 != expected.asset.0
                        || authorization.permitted.amount != expected.amount.0
                        || authorization.witness.to.0 != expected.pay_to.0
                        || authorization.spender.0 != EXACT_PERMIT2_PROXY_ADDRESS
                    {
                        return Err(
                            "x402 v2 Permit2 draft differs from selected payment terms".into()
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn exact_signing_payload(
    header: &str,
    required: &proto::PaymentRequired,
    candidate: &x402_types::scheme::client::PaymentCandidate,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let decoded = Base64Bytes::from(header.as_bytes())
        .decode()
        .map_err(|error| format!("decode x402 unsigned payload: {error}"))?;
    match required {
        proto::PaymentRequired::V1(required) => {
            let payload: v1_exact::types::PaymentPayload = serde_json::from_slice(&decoded)
                .map_err(|error| format!("parse x402 v1 unsigned payload: {error}"))?;
            let authorization = payload.payload.authorization;
            let requirements = required
                .accepts
                .iter()
                .filter_map(|raw| v1_exact::types::PaymentRequirements::try_from(raw).ok())
                .find(|entry| {
                    networks_equivalent(&entry.network, &payload.network)
                        && networks_equivalent(&entry.network, &candidate.chain_id.to_string())
                        && entry
                            .asset
                            .to_string()
                            .eq_ignore_ascii_case(&candidate.asset)
                        && entry.pay_to == authorization.to
                        && entry.max_amount_required == authorization.value
                })
                .ok_or_else(|| {
                    "x402 v1 draft does not match an accepted requirement".to_string()
                })?;
            let chain = ChainId::from_network_name(&requirements.network)
                .ok_or_else(|| "x402 v1 network is not EIP-155".to_string())?;
            let chain_id = Eip155ChainReference::try_from(chain)
                .map_err(|error| error.to_string())?
                .inner();
            let (name, version) = requirements
                .extra
                .map(|extra| (extra.name, extra.version))
                .unwrap_or_default();
            eip3009_preimage(chain_id, requirements.asset, &name, &version, authorization)
        }
        proto::PaymentRequired::V2(_) => {
            let payload: v2_exact::types::PaymentPayload = serde_json::from_slice(&decoded)
                .map_err(|error| format!("parse x402 v2 unsigned payload: {error}"))?;
            let accepted = payload.accepted;
            let chain_id = Eip155ChainReference::try_from(&accepted.network)
                .map_err(|error| error.to_string())?
                .inner();
            match payload.payload {
                v2_exact::ExactEvmPayload::Eip3009(eip3009) => {
                    let (name, version) = match accepted.extra {
                        x402_chain_eip155::chain::AssetTransferMethod::Eip3009 {
                            name,
                            version,
                        } => (name, version),
                        _ => return Err("x402 v2 EIP-3009 payload has Permit2 terms".into()),
                    };
                    eip3009_preimage(
                        chain_id,
                        accepted.asset.0,
                        &name,
                        &version,
                        eip3009.authorization,
                    )
                }
                v2_exact::ExactEvmPayload::Permit2(permit) => {
                    permit2_preimage(chain_id, permit.permit_2_authorization)
                }
            }
        }
    }
}

fn eip3009_preimage(
    chain_id: u64,
    asset: Address,
    name: &str,
    version: &str,
    authorization: v1_exact::ExactEvmPayloadAuthorization,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let domain = eip712_domain! {
        name: name.to_owned(),
        version: version.to_owned(),
        chain_id: chain_id,
        verifying_contract: asset,
    };
    let message = TransferWithAuthorization {
        from: authorization.from,
        to: authorization.to,
        value: authorization.value,
        validAfter: U256::from(authorization.valid_after.as_secs()),
        validBefore: U256::from(authorization.valid_before.as_secs()),
        nonce: authorization.nonce,
    };
    Ok(eip712_preimage(&domain, message.eip712_hash_struct()))
}

fn permit2_preimage(
    chain_id: u64,
    authorization: x402_chain_eip155::chain::permit2::Permit2Authorization<
        x402_chain_eip155::chain::permit2::ExactPermit2Witness,
    >,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let domain = eip712_domain! {
        name: "Permit2",
        chain_id: chain_id,
        verifying_contract: PERMIT2_ADDRESS,
    };
    let message = PermitWitnessTransferFrom {
        permitted: ISignatureTransfer::TokenPermissions {
            token: authorization.permitted.token.0,
            amount: authorization.permitted.amount,
        },
        spender: EXACT_PERMIT2_PROXY_ADDRESS,
        nonce: authorization.nonce,
        deadline: U256::from(authorization.deadline.as_secs()),
        witness: x402ExactPermit2Proxy::Witness {
            to: authorization.witness.to.0,
            validAfter: U256::from(authorization.witness.valid_after.as_secs()),
        },
    };
    Ok(eip712_preimage(&domain, message.eip712_hash_struct()))
}

fn eip712_preimage(domain: &Eip712Domain, struct_hash: FixedBytes<32>) -> (Vec<u8>, [u8; 32]) {
    let mut preimage = Vec::with_capacity(66);
    preimage.extend_from_slice(&[0x19, 0x01]);
    preimage.extend_from_slice(domain.separator().as_slice());
    preimage.extend_from_slice(struct_hash.as_slice());
    let hash = alloy::primitives::keccak256(&preimage).into();
    (preimage, hash)
}

fn replace_payload_signature(header: &str, signature: &[u8; 65]) -> Result<String, String> {
    let decoded = Base64Bytes::from(header.as_bytes())
        .decode()
        .map_err(|error| format!("decode x402 draft for signature replacement: {error}"))?;
    let mut value: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|error| format!("parse x402 draft for signature replacement: {error}"))?;
    let signature_slot = value
        .get_mut("payload")
        .and_then(|payload| payload.get_mut("signature"))
        .ok_or_else(|| "x402 draft has no signature field".to_string())?;
    *signature_slot = serde_json::Value::String(format!("0x{}", hex_lower(signature)));
    let encoded = serde_json::to_vec(&value)
        .map_err(|error| format!("serialize signed x402 payload: {error}"))?;
    Ok(Base64Bytes::encode(encoded).to_string())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        HostX402PaymentSigner, X402PaymentSigner, X402SignContext, candidate_matches_requirement,
        eip3009_preimage, exact_signing_payload, parse_payment_required, proto, v1_exact,
    };
    use alloy::primitives::{Address, U256};
    use async_trait::async_trait;
    use bloom_paid_http::{
        EmptyPaidHttpChainRpcResolver, PaidHttpHostSigner, PaidHttpSigningFacts, ParsedRequest,
        normalize_challenge,
    };
    use reqwest::header::{HeaderMap, HeaderValue};
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use url::Url;
    use x402_types::chain::ChainId;
    use x402_types::proto::OriginalJson;
    use x402_types::scheme::client::{PaymentCandidate, PaymentCandidateSigner, X402Error};
    use x402_types::util::Base64Bytes;

    struct DummyPaymentSigner;

    #[derive(Default)]
    struct ExactHost {
        preimages: Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait]
    impl PaidHttpHostSigner for ExactHost {
        async fn sign_paid_http_payload(
            &self,
            _intent: &str,
            _signing_slot: &str,
            preimage: &[u8],
            signing_hash: [u8; 32],
            _facts: &PaidHttpSigningFacts,
        ) -> Result<[u8; 65], String> {
            assert_eq!(
                alloy::primitives::keccak256(preimage).as_slice(),
                signing_hash
            );
            self.preimages.lock().unwrap().push(preimage.to_vec());
            Ok([2_u8; 65])
        }

        async fn sign_paid_http_hash(
            &self,
            _intent: &str,
            _signing_hash: [u8; 32],
            _facts: &PaidHttpSigningFacts,
        ) -> Result<[u8; 65], String> {
            panic!("hash-only x402 signing must not be used")
        }
    }

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

    #[test]
    fn v1_preimage_reconstruction_keeps_the_selected_asset() {
        let first_asset = "0x1111111111111111111111111111111111111111";
        let selected_asset = "0x2222222222222222222222222222222222222222";
        let pay_to = "0x93053f1e7A5eFEDa532Fe69CbbE43cBEc3A0F13f";
        let requirement = |asset: &str, name: &str, version: &str| {
            serde_json::json!({
                "scheme": "exact",
                "network": "base",
                "maxAmountRequired": "10000",
                "resource": "https://example.test/paid",
                "description": "paid resource",
                "mimeType": "application/json",
                "payTo": pay_to,
                "maxTimeoutSeconds": 300,
                "asset": asset,
                "extra": {"name": name, "version": version}
            })
        };
        let required: proto::v1::PaymentRequired<OriginalJson> =
            serde_json::from_value(serde_json::json!({
                "x402Version": 1,
                "accepts": [
                    requirement(first_asset, "First Token", "1"),
                    requirement(selected_asset, "Selected Token", "2")
                ],
                "error": null
            }))
            .unwrap();
        let payment_required = proto::PaymentRequired::V1(required);
        let unsigned_payload = serde_json::json!({
            "x402Version": 1,
            "scheme": "exact",
            "network": "base",
            "payload": {
                "signature": "0x",
                "authorization": {
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": pay_to,
                    "value": "10000",
                    "validAfter": "1",
                    "validBefore": "301",
                    "nonce": format!("0x{}", "33".repeat(32))
                }
            }
        });
        let header =
            Base64Bytes::encode(serde_json::to_vec(&unsigned_payload).unwrap()).to_string();
        let mut selected = candidate(10_000);
        selected.asset = selected_asset.into();

        let (actual_preimage, actual_hash) =
            exact_signing_payload(&header, &payment_required, &selected).unwrap();
        let decoded = Base64Bytes::from(header.as_bytes()).decode().unwrap();
        let payload: v1_exact::types::PaymentPayload = serde_json::from_slice(&decoded).unwrap();
        let (expected_preimage, expected_hash) = eip3009_preimage(
            8453,
            selected_asset.parse().unwrap(),
            "Selected Token",
            "2",
            payload.payload.authorization,
        )
        .unwrap();

        assert_eq!(actual_preimage, expected_preimage);
        assert_eq!(actual_hash, expected_hash);
    }

    #[tokio::test]
    async fn v2_adapter_persists_draft_and_uses_exact_preimage() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "payment-required",
            HeaderValue::from_static(
                "eyJ4NDAyVmVyc2lvbiI6MiwiZXJyb3IiOiJQYXltZW50IHJlcXVpcmVkIiwicmVzb3VyY2UiOnsidXJsIjoiaHR0cHM6Ly9hcGkubmFuc2VuLmFpL2FwaS92MS90b2tlbi1zY3JlZW5lciIsImRlc2NyaXB0aW9uIjoiUmV0cmlldmUgdG9rZW4gc2NyZWVuZXIgZGF0YSIsIm1pbWVUeXBlIjoiIn0sImFjY2VwdHMiOlt7InNjaGVtZSI6ImV4YWN0IiwibmV0d29yayI6ImVpcDE1NTo4NDUzIiwiYXNzZXQiOiIweDgzMzU4OWZDRDZlRGI2RTA4ZjRjN0MzMkQ0ZjcxYjU0YmRBMDI5MTMiLCJhbW91bnQiOiIxMDAwMCIsInBheVRvIjoiMHg5MzA1M2YxZTdBNWVGRURhNTMyRmU2OUNiYkU0M2NCRWMzQTBGMTNmIiwibWF4VGltZW91dFNlY29uZHMiOjMwMCwiZXh0cmEiOnsibmFtZSI6IlVTRCBDb2luIiwidmVyc2lvbiI6IjIifX1dfQ==",
            ),
        );
        let url = Url::parse("https://api.nansen.ai/api/v1/token-screener").unwrap();
        let challenge = normalize_challenge(&headers, b"{}", &url);
        let requirement = bloom_paid_http::PaymentRequirement {
            scheme: Some("exact".into()),
            network: Some("eip155:8453".into()),
            asset: Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into()),
            amount: Some("10000".into()),
            pay_to: Some("0x93053f1e7A5eFEDa532Fe69CbbE43cBEc3A0F13f".into()),
            resource: Some(url.to_string()),
            raw: serde_json::json!({}),
        };
        let request = ParsedRequest {
            method: "GET".into(),
            url,
            wallet: Some("alice".into()),
            max_amount_usd: Some(1.0),
            headers: BTreeMap::new(),
            body: None,
        };
        let host = Arc::new(ExactHost::default());
        let host_trait: Arc<dyn PaidHttpHostSigner> = host.clone();
        let temporary = tempfile::tempdir().unwrap();
        let draft = temporary.path().join("draft");
        let signer = HostX402PaymentSigner::new();
        let facts = PaidHttpSigningFacts::default();
        for _ in 0..2 {
            let credential = signer
                .sign_x402_payment(&X402SignContext {
                    wallet: "alice",
                    request_id: "req-1",
                    request: &request,
                    challenge: &challenge,
                    requirement: &requirement,
                    rpc_resolver: &EmptyPaidHttpChainRpcResolver,
                    wallet_address: Address::repeat_byte(0x11),
                    host_signer: &host_trait,
                    facts: &facts,
                    draft_path: &draft,
                })
                .await
                .unwrap();
            assert_eq!(credential.header_name, "Payment-Signature");
        }
        {
            let preimages = host.preimages.lock().unwrap();
            assert_eq!(preimages.len(), 2);
            assert_eq!(preimages[0], preimages[1]);
            assert_eq!(preimages[0].len(), 66);
        }

        let encoded = std::fs::read_to_string(&draft).unwrap();
        let mut payload: serde_json::Value =
            serde_json::from_slice(&Base64Bytes::from(encoded.as_bytes()).decode().unwrap())
                .unwrap();
        payload["accepted"]["amount"] = "999999".into();
        std::fs::write(
            &draft,
            Base64Bytes::encode(serde_json::to_vec(&payload).unwrap()).to_string(),
        )
        .unwrap();
        let error = match signer
            .sign_x402_payment(&X402SignContext {
                wallet: "alice",
                request_id: "req-1",
                request: &request,
                challenge: &challenge,
                requirement: &requirement,
                rpc_resolver: &EmptyPaidHttpChainRpcResolver,
                wallet_address: Address::repeat_byte(0x11),
                host_signer: &host_trait,
                facts: &facts,
                draft_path: &draft,
            })
            .await
        {
            Ok(_) => panic!("tampered x402 draft was accepted"),
            Err(error) => error,
        };
        assert!(error.contains("selected payment terms"));
        assert_eq!(host.preimages.lock().unwrap().len(), 2);
    }
}
