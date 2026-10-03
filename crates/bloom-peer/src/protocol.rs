use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{EndpointId, Signature};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

const REQUEST_DOMAIN: &[u8] = b"bloom.review.request/v1\0";
const DECISION_DOMAIN: &[u8] = b"bloom.review.decision/v1\0";

#[derive(Debug, Error)]
pub enum WireError {
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
    #[error("invalid endpoint id: {0}")]
    InvalidEndpoint(String),
    #[error("invalid signature encoding")]
    InvalidSignatureEncoding,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("payload digest mismatch")]
    DigestMismatch,
    #[error("message expired")]
    Expired,
    #[error("message issued too far in the future")]
    FutureIssued,
    #[error("transport peer does not match signed sender")]
    SenderMismatch,
    #[error("unexpected message kind")]
    UnexpectedKind,
    #[error("invalid or unsupported envelope protocol")]
    InvalidProtocol,
    #[error("envelope expiration precedes its issue time")]
    InvalidLifetime,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    ReviewRequest,
    ReviewDecision,
}

impl fmt::Display for MessageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReviewRequest => "review_request",
            Self::ReviewDecision => "review_decision",
        })
    }
}

pub trait SignedMessage: Serialize + DeserializeOwned {
    const KIND: MessageKind;
    const DOMAIN: &'static [u8];
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TradeIntent {
    pub venue: String,
    pub instrument: String,
    pub side: String,
    pub order_type: String,
    pub quantity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_price: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ReviewRequest {
    pub schema: String,
    pub request_id: Uuid,
    pub evaluator_alias: String,
    pub intent: TradeIntent,
    #[serde(default)]
    pub facts: serde_json::Value,
    pub requested_output_schema: String,
    pub expires_at_ms: u64,
}

impl SignedMessage for ReviewRequest {
    const KIND: MessageKind = MessageKind::ReviewRequest;
    const DOMAIN: &'static [u8] = REQUEST_DOMAIN;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionVerdict {
    Approve,
    ApproveWithConditions,
    Reject,
    Abstain,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ReviewDecision {
    pub schema: String,
    pub request_id: Uuid,
    pub request_digest: String,
    pub evaluator_alias: String,
    pub verdict: DecisionVerdict,
    #[serde(default)]
    pub reason_codes: Vec<String>,
    #[serde(default)]
    pub conditions: Vec<serde_json::Value>,
    pub valid_until_ms: u64,
    pub advisory_only: bool,
}

impl SignedMessage for ReviewDecision {
    const KIND: MessageKind = MessageKind::ReviewDecision;
    const DOMAIN: &'static [u8] = DECISION_DOMAIN;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub protocol: String,
    pub message_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<Uuid>,
    pub sender_endpoint: String,
    pub kind: MessageKind,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub nonce: Uuid,
    pub payload_digest: String,
    pub payload: serde_json::Value,
    pub signature: String,
}

#[derive(Serialize)]
struct EnvelopeClaims<'a> {
    protocol: &'a str,
    message_id: Uuid,
    correlation_id: Option<Uuid>,
    sender_endpoint: &'a str,
    kind: &'a MessageKind,
    issued_at_ms: u64,
    expires_at_ms: u64,
    nonce: Uuid,
    payload_digest: &'a str,
}

impl Envelope {
    pub fn sign<T: SignedMessage>(
        identity: &crate::PeerIdentity,
        payload: &T,
        correlation_id: Option<Uuid>,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self, WireError> {
        let canonical = canonical_payload(payload)?;
        let digest = digest(T::DOMAIN, &canonical);
        let mut envelope = Self {
            protocol: "bloom.peer-review/v1".into(),
            message_id: Uuid::new_v4(),
            correlation_id,
            sender_endpoint: identity.endpoint_id().to_string(),
            kind: T::KIND,
            issued_at_ms,
            expires_at_ms,
            nonce: Uuid::new_v4(),
            payload_digest: format!("sha256:{}", hex::encode(digest)),
            payload: serde_json::to_value(payload)?,
            signature: String::new(),
        };
        let signature = identity
            .secret_key()
            .sign(&envelope.signature_digest(T::DOMAIN)?);
        envelope.signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        Ok(envelope)
    }

    pub fn verify<T: SignedMessage>(
        &self,
        transport_peer: EndpointId,
        now_ms: u64,
        max_future_skew_ms: u64,
    ) -> Result<T, WireError> {
        if self.protocol != "bloom.peer-review/v1" {
            return Err(WireError::InvalidProtocol);
        }
        if self.expires_at_ms < self.issued_at_ms {
            return Err(WireError::InvalidLifetime);
        }
        if self.kind != T::KIND {
            return Err(WireError::UnexpectedKind);
        }
        let sender: EndpointId = self
            .sender_endpoint
            .parse()
            .map_err(|_| WireError::InvalidEndpoint(self.sender_endpoint.clone()))?;
        if sender != transport_peer {
            return Err(WireError::SenderMismatch);
        }
        if self.expires_at_ms < now_ms {
            return Err(WireError::Expired);
        }
        if self.issued_at_ms > now_ms.saturating_add(max_future_skew_ms) {
            return Err(WireError::FutureIssued);
        }
        let payload: T = serde_json::from_value(self.payload.clone())?;
        let canonical = canonical_payload(&payload)?;
        let actual = digest(T::DOMAIN, &canonical);
        let expected = format!("sha256:{}", hex::encode(actual));
        if self.payload_digest != expected {
            return Err(WireError::DigestMismatch);
        }
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| WireError::InvalidSignatureEncoding)?;
        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| WireError::InvalidSignatureEncoding)?;
        let signature = Signature::from_bytes(&sig_array);
        sender
            .verify(&self.signature_digest(T::DOMAIN)?, &signature)
            .map_err(|_| WireError::InvalidSignature)?;
        Ok(payload)
    }

    fn signature_digest(&self, domain: &[u8]) -> Result<[u8; 32], WireError> {
        let claims = EnvelopeClaims {
            protocol: &self.protocol,
            message_id: self.message_id,
            correlation_id: self.correlation_id,
            sender_endpoint: &self.sender_endpoint,
            kind: &self.kind,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
            nonce: self.nonce,
            payload_digest: &self.payload_digest,
        };
        let canonical = serde_jcs::to_vec(&claims)
            .map_err(|error| WireError::Canonicalization(error.to_string()))?;
        Ok(digest(domain, &canonical))
    }
}

pub fn payload_digest<T: SignedMessage>(payload: &T) -> Result<String, WireError> {
    let canonical = canonical_payload(payload)?;
    Ok(format!(
        "sha256:{}",
        hex::encode(digest(T::DOMAIN, &canonical))
    ))
}

fn canonical_payload<T: Serialize>(payload: &T) -> Result<Vec<u8>, WireError> {
    serde_jcs::to_vec(payload).map_err(|e| WireError::Canonicalization(e.to_string()))
}

fn digest(domain: &[u8], canonical: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    hasher.finalize().into()
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ReviewRequest {
        ReviewRequest {
            schema: "bloom.trade-review-request/v1".into(),
            request_id: Uuid::new_v4(),
            evaluator_alias: "dummy-risk".into(),
            intent: TradeIntent {
                venue: "hyperliquid".into(),
                instrument: "BTC".into(),
                side: "buy".into(),
                order_type: "limit".into(),
                quantity: "0.01".into(),
                limit_price: Some("62000".into()),
            },
            facts: serde_json::json!({"dummy": true}),
            requested_output_schema: "bloom.trade-review-decision/v1".into(),
            expires_at_ms: now_ms() + 30_000,
        }
    }

    #[test]
    fn signed_envelope_round_trip_and_tamper_detection() {
        let identity = crate::PeerIdentity::generate();
        let now = now_ms();
        let req = request();
        let mut env = Envelope::sign(&identity, &req, None, now, now + 30_000).unwrap();
        let decoded: ReviewRequest = env.verify(identity.endpoint_id(), now, 5_000).unwrap();
        assert_eq!(decoded, req);
        env.payload["evaluator_alias"] = serde_json::json!("evil");
        assert!(matches!(
            env.verify::<ReviewRequest>(identity.endpoint_id(), now, 5_000),
            Err(WireError::DigestMismatch)
        ));
    }

    #[test]
    fn envelope_signature_covers_nonce_ttl_and_correlation() {
        let identity = crate::PeerIdentity::generate();
        let now = now_ms();
        let req = request();
        let mut env = Envelope::sign(&identity, &req, None, now, now + 30_000).unwrap();
        env.nonce = Uuid::new_v4();
        assert!(matches!(
            env.verify::<ReviewRequest>(identity.endpoint_id(), now, 5_000),
            Err(WireError::InvalidSignature)
        ));
    }

    #[test]
    fn signed_sender_must_match_iroh_transport_peer_and_ttl() {
        let identity = crate::PeerIdentity::generate();
        let other = crate::PeerIdentity::generate();
        let now = now_ms();
        let req = request();
        let env = Envelope::sign(&identity, &req, None, now, now + 100).unwrap();
        assert!(matches!(
            env.verify::<ReviewRequest>(other.endpoint_id(), now, 5_000),
            Err(WireError::SenderMismatch)
        ));
        assert!(matches!(
            env.verify::<ReviewRequest>(identity.endpoint_id(), now + 101, 5_000),
            Err(WireError::Expired)
        ));
    }
}
