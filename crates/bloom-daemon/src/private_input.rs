//! Daemon-owned, capability-gated private input sessions for Petal routes.
//!
//! Session values are held only in daemon memory. Public callers receive a
//! bearer URL and lifecycle metadata; the value is released solely through the
//! mediated Petal host call bound to the originating package and route.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine as _;
use bloom_auth_api::ApprovalChallenge;
use bloom_petals::HostError;
use bloom_petals::abi::{
    PendingPrivateInput, PetalRouteContext, PrivateInputKind, PrivateInputOutcome,
    PrivateInputRequest,
};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::ceremony_server::private_input_url;

pub(crate) const PRIVATE_INPUT_TTL_MS: u64 = 10 * 60 * 1000;
const MAX_ACTIVE_PRIVATE_INPUTS: usize = 64;
const ALLOWED_PETAL_ROOT: &str = "privacy-pools";

#[derive(Clone)]
pub(crate) struct PrivateInputMetadata {
    pub token: String,
    pub id: String,
    pub wallet: String,
    pub approval_wallet: String,
    pub title: String,
    pub prompt: String,
    pub kind: PrivateInputKind,
    pub context: PetalRouteContext,
    pub expires_ms: u64,
}

enum PrivateInputState {
    Awaiting,
    Prepared {
        value: Zeroizing<String>,
        challenge: Box<ApprovalChallenge>,
    },
    Ready {
        value: Zeroizing<String>,
    },
}

struct PrivateInputSession {
    metadata: PrivateInputMetadata,
    fingerprint: [u8; 32],
    state: PrivateInputState,
}

#[derive(Default)]
pub(crate) struct PrivateInputManager {
    sessions: Mutex<HashMap<String, PrivateInputSession>>,
}

impl PrivateInputManager {
    pub fn request(
        &self,
        request: PrivateInputRequest,
        now_ms: u64,
    ) -> Result<PrivateInputOutcome, HostError> {
        let context = validate_request(&request)?;
        let fingerprint = request_fingerprint(&request, &context)?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| HostError::Backend("private-input session lock poisoned".into()))?;
        sessions.retain(|_, session| session.metadata.expires_ms > now_ms);

        if let Some(session) = sessions
            .values()
            .find(|session| session.fingerprint == fingerprint)
        {
            return Ok(outcome(session));
        }
        if sessions.len() >= MAX_ACTIVE_PRIVATE_INPUTS {
            return Err(HostError::Backend(
                "too many active private-input ceremonies".into(),
            ));
        }

        let expires_ms = now_ms
            .checked_add(PRIVATE_INPUT_TTL_MS)
            .ok_or_else(|| HostError::Backend("private-input expiry overflow".into()))?;
        let mut token_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token_bytes);
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);
        let metadata = PrivateInputMetadata {
            token: token.clone(),
            id: request.id,
            wallet: request.wallet,
            approval_wallet: request.approval_wallet.ok_or_else(|| {
                HostError::Invalid("private-input approval wallet was not resolved".into())
            })?,
            title: request.title,
            prompt: request.prompt,
            kind: request.kind,
            context,
            expires_ms,
        };
        sessions.insert(
            token,
            PrivateInputSession {
                metadata: metadata.clone(),
                fingerprint,
                state: PrivateInputState::Awaiting,
            },
        );
        Ok(PrivateInputOutcome::Pending(PendingPrivateInput {
            ceremony_url: private_input_url(&metadata.token),
            expires_ms,
        }))
    }

    pub fn metadata(&self, token: &str, now_ms: u64) -> Result<PrivateInputMetadata, HostError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| HostError::Backend("private-input session lock poisoned".into()))?;
        let expired = sessions
            .get(token)
            .is_some_and(|session| session.metadata.expires_ms <= now_ms);
        if expired {
            sessions.remove(token);
            return Err(HostError::Denied("private-input ceremony expired".into()));
        }
        sessions
            .get(token)
            .map(|session| session.metadata.clone())
            .ok_or_else(|| HostError::NotFound("private-input ceremony".into()))
    }

    pub fn set_prepared(
        &self,
        token: &str,
        value: String,
        challenge: ApprovalChallenge,
        now_ms: u64,
    ) -> Result<(), HostError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| HostError::Backend("private-input session lock poisoned".into()))?;
        let session = sessions
            .get_mut(token)
            .ok_or_else(|| HostError::NotFound("private-input ceremony".into()))?;
        if session.metadata.expires_ms <= now_ms {
            return Err(HostError::Denied("private-input ceremony expired".into()));
        }
        if matches!(session.state, PrivateInputState::Ready { .. }) {
            return Err(HostError::Denied(
                "private-input ceremony already completed".into(),
            ));
        }
        session.state = PrivateInputState::Prepared {
            value: Zeroizing::new(value),
            challenge: Box::new(challenge),
        };
        Ok(())
    }

    pub fn prepared_challenge(
        &self,
        token: &str,
        now_ms: u64,
    ) -> Result<ApprovalChallenge, HostError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| HostError::Backend("private-input session lock poisoned".into()))?;
        let session = sessions
            .get(token)
            .ok_or_else(|| HostError::NotFound("private-input ceremony".into()))?;
        if session.metadata.expires_ms <= now_ms {
            return Err(HostError::Denied("private-input ceremony expired".into()));
        }
        match &session.state {
            PrivateInputState::Prepared { challenge, .. } => Ok(challenge.as_ref().clone()),
            PrivateInputState::Awaiting => Err(HostError::Invalid(
                "private-input value has not been prepared".into(),
            )),
            PrivateInputState::Ready { .. } => Err(HostError::Denied(
                "private-input ceremony already completed".into(),
            )),
        }
    }

    pub fn complete(&self, token: &str, action_id: &str, now_ms: u64) -> Result<(), HostError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| HostError::Backend("private-input session lock poisoned".into()))?;
        let session = sessions
            .get_mut(token)
            .ok_or_else(|| HostError::NotFound("private-input ceremony".into()))?;
        if session.metadata.expires_ms <= now_ms {
            return Err(HostError::Denied("private-input ceremony expired".into()));
        }
        let state = std::mem::replace(&mut session.state, PrivateInputState::Awaiting);
        match state {
            PrivateInputState::Prepared { value, challenge }
                if challenge.action_id == action_id =>
            {
                session.state = PrivateInputState::Ready { value };
                Ok(())
            }
            other => {
                session.state = other;
                Err(HostError::Denied(
                    "private-input approval does not match the prepared value".into(),
                ))
            }
        }
    }

    pub fn consume(
        &self,
        id: &str,
        context: Option<PetalRouteContext>,
        now_ms: u64,
    ) -> Result<(), HostError> {
        let context = context.ok_or_else(|| {
            HostError::Denied("private-input consume requires trusted route context".into())
        })?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| HostError::Backend("private-input session lock poisoned".into()))?;
        let token = sessions
            .iter()
            .find(|(_, session)| {
                session.metadata.id == id
                    && same_origin(&session.metadata.context, &context)
                    && session.metadata.expires_ms > now_ms
                    && matches!(session.state, PrivateInputState::Ready { .. })
            })
            .map(|(token, _)| token.clone())
            .ok_or_else(|| HostError::NotFound("ready private-input session".into()))?;
        sessions.remove(&token);
        Ok(())
    }
}

fn validate_request(request: &PrivateInputRequest) -> Result<PetalRouteContext, HostError> {
    let context = request.context.clone().ok_or_else(|| {
        HostError::Denied("private-input request requires trusted route context".into())
    })?;
    if context.petal_root != ALLOWED_PETAL_ROOT {
        return Err(HostError::Denied(
            "private-input ceremonies are restricted to the privacy-pools petal".into(),
        ));
    }
    if request.id.is_empty()
        || request.id.len() > 256
        || request.id.starts_with('/')
        || request.id.contains('\0')
        || request
            .id
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(HostError::Invalid("invalid private-input id".into()));
    }
    if request.wallet.is_empty() || request.wallet.len() > 128 {
        return Err(HostError::Invalid("invalid private-input wallet".into()));
    }
    if request
        .approval_wallet
        .as_ref()
        .is_none_or(|wallet| wallet.is_empty() || wallet.len() > 64)
    {
        return Err(HostError::Invalid(
            "private-input approval wallet must name a passkey wallet".into(),
        ));
    }
    if request.title.is_empty() || request.title.len() > 120 {
        return Err(HostError::Invalid("invalid private-input title".into()));
    }
    if request.prompt.is_empty() || request.prompt.len() > 500 {
        return Err(HostError::Invalid("invalid private-input prompt".into()));
    }
    Ok(context)
}

fn request_fingerprint(
    request: &PrivateInputRequest,
    context: &PetalRouteContext,
) -> Result<[u8; 32], HostError> {
    let encoded = serde_json::to_vec(&serde_json::json!({
        "domain": "bloom.private_input.request.v1",
        "id": request.id,
        "wallet": request.wallet,
        "approval_wallet": request.approval_wallet,
        "title": request.title,
        "prompt": request.prompt,
        "kind": match request.kind { PrivateInputKind::EvmAddress => "evm_address" },
        "petal_root": context.petal_root,
        "package_hash": context.package_hash,
        "route_id": context.route_id,
        "op": context.op,
        "path": context.path,
        "params": context.params,
        "actor": context.actor,
    }))
    .map_err(|error| HostError::Backend(format!("encode private-input request: {error}")))?;
    Ok(*blake3::hash(&encoded).as_bytes())
}

fn same_origin(left: &PetalRouteContext, right: &PetalRouteContext) -> bool {
    left.petal_root == right.petal_root
        && left.package_hash == right.package_hash
        && left.route_id == right.route_id
        && left.op == right.op
        && left.path == right.path
        && left.params == right.params
        && left.actor == right.actor
}

fn outcome(session: &PrivateInputSession) -> PrivateInputOutcome {
    match &session.state {
        PrivateInputState::Ready { value } => PrivateInputOutcome::Ready(value.to_string()),
        PrivateInputState::Awaiting | PrivateInputState::Prepared { .. } => {
            PrivateInputOutcome::Pending(PendingPrivateInput {
                ceremony_url: private_input_url(&session.metadata.token),
                expires_ms: session.metadata.expires_ms,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_auth_api::{APPROVAL_CHALLENGE_SCHEMA_V1, AssuranceLevel};

    fn request() -> PrivateInputRequest {
        PrivateInputRequest {
            id: "privacy-pools/withdraw/dev/note-1".into(),
            wallet: "dev".into(),
            approval_wallet: Some("owner-passkey".into()),
            title: "Private withdrawal destination".into(),
            prompt: "Enter the destination address".into(),
            kind: PrivateInputKind::EvmAddress,
            context: Some(PetalRouteContext {
                petal_root: "privacy-pools".into(),
                package_hash: "ab".repeat(32),
                route_id: "withdraw-private".into(),
                op: "write".into(),
                path: "private-withdrawals/dev/note-1.json".into(),
                params: vec![],
                actor: None,
            }),
        }
    }

    #[test]
    fn request_is_stable_and_redacted() {
        let manager = PrivateInputManager::default();
        let first = manager.request(request(), 1).unwrap();
        let second = manager.request(request(), 2).unwrap();
        assert_eq!(first, second);
        let json = format!("{first:?}");
        assert!(!json.contains("0x"));
    }

    #[test]
    fn rejects_other_petals() {
        let manager = PrivateInputManager::default();
        let mut request = request();
        request.context.as_mut().unwrap().petal_root = "anything-else".into();
        assert!(matches!(
            manager.request(request, 1),
            Err(HostError::Denied(_))
        ));
    }

    fn challenge(action_id: &str) -> ApprovalChallenge {
        ApprovalChallenge {
            schema: APPROVAL_CHALLENGE_SCHEMA_V1.into(),
            action_id: action_id.into(),
            wallet: "dev".into(),
            surface: "petal-private-input".into(),
            petal_id: "pkg:privacy-pools".into(),
            petal_digest: "ab".repeat(32),
            intent_hash: "cd".repeat(32),
            server_nonce: "nonce".into(),
            assurance: AssuranceLevel::Standard,
            daemon_terms_digest: "ef".repeat(32),
            petal_policy_digest: "12".repeat(32),
            policy_version: 0,
            expiry_ms: 600_001,
            ceremony_url: None,
        }
    }

    #[test]
    fn ready_value_is_origin_bound_and_single_use() {
        let manager = PrivateInputManager::default();
        let request = request();
        let context = request.context.clone();
        let pending = manager.request(request.clone(), 1).unwrap();
        let PrivateInputOutcome::Pending(pending) = pending else {
            panic!("expected pending");
        };
        let token = pending.ceremony_url.rsplit('/').next().unwrap();
        manager
            .set_prepared(
                token,
                "0x1111111111111111111111111111111111111111".into(),
                challenge("action-1"),
                2,
            )
            .unwrap();
        assert!(manager.complete(token, "wrong-action", 3).is_err());
        manager.complete(token, "action-1", 3).unwrap();
        assert!(matches!(
            manager.request(request, 4).unwrap(),
            PrivateInputOutcome::Ready(value)
                if value == "0x1111111111111111111111111111111111111111"
        ));

        let mut wrong_context = context.clone().unwrap();
        wrong_context.package_hash = "ff".repeat(32);
        assert!(
            manager
                .consume("privacy-pools/withdraw/dev/note-1", Some(wrong_context), 5,)
                .is_err()
        );
        manager
            .consume("privacy-pools/withdraw/dev/note-1", context, 5)
            .unwrap();
        assert!(manager.metadata(token, 6).is_err());
    }
}
