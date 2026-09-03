use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{EndpointAddr, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{PeerIdentity, now_ms};

const TICKET_PREFIX: &str = "bloom-peer-v1:";
const INVITE_DOMAIN: &[u8] = b"bloom.peer.invite/v1\0";
const MAX_INVITE_TTL_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_CLOCK_SKEW_MS: u64 = 5_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInvite {
    pub schema: String,
    pub endpoint_addr: EndpointAddr,
    pub invite_id: Uuid,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub signature: String,
}

#[derive(Serialize)]
struct InviteClaims<'a> {
    schema: &'a str,
    endpoint_addr: &'a EndpointAddr,
    invite_id: Uuid,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl PeerInvite {
    pub fn create(
        identity: &PeerIdentity,
        endpoint_addr: EndpointAddr,
        ttl_ms: u64,
    ) -> Result<Self> {
        if endpoint_addr.id != identity.endpoint_id() {
            bail!("invite address does not belong to the signing identity");
        }
        if ttl_ms == 0 || ttl_ms > MAX_INVITE_TTL_MS {
            bail!("invite TTL must be between 1 ms and 24 hours");
        }
        let issued_at_ms = now_ms();
        let mut invite = Self {
            schema: "bloom.peer-invite/v1".into(),
            endpoint_addr,
            invite_id: Uuid::new_v4(),
            issued_at_ms,
            expires_at_ms: issued_at_ms.saturating_add(ttl_ms),
            signature: String::new(),
        };
        let digest = invite.digest()?;
        invite.signature = URL_SAFE_NO_PAD.encode(identity.secret_key().sign(&digest).to_bytes());
        Ok(invite)
    }

    pub fn verify(&self, current_ms: u64) -> Result<()> {
        if self.schema != "bloom.peer-invite/v1" {
            bail!("unsupported invite schema");
        }
        if self.expires_at_ms < self.issued_at_ms
            || self.expires_at_ms.saturating_sub(self.issued_at_ms) > MAX_INVITE_TTL_MS
        {
            bail!("invalid peer invite lifetime");
        }
        if self.issued_at_ms > current_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
            bail!("peer invite issued too far in the future");
        }
        if self.expires_at_ms < current_ms {
            bail!("peer invite expired");
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .context("invalid invite signature encoding")?;
        let bytes: [u8; 64] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid invite signature length"))?;
        let signature = Signature::from_bytes(&bytes);
        self.endpoint_addr
            .id
            .verify(&self.digest()?, &signature)
            .map_err(|_| anyhow::anyhow!("invalid peer invite signature"))
    }

    pub fn encode(&self) -> Result<String> {
        Ok(format!(
            "{TICKET_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(self)?)
        ))
    }

    pub fn decode(ticket: &str) -> Result<Self> {
        let encoded = ticket
            .strip_prefix(TICKET_PREFIX)
            .context("invalid Bloom peer ticket prefix")?;
        let invite: Self = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded)?)?;
        invite.verify(now_ms())?;
        Ok(invite)
    }

    fn digest(&self) -> Result<[u8; 32]> {
        let claims = InviteClaims {
            schema: &self.schema,
            endpoint_addr: &self.endpoint_addr,
            invite_id: self.invite_id,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
        };
        let canonical = serde_jcs::to_vec(&claims)?;
        let mut hasher = Sha256::new();
        hasher.update(INVITE_DOMAIN);
        hasher.update(canonical);
        Ok(hasher.finalize().into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrolledPeer {
    pub endpoint_addr: EndpointAddr,
    #[serde(default)]
    pub allowed_evaluators: Vec<String>,
    #[serde(default = "default_true")]
    pub allow_inbound_review: bool,
    #[serde(default = "default_true")]
    pub allow_outbound_review: bool,
    pub enrolled_at_ms: u64,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug)]
pub struct PeerRegistry {
    path: PathBuf,
}

impl PeerRegistry {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn list(&self) -> Result<Vec<EnrolledPeer>> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => {
                Err(error).with_context(|| format!("read peer registry {}", self.path.display()))
            }
        }
    }

    pub fn add_invite(&self, invite: &PeerInvite) -> Result<EnrolledPeer> {
        invite.verify(now_ms())?;
        let mut peers = self.list()?;
        let peer = EnrolledPeer {
            endpoint_addr: invite.endpoint_addr.clone(),
            allowed_evaluators: Vec::new(),
            allow_inbound_review: true,
            allow_outbound_review: true,
            enrolled_at_ms: now_ms(),
        };
        peers.retain(|existing| existing.endpoint_addr.id != peer.endpoint_addr.id);
        peers.push(peer.clone());
        peers.sort_by_key(|entry| entry.endpoint_addr.id);
        self.write(&peers)?;
        Ok(peer)
    }

    pub fn remove(&self, endpoint_id: iroh::EndpointId) -> Result<bool> {
        let mut peers = self.list()?;
        let before = peers.len();
        peers.retain(|peer| peer.endpoint_addr.id != endpoint_id);
        if peers.len() != before {
            self.write(&peers)?;
        }
        Ok(peers.len() != before)
    }

    pub fn set_allowed_evaluators(
        &self,
        endpoint_id: iroh::EndpointId,
        mut evaluators: Vec<String>,
    ) -> Result<()> {
        evaluators.sort();
        evaluators.dedup();
        let mut peers = self.list()?;
        let peer = peers
            .iter_mut()
            .find(|peer| peer.endpoint_addr.id == endpoint_id)
            .context("peer is not enrolled")?;
        peer.allowed_evaluators = evaluators;
        self.write(&peers)
    }

    fn write(&self, peers: &[EnrolledPeer]) -> Result<()> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let tmp = self.path.with_extension("tmp");
        let mut options = fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(&serde_json::to_vec_pretty(peers)?)?;
        file.sync_all()?;
        fs::rename(tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn invite_round_trip_and_registry() {
        let identity = PeerIdentity::generate();
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(identity.secret_key().clone())
            .bind()
            .await
            .unwrap();
        let invite = PeerInvite::create(&identity, endpoint.addr(), 30_000).unwrap();
        let decoded = PeerInvite::decode(&invite.encode().unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let registry = PeerRegistry::open(dir.path().join("peers.json"));
        registry.add_invite(&decoded).unwrap();
        assert_eq!(registry.list().unwrap().len(), 1);
        assert!(registry.remove(identity.endpoint_id()).unwrap());
        assert!(registry.list().unwrap().is_empty());
        endpoint.close().await;
    }
}
