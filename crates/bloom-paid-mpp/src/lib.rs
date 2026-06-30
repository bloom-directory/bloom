//! Tempo MPP protocol adapter for Bloom paid HTTP requests.

use async_trait::async_trait;
use bloom_keystore::{Keystore, KeystoreError, WalletKind};
use bloom_paid_http::{
    EmptyPaidHttpChainRpcResolver, NormalizedChallenge, PaidHttpChainRpcResolver, ParsedRequest,
    usd_to_atomic_units,
};
use bloom_proto::Policy;
use mpp::client::{PaymentProvider, TempoProvider, TempoSessionProvider};
use serde_json::json;
use std::sync::Arc;

#[async_trait]
pub trait PaymentBackend: Send + Sync {
    fn name(&self) -> &'static str;
    async fn prepare(
        &self,
        challenge: &NormalizedChallenge,
        request: &ParsedRequest,
        wallet: &str,
        policy: &Policy,
        request_id: &str,
    ) -> Result<PaymentExecution, String>;
}

pub struct RealMppBackend {
    pub keystore: Keystore,
    pub client: reqwest::Client,
    pub rpc_resolver: Arc<dyn PaidHttpChainRpcResolver>,
}

impl RealMppBackend {
    pub fn new(
        keystore: Keystore,
        client: reqwest::Client,
        rpc_resolver: Arc<dyn PaidHttpChainRpcResolver>,
    ) -> Self {
        Self {
            keystore,
            client,
            rpc_resolver,
        }
    }

    pub fn without_rpc_resolver(keystore: Keystore, client: reqwest::Client) -> Self {
        Self::new(keystore, client, Arc::new(EmptyPaidHttpChainRpcResolver))
    }

    fn signer_error(&self, wallet: &str, err: KeystoreError) -> String {
        match err {
            KeystoreError::Locked(_) => {
                let kind = self
                    .keystore
                    .raw_policy(wallet)
                    .ok()
                    .map(|(_, kind)| kind)
                    .or_else(|| self.keystore.info(wallet).ok().map(|info| info.kind));
                if kind == Some(WalletKind::PasskeyGated) {
                    format!(
                        "passkey wallet '{wallet}' is locked; run the foreground passkey unlock flow (`unlock-passkey` / Keystore::unlock_passkey) before confirming Tempo MPP payments"
                    )
                } else {
                    format!(
                        "wallet '{wallet}' is locked; unlock it before confirming Tempo MPP payments"
                    )
                }
            }
            other => format!("wallet '{wallet}' cannot be used for Tempo MPP signing: {other}"),
        }
    }
}

pub struct PaymentExecution {
    pub credential_metadata: serde_json::Value,
    pub header_name: &'static str,
    pub header_value: String,
}

#[async_trait]
impl PaymentBackend for RealMppBackend {
    fn name(&self) -> &'static str {
        "mpp_tempo"
    }

    async fn prepare(
        &self,
        challenge: &NormalizedChallenge,
        request: &ParsedRequest,
        wallet: &str,
        policy: &Policy,
        _request_id: &str,
    ) -> Result<PaymentExecution, String> {
        let _ = request;
        if challenge.protocol != "mpp" || challenge.network.as_deref() != Some("tempo") {
            return Err(
                "only Tempo MPP challenges can be confirmed by the real MPP backend".to_string(),
            );
        }
        let signer = self
            .keystore
            .signer(wallet)
            .map_err(|e| self.signer_error(wallet, e))?;
        let chain_id = challenge
            .chain_id
            .ok_or_else(|| "Tempo MPP challenge missing chainId".to_string())?;
        let rpc_url = self
            .rpc_resolver
            .http_rpc_url_for_chain_id(chain_id)
            .ok_or_else(|| {
                format!("no configured HTTP RPC URL for Tempo MPP chain_id {chain_id}")
            })?;
        let payment_challenge = parse_stored_mpp_challenge(challenge)?;
        let credential = match challenge.intent.as_str() {
            "charge" => {
                let provider = TempoProvider::new((*signer).clone(), &rpc_url)
                    .map_err(|e| format!("TempoProvider: {e}"))?;
                provider.pay(&payment_challenge).await
            }
            "session" => {
                let mut provider = TempoSessionProvider::new((*signer).clone(), &rpc_url)
                    .map_err(|e| format!("TempoSessionProvider: {e}"))?;
                if let Some(max) = policy
                    .payments
                    .sessions
                    .max_deposit_usd
                    .and_then(|usd| usd_to_atomic_units(challenge.asset.as_deref(), usd))
                {
                    provider = provider.with_max_deposit(max);
                }
                provider.pay(&payment_challenge).await
            }
            other => {
                return Err(format!("unsupported MPP intent '{other}'"));
            }
        }
        .map_err(|e| format!("Tempo MPP credential: {e}"))?;
        let authorization = mpp::format_authorization(&credential)
            .map_err(|e| format!("format MPP Authorization: {e}"))?;
        let authorization_sha256 = bloom_tools::sha256_hex(authorization.as_bytes());
        let credential_value = serde_json::to_value(&credential)
            .map_err(|e| format!("serialize MPP credential metadata: {e}"))?;
        Ok(PaymentExecution {
            credential_metadata: json!({
                "redacted": true,
                "protocol": challenge.protocol,
                "intent": challenge.intent,
                "backend": self.name(),
                "authorization_sha256": authorization_sha256,
                "source": credential_value.get("source").cloned(),
                "payload_type": credential_value.get("payload").and_then(|p| p.get("type")).cloned(),
                "charge_id": challenge.charge_id,
                "session_id": challenge.session_id,
                "channel_id": challenge.channel_id,
                "secret_material_in_vfs": false,
                "raw_authorization_stored": false,
                "raw_signed_payload_stored": false,
                "chain_id": chain_id,
                "rpc_url_configured": true
            }),
            header_name: "Authorization",
            header_value: authorization,
        })
    }
}

fn parse_stored_mpp_challenge(
    challenge: &NormalizedChallenge,
) -> Result<mpp::PaymentChallenge, String> {
    challenge
        .headers
        .get("www-authenticate")
        .and_then(|h| {
            mpp::parse_www_authenticate_all([h.as_str()])
                .into_iter()
                .filter_map(Result::ok)
                .find(|c| c.method.as_str() == "tempo" && c.intent.as_str() == challenge.intent)
        })
        .ok_or_else(|| {
            "stored challenge is missing a parseable Tempo MPP WWW-Authenticate header".to_string()
        })
}
