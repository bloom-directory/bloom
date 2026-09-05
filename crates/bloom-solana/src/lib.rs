//! Read-only Solana chain client.
//!
//! The in-tree analogue of `bloom-evm::ChainClient` for Solana: a typed,
//! genesis-bound read surface over the layered [`SolanaRpcClient`] transport.
//! It performs no signing, no broadcasting, and no account custody — those
//! belong to the `bloom-solana-tx` engine and the Broker/Signer triad.
//!
//! Unlike EVM, Solana has no `alloy` equivalent worth adopting here; this
//! crate's transport is `reqwest`-based (see [`transport`]) and reuses the
//! chain-neutral [`bloom_rpc_common::HealthRegistry`] for endpoint health.

#![forbid(unsafe_code)]

pub mod error;
pub mod retry;
pub mod transport;

use std::sync::Arc;

pub use bloom_proto::SOLANA_MAINNET_BETA_GENESIS_HASH as MAINNET_BETA_GENESIS_HASH;
pub use error::SolanaRpcError;

/// The mainnet-beta canary authorization, re-exported so the transfer engine
/// can enforce its caps without depending on `bloom-proto` directly.
pub use bloom_proto::canary;
pub use transport::SolanaRpcClient;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub use bloom_proto::EndpointSpec;
pub use bloom_proto::SolanaSpec;

/// `getLatestBlockhash` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatestBlockhash {
    /// The recent blockhash, base58-encoded.
    pub blockhash: String,
    /// The last block height at which the blockhash is still valid.
    pub last_valid_block_height: u64,
}

/// One entry of `getSignatureStatuses`'s `value` array (the `null` case is
/// represented by the outer `Option`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureStatus {
    pub slot: u64,
    pub confirmations: Option<u64>,
    #[serde(default)]
    pub err: Option<Value>,
    #[serde(default, alias = "confirmationStatus")]
    pub confirmation_status: Option<String>,
}

/// `simulateTransaction`'s `value` object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Simulation {
    #[serde(default)]
    pub err: Option<Value>,
    #[serde(default)]
    pub logs: Option<Vec<String>>,
    #[serde(default, alias = "unitsConsumed")]
    pub units_consumed: Option<u64>,
    #[serde(default, alias = "returnData")]
    pub return_data: Option<Value>,
}

/// A registry of Solana clients keyed by chain name, mirroring
/// `bloom-evm::ChainRegistry`.
#[derive(Clone, Default)]
pub struct SolanaChainRegistry {
    inner: std::sync::Arc<parking_lot::RwLock<std::collections::BTreeMap<String, SolanaClient>>>,
}

impl SolanaChainRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, client: SolanaClient) {
        let name = client.chain_name().to_string();
        self.inner.write().insert(name, client);
    }

    pub fn get(&self, name: &str) -> Option<SolanaClient> {
        self.inner.read().get(name).cloned()
    }

    pub fn list_names(&self) -> Vec<String> {
        self.inner.read().keys().cloned().collect()
    }

    pub fn from_specs<I: IntoIterator<Item = SolanaSpec>>(
        specs: I,
    ) -> Result<Self, SolanaRpcError> {
        let r = Self::new();
        for spec in specs {
            r.add(SolanaClient::build(&spec)?);
        }
        Ok(r)
    }
}

/// The read-only chain client. Clone is cheap (Arc inside).
#[derive(Clone)]
pub struct SolanaClient {
    inner: Arc<Inner>,
}

struct Inner {
    rpc: Arc<SolanaRpcClient>,
    expected_genesis_base58: Option<String>,
    allow_broadcast: bool,
}

impl SolanaClient {
    /// Build a client over `spec`. Fails on an empty endpoint list.
    pub fn build(spec: &SolanaSpec) -> Result<Self, SolanaRpcError> {
        if spec.allow_broadcast
            && spec
                .expected_genesis_base58
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err(SolanaRpcError::Invalid(format!(
                "chain '{}' enables broadcast without an expected genesis hash",
                spec.name
            )));
        }
        let rpc = Arc::new(SolanaRpcClient::build(spec)?);
        Ok(Self {
            inner: Arc::new(Inner {
                rpc,
                expected_genesis_base58: spec.expected_genesis_base58.clone(),
                allow_broadcast: spec.allow_broadcast,
            }),
        })
    }

    /// The pinned cluster genesis hash, if one is configured. `None` means
    /// nothing is pinned, so a genesis observation cannot be *verified* —
    /// only reported.
    pub fn configured_genesis(&self) -> Option<&str> {
        self.inner.expected_genesis_base58.as_deref()
    }

    /// Whether broadcasting is enabled for this cluster (the operator's
    /// release posture). The transaction engine refuses to submit without it.
    pub fn allow_broadcast(&self) -> bool {
        self.inner.allow_broadcast
    }

    /// The underlying transport's endpoint-health snapshot.
    pub fn endpoints_snapshot(&self) -> Vec<bloom_rpc_common::EndpointHealthSnapshot> {
        self.inner.rpc.endpoints_snapshot()
    }

    /// Chain name this client was built for.
    pub fn chain_name(&self) -> &str {
        self.inner.rpc.chain_name()
    }

    /// Verify the node's current genesis hash matches the spec. This is a
    /// live check on every call; callers use it at stage and broadcast so an
    /// endpoint or DNS change cannot silently cross clusters.
    pub async fn verify_genesis(&self) -> Result<String, SolanaRpcError> {
        let observed = match &self.inner.expected_genesis_base58 {
            Some(expected) => self.inner.rpc.verify_all_genesis(expected).await,
            None => self.get_genesis_hash().await,
        }?;
        if self.inner.allow_broadcast && observed == crate::MAINNET_BETA_GENESIS_HASH {
            // The third independent refusal, checked against the *live*
            // genesis immediately before the client is used to send. It stands
            // unless this binary was built with the non-default canary
            // capability and holds an authorization that is bound to this
            // artifact, names this chain, has not expired, and has not been
            // spent. In a production build the call below is a function that
            // returns `None`, so this refusal is unconditional.
            if bloom_proto::canary::authorization_for(self.chain_name(), now_ms()).is_none() {
                return Err(SolanaRpcError::Invalid(
                    "broadcast to Solana mainnet-beta is disabled".into(),
                ));
            }
            tracing::warn!(
                chain = %self.chain_name(),
                "solana.mainnet_canary_broadcast_permitted"
            );
        }
        Ok(observed)
    }

    /// Node health (`getHealth`). Ok when the node reports `"ok"`.
    pub async fn get_health(&self) -> Result<(), SolanaRpcError> {
        let result = self.inner.rpc.call_raw("getHealth", &json!([])).await?;
        if result.as_str() == Some("ok") {
            Ok(())
        } else {
            Err(SolanaRpcError::Decode(format!(
                "getHealth returned {result}"
            )))
        }
    }

    /// Cluster genesis hash, base58-encoded.
    pub async fn get_genesis_hash(&self) -> Result<String, SolanaRpcError> {
        self.inner.rpc.call("getGenesisHash", &json!([])).await
    }

    /// Current slot.
    pub async fn get_slot(&self) -> Result<u64, SolanaRpcError> {
        self.inner.rpc.call("getSlot", &json!([])).await
    }

    /// Current block height (processed blocks, not necessarily finalized).
    pub async fn get_block_height(&self) -> Result<u64, SolanaRpcError> {
        self.inner
            .rpc
            .call("getBlockHeight", &json!([{ "commitment": "processed" }]))
            .await
    }

    /// Native SOL balance in lamports for a base58 account address.
    pub async fn get_balance(&self, account: &str) -> Result<u64, SolanaRpcError> {
        let result: Value = self.inner.rpc.call("getBalance", &json!([account])).await?;
        result
            .get("value")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| SolanaRpcError::Decode(format!("getBalance: {result}")))
    }

    /// A recent blockhash and its last-valid block height.
    pub async fn get_latest_blockhash(&self) -> Result<LatestBlockhash, SolanaRpcError> {
        let result: Value = self
            .inner
            .rpc
            .call(
                "getLatestBlockhash",
                &json!([{ "commitment": "processed" }]),
            )
            .await?;
        let value = result
            .get("value")
            .ok_or_else(|| SolanaRpcError::Decode(format!("getLatestBlockhash: {result}")))?;
        let blockhash = value
            .get("blockhash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SolanaRpcError::Decode(format!("getLatestBlockhash: {value}")))?;
        let last_valid_block_height = value
            .get("lastValidBlockHeight")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| SolanaRpcError::Decode(format!("getLatestBlockhash: {value}")))?;
        Ok(LatestBlockhash {
            blockhash: blockhash.to_string(),
            last_valid_block_height,
        })
    }

    /// Fee for a serialized message (base64), if the node can quote it.
    pub async fn get_fee_for_message(
        &self,
        message_b64: &str,
    ) -> Result<Option<u64>, SolanaRpcError> {
        let result: Value = self
            .inner
            .rpc
            .call(
                "getFeeForMessage",
                // The message carries the `processed` blockhash fetched by
                // `get_latest_blockhash`. Quote it at the same commitment so
                // a newly produced hash is visible to both calls.
                &json!([message_b64, { "commitment": "processed" }]),
            )
            .await?;
        Ok(result.get("value").and_then(|v| v.as_u64()))
    }

    /// Simulate a signed transaction (base64) without committing it.
    pub async fn simulate_transaction(&self, tx_b64: &str) -> Result<Simulation, SolanaRpcError> {
        let result: Value = self
            .inner
            .rpc
            .call(
                "simulateTransaction",
                &json!([
                    tx_b64,
                    {
                        "encoding": "base64",
                        "sigVerify": true,
                        "replaceRecentBlockhash": false,
                        "commitment": "processed"
                    }
                ]),
            )
            .await?;
        let value = result.get("value").cloned().unwrap_or(Value::Null);
        serde_json::from_value::<Simulation>(value)
            .map_err(|e| SolanaRpcError::Decode(format!("simulateTransaction: {e}")))
    }

    /// Submit a signed transaction (base64) to the cluster. Returns the
    /// transaction signature.
    ///
    /// Every configured endpoint must first prove the pinned genesis. The
    /// transaction is then sent exactly once through the highest-priority
    /// endpoint; an ambiguous response is reconciled by signature and is never
    /// retried by the transport. Mainnet-beta remains unconditionally blocked
    /// here; only [`Self::send_mainnet_canary_transaction`] can consume the
    /// canary authorization in a canary build.
    pub async fn send_transaction(&self, tx_b64: &str) -> Result<String, SolanaRpcError> {
        if !self.inner.allow_broadcast {
            return Err(SolanaRpcError::Invalid(format!(
                "broadcast is disabled for chain '{}'",
                self.chain_name()
            )));
        }
        let expected = self
            .inner
            .expected_genesis_base58
            .as_deref()
            .ok_or_else(|| {
                SolanaRpcError::Invalid(format!(
                    "chain '{}' cannot broadcast without an expected genesis hash",
                    self.chain_name()
                ))
            })?;
        if expected == crate::MAINNET_BETA_GENESIS_HASH {
            return Err(SolanaRpcError::Invalid(
                "broadcast to Solana mainnet-beta is disabled".into(),
            ));
        }
        self.inner
            .rpc
            .call_raw_after_genesis_check(
                expected,
                "sendTransaction",
                // Preflight must observe the same bank used to fetch the
                // transaction's recent blockhash. Otherwise a valid, newly
                // staged transaction can fail as "Blockhash not found".
                &json!([
                    tx_b64,
                    {
                        "encoding": "base64",
                        "preflightCommitment": "processed"
                    }
                ]),
                || Ok(()),
            )
            .await
            .and_then(|value| {
                serde_json::from_value(value)
                    .map_err(|error| SolanaRpcError::Decode(format!("sendTransaction: {error}")))
            })
    }

    /// Submit the one explicitly authorized mainnet-beta canary transaction.
    ///
    /// This entry point does not exist in a production build. It revalidates
    /// the active artifact-bound authorization, proves the genesis of every
    /// configured endpoint, durably spends the authorization, and only then
    /// makes one non-retrying `sendTransaction` attempt.
    #[cfg(feature = "mainnet-canary")]
    pub async fn send_mainnet_canary_transaction(
        &self,
        tx_b64: &str,
        loaded: &bloom_proto::canary::LoadedAuthorization,
        spend_note: &str,
    ) -> Result<String, SolanaRpcError> {
        if !self.inner.allow_broadcast {
            return Err(SolanaRpcError::Invalid(format!(
                "broadcast is disabled for chain '{}'",
                self.chain_name()
            )));
        }
        let expected = self
            .inner
            .expected_genesis_base58
            .as_deref()
            .ok_or_else(|| {
                SolanaRpcError::Invalid(format!(
                    "chain '{}' cannot broadcast without an expected genesis hash",
                    self.chain_name()
                ))
            })?;
        if expected != crate::MAINNET_BETA_GENESIS_HASH {
            return Err(SolanaRpcError::Invalid(
                "mainnet canary send requires the pinned mainnet-beta genesis".into(),
            ));
        }
        self.inner
            .rpc
            .call_raw_after_genesis_check(
                expected,
                "sendTransaction",
                &json!([
                    tx_b64,
                    {
                        "encoding": "base64",
                        "preflightCommitment": "processed"
                    }
                ]),
                || {
                    // Re-read after the live endpoint checks, immediately
                    // before the sole network write. An authorization that
                    // expired or changed while those checks ran is dead.
                    let active =
                        bloom_proto::canary::authorization_for(self.chain_name(), now_ms())
                            .ok_or_else(|| {
                                SolanaRpcError::Invalid(
                                    "mainnet canary authorization is not active".into(),
                                )
                            })?;
                    if active.path != loaded.path || active.authorization != loaded.authorization {
                        return Err(SolanaRpcError::Invalid(
                            "mainnet canary authorization changed after transfer validation".into(),
                        ));
                    }
                    loaded
                        .claim_single_use(spend_note)
                        .map_err(|error| SolanaRpcError::Invalid(error.to_string()))?;
                    tracing::warn!(
                        chain = %self.chain_name(),
                        "solana.mainnet_canary_single_use_claimed"
                    );
                    Ok(())
                },
            )
            .await
            .and_then(|value| {
                serde_json::from_value(value)
                    .map_err(|error| SolanaRpcError::Decode(format!("sendTransaction: {error}")))
            })
    }

    /// Request a faucet airdrop to a base58 account (local/devnet only). The
    /// returned value is the airdrop transaction signature.
    pub async fn request_airdrop(
        &self,
        account: &str,
        lamports: u64,
    ) -> Result<String, SolanaRpcError> {
        self.inner
            .rpc
            .call("requestAirdrop", &json!([account, lamports]))
            .await
    }

    /// Confirmation status for a list of transaction signatures. The outer
    /// `Option` mirrors the node's `null` entries (signature not seen).
    pub async fn get_signature_statuses(
        &self,
        signatures: &[String],
    ) -> Result<Vec<Option<SignatureStatus>>, SolanaRpcError> {
        let result: Value = self
            .inner
            .rpc
            // Ask the node for terminal status directly. Reconciliation
            // writes durable receipts only from finalized observations.
            .call(
                "getSignatureStatuses",
                &json!([
                    signatures,
                    {
                        "commitment": "finalized",
                        "searchTransactionHistory": true
                    }
                ]),
            )
            .await?;
        let values = result
            .get("value")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        values
            .into_iter()
            .map(|v| {
                if v.is_null() {
                    Ok(None)
                } else {
                    serde_json::from_value::<SignatureStatus>(v)
                        .map(Some)
                        .map_err(|e| SolanaRpcError::Decode(format!("getSignatureStatuses: {e}")))
                }
            })
            .collect()
    }

    /// Ask every configured endpoint, independently, for one signature's
    /// finalized status. Each probe is a single direct request — no retry,
    /// no failover — so the returned quorum is honest per-endpoint evidence.
    ///
    /// Reconciliation uses this before turning a `null` from the ordinary
    /// failover path into a terminal "never landed": one lagging or
    /// non-archival endpoint must not be able to outweigh an endpoint that
    /// actually observed the signature.
    pub async fn probe_signature_status_all_endpoints(
        &self,
        signature: &str,
    ) -> Vec<SignatureStatusProbe> {
        self.inner
            .rpc
            .probe_all_endpoints(
                "getSignatureStatuses",
                &json!([
                    [signature],
                    {
                        "commitment": "finalized",
                        "searchTransactionHistory": true
                    }
                ]),
            )
            .await
            .into_iter()
            .map(|probe| SignatureStatusProbe {
                endpoint_label: probe.endpoint_label,
                status: probe.outcome.and_then(|result| {
                    let entry = result
                        .get("value")
                        .and_then(|v| v.as_array())
                        .and_then(|v| v.first().cloned())
                        .ok_or_else(|| {
                            SolanaRpcError::Decode(
                                "getSignatureStatuses: response has no value array".into(),
                            )
                        })?;
                    if entry.is_null() {
                        Ok(None)
                    } else {
                        serde_json::from_value::<SignatureStatus>(entry)
                            .map(Some)
                            .map_err(|e| {
                                SolanaRpcError::Decode(format!("getSignatureStatuses: {e}"))
                            })
                    }
                }),
            })
            .collect()
    }
}

/// One endpoint's independent finalized-status observation for a single
/// signature, from [`SolanaClient::probe_signature_status_all_endpoints`].
pub struct SignatureStatusProbe {
    /// Sanitized endpoint origin; never carries URL credentials.
    pub endpoint_label: String,
    /// `Ok(None)` is that endpoint reporting the signature unseen.
    pub status: Result<Option<SignatureStatus>, SolanaRpcError>,
}

/// Wall-clock milliseconds, for canary expiry checks.
fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(u128::MAX)
}
