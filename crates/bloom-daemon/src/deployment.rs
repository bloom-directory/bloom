//! Wallet-scoped deployment RPC operations owned by Machine. The CLI listener
//! cannot access Broker directly and cannot request arbitrary signing methods.
use crate::Daemon;
use alloy::{primitives::Address, providers::Provider};
use bloom_tx::{OutboxState, TxEngineError, deployment::DeploymentTransaction};
use serde_json::{Value, json};

impl Daemon {
    pub async fn deployment_rpc(
        &self,
        wallet: &str,
        chain_name: &str,
        method: &str,
        params: Value,
    ) -> Value {
        match self
            .deployment_call(wallet, chain_name, method, params)
            .await
        {
            Ok(value) => json!({"result":value}),
            Err((code, message)) => json!({"error":{"code":code,"message":message}}),
        }
    }

    async fn deployment_call(
        &self,
        wallet: &str,
        chain_name: &str,
        method: &str,
        params: Value,
    ) -> Result<Value, (i64, String)> {
        let invalid = |s: &str| (-32602, s.to_owned());
        if [wallet, chain_name].iter().any(|s| {
            s.is_empty()
                || s.len() > 64
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        }) {
            return Err(invalid("invalid wallet or chain name"));
        }
        let chain = self
            .chains
            .get(chain_name)
            .ok_or_else(|| invalid("unknown chain"))?;
        let inspection = matches!(method, "bloom_deploymentStatus" | "bloom_deploymentList");
        if !inspection
            && chain
                .chain_id()
                .await
                .map_err(|_| invalid("chain ID lookup failed"))?
                != chain.spec().chain_id
        {
            return Err(invalid(
                "upstream chain ID does not match the Bloom chain profile",
            ));
        }
        let backend = |_| {
            (
                -32000,
                "Bloom backend unavailable; inspect the selected wallet and chain".to_owned(),
            )
        };
        let wallet_id =
            bloom_broker_api::Token::new(wallet).map_err(|_| invalid("invalid wallet"))?;
        let projection = if inspection {
            None
        } else {
            Some(
                self.wallet_projections
                    .get_wallet(&wallet_id)
                    .await
                    .map_err(backend)?,
            )
        };
        let from: Address = if let Some(projection) = &projection {
            projection
                .primary_address()
                .map_err(backend)?
                .parse()
                .map_err(|_| invalid("wallet has no EVM address"))?
        } else {
            Address::ZERO
        };
        let args = params
            .as_array()
            .ok_or_else(|| invalid("params must be an array"))?;
        match method {
            "eth_accounts" => Ok(json!([from])),
            "eth_chainId" => Ok(json!(format!("0x{:x}", chain.spec().chain_id))),
            "net_version" => Ok(json!(chain.spec().chain_id.to_string())),
            "web3_clientVersion" => Ok(json!("Bloom deployment RPC/1")),
            "bloom_deploymentInfo" => Ok(
                json!({"wallet":wallet,"chain":chain_name,"from":from,"chainId":chain.spec().chain_id}),
            ),
            "eth_sendTransaction" => {
                if args.len() != 1 {
                    return Err(invalid("sendTransaction expects one transaction"));
                }
                let tx = DeploymentTransaction::parse(
                    &args[0],
                    from,
                    chain.spec().chain_id,
                    chain.spec().legacy_tx,
                )
                .map_err(|e| (-32602, e))?;
                let policy = deployment_policy(
                    projection
                        .as_ref()
                        .ok_or_else(|| invalid("wallet projection required"))?,
                    &chain,
                )
                .map_err(|_| invalid("invalid wallet policy"))?;
                let permit = self
                    .home_write_permit
                    .as_deref()
                    .ok_or_else(|| invalid("Machine has no write permit"))?;
                let _guard = self.deployment_lock.lock().await;
                let staged = self
                    .tx_engine
                    .stage_deployment(permit, wallet, &tx, &chain, &policy)
                    .await
                    .map_err(|e| (-32000, e.to_string()))?;
                // Submission only stages. Execution requires an explicit continue
                // operation from the live client after the plan has been exposed.
                Ok(json!({"id":staged.id,"status":"staged"}))
            }
            "bloom_deploymentList" => {
                let mut rows = Vec::new();
                for state in [OutboxState::Pending, OutboxState::Sent, OutboxState::Failed] {
                    for id in self
                        .tx_engine
                        .outbox
                        .list(wallet, chain_name, state)
                        .map_err(|_| invalid("cannot list deployment outbox"))?
                    {
                        if id.starts_with("deploy-") {
                            rows.push(id);
                        }
                    }
                }
                rows.sort();
                Ok(json!(rows))
            }
            "bloom_deploymentStatus" | "bloom_deploymentContinue" => {
                if args.len() != 1 {
                    return Err(invalid("expected one deployment ID"));
                }
                let id = args[0]
                    .as_str()
                    .ok_or_else(|| invalid("expected deployment ID"))?;
                if !id.starts_with("deploy-")
                    || id.len() != 71
                    || !id[7..].bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(invalid("invalid deployment ID"));
                }
                let _guard = self.deployment_lock.lock().await;
                let entry = self
                    .tx_engine
                    .outbox
                    .read(wallet, chain_name, id)
                    .map_err(|_| invalid("deployment not found"))?;
                if entry.staged.chain_id != chain.spec().chain_id {
                    return Err(invalid(
                        "deployment belongs to a different chain ID than the current profile",
                    ));
                }
                let mut approval = Value::Null;
                let mut error = if inspection {
                    std::fs::read(entry.dir.join("deployment-status.json"))
                        .ok()
                        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                        .unwrap_or(Value::Null)
                } else {
                    Value::Null
                };
                if inspection
                    && entry.state == OutboxState::Pending
                    && let Ok(bytes) = std::fs::read(entry.dir.join("ceremony.json"))
                    && let Ok(state) = serde_json::from_slice::<Value>(&bytes)
                    && state["ceremony_url"].is_string()
                {
                    approval = json!({"ceremony_url":state["ceremony_url"],"expires_ms":state["ceremony_expires_at_ms"],"reason":"cached ceremony; continue the same submission to reconcile approval"});
                }
                if method == "bloom_deploymentContinue" && entry.state == OutboxState::Pending {
                    let policy = deployment_policy(
                        projection
                            .as_ref()
                            .ok_or_else(|| invalid("wallet projection required"))?,
                        &chain,
                    )
                    .map_err(|_| invalid("invalid wallet policy"))?;
                    let permit = self
                        .home_write_permit
                        .as_deref()
                        .ok_or_else(|| invalid("Machine has no write permit"))?;
                    match self
                        .tx_engine
                        .confirm(permit, wallet, chain_name, id, &chain, &policy, "y")
                        .await
                    {
                        Ok(_) => {}
                        Err(TxEngineError::ApprovalRequired(a)) => {
                            approval = json!({"ceremony_url":a.ceremony_url,"expires_ms":a.expires_ms,"reason":a.reason})
                        }
                        Err(e) => error = json!(e.to_string()),
                    }
                }
                let entry = self
                    .tx_engine
                    .outbox
                    .read(wallet, chain_name, id)
                    .map_err(|_| invalid("cannot read deployment"))?;
                if !inspection {
                    self.tx_engine
                        .outbox
                        .write_artefact(
                            &entry.dir,
                            "deployment-status.json",
                            &serde_json::to_vec(&error).unwrap(),
                        )
                        .map_err(|_| invalid("cannot persist deployment status"))?;
                }
                let mut receipt = self
                    .tx_engine
                    .outbox
                    .read_receipt(wallet, chain_name, id)
                    .map_err(|_| invalid("cannot read persisted receipt"))?;
                if let Some(hash) = entry.staged.tx_hash.as_deref()
                    && let Ok(Ok(Some(found))) = tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        chain.receipt(
                            hash.parse()
                                .map_err(|_| invalid("invalid persisted hash"))?,
                        ),
                    )
                    .await
                {
                    let success = found.status();
                    let record = bloom_tx::outbox::MinedReceipt {
                        outcome: if success { "success" } else { "reverted" }.into(),
                        tx_hash: hash.into(),
                        block_number: found.block_number,
                        contract_address: found
                            .contract_address
                            .filter(|_| success)
                            .map(|a| format!("{a:#x}")),
                        revert_reason: None,
                    };
                    if self.home_write_permit.is_some() {
                        self.tx_engine
                            .outbox
                            .write_artefact(
                                &entry.dir,
                                "receipt.json",
                                &serde_json::to_vec(&record).unwrap(),
                            )
                            .map_err(|_| invalid("cannot persist mined receipt"))?;
                    }
                    receipt = Some(record);
                }
                let status = if let Some(r) = &receipt {
                    if r.outcome == "success" {
                        "mined"
                    } else {
                        "reverted"
                    }
                } else if entry.staged.tx_hash.is_some() {
                    "broadcast"
                } else if entry.state == OutboxState::Failed {
                    "failed"
                } else if !approval.is_null() {
                    "approval_required"
                } else if !error.is_null() {
                    "blocked"
                } else {
                    "staged"
                };
                let plan = bloom_proto::PlanRender::render(
                    &entry.staged,
                    &chain.spec().native_symbol,
                    chain.spec().native_decimals,
                );
                Ok(
                    json!({"id":id,"status":status,"transaction":entry.staged,"plan":plan,"approval":approval,"error":error,"receipt":receipt}),
                )
            }
            "hardhat_metadata" if chain.spec().chain_id == 31337 && args.is_empty() => {
                // Ignition uses the upstream instance ID to invalidate local
                // deployment journals after node resets. Never invent one or
                // expose arbitrary node configuration fields.
                let metadata: Value = chain
                    .provider()
                    .raw_request("hardhat_metadata".into(), json!([]))
                    .await
                    .map_err(|_| {
                        (
                            -32601,
                            "local node does not support hardhat_metadata".into(),
                        )
                    })?;
                let instance = metadata["instanceId"]
                    .as_str()
                    .ok_or_else(|| invalid("invalid local node instance ID"))?;
                Ok(
                    json!({"instanceId":instance,"chainId":31337,"clientVersion":"Bloom deployment RPC/1"}),
                )
            }
            "eth_blockNumber"
            | "eth_gasPrice"
            | "eth_maxPriorityFeePerGas"
            | "eth_feeHistory"
            | "eth_getBalance"
            | "eth_getCode"
            | "eth_getStorageAt"
            | "eth_getTransactionCount"
            | "eth_getBlockByNumber"
            | "eth_getBlockByHash"
            | "eth_getTransactionByHash"
            | "eth_getTransactionReceipt"
            | "eth_call"
            | "eth_estimateGas"
            | "eth_getLogs" => {
                let provider = chain.provider();
                // RPC engine retains endpoint failover and private upstream credentials.
                provider
                    .raw_request::<_, Value>(method.to_owned().into(), params)
                    .await
                    .map_err(|_| (-32000, "upstream RPC rejected the read request".into()))
            }
            _ => Err((
                -32601,
                "method is not supported by the Bloom deployment endpoint".into(),
            )),
        }
    }
}

fn deployment_policy(
    projection: &bloom_machine_client::WalletProjection,
    chain: &bloom_evm::ChainClient,
) -> Result<bloom_proto::Policy, String> {
    bloom_vfs::advisory_exact_evm_policy(projection, &chain.spec().name, chain.spec().chain_id)
}
