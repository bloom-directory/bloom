//! Category: integration
//!
//! Integration tests for the ERC-20 + replace/cancel paths in
//! `bloom_tx::TxEngine`.
//!
//! These tests run by default because WS-4 requires EVM auth-hardening
//! integration coverage:
//!
//! ```text
//! cargo test -p bloom-it --test erc20_e2e
//! ```
//!
//! They spawn a local `anvil` from `$PATH` (or `BLOOM_ANVIL_BIN`).

use std::net::TcpListener;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, B256, U256};
use alloy::sol_types::SolCall;
use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use bloom_auth::AuthStore;
use bloom_auth::grant_store::InMemoryGrantStore;
use bloom_auth_api::{
    ApprovalChallenge, ApprovalVerifier, AssuranceLevel, AuditEvent, AuthApiError, AuthEntryRecord,
    AuthStoreWriter, CanonicalEnvelope, CanonicalIntentHeader, DaemonGrantTerms,
    DefaultAttestationRegistry, EVM_ERC20_TRANSFER_METHOD, EVM_OWNER_SESSION_USE_ACTION_KIND,
    EVM_SEALED_INTENT_SUBJECT_KIND, EVM_SEALED_INTENT_SUBJECT_SCHEMA_V1, EVM_TX_SIGN_INTENT,
    EvmFeePolicy, EvmOwnerSigningSessionCounters, EvmOwnerSigningSessionScope,
    EvmOwnerSigningSessionUse, ExecutorKind, GrantStore, PetalHost, PetalPolicySnapshot,
    ReviewSessionRecord, SealedAction, SealedPetalContext, SealedSignature, SignHashRequest,
    SignedApproval, SigningAttestation, SigningAttestationSchemaRegistry,
    petal_identity::{PETAL_ID_EVM_WALLET, PLACEHOLDER_DIGEST_EVM_WALLET},
};
use bloom_chain::{ChainClient, IERC20};
use bloom_it::mint_evm_test_grant;
use bloom_proto::{AgentAutonomyMode, ChainSpec, Policy, RawIntent, RawIntentBody};
use bloom_tx::Outbox;
use bloom_tx::tx_engine::{TxEngine, TxEngineError};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;

/// Anvil prefunded account #0.
const ANVIL_PK0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL_ADDR0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
/// Anvil prefunded account #1 (recipient).
const ANVIL_ADDR1: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

fn now_ms_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

struct DenyingApprovalVerifier;

#[async_trait::async_trait]
impl ApprovalVerifier for DenyingApprovalVerifier {
    async fn verify_and_consume(
        &self,
        _approval: SignedApproval,
        _now_ms: u64,
    ) -> std::result::Result<(), AuthApiError> {
        Err(AuthApiError::Denied(
            "integration test uses pre-minted grants".into(),
        ))
    }
}

struct UnusedAuthWriter;

#[async_trait::async_trait]
impl AuthStoreWriter for UnusedAuthWriter {
    async fn stage_entry(
        &self,
        _envelope: bloom_auth_api::CanonicalEnvelope,
        _assurance: AssuranceLevel,
        _now_ms: u64,
    ) -> std::result::Result<AuthEntryRecord, AuthApiError> {
        Err(AuthApiError::Store(
            "integration test expected an active grant".into(),
        ))
    }

    async fn issue_challenge(
        &self,
        _surface: &str,
        _action_id: &str,
        _server_nonce: &str,
        _expiry_ms: u64,
        _now_ms: u64,
    ) -> std::result::Result<ApprovalChallenge, AuthApiError> {
        Err(AuthApiError::Store(
            "integration test expected an active grant".into(),
        ))
    }

    async fn issue_review_session(
        &self,
        _review_session_id: &str,
        _surface: &str,
        _action_id: &str,
        _expires_ms: u64,
        _now_ms: u64,
    ) -> std::result::Result<ReviewSessionRecord, AuthApiError> {
        Err(AuthApiError::Store(
            "integration test does not issue review sessions".into(),
        ))
    }
}

struct AnvilPetalHost {
    grant_store: Arc<dyn GrantStore>,
}

#[async_trait::async_trait]
impl PetalHost for AnvilPetalHost {
    async fn seal_context(
        &self,
        petal_id: &str,
    ) -> std::result::Result<SealedPetalContext, AuthApiError> {
        Ok(SealedPetalContext {
            canonical_intent_bytes_hash: "0".repeat(64),
            intent_hash: "integration-intent".into(),
            daemon_terms_digest: DaemonGrantTerms::minimal(AssuranceLevel::Standard)
                .daemon_terms_digest()?,
            petal_policy_digest: "0".repeat(64),
            policy_version: 0,
            petal_id: petal_id.into(),
        })
    }

    async fn sealed_policy_snapshot(
        &self,
        wallet: &str,
        petal_id: &str,
    ) -> std::result::Result<PetalPolicySnapshot, AuthApiError> {
        Ok(PetalPolicySnapshot {
            policy_version: 0,
            wallet: wallet.into(),
            petal_id: petal_id.into(),
            petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET.into(),
            caps: Default::default(),
            hard_rules: Vec::new(),
            step_up_rules: Vec::new(),
            config: Default::default(),
            budget_state: Default::default(),
            session_scope: None,
        })
    }

    async fn sign_hash(
        &self,
        request: SignHashRequest,
        attestation: &SigningAttestation,
        now_ms: u64,
    ) -> std::result::Result<SealedSignature, AuthApiError> {
        DefaultAttestationRegistry::new().validate_attestation(attestation)?;
        let grant = self
            .grant_store
            .get_active(
                &request.wallet,
                &request.action_id,
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                now_ms,
            )
            .await?
            .ok_or_else(|| AuthApiError::Denied("missing integration test grant".into()))?;
        self.grant_store
            .consume_signature(&grant.grant_id, &request.intent, now_ms)
            .await?;
        let hash = request
            .hash_hex
            .parse()
            .map_err(|e| AuthApiError::Denied(format!("hash: {e}")))?;
        let signer: alloy::signers::local::PrivateKeySigner = ANVIL_PK0
            .parse()
            .map_err(|e| AuthApiError::Denied(format!("signer: {e}")))?;
        use alloy::signers::SignerSync;
        let signature = signer
            .sign_hash_sync(&hash)
            .map_err(|e| AuthApiError::Denied(format!("sign hash: {e}")))?;
        Ok(SealedSignature {
            intent_hash: grant.intent_hash,
            signature_b64: base64::engine::general_purpose::STANDARD.encode(signature.as_bytes()),
            signed_at_ms: now_ms,
        })
    }

    async fn audit(&self, _event: AuditEvent) -> std::result::Result<(), AuthApiError> {
        Ok(())
    }
}

struct AnvilGuard {
    child: Option<Child>,
    port: u16,
}

impl AnvilGuard {
    fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for AnvilGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.start_kill();
        }
    }
}

fn pick_free_port() -> Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

fn anvil_bin() -> String {
    std::env::var("BLOOM_ANVIL_BIN").unwrap_or_else(|_| "anvil".to_string())
}

fn forge_bin() -> String {
    std::env::var("BLOOM_FORGE_BIN").unwrap_or_else(|_| "forge".to_string())
}

async fn spawn_anvil(no_mining: bool) -> Result<AnvilGuard> {
    let port = pick_free_port()?;
    let mut cmd = Command::new(anvil_bin());
    cmd.arg("--port")
        .arg(port.to_string())
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--chain-id")
        .arg("31337");
    if no_mining {
        // Hold txs in the mempool so we can submit a replacement.
        cmd.arg("--no-mining");
    }
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().context("spawn anvil")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("anvil stdout missing"))?;
    let mut reader = BufReader::new(stdout).lines();
    let wait = async {
        loop {
            match reader.next_line().await? {
                Some(line) => {
                    if line.contains("Listening on") {
                        return Ok::<(), anyhow::Error>(());
                    }
                }
                None => return Err(anyhow!("anvil exited before becoming ready")),
            }
        }
    };
    timeout(Duration::from_secs(15), wait)
        .await
        .map_err(|_| anyhow!("timed out waiting for anvil to start"))??;
    Ok(AnvilGuard {
        child: Some(child),
        port,
    })
}

fn anvil_chain_spec(rpc_url: &str) -> ChainSpec {
    let mut spec = ChainSpec::anvil_default();
    spec.rpc_urls = vec![rpc_url.to_string()];
    spec.allow_broadcast = true;
    spec
}

async fn deploy_mock_erc20(rpc_url: &str, owner: &str, supply: &str) -> Result<Address> {
    let tmp = tempfile::tempdir()?;
    let src = tmp.path().join("MockERC20.sol");
    std::fs::write(
        &src,
        r#"
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract MockERC20 {
    string public name = "Mock USDC";
    string public symbol = "mUSDC";
    uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;

    constructor(address owner, uint256 supply) {
        balanceOf[owner] = supply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
"#,
    )?;
    let output = Command::new(forge_bin())
        .arg("create")
        .arg("--json")
        .arg("--broadcast")
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("--private-key")
        .arg(ANVIL_PK0)
        .arg(format!("{}:MockERC20", src.display()))
        .arg("--constructor-args")
        .arg(owner)
        .arg(supply)
        .kill_on_drop(true)
        .output()
        .await
        .context("forge create MockERC20")?;
    if !output.status.success() {
        return Err(anyhow!(
            "forge create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let deployed = value
        .get("deployedTo")
        .and_then(|v| v.as_str())
        .or_else(|| value.get("deployed_to").and_then(|v| v.as_str()))
        .or_else(|| value.get("contractAddress").and_then(|v| v.as_str()))
        .ok_or_else(|| {
            anyhow!(
                "forge create JSON missing deployed address: stdout={}, stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })?;
    deployed
        .parse()
        .map_err(|e| anyhow!("parse deployed token address: {e}"))
}

fn erc20_transfer_calldata(recipient: Address, amount: u128) -> String {
    let call = IERC20::transferCall {
        to: recipient,
        amount: U256::from(amount),
    };
    format!("0x{}", hex::encode(call.abi_encode()))
}

async fn mint_owner_session_test_grant(
    grant_store: &dyn GrantStore,
    wallet: &str,
    session_id: &str,
    chain_id: u64,
    account: &str,
    max_signatures: u32,
    now_ms: u64,
) -> Result<()> {
    let expires_ms = now_ms.saturating_add(120_000);
    let header = CanonicalIntentHeader {
        schema: bloom_auth_api::CANONICAL_INTENT_HEADER_SCHEMA_V2.into(),
        wallet: wallet.into(),
        surface: "policy-session".into(),
        action_id: session_id.into(),
        petal_id: PETAL_ID_EVM_WALLET.into(),
        petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET.into(),
        petal_version: bloom_auth_api::petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
        executor_kind: ExecutorKind::FirstParty,
        network: format!("eip155:{chain_id}"),
        account: account.into(),
        action_kind: EVM_OWNER_SESSION_USE_ACTION_KIND.into(),
        value_movement: true,
        authority_change: false,
        expires_ms,
    };
    let envelope = CanonicalEnvelope::new(
        header.clone(),
        EVM_SEALED_INTENT_SUBJECT_KIND,
        EVM_SEALED_INTENT_SUBJECT_SCHEMA_V1,
        serde_json::to_vec(&serde_json::json!({
            "schema": "bloom.it.evm_owner_session_test_grant_subject.v1",
            "wallet": wallet,
            "session_id": session_id,
            "chain_id": chain_id,
            "account": account,
        }))?,
    );
    let mut terms = DaemonGrantTerms::minimal(AssuranceLevel::Hardened);
    terms.allowed_sign_intents = vec![EVM_TX_SIGN_INTENT.into()];
    terms.max_signatures = max_signatures;
    let action = SealedAction::new(
        envelope,
        format!("integration owner-session grant {session_id}"),
        Vec::new(),
        terms,
        PetalPolicySnapshot::minimal(&header),
        now_ms,
    )?;
    grant_store.mint(&action, expires_ms, now_ms).await?;
    Ok(())
}

/// Stage an ERC-20 transfer to a hardcoded token symbol that resolves
/// to the canonical mainnet address. On a fresh anvil there is no code
/// at that address, so `decimals()` returns empty and stage fails with
/// a `Token` error — which proves the path is wired end-to-end.
#[tokio::test(flavor = "multi_thread")]
async fn erc20_stage_fails_when_decimals_unreadable() -> Result<()> {
    let anvil = spawn_anvil(false).await?;
    let rpc_url = anvil.rpc_url();
    let chain = ChainClient::new(anvil_chain_spec(&rpc_url)).map_err(|e| anyhow!("chain: {e}"))?;

    let tmp = tempfile::tempdir()?;
    let permit = bloom_proto::HomeWritePermit::acquire(&bloom_proto::HomeDir::at(tmp.path()))?;
    let outbox = Outbox::new(tmp.path().join("outbox")).map_err(|e| anyhow!("outbox: {e}"))?;
    let engine = TxEngine::new(outbox, 60_000, false);

    let from = ANVIL_ADDR0.parse().unwrap();
    let intent = RawIntent {
        body: RawIntentBody::Send {
            to: ANVIL_ADDR1.to_string(),
            value: String::new(),
            token: Some("USDC".into()),
            amount: "100".into(),
            data: None,
        },
        chain: Some("anvil".to_string()),
        gas: Default::default(),
        nonce: None,
        gas_limit_hint: None,
        usd_value_hint: None,
    };

    let res = engine
        .stage(
            &permit,
            "alice",
            from,
            intent,
            &chain,
            &Policy::permissive(),
            None,
        )
        .await;
    let err = match res {
        Ok(_) => return Err(anyhow!("expected staging to fail (no code at USDC addr)")),
        Err(e) => e,
    };
    match err {
        TxEngineError::Token(_) => {}
        other => return Err(anyhow!("expected Token error, got {other:?}")),
    }
    Ok(())
}

/// Stage a native send, broadcast via `confirm`, then call `replace`
/// with a 15% fee bump. Asserts that the replacement carries the same
/// nonce and strictly higher fees.
#[tokio::test(flavor = "multi_thread")]
async fn replace_keeps_nonce_and_bumps_fees() -> Result<()> {
    let anvil = spawn_anvil(true).await?;
    let rpc_url = anvil.rpc_url();
    let chain = ChainClient::new(anvil_chain_spec(&rpc_url)).map_err(|e| anyhow!("chain: {e}"))?;

    let tmp = tempfile::tempdir()?;
    let permit = bloom_proto::HomeWritePermit::acquire(&bloom_proto::HomeDir::at(tmp.path()))?;
    let outbox = Outbox::new(tmp.path().join("outbox")).map_err(|e| anyhow!("outbox: {e}"))?;
    let grant_store: Arc<dyn GrantStore> = Arc::new(InMemoryGrantStore::default());
    let engine = TxEngine::new(outbox, 60_000, false)
        .with_auth_services(
            Arc::new(DenyingApprovalVerifier),
            Arc::new(UnusedAuthWriter),
        )
        .with_host_signing_services(
            grant_store.clone(),
            Arc::new(AnvilPetalHost {
                grant_store: grant_store.clone(),
            }),
        );

    // Use anvil's prefunded account #0 as the signer.
    let signer: alloy::signers::local::PrivateKeySigner = ANVIL_PK0.parse()?;
    let from = signer.address();

    // Keep the staged transaction inside ordinary policy limits. Confirm and
    // replace still require separate pre-minted Sealed Approval grants below.
    let policy = {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        p.limits.max_tx_usd = Some("1000".into());
        p.limits.max_day_usd = Some("10000".into());
        p
    };

    let intent = RawIntent {
        body: RawIntentBody::Send {
            to: ANVIL_ADDR1.to_string(),
            value: "0.01 eth".into(),
            token: None,
            amount: String::new(),
            data: None,
        },
        chain: Some("anvil".to_string()),
        gas: Default::default(),
        nonce: None,
        gas_limit_hint: None,
        usd_value_hint: Some("1".into()),
    };

    let staged = engine
        .stage(&permit, "alice", from, intent, &chain, &policy, None)
        .await
        .map_err(|e| anyhow!("stage: {e}"))?;
    let original_nonce = staged.nonce;
    let original_max_fee: u128 = staged
        .max_fee_per_gas
        .as_deref()
        .ok_or_else(|| anyhow!("missing max_fee_per_gas"))?
        .parse()?;

    mint_evm_test_grant(
        grant_store.as_ref(),
        "alice",
        &format!("{}:{}", staged.chain_id, staged.id),
        "confirm",
        staged.chain_id,
        ANVIL_ADDR0,
        now_ms_u64(),
    )
    .await
    .map_err(|e| anyhow!("mint confirm grant: {e}"))?;
    let confirmed = engine
        .confirm(&permit, "alice", "anvil", &staged.id, &chain, &policy, "y")
        .await
        .map_err(|e| anyhow!("confirm: {e}"))?;
    assert!(confirmed.tx_hash.is_some(), "confirm produced no tx hash");

    // Replace with +15% fees.
    mint_evm_test_grant(
        grant_store.as_ref(),
        "alice",
        &format!("{}:{}:replace", staged.chain_id, staged.id),
        "replace",
        staged.chain_id,
        ANVIL_ADDR0,
        now_ms_u64(),
    )
    .await
    .map_err(|e| anyhow!("mint replace grant: {e}"))?;
    let replaced = engine
        .replace(&permit, "alice", "anvil", &staged.id, &chain, 15, &policy)
        .await
        .map_err(|e| anyhow!("replace: {e}"))?;
    assert_eq!(replaced.nonce, original_nonce, "nonce must match");
    let new_max_fee: u128 = replaced
        .max_fee_per_gas
        .as_deref()
        .ok_or_else(|| anyhow!("missing replacement max_fee_per_gas"))?
        .parse()?;
    assert!(
        new_max_fee > original_max_fee,
        "fee not bumped: {} -> {}",
        original_max_fee,
        new_max_fee
    );
    assert!(
        replaced.tx_hash.is_some(),
        "replacement broadcast produced no tx hash"
    );

    drop(anvil);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn owner_session_executes_erc20_until_daily_cap_then_denies() -> Result<()> {
    let anvil = spawn_anvil(false).await?;
    let rpc_url = anvil.rpc_url();
    let chain = ChainClient::new(anvil_chain_spec(&rpc_url)).map_err(|e| anyhow!("chain: {e}"))?;
    let token = deploy_mock_erc20(&rpc_url, ANVIL_ADDR0, "1000000000").await?;
    let owner: Address = ANVIL_ADDR0.parse()?;
    let recipient: Address = ANVIL_ADDR1.parse()?;

    let grant_store: Arc<dyn GrantStore> = Arc::new(InMemoryGrantStore::default());
    let engine = TxEngine::new(
        Outbox::new(tempfile::tempdir()?.path().join("outbox"))?,
        60_000,
        false,
    )
    .with_host_signing_services(
        grant_store.clone(),
        Arc::new(AnvilPetalHost {
            grant_store: grant_store.clone(),
        }),
    );

    let now = now_ms_u64();
    let session_id = "evm-owner-session-it-1";
    let scope = EvmOwnerSigningSessionScope {
        wallet: "alice".into(),
        chain_id: 31337,
        token_contract: bloom_proto::checksum_address(&token),
        recipient: bloom_proto::checksum_address(&recipient),
        method: EVM_ERC20_TRANSFER_METHOD.into(),
        daily_cap_base_units: "100000000".into(),
        ttl_ms: 120_000,
        fee_policy: EvmFeePolicy {
            max_fee_per_gas_wei: Some("2000000000".into()),
            max_priority_fee_per_gas_wei: Some("1000000".into()),
            max_total_fee_wei: Some("200000000000000".into()),
        },
        max_signature_count: 5,
        autonomy_classification: "bounded_owner_signing".into(),
        policy_snapshot_digest: "it-policy".into(),
        petal_id: PETAL_ID_EVM_WALLET.into(),
        petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET.into(),
        petal_version: bloom_auth_api::petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
        reason: "integration bounded USDC payments".into(),
        native_transfers_allowed: false,
    };
    let counters = EvmOwnerSigningSessionCounters {
        daily_window_start_ms: now,
        spent_base_units: "0".into(),
        reserved_base_units: "0".into(),
        signature_count: 0,
        pending_reservations: Default::default(),
    };
    let mut auth_store = AuthStore::open(tempfile::tempdir()?.path().join("auth.sqlite"))?;
    auth_store.create_standing_session(
        session_id,
        "alice",
        PETAL_ID_EVM_WALLET,
        bloom_auth_api::EVM_OWNER_SIGNING_SESSION_KIND,
        &serde_json::to_string(&scope)?,
        &serde_json::to_string(&counters)?,
        0,
        PLACEHOLDER_DIGEST_EVM_WALLET,
        now,
        now + 120_000,
        now,
    )?;
    mint_owner_session_test_grant(
        grant_store.as_ref(),
        "alice",
        session_id,
        31337,
        ANVIL_ADDR0,
        5,
        now,
    )
    .await?;

    for (idx, amount) in [40_000_000u128, 60_000_000u128].into_iter().enumerate() {
        let request = EvmOwnerSigningSessionUse {
            wallet: "alice".into(),
            chain_id: 31337,
            chain: Some("anvil".into()),
            token_contract: bloom_proto::checksum_address(&token),
            recipient: bloom_proto::checksum_address(&recipient),
            method: EVM_ERC20_TRANSFER_METHOD.into(),
            calldata_hex: erc20_transfer_calldata(recipient, amount),
            amount_base_units: amount.to_string(),
            value_wei: "0".into(),
            nonce: None,
            gas_limit: Some(100_000),
            max_fee_per_gas_wei: Some("2000000000".into()),
            max_priority_fee_per_gas_wei: Some("1000000".into()),
            max_total_fee_wei: Some("200000000000000".into()),
        };
        let reservation_id = format!("res-{idx}");
        let reserved = auth_store.reserve_evm_owner_session_use(
            session_id,
            &reservation_id,
            &request,
            true,
            now + idx as u64 + 1,
        )?;
        let execution = engine
            .execute_evm_owner_session_use(
                "alice",
                session_id,
                &reservation_id,
                &request,
                &reserved,
                "anvil",
                &chain,
                owner,
                &Policy::permissive(),
            )
            .await?;
        assert_ne!(execution.tx_hash, B256::ZERO);
        auth_store.commit_evm_owner_session_use(
            session_id,
            &reservation_id,
            now + idx as u64 + 2,
        )?;
    }

    let balance = chain
        .erc20_balance(token, recipient)
        .await?
        .ok_or_else(|| anyhow!("recipient token balance missing"))?;
    assert_eq!(balance, U256::from(100_000_000u128));
    let session = auth_store
        .standing_session(session_id)?
        .ok_or_else(|| anyhow!("missing owner session"))?;
    assert_eq!(session.counters["spent_base_units"], "100000000");
    assert_eq!(session.counters["signature_count"], 2);

    let over_cap = EvmOwnerSigningSessionUse {
        wallet: "alice".into(),
        chain_id: 31337,
        chain: Some("anvil".into()),
        token_contract: bloom_proto::checksum_address(&token),
        recipient: bloom_proto::checksum_address(&recipient),
        method: EVM_ERC20_TRANSFER_METHOD.into(),
        calldata_hex: erc20_transfer_calldata(recipient, 1),
        amount_base_units: "1".into(),
        value_wei: "0".into(),
        nonce: None,
        gas_limit: Some(100_000),
        max_fee_per_gas_wei: Some("2000000000".into()),
        max_priority_fee_per_gas_wei: Some("1000000".into()),
        max_total_fee_wei: Some("200000000000000".into()),
    };
    let err = auth_store
        .reserve_evm_owner_session_use(session_id, "res-over-cap", &over_cap, true, now + 10)
        .unwrap_err();
    assert!(
        err.to_string().contains("session_budget_exhausted"),
        "{err}"
    );

    drop(anvil);
    Ok(())
}
