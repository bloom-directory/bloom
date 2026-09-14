//! Full CLI HTTP -> Machine IPC -> transaction engine -> mock Broker -> Anvil.
//! Run explicitly after `cargo build -p bloom`. No wallet keys reach build tools.
use anyhow::{Context, Result, ensure};
use bloom_daemon::{
    Daemon,
    ipc::{
        IpcServer, MachineCommand, MachineCommandFuture, MachineCommandOutput,
        MachineCommandService, MachineError, MachineErrorKind,
    },
};
use bloom_it::{FUNDER_PRIV_KEY, exact_signing_broker, exact_signing_catalog, spawn_anvil};
use bloom_proto::{ChainSpec, Config, HomeDir, HomeWritePermit};
use serde_json::{Value, json};
use std::{path::Path, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

struct Commands(Daemon);
impl MachineCommandService for Commands {
    fn execute(&self, c: MachineCommand) -> MachineCommandFuture<'_> {
        Box::pin(async move {
            match c {
                MachineCommand::DeploymentRpc {
                    wallet,
                    chain,
                    method,
                    params,
                } => Ok(MachineCommandOutput {
                    stdout: self
                        .0
                        .deployment_rpc(&wallet, &chain, &method, params)
                        .await
                        .to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                }),
                _ => Err(MachineError::new(
                    MachineErrorKind::InvalidParams,
                    "INVALID_ARGUMENT",
                    "unsupported test command",
                )),
            }
        })
    }
}
fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Explicit allowlist: the user's checkout and credential-bearing files are never copied.
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &to.join(name.as_ref()))?;
        } else if entry.file_type()?.is_file() && name.ends_with(".sol") {
            std::fs::copy(entry.path(), to.join(name.as_ref()))?;
        }
    }
    Ok(())
}
async fn rpc(url: &str, method: &str, params: Value) -> Result<Value> {
    Ok(reqwest::Client::new()
        .post(url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await?
        .json()
        .await?)
}
async fn run_tool(mut cmd: Command) -> Result<String> {
    let output =
        tokio::time::timeout(Duration::from_secs(240), cmd.kill_on_drop(true).output()).await??;
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(output.status.success(), "tool failed: {text}");
    Ok(text)
}
fn clean_tool(name: &str, dir: &Path) -> Command {
    let mut c = Command::new(name);
    c.current_dir(dir)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("RAYON_NUM_THREADS", "2");
    c
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a built bloom binary, Forge/Anvil, and npm; runs external compatibility projects"]
async fn deployment_tools_and_recovery() -> Result<()> {
    let mut anvil = spawn_anvil().await?;
    let dir = tempfile::tempdir()?;
    let mut config = Config::local_default();
    let mut spec = ChainSpec::anvil_default();
    spec.rpc_urls = vec![anvil.rpc_url()];
    spec.allow_broadcast = true;
    config.chains.insert("anvil".into(), spec);
    config.save(&dir.path().join("config.toml"))?;
    let home = HomeDir::at(dir.path());
    let permit = Arc::new(HomeWritePermit::acquire(&home)?);
    let (broker, fixture) = exact_signing_broker(FUNDER_PRIV_KEY)?;
    fixture.allow_test_deployments();
    let daemon = Daemon::from_home_with_permit_and_broker(
        home,
        permit,
        broker,
        exact_signing_catalog(&["transaction.confirm"]),
    )?;
    let socket = dir.path().join("run/bloom.sock");
    let server = IpcServer::new(daemon.vfs.clone(), "deployment-test", vec!["anvil".into()])
        .with_machine_commands(Arc::new(Commands(daemon.clone())));
    let stopped = server.clone();
    let served = socket.clone();
    let ipc = tokio::spawn(async move { server.serve(&served).await });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let binary = std::env::var_os("BLOOM_TEST_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| root.join("target/debug/bloom"));
    let mut child = Command::new(&binary)
        .args([
            "--connect",
            &format!("unix:{}", socket.display()),
            "deploy",
            "--wallet",
            "alice",
            "--chain",
            "anvil",
            "rpc",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::from(std::fs::File::create(
            dir.path().join("bridge.log"),
        )?))
        .kill_on_drop(true)
        .spawn()?;
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let line = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
        .await??
        .context("bridge exited without URL")?;
    let info: Value = serde_json::from_str(&line)?;
    let url = info["rpc_url"].as_str().context("missing RPC URL")?;
    let sender = info["from"].as_str().unwrap();
    ensure!(rpc(url, "eth_accounts", json!([])).await?["result"] == json!([sender]));
    for method in [
        "eth_sign",
        "eth_signTransaction",
        "eth_sendRawTransaction",
        "personal_unlockAccount",
        "anvil_setCode",
    ] {
        ensure!(rpc(url, method, json!([])).await?["error"]["code"] == -32601);
    }
    let http = reqwest::Client::new();
    let origin = http
        .post(url)
        .header("origin", "https://evil.invalid")
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"eth_accounts"}))
        .send()
        .await?;
    ensure!(origin.status() == 403);
    let host = http
        .post(url)
        .header("host", "evil.invalid")
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"eth_accounts"}))
        .send()
        .await?;
    ensure!(host.status() == 403);
    let mut unauthorized = url::Url::parse(url)?;
    unauthorized.set_path("/wrong");
    ensure!(
        http.post(unauthorized.as_str())
            .json(&json!({}))
            .send()
            .await?
            .status()
            == 404
    );

    // Test-only owner: first prove staging cannot sign; then activate exact fixture
    // approvals and explicitly continue each staged action just as an agent would.
    let initial = json!({"from":sender,"nonce":"0x0","data":"0x60006000f3","gas":"0x186a0"});
    let dropped_url = url.to_owned();
    let dropped_request = initial.clone();
    let dropped = tokio::spawn(async move {
        rpc(
            &dropped_url,
            "eth_sendTransaction",
            json!([dropped_request]),
        )
        .await
    });
    for _ in 0..100 {
        let rows = daemon
            .deployment_rpc("alice", "anvil", "bloom_deploymentList", json!([]))
            .await;
        if rows["result"].as_array().is_some_and(|a| !a.is_empty()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    dropped.abort(); // Lose the HTTP response while owner approval is pending.
    let staged = daemon
        .deployment_rpc(
            "alice",
            "anvil",
            "eth_sendTransaction",
            json!([initial.clone()]),
        )
        .await;
    let id = staged["result"]["id"].as_str().context("stage failed")?;
    let pending = daemon
        .deployment_rpc("alice", "anvil", "bloom_deploymentContinue", json!([id]))
        .await;
    ensure!(
        pending["result"]["status"] == "approval_required",
        "{pending}"
    );
    ensure!(pending["result"]["transaction"]["tx_hash"].is_null());
    let retry = daemon
        .deployment_rpc(
            "alice",
            "anvil",
            "eth_sendTransaction",
            json!([initial.clone()]),
        )
        .await;
    ensure!(retry["result"]["id"] == id);
    fixture.activate();
    let mut sent = daemon
        .deployment_rpc("alice", "anvil", "bloom_deploymentContinue", json!([id]))
        .await;
    // Broadcast acceptance can precede automining; wait for the receipt without
    // issuing another execution request or assuming synchronous block production.
    for _ in 0..100 {
        if sent["result"]["status"] == "mined" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        sent = daemon
            .deployment_rpc("alice", "anvil", "bloom_deploymentStatus", json!([id]))
            .await;
    }
    ensure!(sent["result"]["status"] == "mined", "{sent}");
    let sent_retry = daemon
        .deployment_rpc(
            "alice",
            "anvil",
            "eth_sendTransaction",
            json!([initial.clone()]),
        )
        .await;
    ensure!(sent_retry["result"]["id"] == id);
    let before = rpc(url, "eth_getTransactionCount", json!([sender, "latest"])).await?;
    let observed = daemon
        .deployment_rpc("alice", "anvil", "bloom_deploymentStatus", json!([id]))
        .await;
    ensure!(
        observed["result"]["transaction"]["tx_hash"] == sent["result"]["transaction"]["tx_hash"]
    );
    ensure!(rpc(url, "eth_getTransactionCount", json!([sender, "latest"])).await? == before);
    // Recreate the transaction engine from persisted files: no request map or
    // previous engine memory is used to recognize the completed submission.
    let recovered = bloom_tx::TxEngine::new(
        bloom_tx::Outbox::new(daemon.tx_engine.outbox.root())?,
        60000,
    );
    let chain = daemon.chains.get("anvil").unwrap();
    let request =
        bloom_tx::deployment::DeploymentTransaction::parse(&initial, sender.parse()?, 31337, false)
            .map_err(anyhow::Error::msg)?;
    let restored = recovered
        .stage_deployment(
            daemon.home_write_permit.as_deref().unwrap(),
            "alice",
            &request,
            &chain,
            &bloom_proto::Policy::default(),
        )
        .await?;
    ensure!(restored.tx_hash.as_deref() == sent["result"]["transaction"]["tx_hash"].as_str());

    // Hold a legacy transaction in the mempool and verify automatic staging
    // uses pending nonce semantics even after the transaction leaves pending/.
    rpc(&anvil.rpc_url(), "evm_setAutomine", json!([false])).await?;
    let queued = daemon.deployment_rpc("alice","anvil","eth_sendTransaction",json!([{"from":sender,"to":"0x0000000000000000000000000000000000000000","nonce":"0x1","gas":"0x5208","gasPrice":"0x77359400"}])).await;
    let queued_id = queued["result"]["id"].as_str().context("queue stage")?;
    daemon
        .deployment_rpc(
            "alice",
            "anvil",
            "bloom_deploymentContinue",
            json!([queued_id]),
        )
        .await;
    let queued_sent = daemon
        .deployment_rpc(
            "alice",
            "anvil",
            "bloom_deploymentContinue",
            json!([queued_id]),
        )
        .await;
    ensure!(
        queued_sent["result"]["status"] == "broadcast",
        "{queued_sent}"
    );
    let auto = daemon
        .tx_engine
        .stage(
            daemon.home_write_permit.as_deref().unwrap(),
            "alice",
            sender.parse()?,
            bloom_tx::intent_parser::parse(
                r#"{"kind":"send","to":"0x0000000000000000000000000000000000000000","value":"0"}"#,
            )?,
            &chain,
            &bloom_proto::Policy::default(),
            None,
        )
        .await?;
    ensure!(auto.nonce == 2, "auto nonce reused an unmined transaction");
    let unsigned = daemon.tx_engine.outbox.read("alice", "anvil", &auto.id)?;
    daemon
        .tx_engine
        .outbox
        .transition(&unsigned, bloom_tx::OutboxState::Failed)?;
    rpc(&anvil.rpc_url(), "evm_setAutomine", json!([true])).await?;
    rpc(&anvil.rpc_url(), "evm_mine", json!([])).await?;
    let drive = daemon.clone();
    let driver = tokio::spawn(async move {
        loop {
            if let Ok(ids) =
                drive
                    .tx_engine
                    .outbox
                    .list("alice", "anvil", bloom_tx::OutboxState::Pending)
            {
                for id in ids {
                    if id.starts_with("deploy-") {
                        let _ = drive
                            .deployment_rpc(
                                "alice",
                                "anvil",
                                "bloom_deploymentContinue",
                                json!([id]),
                            )
                            .await;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    let project = dir.path().join("foundry");
    std::fs::create_dir_all(&project)?;
    for folder in ["contracts", "script"] {
        copy_tree(
            &root.join("examples/evm-deploy").join(folder),
            &project.join(folder),
        )?;
    }
    std::fs::copy(
        root.join("examples/evm-deploy/foundry.toml"),
        project.join("foundry.toml"),
    )?;
    let mut forge = clean_tool("forge", &project);
    forge.args([
        "script",
        "script/Deploy.s.sol:Deploy",
        "--rpc-url",
        url,
        "--sender",
        sender,
        "--unlocked",
        "--broadcast",
        "--slow",
    ]);
    let output = run_tool(forge).await?;
    eprintln!("Foundry: {output}");
    let mut resume = clean_tool("forge", &project);
    resume.args([
        "script",
        "script/Deploy.s.sol:Deploy",
        "--rpc-url",
        url,
        "--sender",
        sender,
        "--unlocked",
        "--broadcast",
        "--resume",
        "--slow",
    ]);
    let nonce_before = rpc(url, "eth_getTransactionCount", json!([sender, "latest"])).await?;
    run_tool(resume).await?;
    ensure!(
        rpc(url, "eth_getTransactionCount", json!([sender, "latest"])).await? == nonce_before,
        "Foundry resume sent a duplicate"
    );

    if let Some(external) = std::env::var_os("BLOOM_TEST_FOUNDRY_PROJECT") {
        let external = Path::new(&external);
        let copied = dir.path().join("external");
        for folder in ["src", "script", "lib/forge-std/src"] {
            copy_tree(&external.join(folder), &copied.join(folder))?;
        }
        std::fs::copy(external.join("foundry.toml"), copied.join("foundry.toml"))?;
        for pass in 0..2 {
            let before = rpc(url, "eth_getTransactionCount", json!([sender, "latest"])).await?;
            let mut forge = clean_tool("forge", &copied);
            forge.args([
                "script",
                "script/Deploy.s.sol:Deploy",
                "--rpc-url",
                url,
                "--sender",
                sender,
                "--unlocked",
                "--broadcast",
                "--slow",
            ]);
            let output = run_tool(forge).await?;
            eprintln!("External project pass {pass}: {output}");
            if pass == 1 {
                ensure!(
                    rpc(url, "eth_getTransactionCount", json!([sender, "latest"])).await? == before,
                    "external project's idempotent rerun sent another transaction"
                );
            }
        }
    }
    let hardhat = dir.path().join("hardhat");
    std::fs::create_dir_all(&hardhat)?;
    copy_tree(
        &root.join("examples/evm-deploy/contracts"),
        &hardhat.join("contracts"),
    )?;
    for file in [
        "package.json",
        "package-lock.json",
        "hardhat.config.ts",
        "scripts/deploy.ts",
        "ignition/modules/Deployment.ts",
    ] {
        let target = hardhat.join(file);
        std::fs::create_dir_all(target.parent().unwrap())?;
        std::fs::copy(root.join("examples/evm-deploy").join(file), target)?;
    }
    std::fs::write(hardhat.join("rpc.json"), info.to_string())?;
    let mut npm = clean_tool("npm", &hardhat);
    npm.args([
        "--userconfig",
        "/dev/null",
        "ci",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
    ]);
    run_tool(npm).await?;
    let mut script = clean_tool("node", &hardhat);
    script.args([
        "node_modules/hardhat/dist/src/cli.js",
        "run",
        "scripts/deploy.ts",
        "--network",
        "bloom",
    ]);
    eprintln!("Hardhat script: {}", run_tool(script).await?);
    let mut ignition = clean_tool("node", &hardhat);
    ignition.args([
        "node_modules/hardhat/dist/src/cli.js",
        "ignition",
        "deploy",
        "ignition/modules/Deployment.ts",
        "--network",
        "bloom",
    ]);
    eprintln!("Hardhat Ignition: {}", run_tool(ignition).await?);
    let nonce_before = rpc(url, "eth_getTransactionCount", json!([sender, "latest"])).await?;
    let mut ignition = clean_tool("node", &hardhat);
    ignition.args([
        "node_modules/hardhat/dist/src/cli.js",
        "ignition",
        "deploy",
        "ignition/modules/Deployment.ts",
        "--network",
        "bloom",
    ]);
    run_tool(ignition).await?;
    ensure!(
        rpc(url, "eth_getTransactionCount", json!([sender, "latest"])).await? == nonce_before,
        "Ignition reconciliation sent a duplicate"
    );
    driver.abort();
    if let Some(mut node) = anvil.take_child() {
        node.kill().await?;
    }
    let offline = daemon
        .deployment_rpc("alice", "anvil", "bloom_deploymentStatus", json!([id]))
        .await;
    ensure!(
        offline["result"]["status"] == "mined",
        "persisted receipt unavailable offline: {offline}"
    );
    ensure!(offline["result"]["receipt"]["contract_address"].is_string());
    child.kill().await?;
    stopped.trigger_shutdown();
    ipc.await??;
    Ok(())
}
