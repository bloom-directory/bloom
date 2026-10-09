//! Installed component acceptance checks. Synthetic note, RPC and outbox data;
//! these exercise account authority/storage, not on-chain settlement or proving.
use async_trait::async_trait;
use bloom_petals::abi::{ChainRequest, ChainResponse};
use bloom_petals::private_store::account_digest;
use bloom_petals::{
    HostError, HostVfsEntry, PetalHost, PetalRouter, PetalRunner, PetalStore, PetalVm,
};
use bloom_vfs::{Handler, Vfs, path::VfsPath};
use parking_lot::Mutex;
use serde_json::json;
use std::sync::Arc;

#[derive(Default)]
struct FixtureHost {
    reads: Mutex<Vec<String>>,
}
#[async_trait]
impl PetalHost for FixtureHost {
    async fn vfs_lookup(&self, _: &str) -> Result<HostVfsEntry, HostError> {
        Err(HostError::NotFound("fixture".into()))
    }
    async fn vfs_list(&self, _: &str) -> Result<Vec<HostVfsEntry>, HostError> {
        Err(HostError::Denied("fixture".into()))
    }
    async fn vfs_write(&self, _: &str, _: &[u8]) -> Result<(), HostError> {
        Err(HostError::Denied("fixture".into()))
    }
    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
        if path == "wallets/fixture/1/account.json" || path == "wallets/fixture/0/account.json" {
            let number = if path.contains("/1/") { 1 } else { 0 };
            return Ok(serde_json::to_vec(&json!({"schema":"bloom.account.v1","wallet":"fixture","number":number,"freshness":"fresh","evm":{"state":"active","public_key_fingerprint":format!("{:064x}",number+1)},"solana":{"state":"missing"}})).unwrap());
        }
        self.reads.lock().push(path.to_string());
        if path == "wallets/fixture/1/address.evm" {
            Ok(format!("0x{}", "22".repeat(20)).into_bytes())
        } else {
            Err(HostError::NotFound(path.into()))
        }
    }
    async fn chain_read(&self, request: ChainRequest) -> Result<ChainResponse, HostError> {
        assert_eq!(request.method, "eth_call");
        Ok(ChainResponse {
            result_json: serde_json::to_string(&format!("0x{}", "00".repeat(32))).unwrap(),
        })
    }
}

fn direct_calldata(processor: u8) -> String {
    let mut data = hex::decode("30c0766d").unwrap();
    let mut words = [[0u8; 32]; 20];
    words[0][30..].copy_from_slice(&(17u16 * 32).to_be_bytes());
    words[17][12..].fill(processor);
    words[18][31] = 64;
    for word in words {
        data.extend(word);
    }
    format!("0x{}", hex::encode(data))
}

#[tokio::test]
async fn installed_routes_select_account_and_keep_private_relay_in_account_store() {
    let package =
        std::env::var("PRIVACY_POOLS_PACKAGE").expect("set PRIVACY_POOLS_PACKAGE to built package");
    let home = tempfile::tempdir().unwrap();
    let store = PetalStore::open(home.path().join("petals")).unwrap();
    let (installed, _, _) = store.install_petal_package_dir(package).unwrap();
    let account = home
        .path()
        .join("petals/data-accounts")
        .join(&installed.hash)
        .join(account_digest("fixture", 1));
    let note = account.join("secrets/privacy-pools/notes/fixture/note");
    std::fs::create_dir_all(note.parent().unwrap()).unwrap();
    std::fs::write(&note, serde_json::to_vec(&json!({
        "wallet":"fixture", "asset":"eth", "amount_wei":"100", "nullifier":"0x01", "secret":"0x02",
        "precommitment":"0x03", "status":"confirmed", "tx":{"chain":"mainnet", "outbox_id":"private-relay"},
        "value":"100", "label":"0x04", "commitment":"0x05", "spent":false,"backup_verified":true
    })).unwrap()).unwrap();
    let registry =
        Arc::new(bloom_petals::NameRegistry::open(home.path().join("registry")).unwrap());
    let runner = PetalRunner::new(store, registry, PetalVm::new().unwrap());
    let host = Arc::new(FixtureHost::default());
    let vfs = Vfs::builder()
        .mount("petals", Arc::new(PetalRouter::new(runner, host.clone())))
        .build();
    let route = VfsPath::parse("/petals/privacy-pools/withdrawals/fixture/1/note.json").unwrap();
    let request = |processor| {
        serde_json::to_vec(
            &json!({"calldata":direct_calldata(processor),"replacement_id":"replacement"}),
        )
        .unwrap()
    };
    let wrong = vfs
        .write(&route, &request(0x11))
        .await
        .unwrap_err()
        .to_string();
    assert!(wrong.contains("invalid"), "{wrong}");
    assert_eq!(
        host.reads.lock().as_slice(),
        &["wallets/fixture/1/address.evm"]
    );
    // The matching processor gets beyond account validation and fails the
    // deliberately fabricated proof's nullifier check.
    assert!(vfs.write(&route, &request(0x22)).await.is_err());
    assert_eq!(host.reads.lock().len(), 2);
    let private = serde_json::to_vec(
        &json!({"mode":"private-relay","replacement_id":"replacement","amount_wei":"50"}),
    )
    .unwrap();
    vfs.write(&route, &private).await.unwrap();
    vfs.write(&route, &private).await.unwrap();
    let public = vfs.read(&route).await.unwrap();
    let status: serde_json::Value = serde_json::from_slice(&public).unwrap();
    assert_eq!(status["status"], "awaiting-owner-input");
    assert!(!String::from_utf8(public).unwrap().contains("recipient"));
    assert!(
        account
            .join("state/privacy-pools/private-relays/fixture/note")
            .exists()
    );
    let other = VfsPath::parse("/petals/privacy-pools/withdrawals/fixture/0/note.json").unwrap();
    assert!(
        vfs.write(&other, &private).await.is_err(),
        "account 0 must not read account 1 note"
    );
    let legacy = VfsPath::parse("/petals/privacy-pools/withdrawals/fixture/note.json").unwrap();
    assert!(vfs.write(&legacy, &private).await.is_err());
}
