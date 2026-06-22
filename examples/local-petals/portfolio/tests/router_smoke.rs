use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use async_trait::async_trait;
use bloom_petal_manifest::extract_local_petal_manifest;
use bloom_petals::{
    HostError, NameRegistry, PetalHost, PetalMode, PetalRouter, PetalRunner, PetalStore, PetalVm,
};
use bloom_vfs::Handler;
use bloom_vfs::path::VfsPath;

#[tokio::test]
async fn compiled_portfolio_petal_walks_wallets_via_vfs_read_capability() {
    let root = workspace_root();
    if !wasm32_wasip1_installed(&root) {
        eprintln!("skipping portfolio router smoke test: wasm32-wasip1 target is not installed");
        return;
    }
    let target_dir = root.join("target/local-petal-portfolio-test");
    let status = Command::new(env!("CARGO"))
        .current_dir(&root)
        .args([
            "build",
            "-p",
            "bloom-local-petal-portfolio",
            "--target",
            "wasm32-wasip1",
            "--target-dir",
        ])
        .arg(&target_dir)
        .status()
        .expect("cargo build must run");
    assert!(status.success(), "wasm build failed with {status}");

    let wasm_path = target_dir.join("wasm32-wasip1/debug/bloom_local_petal_portfolio.wasm");
    let wasm = std::fs::read(&wasm_path)
        .unwrap_or_else(|e| panic!("read wasm {}: {e}", wasm_path.display()));

    let manifest = extract_local_petal_manifest(&wasm, std::iter::empty::<&str>())
        .expect("local manifest must extract");
    assert_eq!(manifest.provides.mount, "portfolio");
    assert_eq!(manifest.provides.caps.len(), 1);
    assert_eq!(manifest.provides.caps[0].as_str(), "vfs.read");

    let tmp = tempfile::tempdir().unwrap();
    let store = PetalStore::open(tmp.path().join("store")).unwrap();
    let registry = Arc::new(NameRegistry::open(tmp.path().join("names")).unwrap());
    let runner = PetalRunner::new(store, registry, PetalVm::new().unwrap());
    runner
        .install(&wasm, None, &BTreeSet::new(), PetalMode::Local)
        .unwrap();

    let router = PetalRouter::new(runner, Arc::new(MockVfsHost::fixture()));
    let summary = router
        .read(&VfsPath::parse("portfolio/summary.md").unwrap())
        .await
        .unwrap();
    let summary = String::from_utf8(summary).unwrap();
    assert!(summary.contains("| wallet | chain | address | balance |"));
    assert!(summary.contains("| alice | base | 0xA11CE | 1.25 ETH |"));
    assert!(summary.contains("| bob | polygon | 0xB0B | 42 POL |"));
    assert!(!summary.contains("new"));
}

#[derive(Default)]
struct MockVfsHost {
    reads: BTreeMap<String, Vec<u8>>,
    lists: BTreeMap<String, Vec<String>>,
}

impl MockVfsHost {
    fn fixture() -> Self {
        let mut host = Self::default();
        host.lists.insert(
            "wallets".into(),
            vec!["alice".into(), "new".into(), "bob".into()],
        );
        host.lists
            .insert("wallets/alice/chains".into(), vec!["base".into()]);
        host.lists
            .insert("wallets/bob/chains".into(), vec!["polygon".into()]);
        host.reads
            .insert("wallets/alice/address".into(), b"0xA11CE\n".to_vec());
        host.reads.insert(
            "wallets/alice/chains/base/balance.eth".into(),
            b"1.25 ETH\n".to_vec(),
        );
        host.reads
            .insert("wallets/bob/address".into(), b"0xB0B\n".to_vec());
        host.reads.insert(
            "wallets/bob/chains/polygon/balance.eth".into(),
            b"42 POL\n".to_vec(),
        );
        host
    }
}

#[async_trait]
impl PetalHost for MockVfsHost {
    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
        self.reads
            .get(path)
            .cloned()
            .ok_or_else(|| HostError::NotFound(path.into()))
    }

    async fn vfs_list(&self, path: &str) -> Result<Vec<String>, HostError> {
        self.lists
            .get(path)
            .cloned()
            .ok_or_else(|| HostError::NotFound(path.into()))
    }

    async fn vfs_write(&self, _path: &str, _bytes: &[u8]) -> Result<(), HostError> {
        Err(HostError::Denied("read-only test host".into()))
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("example path has workspace root")
        .to_path_buf()
}

fn wasm32_wasip1_installed(root: &Path) -> bool {
    let output = Command::new("rustup")
        .current_dir(root)
        .args(["target", "list", "--installed"])
        .output();
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.trim() == "wasm32-wasip1")
}
