use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bloom_petal_manifest::extract_local_petal_manifest;
use bloom_petals::{
    HostError, NameRegistry, PetalHost, PetalMode, PetalRouter, PetalRunner, PetalStore, PetalVm,
};
use bloom_vfs::Handler;
use bloom_vfs::path::VfsPath;

#[tokio::test]
async fn compiled_polymarket_bridge_proxies_native_vfs_surface() {
    let root = workspace_root();
    if !wasm32_wasip1_installed(&root) {
        eprintln!("skipping polymarket bridge smoke test: wasm32-wasip1 target is not installed");
        return;
    }
    let target_dir = root.join("target/local-petal-polymarket-test");
    let status = Command::new(env!("CARGO"))
        .current_dir(&root)
        .args([
            "build",
            "-p",
            "bloom-local-petal-polymarket",
            "--target",
            "wasm32-wasip1",
            "--target-dir",
        ])
        .arg(&target_dir)
        .status()
        .expect("cargo build must run");
    assert!(status.success(), "wasm build failed with {status}");

    let wasm_path = target_dir.join("wasm32-wasip1/debug/bloom_local_petal_polymarket.wasm");
    let wasm = std::fs::read(&wasm_path)
        .unwrap_or_else(|e| panic!("read wasm {}: {e}", wasm_path.display()));

    let manifest = extract_local_petal_manifest(&wasm, std::iter::empty::<&str>())
        .expect("local manifest must extract");
    assert_eq!(manifest.provides.mount, "polymarket");
    assert_eq!(
        manifest
            .provides
            .caps
            .iter()
            .map(|cap| cap.as_str())
            .collect::<Vec<_>>(),
        vec!["vfs.read", "vfs.write"]
    );

    let tmp = tempfile::tempdir().unwrap();
    let store = PetalStore::open(tmp.path().join("store")).unwrap();
    let registry = Arc::new(NameRegistry::open(tmp.path().join("names")).unwrap());
    let runner = PetalRunner::new(store, registry, PetalVm::new().unwrap());
    runner
        .install(&wasm, None, &BTreeSet::new(), PetalMode::Local)
        .unwrap();

    let host = Arc::new(MockVfsHost::fixture());
    let router = PetalRouter::new(runner, host.clone());

    let root_entries = router
        .list(&VfsPath::parse("polymarket").unwrap())
        .await
        .unwrap();
    assert!(root_entries.iter().any(|entry| entry.name == "markets"));
    assert!(root_entries.iter().any(|entry| entry.name == "trade"));

    let market = router
        .read(&VfsPath::parse("polymarket/markets/test-market/market.json").unwrap())
        .await
        .unwrap();
    assert_eq!(market, br#"{"slug":"test-market"}"#);

    router
        .write(
            &VfsPath::parse("polymarket/trade/alice/new").unwrap(),
            br#"{"slug":"test-market"}"#,
        )
        .await
        .unwrap();
    assert_eq!(
        host.writes
            .lock()
            .unwrap()
            .get("polymarket/trade/alice/new"),
        Some(&br#"{"slug":"test-market"}"#.to_vec())
    );

    assert!(
        router
            .write(
                &VfsPath::parse("polymarket/markets/test-market/market.json").unwrap(),
                b"nope",
            )
            .await
            .is_err()
    );
}

#[derive(Default)]
struct MockVfsHost {
    reads: BTreeMap<String, Vec<u8>>,
    lists: BTreeMap<String, Vec<String>>,
    writes: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl MockVfsHost {
    fn fixture() -> Self {
        let mut host = Self::default();
        host.lists.insert(
            "polymarket".into(),
            vec!["markets".into(), "search".into(), "trade".into()],
        );
        host.lists
            .insert("polymarket/markets".into(), vec!["test-market".into()]);
        host.lists.insert(
            "polymarket/markets/test-market".into(),
            vec!["market.json".into(), "book.json".into()],
        );
        host.lists
            .insert("polymarket/trade".into(), vec!["alice".into()]);
        host.lists.insert(
            "polymarket/trade/alice".into(),
            vec!["new".into(), "drafts".into()],
        );
        host.reads.insert(
            "polymarket/markets/test-market/market.json".into(),
            br#"{"slug":"test-market"}"#.to_vec(),
        );
        host.reads.insert(
            "polymarket/markets/test-market/book.json".into(),
            br#"{"bids":[],"asks":[]}"#.to_vec(),
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
            .ok_or_else(|| HostError::Invalid(format!("{path} is not a dir")))
    }

    async fn vfs_write(&self, path: &str, bytes: &[u8]) -> Result<(), HostError> {
        self.writes
            .lock()
            .unwrap()
            .insert(path.into(), bytes.to_vec());
        Ok(())
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
