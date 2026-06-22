use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use bloom_petal_manifest::extract_local_petal_manifest;
use bloom_petals::{
    DenyHost, NameRegistry, PetalMode, PetalRouter, PetalRunner, PetalStore, PetalVm,
};
use bloom_vfs::Handler;
use bloom_vfs::path::VfsPath;

#[tokio::test]
async fn compiled_misc_tools_petal_installs_and_serves_via_router() {
    let root = workspace_root();
    if !wasm32_wasip1_installed(&root) {
        eprintln!("skipping router smoke test: wasm32-wasip1 target is not installed");
        return;
    }
    let target_dir = root.join("target/local-petal-misc-tools-test");
    let status = Command::new(env!("CARGO"))
        .current_dir(&root)
        .args([
            "build",
            "-p",
            "bloom-local-petal-misc-tools",
            "--target",
            "wasm32-wasip1",
            "--target-dir",
        ])
        .arg(&target_dir)
        .status()
        .expect("cargo build must run");
    assert!(status.success(), "wasm build failed with {status}");

    let wasm_path = target_dir.join("wasm32-wasip1/debug/bloom_local_petal_misc_tools.wasm");
    let wasm = std::fs::read(&wasm_path)
        .unwrap_or_else(|e| panic!("read wasm {}: {e}", wasm_path.display()));

    let manifest = extract_local_petal_manifest(&wasm, std::iter::empty::<&str>())
        .expect("local manifest must extract");
    assert_eq!(manifest.provides.mount, "misc-tools");
    assert!(manifest.provides.caps.is_empty());

    let tmp = tempfile::tempdir().unwrap();
    let store = PetalStore::open(tmp.path().join("store")).unwrap();
    let registry = Arc::new(NameRegistry::open(tmp.path().join("names")).unwrap());
    let runner = PetalRunner::new(store, registry, PetalVm::new().unwrap());
    runner
        .install(&wasm, None, &BTreeSet::new(), PetalMode::Local)
        .unwrap();

    let router = PetalRouter::new(runner, Arc::new(DenyHost));
    let mounts = router.list(&VfsPath::root()).await.unwrap();
    assert_eq!(mounts[0].name, "misc-tools");

    let entries = router
        .list(&VfsPath::parse("misc-tools").unwrap())
        .await
        .unwrap();
    let names: Vec<_> = entries.into_iter().map(|entry| entry.name).collect();
    assert_eq!(names, ["echo", "hash", "gas-now"]);

    assert_eq!(
        router
            .read(&VfsPath::parse("misc-tools/echo/hello").unwrap())
            .await
            .unwrap(),
        b"hello\n"
    );
    assert_eq!(
        router
            .read(&VfsPath::parse("misc-tools/hash/hello").unwrap())
            .await
            .unwrap(),
        b"0xa430d84680aabd0b\n"
    );
    let gas = router
        .read(&VfsPath::parse("misc-tools/gas-now").unwrap())
        .await
        .unwrap();
    assert!(String::from_utf8(gas).unwrap().contains("\"fast_gwei\":30"));
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
