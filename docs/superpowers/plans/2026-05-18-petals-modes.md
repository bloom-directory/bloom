# Petals Local/Onchain Modes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split bloom petals into deterministic-replay `Onchain` and unrestricted `Local` modes, gated at install time and enforced by a mode-branched wasmtime linker, plus a `bloom petals replay` CLI that observes the determinism contract.

**Architecture:** Mode is install-record metadata, not a property of the wasm bytes. A single `PetalVm` matches on `PetalMode` and links one of two host-import sets (`link_local_imports` keeps today's `bloom.vfs_*`; `link_onchain_imports` exposes `bloom.chain_read_at` only). The full WASI preview-1 linker is wired for both modes in v1 — narrowing onchain WASI to a deterministic clock/RNG is a documented follow-up. Storage stays content-addressed; the VFS exposes `public/{local,onchain,names}/...`. Onchain runs emit a `PetalAttestation { petal_hash, input_hash, output_hash, block_pin, wasmtime_version }` that the replay CLI compares against.

**Tech Stack:** Rust, wasmtime 26 (async + WASI preview-1), BLAKE3, serde + serde_json, tempfile, parking_lot, async-trait. CLI tests use `assert_cmd` + `predicates`. Spec: [`docs/superpowers/specs/2026-05-18-petals-modes-design.md`](../specs/2026-05-18-petals-modes-design.md).

**Spec deviation note:** The on-disk meta format stays `meta/<hash>.json` (existing v0 layout), not `installs/<hash>.toml` as the spec described. The spec wording was inaccurate about a v0 detail; everything else is faithful.

---

## File Structure

Files created or modified:

**Created:**
- `crates/bloom-petals/src/attestation.rs` — `PetalAttestation` struct + helpers
- `crates/bloom-petals/tests/fixtures/onchain_echo.wat` — onchain test fixture
- `crates/bloom-petals/tests/onchain_run.rs` — end-to-end onchain run integration test
- `crates/bloom/tests/fixtures/onchain_echo.wat` — onchain CLI fixture
- `crates/bloom/tests/fixtures/probe_clock.wat` — onchain WAT that imports `clock_time_get` (used in instantiation-failure test)

**Modified:**
- `crates/bloom-petals/src/lib.rs` — export new types
- `crates/bloom-petals/src/meta.rs` — `PetalMode`, `Capability::ChainRead`, `validate_mode_caps`
- `crates/bloom-petals/src/error.rs` — `ModeConflict`, `ModeCapMismatch`, `BlockNotPinnable`, `ChainUnavailable`, `ChainPathUnknown`, `CapMismatch`
- `crates/bloom-petals/src/store.rs` — install takes `mode`, ModeConflict path, `uninstall`, `list_with_meta`, `list_hashes_by_mode`
- `crates/bloom-petals/src/host.rs` — `PetalHost::chain_read_at`, new HostError variants, new wasm error codes
- `crates/bloom-petals/src/vm.rs` — `link_local_imports` / `link_onchain_imports` / `link_imports_for_mode`, mode-branched WasiCtxBuilder, `chain_read_at` host fn, deterministic config knobs, `run` takes `mode`
- `crates/bloom-petals/src/handler.rs` — path-segmented layout under `public/{local,onchain,names}`
- `crates/bloom-petals/src/runner.rs` — `install` takes `mode`, `uninstall`, attestation-emitting onchain run, `BlockTrackingHost` wrapper
- `crates/bloom-daemon/src/ipc.rs` — `mode` field on install, `petals.uninstall`, `petals.replay`, attestation in `petals.run` response
- `crates/bloom/src/main.rs` — `--mode` flag, `uninstall`/`replay` subcommands, `ls` mode column
- `crates/bloom/tests/cli.rs` — new tests for mode flow, uninstall, replay

---

## Task 1: Add PetalMode enum

**Files:**
- Modify: `crates/bloom-petals/src/meta.rs`

- [ ] **Step 1: Write failing test**

Add at the bottom of the `tests` mod in `crates/bloom-petals/src/meta.rs`:

```rust
#[test]
fn petal_mode_serde_roundtrips_as_lowercase() {
    assert_eq!(serde_json::to_string(&PetalMode::Local).unwrap(), "\"local\"");
    assert_eq!(serde_json::to_string(&PetalMode::Onchain).unwrap(), "\"onchain\"");
    let m: PetalMode = serde_json::from_str("\"local\"").unwrap();
    assert_eq!(m, PetalMode::Local);
    let m: PetalMode = serde_json::from_str("\"onchain\"").unwrap();
    assert_eq!(m, PetalMode::Onchain);
}

#[test]
fn meta_serde_defaults_mode_to_local_when_missing() {
    let s = r#"{"hash":"x","size":1,"installed_at_ms":2}"#;
    let m: PetalMeta = serde_json::from_str(s).unwrap();
    assert_eq!(m.mode, PetalMode::Local);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p bloom-petals meta::tests::petal_mode_serde_roundtrips_as_lowercase`
Expected: FAIL with `cannot find type 'PetalMode' in this scope`.

- [ ] **Step 3: Add `PetalMode` enum and `mode` field**

Edit `crates/bloom-petals/src/meta.rs`. Just below the `Capability` impl (around line 35), insert:

```rust
/// What execution surface a petal targets. Drives which host imports
/// the VM links and which WASI capabilities the ctx exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PetalMode {
    Local,
    Onchain,
}

impl Default for PetalMode {
    fn default() -> Self {
        PetalMode::Local
    }
}
```

Then modify the `PetalMeta` struct (around line 36) by adding a `mode` field with a serde default:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetalMeta {
    pub hash: String,
    pub size: u64,
    pub installed_at_ms: u64,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub caps: BTreeSet<Capability>,
    #[serde(default)]
    pub mode: PetalMode,
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p bloom-petals meta::`
Expected: PASS (all `meta::tests`).

- [ ] **Step 5: Commit**

```bash
git add crates/bloom-petals/src/meta.rs
git commit -m "petals: add PetalMode enum and mode field on PetalMeta"
```

---

## Task 2: Add `Capability::ChainRead`

**Files:**
- Modify: `crates/bloom-petals/src/meta.rs`

- [ ] **Step 1: Extend the roundtrip test**

In `crates/bloom-petals/src/meta.rs`, replace `capability_string_roundtrip` with:

```rust
#[test]
fn capability_string_roundtrip() {
    assert_eq!(Capability::VfsRead.as_str(), "vfs.read");
    assert_eq!(Capability::VfsWrite.as_str(), "vfs.write");
    assert_eq!(Capability::ChainRead.as_str(), "chain.read");
    assert_eq!(Capability::parse("vfs.read"), Some(Capability::VfsRead));
    assert_eq!(Capability::parse("vfs.write"), Some(Capability::VfsWrite));
    assert_eq!(Capability::parse("chain.read"), Some(Capability::ChainRead));
    assert_eq!(Capability::parse("nope"), None);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p bloom-petals meta::tests::capability_string_roundtrip`
Expected: FAIL with `no variant or associated item named 'ChainRead'`.

- [ ] **Step 3: Add `ChainRead` variant**

In `crates/bloom-petals/src/meta.rs`, modify the `Capability` enum and its impls:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    #[serde(rename = "vfs.read")]
    VfsRead,
    #[serde(rename = "vfs.write")]
    VfsWrite,
    #[serde(rename = "chain.read")]
    ChainRead,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::VfsRead => "vfs.read",
            Capability::VfsWrite => "vfs.write",
            Capability::ChainRead => "chain.read",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "vfs.read" => Some(Capability::VfsRead),
            "vfs.write" => Some(Capability::VfsWrite),
            "chain.read" => Some(Capability::ChainRead),
            _ => None,
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p bloom-petals meta::tests::capability_string_roundtrip`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/bloom-petals/src/meta.rs
git commit -m "petals: add chain.read capability variant"
```

---

## Task 3: Mode/cap validation

**Files:**
- Modify: `crates/bloom-petals/src/meta.rs`
- Modify: `crates/bloom-petals/src/error.rs`

- [ ] **Step 1: Write failing test**

In `crates/bloom-petals/src/meta.rs` tests mod, append:

```rust
#[test]
fn validate_mode_caps_matrix() {
    use crate::error::PetalError;

    let mut empty = BTreeSet::new();
    assert!(validate_mode_caps(PetalMode::Local, &empty).is_ok());
    assert!(validate_mode_caps(PetalMode::Onchain, &empty).is_ok());

    let mut vfs_read = BTreeSet::new();
    vfs_read.insert(Capability::VfsRead);
    assert!(validate_mode_caps(PetalMode::Local, &vfs_read).is_ok());
    assert!(matches!(
        validate_mode_caps(PetalMode::Onchain, &vfs_read),
        Err(PetalError::ModeCapMismatch { .. })
    ));

    let mut chain_read = BTreeSet::new();
    chain_read.insert(Capability::ChainRead);
    assert!(validate_mode_caps(PetalMode::Onchain, &chain_read).is_ok());
    assert!(matches!(
        validate_mode_caps(PetalMode::Local, &chain_read),
        Err(PetalError::ModeCapMismatch { .. })
    ));

    let mut mixed = BTreeSet::new();
    mixed.insert(Capability::ChainRead);
    mixed.insert(Capability::VfsRead);
    assert!(matches!(
        validate_mode_caps(PetalMode::Local, &mixed),
        Err(PetalError::ModeCapMismatch { .. })
    ));
    assert!(matches!(
        validate_mode_caps(PetalMode::Onchain, &mixed),
        Err(PetalError::ModeCapMismatch { .. })
    ));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p bloom-petals meta::tests::validate_mode_caps_matrix`
Expected: FAIL with `cannot find function 'validate_mode_caps'`.

- [ ] **Step 3: Add `ModeCapMismatch` to PetalError**

In `crates/bloom-petals/src/error.rs`, add inside the `PetalError` enum (before the closing brace):

```rust
    #[error("mode/cap mismatch: mode={mode:?} disallows cap={cap}")]
    ModeCapMismatch { mode: crate::meta::PetalMode, cap: String },
```

- [ ] **Step 4: Add `validate_mode_caps` function**

In `crates/bloom-petals/src/meta.rs`, append to the module (after the `impl PetalMeta` block, before the `#[cfg(test)]`):

```rust
/// Validate that a (mode, caps) pair is allowed at install time.
///
/// - `Local` may declare `{vfs.read, vfs.write}`; `chain.read` is rejected.
/// - `Onchain` may declare `{chain.read}`; vfs caps are rejected.
pub fn validate_mode_caps(
    mode: PetalMode,
    caps: &BTreeSet<Capability>,
) -> Result<(), crate::error::PetalError> {
    for cap in caps {
        let ok = match (mode, *cap) {
            (PetalMode::Local, Capability::VfsRead | Capability::VfsWrite) => true,
            (PetalMode::Onchain, Capability::ChainRead) => true,
            _ => false,
        };
        if !ok {
            return Err(crate::error::PetalError::ModeCapMismatch {
                mode,
                cap: cap.as_str().to_string(),
            });
        }
    }
    Ok(())
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p bloom-petals meta::tests::validate_mode_caps_matrix`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/bloom-petals/src/meta.rs crates/bloom-petals/src/error.rs
git commit -m "petals: validate (mode, caps) combinations"
```

---

## Task 4: Store install takes mode + ModeConflict

**Files:**
- Modify: `crates/bloom-petals/src/error.rs`
- Modify: `crates/bloom-petals/src/store.rs`

- [ ] **Step 1: Write failing test**

In `crates/bloom-petals/src/store.rs` tests mod, append:

```rust
#[test]
fn install_records_mode() {
    let (_d, store) = store();
    let (_r, m) = store
        .install(b"abc", Some("a"), &BTreeSet::new(), PetalMode::Onchain)
        .unwrap();
    assert_eq!(m.mode, PetalMode::Onchain);
}

#[test]
fn install_same_hash_different_mode_returns_mode_conflict() {
    let (_d, store) = store();
    let (_r, _m) = store
        .install(b"xyz", None, &BTreeSet::new(), PetalMode::Local)
        .unwrap();
    let err = store
        .install(b"xyz", None, &BTreeSet::new(), PetalMode::Onchain)
        .unwrap_err();
    assert!(
        matches!(err, PetalError::ModeConflict { existing } if existing == PetalMode::Local),
        "{err:?}"
    );
}

#[test]
fn install_same_hash_same_mode_is_idempotent() {
    let (_d, store) = store();
    let (r1, _) = store
        .install(b"qqq", Some("a"), &BTreeSet::new(), PetalMode::Local)
        .unwrap();
    let (r2, m) = store
        .install(b"qqq", Some("b"), &BTreeSet::new(), PetalMode::Local)
        .unwrap();
    assert_eq!(r1.hash, r2.hash);
    assert!(r2.already_present);
    assert_eq!(m.name.as_deref(), Some("b"));
    assert_eq!(m.mode, PetalMode::Local);
}
```

Add the import at the top of the tests mod:

```rust
use crate::meta::PetalMode;
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bloom-petals store::tests::install_records_mode`
Expected: FAIL with `this function takes 3 arguments but 4 arguments were supplied`.

- [ ] **Step 3: Add `ModeConflict` to PetalError**

In `crates/bloom-petals/src/error.rs`, add inside the `PetalError` enum:

```rust
    #[error("mode conflict: petal already installed as {existing:?}; uninstall first")]
    ModeConflict { existing: crate::meta::PetalMode },
```

- [ ] **Step 4: Change `PetalStore::install` signature and logic**

In `crates/bloom-petals/src/store.rs`, replace the `install` method with:

```rust
    pub fn install(
        &self,
        wasm: &[u8],
        name: Option<&str>,
        caps: &BTreeSet<Capability>,
        mode: PetalMode,
    ) -> Result<(InstallResult, PetalMeta), PetalError> {
        let hash = hex::encode(blake3::hash(wasm).as_bytes());
        let obj_path = self.object_path(&hash);
        let already_present = obj_path.exists();

        if !already_present {
            atomic_write(&obj_path, wasm)?;
        }

        let mut meta = match self.load_meta(&hash) {
            Ok(existing) => {
                if existing.mode != mode {
                    return Err(PetalError::ModeConflict {
                        existing: existing.mode,
                    });
                }
                existing
            }
            Err(PetalError::NotFound(_)) => PetalMeta {
                hash: hash.clone(),
                size: wasm.len() as u64,
                installed_at_ms: now_ms(),
                name: None,
                caps: BTreeSet::new(),
                mode,
            },
            Err(e) => return Err(e),
        };
        if let Some(n) = name {
            meta.name = Some(n.to_string());
        }
        meta.caps.extend(caps.iter().copied());
        meta.size = wasm.len() as u64;
        self.write_meta(&meta)?;

        Ok((
            InstallResult {
                hash: hash.clone(),
                size: wasm.len() as u64,
                already_present,
            },
            meta,
        ))
    }
```

Also add `PetalMode` to the imports at the top of the file:

```rust
use crate::meta::{Capability, PetalMeta, PetalMode};
```

- [ ] **Step 5: Update the existing v0 test that calls install**

In the same file, update `install_writes_object_and_meta`, `install_is_idempotent_on_hash_and_unions_caps`, and `list_hashes_filters_non_hash_entries` to pass `PetalMode::Local`:

```rust
    #[test]
    fn install_writes_object_and_meta() {
        let (_d, store) = store();
        let mut caps = BTreeSet::new();
        caps.insert(Capability::VfsRead);
        let (r, m) = store
            .install(b"hello-wasm", Some("greet"), &caps, PetalMode::Local)
            .unwrap();
        assert_eq!(r.size, 10);
        assert!(!r.already_present);
        assert!(store.contains(&r.hash));
        assert_eq!(m.name.as_deref(), Some("greet"));
        assert!(m.has_cap(Capability::VfsRead));
    }

    #[test]
    fn install_is_idempotent_on_hash_and_unions_caps() {
        let (_d, store) = store();
        let mut caps_a = BTreeSet::new();
        caps_a.insert(Capability::VfsRead);
        let (r1, _) = store.install(b"x", Some("a"), &caps_a, PetalMode::Local).unwrap();
        let mut caps_b = BTreeSet::new();
        caps_b.insert(Capability::VfsWrite);
        let (r2, m) = store.install(b"x", Some("b"), &caps_b, PetalMode::Local).unwrap();
        assert_eq!(r1.hash, r2.hash);
        assert!(r2.already_present);
        assert_eq!(m.name.as_deref(), Some("b"));
        assert!(m.has_cap(Capability::VfsRead));
        assert!(m.has_cap(Capability::VfsWrite));
    }

    #[test]
    fn list_hashes_filters_non_hash_entries() {
        let (d, store) = store();
        let (r, _) = store.install(b"abc", None, &BTreeSet::new(), PetalMode::Local).unwrap();
        std::fs::write(d.path().join(OBJECTS).join("README"), b"junk").unwrap();
        let hashes = store.list_hashes().unwrap();
        assert_eq!(hashes, vec![r.hash]);
    }
```

- [ ] **Step 6: Run all store tests**

Run: `cargo test -p bloom-petals store::`
Expected: PASS (all store tests, including new ones).

- [ ] **Step 7: Commit**

```bash
git add crates/bloom-petals/src/store.rs crates/bloom-petals/src/error.rs
git commit -m "petals: install records mode; ModeConflict on cross-mode reinstall"
```

---

## Task 5: Store `uninstall` and `list_hashes_by_mode`

**Files:**
- Modify: `crates/bloom-petals/src/store.rs`

- [ ] **Step 1: Write failing tests**

Append to the `tests` mod in `crates/bloom-petals/src/store.rs`:

```rust
#[test]
fn uninstall_removes_object_and_meta() {
    let (_d, store) = store();
    let (r, _) = store.install(b"toremove", None, &BTreeSet::new(), PetalMode::Local).unwrap();
    assert!(store.contains(&r.hash));
    let removed = store.uninstall(&r.hash).unwrap();
    assert!(removed);
    assert!(!store.contains(&r.hash));
    assert!(matches!(store.load_meta(&r.hash), Err(PetalError::NotFound(_))));
}

#[test]
fn uninstall_missing_returns_false() {
    let (_d, store) = store();
    let absent = "0".repeat(64);
    assert!(!store.uninstall(&absent).unwrap());
}

#[test]
fn list_hashes_by_mode_filters_correctly() {
    let (_d, store) = store();
    let (rl, _) = store.install(b"local-bytes", None, &BTreeSet::new(), PetalMode::Local).unwrap();
    let mut chain = BTreeSet::new();
    chain.insert(Capability::ChainRead);
    let (rc, _) = store.install(b"onchain-bytes", None, &chain, PetalMode::Onchain).unwrap();
    let locals = store.list_hashes_by_mode(PetalMode::Local).unwrap();
    let onchain = store.list_hashes_by_mode(PetalMode::Onchain).unwrap();
    assert_eq!(locals, vec![rl.hash]);
    assert_eq!(onchain, vec![rc.hash]);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bloom-petals store::tests::uninstall_removes_object_and_meta`
Expected: FAIL with `no method named 'uninstall' found`.

- [ ] **Step 3: Implement `uninstall` and `list_hashes_by_mode`**

In `crates/bloom-petals/src/store.rs`, add inside `impl PetalStore` (after `list_hashes`):

```rust
    /// Remove an installed petal's object and metadata. Returns `true`
    /// if anything was removed, `false` if the hash was not installed.
    /// The caller is responsible for clearing any registry entries that
    /// point at this hash.
    pub fn uninstall(&self, hash: &str) -> Result<bool, PetalError> {
        let obj_path = self.object_path(hash);
        let meta_path = self.meta_path(hash);
        let had = obj_path.exists() || meta_path.exists();
        for p in [&obj_path, &meta_path] {
            match std::fs::remove_file(p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(PetalError::Io(e)),
            }
        }
        Ok(had)
    }

    /// List hashes whose meta records have the given mode. Ignores
    /// objects with missing metadata (which would be a corruption).
    pub fn list_hashes_by_mode(&self, mode: PetalMode) -> Result<Vec<String>, PetalError> {
        let mut out = Vec::new();
        for hash in self.list_hashes()? {
            match self.load_meta(&hash) {
                Ok(m) if m.mode == mode => out.push(hash),
                Ok(_) => {}
                Err(PetalError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p bloom-petals store::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/bloom-petals/src/store.rs
git commit -m "petals: add uninstall and list_hashes_by_mode"
```

---

## Task 6: PetalHost `chain_read_at` trait method

**Files:**
- Modify: `crates/bloom-petals/src/host.rs`

- [ ] **Step 1: Write failing tests**

In `crates/bloom-petals/src/host.rs`, replace the `error_codes_are_distinct` test and add a new one:

```rust
#[test]
fn error_codes_are_distinct() {
    let codes: Vec<i32> = vec![
        HostError::NotFound("x".into()).as_wasm_code(),
        HostError::Denied("x".into()).as_wasm_code(),
        HostError::Invalid("x".into()).as_wasm_code(),
        HostError::Backend("x".into()).as_wasm_code(),
        HostError::BlockNotPinnable.as_wasm_code(),
        HostError::ChainUnavailable("eth".into()).as_wasm_code(),
        HostError::ChainPathUnknown("p".into()).as_wasm_code(),
    ];
    let mut sorted = codes.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), codes.len(), "codes overlap: {codes:?}");
    for c in codes {
        assert!(c < 0, "host error codes must be negative, got {c}");
    }
}

#[tokio::test]
async fn deny_host_denies_chain_read() {
    let h = DenyHost;
    assert!(matches!(
        h.chain_read_at("eth", "chains/eth/state/0x0/balance", 1).await,
        Err(HostError::Denied(_))
    ));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bloom-petals host::tests::error_codes_are_distinct`
Expected: FAIL with `no variant or associated item named 'BlockNotPinnable'`.

- [ ] **Step 3: Extend `HostError` and the trait**

Replace the `HostError` enum and `as_wasm_code` in `crates/bloom-petals/src/host.rs`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("denied: {0}")]
    Denied(String),
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("backend: {0}")]
    Backend(String),
    #[error("block not pinnable (block=0)")]
    BlockNotPinnable,
    #[error("chain unavailable: {0}")]
    ChainUnavailable(String),
    #[error("chain path unknown: {0}")]
    ChainPathUnknown(String),
}

impl HostError {
    /// Stable negative error codes returned to wasm.
    pub fn as_wasm_code(&self) -> i32 {
        match self {
            HostError::NotFound(_) => -1,
            HostError::Denied(_) => -2,
            HostError::Invalid(_) => -3,
            HostError::Backend(_) => -4,
            HostError::BlockNotPinnable => -5,
            HostError::ChainUnavailable(_) => -6,
            HostError::ChainPathUnknown(_) => -7,
        }
    }
}
```

Then add the `chain_read_at` method to the trait and `DenyHost`:

```rust
#[async_trait]
pub trait PetalHost: Send + Sync {
    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError>;
    async fn vfs_write(&self, path: &str, bytes: &[u8]) -> Result<(), HostError>;

    /// Read a pinned-block view of a chain VFS path. `chain` is the
    /// canonical chain id (e.g. `"ethereum"`); `path` is the
    /// chains-VFS-relative path; `block` is the block number.
    ///
    /// Onchain petals call this via `bloom.chain_read_at`. Local petals
    /// reach the live chain state via `vfs_read` instead.
    async fn chain_read_at(
        &self,
        chain: &str,
        path: &str,
        block: u64,
    ) -> Result<Vec<u8>, HostError>;
}

pub struct DenyHost;

#[async_trait]
impl PetalHost for DenyHost {
    async fn vfs_read(&self, _path: &str) -> Result<Vec<u8>, HostError> {
        Err(HostError::Denied("DenyHost".into()))
    }
    async fn vfs_write(&self, _path: &str, _bytes: &[u8]) -> Result<(), HostError> {
        Err(HostError::Denied("DenyHost".into()))
    }
    async fn chain_read_at(
        &self,
        _chain: &str,
        _path: &str,
        _block: u64,
    ) -> Result<Vec<u8>, HostError> {
        Err(HostError::Denied("DenyHost".into()))
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p bloom-petals host::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/bloom-petals/src/host.rs
git commit -m "petals: PetalHost::chain_read_at and onchain error codes"
```

---

## Task 7: Mode-branched linker in PetalVm

**Files:**
- Modify: `crates/bloom-petals/src/vm.rs`

- [ ] **Step 1: Write failing tests**

In `crates/bloom-petals/src/vm.rs` tests mod, add (after the existing `MockHost` impl, extending it to implement the new trait method):

```rust
#[async_trait]
impl PetalHost for MockHost {
    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
        self.store.lock().get(path).cloned().ok_or_else(|| HostError::NotFound(path.into()))
    }
    async fn vfs_write(&self, path: &str, bytes: &[u8]) -> Result<(), HostError> {
        self.store.lock().insert(path.into(), bytes.to_vec());
        Ok(())
    }
    async fn chain_read_at(&self, chain: &str, path: &str, block: u64) -> Result<Vec<u8>, HostError> {
        let key = format!("@{block}:{chain}/{path}");
        self.store.lock().get(&key).cloned().ok_or_else(|| HostError::NotFound(key))
    }
}
```

(Replace the existing `impl PetalHost for MockHost` block with the above.) Then append these tests:

```rust
const ONCHAIN_TRIES_VFS_READ: &str = r#"
    (module
      (import "bloom" "vfs_read"
        (func $vfs_read (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 1)
      (func (export "_start") nop)
    )
"#;

#[tokio::test]
async fn onchain_vm_refuses_to_link_vfs_imports() {
    let vm = PetalVm::new().unwrap();
    let out = vm
        .run(
            &wat(ONCHAIN_TRIES_VFS_READ),
            Vec::new(),
            BTreeSet::new(),
            Arc::new(DenyHost),
            "h",
            PetalMode::Onchain,
            RunOptions::default(),
        )
        .await
        .unwrap();
    // Instantiation should fail (linker has no bloom.vfs_read in onchain mode).
    assert_eq!(out.exit_code, 127);
}

#[tokio::test]
async fn local_run_takes_mode_parameter_and_keeps_working() {
    let vm = PetalVm::new().unwrap();
    let out = vm
        .run(
            &wat(NOOP_WASI),
            Vec::new(),
            BTreeSet::new(),
            Arc::new(DenyHost),
            "h",
            PetalMode::Local,
            RunOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(out.exit_code, 0);
}
```

Add the imports at the top of the tests mod:

```rust
use crate::meta::PetalMode;
```

(Existing `vfs_read_denied_without_capability` etc. will need a `PetalMode::Local` argument — fix them in Step 4.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bloom-petals vm::tests::onchain_vm_refuses_to_link_vfs_imports`
Expected: FAIL — `run` doesn't take a `PetalMode` argument yet.

- [ ] **Step 3: Modify `PetalVm::run` signature and add mode dispatch**

In `crates/bloom-petals/src/vm.rs`, change the `run` method signature and add a `mode` parameter (around line 113). Replace the whole method body:

```rust
    pub async fn run(
        &self,
        wasm: &[u8],
        stdin: Vec<u8>,
        caps: BTreeSet<Capability>,
        host: Arc<dyn PetalHost>,
        petal_hash: &str,
        mode: crate::meta::PetalMode,
        opts: RunOptions,
    ) -> Result<RunOutput, PetalError> {
        let module =
            Module::new(&self.engine, wasm).map_err(|e| PetalError::InvalidWasm(e.to_string()))?;

        let stdout = MemoryOutputPipe::new(STDOUT_CAP);
        let stderr = MemoryOutputPipe::new(STDOUT_CAP);

        let mut wasi_builder = WasiCtxBuilder::new();
        wasi_builder
            .stdin(MemoryInputPipe::new(stdin))
            .stdout(stdout.clone())
            .stderr(stderr.clone());
        // v1 caveat: wasmtime-wasi 26's default WasiCtx exposes the
        // host wall/monotonic clock and a secure RNG, and the builder
        // does not expose a one-call "deny clock/random" switch. So
        // onchain petals that *call* clock_time_get/random_get today
        // will succeed with non-deterministic values. The replay
        // tooling will catch this as an output_hash mismatch; a
        // follow-up task wires deterministic clock+RNG via
        // `wall_clock(...)` / `secure_random(...)` for onchain mode.
        // (`mode` is still threaded into the linker dispatch and
        // StoreData below — only the WASI ctx is symmetric in v1.)
        let wasi_ctx = wasi_builder.build_p1();

        let mut store = Store::new(
            &self.engine,
            StoreData {
                wasi: wasi_ctx,
                host,
                caps,
                petal_hash: petal_hash.to_string(),
                mode,
            },
        );
        store
            .set_fuel(opts.fuel)
            .map_err(|e| PetalError::vm(e.to_string()))?;
        store.limiter(move |_| {
            Box::leak(Box::new(MemLimiter::new(opts.memory_pages)))
        });

        let mut linker = Linker::<StoreData>::new(&self.engine);
        link_wasi_for_mode(&mut linker, mode).map_err(|e| PetalError::vm(e.to_string()))?;
        link_imports_for_mode(&mut linker, mode).map_err(|e| PetalError::vm(e.to_string()))?;

        let exit_code = run_command(&mut store, &linker, &module).await;
        let fuel_consumed = opts.fuel.saturating_sub(store.get_fuel().unwrap_or(0));

        Ok(RunOutput {
            stdout: stdout.contents().to_vec(),
            stderr: stderr.contents().to_vec(),
            exit_code,
            fuel_consumed,
        })
    }
```

Add the `mode` field to `StoreData`:

```rust
pub struct StoreData {
    wasi: WasiP1Ctx,
    host: Arc<dyn PetalHost>,
    caps: BTreeSet<Capability>,
    petal_hash: String,
    mode: crate::meta::PetalMode,
}
```

Replace `add_bloom_host` with mode-branched helpers. Below the existing helper functions (after `run_command`), replace `fn add_bloom_host` with:

```rust
fn link_wasi_for_mode(linker: &mut Linker<StoreData>, _mode: crate::meta::PetalMode) -> anyhow::Result<()> {
    // v1 wires the full preview-1 linker for both modes. The mode
    // split is enforced by the bloom.* host-import set (no vfs_* in
    // onchain mode; no chain_read_at in local mode). A follow-up will
    // narrow the onchain WASI surface by overriding clock/random with
    // deterministic implementations.
    preview1::add_to_linker_async(linker, |s: &mut StoreData| &mut s.wasi)?;
    Ok(())
}

fn link_imports_for_mode(linker: &mut Linker<StoreData>, mode: crate::meta::PetalMode) -> anyhow::Result<()> {
    use crate::meta::PetalMode;
    match mode {
        PetalMode::Local => link_local_imports(linker),
        PetalMode::Onchain => link_onchain_imports(linker),
    }
}

fn link_local_imports(linker: &mut Linker<StoreData>) -> anyhow::Result<()> {
    linker.func_wrap_async(
        "bloom",
        "vfs_read",
        |mut caller: Caller<'_, StoreData>,
         params: (i32, i32, i32, i32)|
         -> Box<dyn std::future::Future<Output = i32> + Send + '_> {
            let (path_ptr, path_len, dst_ptr, dst_max) = params;
            Box::new(async move {
                let cap_ok = caller.data().caps.contains(&Capability::VfsRead);
                if !cap_ok {
                    log_denied(caller.data(), "vfs_read");
                    return HostError::Denied("vfs.read".into()).as_wasm_code();
                }
                let mem = match get_memory(&mut caller) {
                    Some(m) => m,
                    None => return HostError::Invalid("no exported memory".into()).as_wasm_code(),
                };
                let path = match read_string(&mem, &mut caller, path_ptr, path_len) {
                    Ok(s) => s,
                    Err(c) => return c,
                };
                let host = caller.data().host.clone();
                match host.vfs_read(&path).await {
                    Ok(bytes) => {
                        if dst_max < 0 {
                            return HostError::Invalid("dst_max < 0".into()).as_wasm_code();
                        }
                        let need = bytes.len();
                        if need > dst_max as usize {
                            return -((need as i32).saturating_add(PetalVm::OVERFLOW_BIAS));
                        }
                        if let Err(c) = write_bytes(&mem, &mut caller, dst_ptr, &bytes) {
                            return c;
                        }
                        need as i32
                    }
                    Err(e) => e.as_wasm_code(),
                }
            })
        },
    )?;

    linker.func_wrap_async(
        "bloom",
        "vfs_write",
        |mut caller: Caller<'_, StoreData>,
         params: (i32, i32, i32, i32)|
         -> Box<dyn std::future::Future<Output = i32> + Send + '_> {
            let (path_ptr, path_len, src_ptr, src_len) = params;
            Box::new(async move {
                let cap_ok = caller.data().caps.contains(&Capability::VfsWrite);
                if !cap_ok {
                    log_denied(caller.data(), "vfs_write");
                    return HostError::Denied("vfs.write".into()).as_wasm_code();
                }
                let mem = match get_memory(&mut caller) {
                    Some(m) => m,
                    None => return HostError::Invalid("no exported memory".into()).as_wasm_code(),
                };
                let path = match read_string(&mem, &mut caller, path_ptr, path_len) {
                    Ok(s) => s,
                    Err(c) => return c,
                };
                let bytes = match read_bytes(&mem, &mut caller, src_ptr, src_len) {
                    Ok(b) => b,
                    Err(c) => return c,
                };
                let host = caller.data().host.clone();
                match host.vfs_write(&path, &bytes).await {
                    Ok(()) => 0,
                    Err(e) => e.as_wasm_code(),
                }
            })
        },
    )?;
    Ok(())
}

fn link_onchain_imports(linker: &mut Linker<StoreData>) -> anyhow::Result<()> {
    linker.func_wrap_async(
        "bloom",
        "chain_read_at",
        |mut caller: Caller<'_, StoreData>,
         params: (i32, i32, i64, i32, i32)|
         -> Box<dyn std::future::Future<Output = i32> + Send + '_> {
            let (chain_ptr, chain_len, block, dst_ptr, dst_max) = params;
            Box::new(async move {
                let cap_ok = caller.data().caps.contains(&Capability::ChainRead);
                if !cap_ok {
                    log_denied(caller.data(), "chain_read_at");
                    return HostError::Denied("chain.read".into()).as_wasm_code();
                }
                if block == 0 {
                    return HostError::BlockNotPinnable.as_wasm_code();
                }
                let mem = match get_memory(&mut caller) {
                    Some(m) => m,
                    None => return HostError::Invalid("no exported memory".into()).as_wasm_code(),
                };
                // Argument layout is chain followed by path, both as
                // utf-8 byte slices. To keep the wasm ABI tight we
                // declared just (chain_ptr, chain_len). Path is encoded
                // as a separate sub-slice the wasm wrote in the chain
                // buffer with a NUL separator, OR (preferred) we
                // pass an additional pair. For v1 we use a single
                // utf-8 buffer of the form "<chain>\0<path>" so we
                // don't change the WAT ABI for this task. See vm.rs
                // for the parsing.
                let raw = match read_bytes(&mem, &mut caller, chain_ptr, chain_len) {
                    Ok(b) => b,
                    Err(c) => return c,
                };
                let (chain_bytes, path_bytes) = match raw.split(|b| *b == 0).collect::<Vec<_>>().as_slice() {
                    [c, p] => (c.to_vec(), p.to_vec()),
                    _ => return HostError::Invalid("chain_read_at: expected <chain>\\0<path> buffer".into()).as_wasm_code(),
                };
                let chain = match String::from_utf8(chain_bytes) {
                    Ok(s) => s,
                    Err(_) => return HostError::Invalid("chain not utf-8".into()).as_wasm_code(),
                };
                let path = match String::from_utf8(path_bytes) {
                    Ok(s) => s,
                    Err(_) => return HostError::Invalid("path not utf-8".into()).as_wasm_code(),
                };
                let host = caller.data().host.clone();
                match host.chain_read_at(&chain, &path, block as u64).await {
                    Ok(bytes) => {
                        if dst_max < 0 {
                            return HostError::Invalid("dst_max < 0".into()).as_wasm_code();
                        }
                        let need = bytes.len();
                        if need > dst_max as usize {
                            return -((need as i32).saturating_add(PetalVm::OVERFLOW_BIAS));
                        }
                        if let Err(c) = write_bytes(&mem, &mut caller, dst_ptr, &bytes) {
                            return c;
                        }
                        need as i32
                    }
                    Err(e) => e.as_wasm_code(),
                }
            })
        },
    )?;
    Ok(())
}
```

Note: the `chain_read_at` ABI takes a single combined `chain\0path` buffer rather than two separate `(ptr,len)` pairs. This keeps the wasm-side function signature at 5 params instead of 7 and matches the WAT fixture. Document this in the wasm-facing spec.

- [ ] **Step 4: Update all existing `run` call sites in tests to pass `PetalMode::Local`**

In `crates/bloom-petals/src/vm.rs` tests mod, find `vm.run(...)` and `host` calls and append `PetalMode::Local,` before the `RunOptions::default()` arg. Affected tests: `runs_noop_petal_and_returns_exit_code_zero`, `captures_stdout_from_wasi_fd_write`, `vfs_read_denied_without_capability`, `vfs_read_returns_payload_length_when_allowed`. Each becomes e.g.:

```rust
        let out = vm
            .run(
                &wat(NOOP_WASI),
                Vec::new(),
                BTreeSet::new(),
                Arc::new(DenyHost),
                "deadbeef",
                PetalMode::Local,
                RunOptions::default(),
            )
            .await
            .unwrap();
```

- [ ] **Step 5: Update `PetalRunner::run` and its test**

In `crates/bloom-petals/src/runner.rs`, update `PetalRunner::run` to thread `mode` through from meta:

```rust
    pub async fn run(
        &self,
        name_or_hash: &str,
        stdin: Vec<u8>,
        host: Arc<dyn PetalHost>,
        cap_mask: Option<BTreeSet<Capability>>,
        opts: RunOptions,
    ) -> Result<RunOutput, PetalError> {
        let hash = self.resolve(name_or_hash)?;
        let wasm = self.store.read_wasm(&hash)?;
        let meta = self.store.load_meta(&hash)?;
        let caps = match cap_mask {
            Some(mask) => meta.caps.intersection(&mask).copied().collect(),
            None => meta.caps.clone(),
        };
        self.vm.run(&wasm, stdin, caps, host, &hash, meta.mode, opts).await
    }
```

Update `PetalRunner::install` to take and forward a mode:

```rust
    pub fn install(
        &self,
        bytes: &[u8],
        name: Option<&str>,
        caps: &BTreeSet<Capability>,
        mode: crate::meta::PetalMode,
    ) -> Result<(InstallResult, PetalMeta), PetalError> {
        crate::meta::validate_mode_caps(mode, caps)?;
        let wasm = if bytes.starts_with(b"\0asm") {
            bytes.to_vec()
        } else {
            let s = std::str::from_utf8(bytes)
                .map_err(|_| PetalError::InvalidWasm("not wasm and not utf-8 WAT".into()))?;
            wat::parse_str(s).map_err(|e| PetalError::InvalidWasm(format!("wat: {e}")))?
        };
        let (result, meta) = self.store.install(&wasm, name, caps, mode)?;
        if let Some(n) = name {
            self.registry.set(n, &result.hash)?;
        }
        Ok((result, meta))
    }
```

Update the runner tests in the same file to pass `PetalMode::Local`:

```rust
        let (res, _meta) = r
            .install(HELLO_WAT.as_bytes(), Some("hello"), &BTreeSet::new(), crate::meta::PetalMode::Local)
            .unwrap();
```

(Apply the same change in `resolve_prefers_hash_then_name`.)

- [ ] **Step 6: Update store tests' `MockHost` and run the suite**

Run: `cargo test -p bloom-petals`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/bloom-petals/src/vm.rs crates/bloom-petals/src/runner.rs
git commit -m "petals: mode-branched linker and runner threads mode through"
```

---

## Task 8: Deterministic engine knobs

**Files:**
- Modify: `crates/bloom-petals/src/vm.rs`

- [ ] **Step 1: Write smoke test**

In `crates/bloom-petals/src/vm.rs` tests mod, append:

```rust
#[test]
fn vm_construction_with_deterministic_knobs_succeeds() {
    let vm = PetalVm::new().unwrap();
    drop(vm);
}
```

- [ ] **Step 2: Run test (passes trivially today)**

Run: `cargo test -p bloom-petals vm::tests::vm_construction_with_deterministic_knobs_succeeds`
Expected: PASS — this is a smoke test confirming construction still works after we flip the knobs.

- [ ] **Step 3: Enable the knobs in `PetalVm::new`**

In `crates/bloom-petals/src/vm.rs`, replace `PetalVm::new`:

```rust
    pub fn new() -> Result<Self, PetalError> {
        let mut config = Config::new();
        config.async_support(true);
        config.consume_fuel(true);
        config.cranelift_opt_level(wasmtime::OptLevel::Speed);
        // Cross-machine determinism cheap-knobs. NaN canonicalization
        // makes float ops bit-identical across CPUs that follow the
        // IEEE spec differently. wasm_relaxed_simd_deterministic forces
        // a single profile of the relaxed-SIMD ops. Engine-version
        // determinism is NOT addressed here.
        config.cranelift_nan_canonicalization(true);
        config.wasm_relaxed_simd(true);
        config.wasm_relaxed_simd_deterministic(true);
        let engine = Engine::new(&config).map_err(|e| PetalError::vm(e.to_string()))?;
        Ok(Self { engine })
    }
```

- [ ] **Step 4: Run full crate tests**

Run: `cargo test -p bloom-petals`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/bloom-petals/src/vm.rs
git commit -m "petals: enable NaN canonicalization + deterministic relaxed-SIMD"
```

---

## Task 9: Path-segmented VFS handler

**Files:**
- Modify: `crates/bloom-petals/src/handler.rs`

- [ ] **Step 1: Update failing tests**

Replace the existing tests in `crates/bloom-petals/src/handler.rs` `tests` mod with the path-segmented expectations:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::{Capability, PetalMode};
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    fn setup_with_modes() -> (TempDir, PetalsHandler, String, String) {
        let dir = TempDir::new().unwrap();
        let store = PetalStore::open(dir.path().join("store")).unwrap();
        let reg = Arc::new(NameRegistry::open(dir.path().join("reg")).unwrap());
        let mut local_caps = BTreeSet::new();
        local_caps.insert(Capability::VfsRead);
        let (rl, _) = store.install(b"\x00asm\x01\x00\x00\x00local", Some("greet"), &local_caps, PetalMode::Local).unwrap();
        let mut chain_caps = BTreeSet::new();
        chain_caps.insert(Capability::ChainRead);
        let (rc, _) = store.install(b"\x00asm\x01\x00\x00\x00onchain", Some("snap"), &chain_caps, PetalMode::Onchain).unwrap();
        reg.set("greet", &rl.hash).unwrap();
        reg.set("snap", &rc.hash).unwrap();
        let h = PetalsHandler::new(store, reg);
        (dir, h, rl.hash, rc.hash)
    }

    #[tokio::test]
    async fn root_lists_local_onchain_names() {
        let (_d, h, _, _) = setup_with_modes();
        let entries = h.list(&VfsPath::parse("/").unwrap()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"local"));
        assert!(names.contains(&"onchain"));
        assert!(names.contains(&"names"));
    }

    #[tokio::test]
    async fn local_subtree_lists_only_local_petals() {
        let (_d, h, local_hash, _onchain_hash) = setup_with_modes();
        let entries = h.list(&VfsPath::parse("/local").unwrap()).await.unwrap();
        let hashes: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(hashes.contains(&local_hash.as_str()), "missing local: {hashes:?}");
        assert!(hashes.iter().all(|n| n != &"snap" || *n == "greet"), "leaked onchain hash into local: {hashes:?}");
    }

    #[tokio::test]
    async fn onchain_hash_in_local_path_is_not_found() {
        let (_d, h, _local_hash, onchain_hash) = setup_with_modes();
        let p = VfsPath::parse(&format!("/local/{onchain_hash}")).unwrap();
        let err = h.lookup(&p).await.unwrap_err();
        assert!(matches!(err, HandlerError::NotFound(_)), "{err:?}");
    }

    #[tokio::test]
    async fn read_wasm_under_correct_mode_subtree() {
        let (_d, h, local_hash, _) = setup_with_modes();
        let p = VfsPath::parse(&format!("/local/{local_hash}/wasm")).unwrap();
        let body = h.read(&p).await.unwrap();
        assert_eq!(body, b"\x00asm\x01\x00\x00\x00local");
    }

    #[tokio::test]
    async fn write_to_names_sets_registry() {
        let (_d, h, local_hash, _) = setup_with_modes();
        let p = VfsPath::parse("/names/anothername").unwrap();
        h.write(&p, local_hash.as_bytes()).await.unwrap();
        assert_eq!(h.registry().lookup("anothername"), Some(local_hash));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bloom-petals handler::tests::root_lists_local_onchain_names`
Expected: FAIL — current handler exposes `<hash>` at top level, not `<mode>/<hash>`.

- [ ] **Step 3: Rewrite the handler routing**

Replace the entire `impl Handler for PetalsHandler` block (and `NAMES_DIR` is already declared above it) in `crates/bloom-petals/src/handler.rs` with:

```rust
const LOCAL_DIR: &str = "local";
const ONCHAIN_DIR: &str = "onchain";

use crate::meta::PetalMode;

#[async_trait]
impl Handler for PetalsHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        match path.segments() {
            [] => Ok(Entry::dir("")),
            [seg] if seg == NAMES_DIR => Ok(Entry::dir(NAMES_DIR)),
            [seg] if seg == LOCAL_DIR => Ok(Entry::dir(LOCAL_DIR)),
            [seg] if seg == ONCHAIN_DIR => Ok(Entry::dir(ONCHAIN_DIR)),
            [first, rest @ ..] if first == NAMES_DIR => match rest {
                [name] => {
                    validate_name(name).map_err(map_err)?;
                    let entry = match self.registry.lookup(name) {
                        Some(_) => {
                            let mut e = Entry::writable_file(name);
                            e.size = 64;
                            e
                        }
                        None => Entry::writable_file(name),
                    };
                    Ok(entry)
                }
                _ => Err(HandlerError::NotFound(path.to_string_path())),
            },
            [mode_seg, hash, rest @ ..] if is_mode_dir(mode_seg) && is_valid_hex_hash(hash) => {
                let expected_mode = mode_for_seg(mode_seg);
                let meta = self.store.load_meta(hash).map_err(map_err)?;
                if meta.mode != expected_mode {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                }
                match rest {
                    [] => Ok(Entry::dir(hash)),
                    [child] if child == "wasm" => {
                        let mut e = Entry::read_only_file("wasm");
                        e.size = meta.size;
                        Ok(e)
                    }
                    [child] if child == "meta.json" => {
                        let body = serde_json::to_vec_pretty(&meta)
                            .map_err(|e| HandlerError::Backend(e.to_string()))?;
                        let mut e = Entry::read_only_file("meta.json");
                        e.size = body.len() as u64;
                        Ok(e)
                    }
                    _ => Err(HandlerError::NotFound(path.to_string_path())),
                }
            }
            [mode_seg, name] if is_mode_dir(mode_seg) => {
                let expected_mode = mode_for_seg(mode_seg);
                let Some(hash) = self.registry.lookup(name) else {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                };
                let meta = self.store.load_meta(&hash).map_err(map_err)?;
                if meta.mode != expected_mode {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                }
                Ok(Entry::symlink(name, &hash))
            }
            _ => Err(HandlerError::NotFound(path.to_string_path())),
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        match path.segments() {
            [first, rest @ ..] if first == NAMES_DIR => match rest {
                [name] => {
                    validate_name(name).map_err(map_err)?;
                    match self.registry.lookup(name) {
                        Some(hash) => {
                            let mut out = hash.into_bytes();
                            out.push(b'\n');
                            Ok(out)
                        }
                        None => Err(HandlerError::NotFound(path.to_string_path())),
                    }
                }
                _ => Err(HandlerError::NotAFile(path.to_string_path())),
            },
            [mode_seg, hash, child] if is_mode_dir(mode_seg) && is_valid_hex_hash(hash) => {
                let expected_mode = mode_for_seg(mode_seg);
                let meta = self.store.load_meta(hash).map_err(map_err)?;
                if meta.mode != expected_mode {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                }
                match child.as_str() {
                    "wasm" => self.store.read_wasm(hash).map_err(map_err),
                    "meta.json" => {
                        serde_json::to_vec_pretty(&meta)
                            .map(|mut v| {
                                v.push(b'\n');
                                v
                            })
                            .map_err(|e| HandlerError::Backend(e.to_string()))
                    }
                    _ => Err(HandlerError::NotFound(path.to_string_path())),
                }
            }
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        match path.segments() {
            [first, rest @ ..] if first == NAMES_DIR => match rest {
                [name] => {
                    validate_name(name).map_err(map_err)?;
                    let body = std::str::from_utf8(data)
                        .map_err(|_| HandlerError::invalid("name body not utf-8"))?
                        .trim();
                    if body.is_empty() {
                        self.registry.unset(name).map_err(map_err)?;
                        return Ok(());
                    }
                    if !is_valid_hex_hash(body) {
                        return Err(HandlerError::invalid(format!(
                            "expected 64-char hex hash, got {body:?}"
                        )));
                    }
                    if !self.store.contains(body) {
                        return Err(HandlerError::NotFound(format!("petal {body}")));
                    }
                    self.registry.set(name, body).map_err(map_err)
                }
                _ => Err(HandlerError::PermissionDenied),
            },
            _ => Err(HandlerError::PermissionDenied),
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        match path.segments() {
            [] => Ok(vec![
                Entry::dir(LOCAL_DIR),
                Entry::dir(ONCHAIN_DIR),
                Entry::dir(NAMES_DIR),
            ]),
            [seg] if seg == NAMES_DIR => {
                let mut out = Vec::new();
                for (name, _hash) in self.registry.snapshot() {
                    let mut e = Entry::writable_file(&name);
                    e.size = 64;
                    out.push(e);
                }
                Ok(out)
            }
            [seg] if is_mode_dir(seg) => {
                let mode = mode_for_seg(seg);
                let mut out = Vec::new();
                for hash in self.store.list_hashes_by_mode(mode).map_err(map_err)? {
                    out.push(Entry::dir(&hash));
                }
                for (name, hash) in self.registry.snapshot() {
                    if let Ok(meta) = self.store.load_meta(&hash) {
                        if meta.mode == mode {
                            out.push(Entry::symlink(&name, &hash));
                        }
                    }
                }
                Ok(out)
            }
            [mode_seg, hash] if is_mode_dir(mode_seg) && is_valid_hex_hash(hash) => {
                let expected_mode = mode_for_seg(mode_seg);
                let meta = self.store.load_meta(hash).map_err(map_err)?;
                if meta.mode != expected_mode {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                }
                let mut wasm = Entry::read_only_file("wasm");
                wasm.size = meta.size;
                let meta_body = serde_json::to_vec_pretty(&meta)
                    .map_err(|e| HandlerError::Backend(e.to_string()))?;
                let mut meta_entry = Entry::read_only_file("meta.json");
                meta_entry.size = (meta_body.len() + 1) as u64;
                Ok(vec![wasm, meta_entry])
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }
}

fn is_mode_dir(s: &str) -> bool {
    s == LOCAL_DIR || s == ONCHAIN_DIR
}

fn mode_for_seg(s: &str) -> PetalMode {
    if s == ONCHAIN_DIR {
        PetalMode::Onchain
    } else {
        PetalMode::Local
    }
}
```

Note: the existing `map_err` helper at the bottom of the file already includes an arm for `PetalError::Io`; you'll need to extend it for the new error variants. Add inside the `match e` block (anywhere before the closing brace):

```rust
        PetalError::ModeConflict { existing } => HandlerError::invalid(format!("mode conflict: {existing:?}")),
        PetalError::ModeCapMismatch { mode, cap } => HandlerError::invalid(format!("mode/cap mismatch: {mode:?}/{cap}")),
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p bloom-petals handler::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/bloom-petals/src/handler.rs
git commit -m "petals: path-segmented VFS under public/{local,onchain,names}"
```

---

## Task 10: PetalAttestation type

**Files:**
- Create: `crates/bloom-petals/src/attestation.rs`
- Modify: `crates/bloom-petals/src/lib.rs`

- [ ] **Step 1: Write the file with its tests**

Create `crates/bloom-petals/src/attestation.rs`:

```rust
//! Replayability attestation tuple emitted for onchain petal runs.
//!
//! An attestation is the public summary of an onchain run that someone
//! else can use to *verify* the run by re-executing the named petal
//! against the named input and checking the output hash matches. Block
//! pinning is captured so a verifier knows the historical context.

use serde::{Deserialize, Serialize};

/// BLAKE3 of arbitrary bytes, hex-encoded.
pub fn blake3_hex(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PetalAttestation {
    /// Content hash of the petal wasm.
    pub petal_hash: String,
    /// BLAKE3 of the stdin bytes passed to the run.
    pub input_hash: String,
    /// BLAKE3 of the stdout bytes captured from the run.
    pub output_hash: String,
    /// Highest block number observed in any `chain_read_at` call, or
    /// `None` if the petal made no chain reads.
    pub block_pin: Option<u64>,
    /// Wasmtime version used to execute the run. Diagnostic only.
    pub wasmtime_version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_hex_matches_known_vector() {
        // BLAKE3 of empty input is a known constant.
        assert_eq!(
            blake3_hex(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn attestation_serde_roundtrip() {
        let a = PetalAttestation {
            petal_hash: "p".into(),
            input_hash: "i".into(),
            output_hash: "o".into(),
            block_pin: Some(42),
            wasmtime_version: "26.0.0".into(),
        };
        let s = serde_json::to_string(&a).unwrap();
        let a2: PetalAttestation = serde_json::from_str(&s).unwrap();
        assert_eq!(a, a2);
    }
}
```

- [ ] **Step 2: Export from `lib.rs`**

In `crates/bloom-petals/src/lib.rs`, add the module declaration and re-exports. After the existing `pub mod` declarations:

```rust
pub mod attestation;
pub use attestation::{PetalAttestation, blake3_hex};
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p bloom-petals attestation::`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/bloom-petals/src/attestation.rs crates/bloom-petals/src/lib.rs
git commit -m "petals: add PetalAttestation tuple and BLAKE3 helper"
```

---

## Task 11: BlockTrackingHost and runner attestation

**Files:**
- Modify: `crates/bloom-petals/src/runner.rs`

- [ ] **Step 1: Write failing test**

Append to `crates/bloom-petals/src/runner.rs` tests mod:

```rust
const ONCHAIN_NOOP: &str = r#"
    (module
      (import "wasi_snapshot_preview1" "proc_exit"
        (func $exit (param i32)))
      (memory (export "memory") 1)
      (func (export "_start")
        i32.const 0
        call $exit)
    )
"#;

#[tokio::test]
async fn onchain_run_returns_attestation_with_input_and_output_hashes() {
    let (_d, r) = runner();
    let (res, _) = r
        .install(
            ONCHAIN_NOOP.as_bytes(),
            Some("noop"),
            &BTreeSet::new(),
            crate::meta::PetalMode::Onchain,
        )
        .unwrap();
    let stdin = b"hello".to_vec();
    let (out, att) = r
        .run_attested(
            "noop",
            stdin.clone(),
            Arc::new(crate::host::DenyHost),
            None,
            RunOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(out.exit_code, 0);
    let att = att.expect("onchain run must produce attestation");
    assert_eq!(att.petal_hash, res.hash);
    assert_eq!(att.input_hash, crate::attestation::blake3_hex(&stdin));
    assert_eq!(att.output_hash, crate::attestation::blake3_hex(&out.stdout));
    assert!(att.block_pin.is_none(), "noop petal makes no chain reads");
}

#[tokio::test]
async fn local_run_returns_no_attestation() {
    let (_d, r) = runner();
    let (_res, _) = r
        .install(HELLO_WAT.as_bytes(), Some("hello"), &BTreeSet::new(), crate::meta::PetalMode::Local)
        .unwrap();
    let (_out, att) = r
        .run_attested("hello", Vec::new(), Arc::new(crate::host::DenyHost), None, RunOptions::default())
        .await
        .unwrap();
    assert!(att.is_none(), "local runs do not produce attestations");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bloom-petals runner::tests::onchain_run_returns_attestation_with_input_and_output_hashes`
Expected: FAIL with `no method named 'run_attested' found`.

- [ ] **Step 3: Add `BlockTrackingHost` wrapper and `run_attested`**

In `crates/bloom-petals/src/runner.rs`, add after `VfsHost`:

```rust
/// Wraps any `PetalHost` and records the maximum `block` argument seen
/// across `chain_read_at` calls. Used by `PetalRunner::run_attested` to
/// stamp `block_pin` into the attestation tuple.
pub struct BlockTrackingHost {
    inner: Arc<dyn PetalHost>,
    max_block: parking_lot::Mutex<Option<u64>>,
}

impl BlockTrackingHost {
    pub fn new(inner: Arc<dyn PetalHost>) -> Self {
        Self { inner, max_block: parking_lot::Mutex::new(None) }
    }

    pub fn max_block(&self) -> Option<u64> {
        *self.max_block.lock()
    }
}

#[async_trait]
impl PetalHost for BlockTrackingHost {
    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
        self.inner.vfs_read(path).await
    }
    async fn vfs_write(&self, path: &str, bytes: &[u8]) -> Result<(), HostError> {
        self.inner.vfs_write(path, bytes).await
    }
    async fn chain_read_at(&self, chain: &str, path: &str, block: u64) -> Result<Vec<u8>, HostError> {
        {
            let mut m = self.max_block.lock();
            *m = Some(match *m { Some(prev) => prev.max(block), None => block });
        }
        self.inner.chain_read_at(chain, path, block).await
    }
}
```

Add to `impl PetalRunner` (after `run`):

```rust
    /// Run a petal and, when the petal is onchain, also return a
    /// `PetalAttestation` summarizing (input_hash, output_hash, block_pin).
    pub async fn run_attested(
        &self,
        name_or_hash: &str,
        stdin: Vec<u8>,
        host: Arc<dyn PetalHost>,
        cap_mask: Option<BTreeSet<Capability>>,
        opts: RunOptions,
    ) -> Result<(RunOutput, Option<crate::attestation::PetalAttestation>), PetalError> {
        let hash = self.resolve(name_or_hash)?;
        let wasm = self.store.read_wasm(&hash)?;
        let meta = self.store.load_meta(&hash)?;
        let caps = match cap_mask {
            Some(mask) => meta.caps.intersection(&mask).copied().collect(),
            None => meta.caps.clone(),
        };
        let tracker = Arc::new(BlockTrackingHost::new(host));
        let stdin_hash = crate::attestation::blake3_hex(&stdin);
        let out = self
            .vm
            .run(&wasm, stdin.clone(), caps, tracker.clone(), &hash, meta.mode, opts)
            .await?;
        let att = match meta.mode {
            crate::meta::PetalMode::Onchain => Some(crate::attestation::PetalAttestation {
                petal_hash: hash.clone(),
                input_hash: stdin_hash,
                output_hash: crate::attestation::blake3_hex(&out.stdout),
                block_pin: tracker.max_block(),
                wasmtime_version: env!("CARGO_PKG_VERSION").to_string(),
            }),
            crate::meta::PetalMode::Local => None,
        };
        Ok((out, att))
    }
```

Note: `env!("CARGO_PKG_VERSION")` records the bloom-petals crate version, not wasmtime's. For v1 this is acceptable as a diagnostic — a more accurate option (`wasmtime::VERSION`) is a follow-up.

Also add `parking_lot` to `crates/bloom-petals/Cargo.toml` `[dependencies]` if it's not already there. Check:

```bash
grep parking_lot crates/bloom-petals/Cargo.toml
```

If missing, add: `parking_lot.workspace = true`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p bloom-petals runner::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/bloom-petals/src/runner.rs crates/bloom-petals/Cargo.toml
git commit -m "petals: BlockTrackingHost + run_attested emits onchain attestation"
```

---

## Task 12: Runner `uninstall`

**Files:**
- Modify: `crates/bloom-petals/src/runner.rs`

- [ ] **Step 1: Write failing test**

Append to `crates/bloom-petals/src/runner.rs` tests mod:

```rust
#[tokio::test]
async fn uninstall_removes_object_meta_and_petname() {
    let (_d, r) = runner();
    let (res, _) = r
        .install(HELLO_WAT.as_bytes(), Some("byename"), &BTreeSet::new(), crate::meta::PetalMode::Local)
        .unwrap();
    assert!(r.store().contains(&res.hash));
    assert_eq!(r.registry().lookup("byename"), Some(res.hash.clone()));
    let removed = r.uninstall(&res.hash).unwrap();
    assert!(removed);
    assert!(!r.store().contains(&res.hash));
    assert!(r.registry().lookup("byename").is_none());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p bloom-petals runner::tests::uninstall_removes_object_meta_and_petname`
Expected: FAIL with `no method named 'uninstall' found`.

- [ ] **Step 3: Implement `PetalRunner::uninstall`**

Add to `impl PetalRunner`:

```rust
    /// Remove an installed petal and any petname pointing at it.
    /// Returns true if anything was removed.
    pub fn uninstall(&self, hash: &str) -> Result<bool, PetalError> {
        // Snapshot petnames before deleting the meta so we can find
        // the ones to unset.
        let to_unset: Vec<String> = self
            .registry
            .snapshot()
            .into_iter()
            .filter_map(|(n, h)| if h == hash { Some(n) } else { None })
            .collect();
        let removed = self.store.uninstall(hash)?;
        for n in to_unset {
            self.registry.unset(&n)?;
        }
        Ok(removed)
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p bloom-petals runner::tests::uninstall_removes_object_meta_and_petname`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/bloom-petals/src/runner.rs
git commit -m "petals: PetalRunner::uninstall removes petnames too"
```

---

## Task 13: Replay helper on PetalRunner

**Files:**
- Modify: `crates/bloom-petals/src/runner.rs`

- [ ] **Step 1: Write failing test**

Append to `crates/bloom-petals/src/runner.rs` tests mod:

```rust
#[tokio::test]
async fn replay_match_returns_ok_with_expected_hash() {
    let (_d, r) = runner();
    let (_res, _) = r
        .install(ONCHAIN_NOOP.as_bytes(), Some("rnoop"), &BTreeSet::new(), crate::meta::PetalMode::Onchain)
        .unwrap();
    let stdin = b"x".to_vec();
    // First, capture the real output hash.
    let (_out, att) = r
        .run_attested("rnoop", stdin.clone(), Arc::new(crate::host::DenyHost), None, RunOptions::default())
        .await
        .unwrap();
    let expected = att.unwrap().output_hash;
    let outcome = r
        .replay("rnoop", stdin.clone(), &expected, Arc::new(crate::host::DenyHost), RunOptions::default())
        .await
        .unwrap();
    assert!(outcome.matched);
    assert_eq!(outcome.actual_output_hash, expected);
}

#[tokio::test]
async fn replay_mismatch_returns_outcome_with_flag_false() {
    let (_d, r) = runner();
    let (_res, _) = r
        .install(ONCHAIN_NOOP.as_bytes(), Some("rnoop2"), &BTreeSet::new(), crate::meta::PetalMode::Onchain)
        .unwrap();
    let outcome = r
        .replay(
            "rnoop2",
            b"input".to_vec(),
            "0".repeat(64).as_str(),
            Arc::new(crate::host::DenyHost),
            RunOptions::default(),
        )
        .await
        .unwrap();
    assert!(!outcome.matched);
}

#[tokio::test]
async fn replay_refuses_local_petal() {
    let (_d, r) = runner();
    let (_res, _) = r
        .install(HELLO_WAT.as_bytes(), Some("loc"), &BTreeSet::new(), crate::meta::PetalMode::Local)
        .unwrap();
    let err = r
        .replay("loc", Vec::new(), &"0".repeat(64), Arc::new(crate::host::DenyHost), RunOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(err, PetalError::Vm(_)), "{err:?}");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bloom-petals runner::tests::replay_match_returns_ok_with_expected_hash`
Expected: FAIL with `no method named 'replay' found`.

- [ ] **Step 3: Implement `ReplayOutcome` and `PetalRunner::replay`**

Add to `crates/bloom-petals/src/runner.rs`:

```rust
#[derive(Debug, Clone)]
pub struct ReplayOutcome {
    pub matched: bool,
    pub actual_output_hash: String,
    pub run: RunOutput,
    pub attestation: crate::attestation::PetalAttestation,
}

impl PetalRunner {
    pub async fn replay(
        &self,
        name_or_hash: &str,
        stdin: Vec<u8>,
        expected_output_hash: &str,
        host: Arc<dyn PetalHost>,
        opts: RunOptions,
    ) -> Result<ReplayOutcome, PetalError> {
        let hash = self.resolve(name_or_hash)?;
        let meta = self.store.load_meta(&hash)?;
        if meta.mode != crate::meta::PetalMode::Onchain {
            return Err(PetalError::Vm("replay only valid for onchain petals".into()));
        }
        let (run, att) = self.run_attested(name_or_hash, stdin, host, None, opts).await?;
        let att = att.expect("onchain run must produce attestation");
        let matched = att.output_hash == expected_output_hash;
        Ok(ReplayOutcome {
            matched,
            actual_output_hash: att.output_hash.clone(),
            run,
            attestation: att,
        })
    }
}
```

Note: this is a `impl PetalRunner` block separate from the existing one. Rust accepts multiple `impl` blocks for the same type.

Also export `ReplayOutcome` from `crates/bloom-petals/src/lib.rs`:

```rust
pub use runner::{PetalRunner, ReplayOutcome, BlockTrackingHost};
```

(Add to the existing re-export line; if the line doesn't exist, add it after the `pub mod runner;` declaration.)

- [ ] **Step 4: Run tests**

Run: `cargo test -p bloom-petals runner::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/bloom-petals/src/runner.rs crates/bloom-petals/src/lib.rs
git commit -m "petals: PetalRunner::replay diffs output hash against expected"
```

---

## Task 14: IPC — mode on install, uninstall, replay, attestation in run response

**Files:**
- Modify: `crates/bloom-daemon/src/ipc.rs`

- [ ] **Step 1: Inspect current IPC handlers**

Run: `grep -n "petals\\." crates/bloom-daemon/src/ipc.rs`
Expected: locates `do_petals_install`, `do_petals_run`, `do_petals_ls`, `do_petals_name`. Note the line ranges.

- [ ] **Step 2: Add `mode` field to install request**

In `crates/bloom-daemon/src/ipc.rs`, find `do_petals_install` and modify the param parsing to accept `mode`. Replace the function body with:

```rust
    async fn do_petals_install(&self, params: &Value) -> Result<Value, PetalError> {
        let runner = self.petals.as_ref().ok_or_else(|| PetalError::vm("petals not enabled"))?;
        let path = params.get("path").and_then(|v| v.as_str())
            .ok_or_else(|| PetalError::vm("install: path required"))?;
        let name = params.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
        let caps = parse_caps(params.get("caps"))?;
        let mode = match params.get("mode").and_then(|v| v.as_str()).unwrap_or("local") {
            "local" => bloom_petals::meta::PetalMode::Local,
            "onchain" => bloom_petals::meta::PetalMode::Onchain,
            other => return Err(PetalError::vm(format!("install: unknown mode {other:?}"))),
        };
        let bytes = tokio::fs::read(path).await.map_err(|e| PetalError::Io(e))?;
        let (res, meta) = runner.install(&bytes, name.as_deref(), &caps, mode)?;
        Ok(serde_json::json!({
            "hash": res.hash,
            "mode": meta.mode_str(),
        }))
    }
```

You'll need a helper `mode_str` on `PetalMode`. Add to `crates/bloom-petals/src/meta.rs`:

```rust
impl PetalMode {
    pub fn as_str(self) -> &'static str {
        match self {
            PetalMode::Local => "local",
            PetalMode::Onchain => "onchain",
        }
    }
}

// And on PetalMeta as a convenience used by IPC:
impl PetalMeta {
    pub fn mode_str(&self) -> &'static str {
        self.mode.as_str()
    }
}
```

- [ ] **Step 3: Echo `mode` in `petals.run` response and emit attestation**

Find `do_petals_run` in `crates/bloom-daemon/src/ipc.rs` and modify the response. The relevant snippet (current shape — adapt to actual code):

```rust
    async fn do_petals_run(&self, params: &Value) -> Result<Value, PetalError> {
        let runner = self.petals.as_ref().ok_or_else(|| PetalError::vm("petals not enabled"))?;
        let nh = params.get("name_or_hash").and_then(|v| v.as_str())
            .ok_or_else(|| PetalError::vm("run: name_or_hash required"))?;
        let stdin = decode_b64_field(params, "input_b64")?;
        let mask = params.get("cap_mask").map(parse_caps).transpose()?;
        let host = Arc::new(bloom_petals::runner::VfsHost::new(self.vfs_arc.clone())) as Arc<dyn bloom_petals::host::PetalHost>;
        let (out, att) = runner
            .run_attested(nh, stdin, host, mask, bloom_petals::vm::RunOptions::default())
            .await?;
        let hash = runner.resolve(nh)?;
        let meta = runner.store().load_meta(&hash)?;
        let mut body = serde_json::json!({
            "stdout_b64": base64_encode(&out.stdout),
            "stderr_b64": base64_encode(&out.stderr),
            "exit": out.exit_code,
            "mode": meta.mode_str(),
        });
        if let Some(a) = att {
            body["attestation"] = serde_json::to_value(&a).map_err(|e| PetalError::Serde(e.to_string()))?;
        }
        Ok(body)
    }
```

Adapt to the actual symbol names in the current file (`decode_b64_field`, `base64_encode`, `parse_caps` may have slightly different shapes — preserve what's there).

- [ ] **Step 4: Add `do_petals_uninstall` and `do_petals_replay`**

In `crates/bloom-daemon/src/ipc.rs`, add two new methods alongside the existing `do_petals_*` family:

```rust
    async fn do_petals_uninstall(&self, params: &Value) -> Result<Value, PetalError> {
        let runner = self.petals.as_ref().ok_or_else(|| PetalError::vm("petals not enabled"))?;
        let hash = params.get("hash").and_then(|v| v.as_str())
            .ok_or_else(|| PetalError::vm("uninstall: hash required"))?;
        let removed = runner.uninstall(hash)?;
        Ok(serde_json::json!({ "ok": removed }))
    }

    async fn do_petals_replay(&self, params: &Value) -> Result<Value, PetalError> {
        let runner = self.petals.as_ref().ok_or_else(|| PetalError::vm("petals not enabled"))?;
        let nh = params.get("name_or_hash").and_then(|v| v.as_str())
            .ok_or_else(|| PetalError::vm("replay: name_or_hash required"))?;
        let stdin = decode_b64_field(params, "input_b64")?;
        let expect = params.get("expect_output_hash").and_then(|v| v.as_str())
            .ok_or_else(|| PetalError::vm("replay: expect_output_hash required"))?;
        let host = Arc::new(bloom_petals::runner::VfsHost::new(self.vfs_arc.clone())) as Arc<dyn bloom_petals::host::PetalHost>;
        let outcome = runner.replay(nh, stdin, expect, host, bloom_petals::vm::RunOptions::default()).await?;
        Ok(serde_json::json!({
            "actual_output_hash": outcome.actual_output_hash,
            "match": outcome.matched,
            "exit": outcome.run.exit_code,
            "attestation": serde_json::to_value(&outcome.attestation)
                .map_err(|e| PetalError::Serde(e.to_string()))?,
        }))
    }
```

Then wire them into the dispatch (the `match method { ... }` block in the same file):

```rust
            "petals.uninstall" => self.do_petals_uninstall(&req.params).await.map(Value::from),
            "petals.replay" => self.do_petals_replay(&req.params).await.map(Value::from),
```

(Match the existing routing style.)

- [ ] **Step 5: Build to verify**

Run: `cargo build -p bloom-daemon`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/bloom-daemon/src/ipc.rs crates/bloom-petals/src/meta.rs
git commit -m "ipc: petals install mode, uninstall, replay, attestation in run response"
```

---

## Task 15: CLI `--mode`, uninstall, replay, ls mode column

**Files:**
- Modify: `crates/bloom/src/main.rs`

- [ ] **Step 1: Inspect current `PetalsCmd`**

Run: `grep -n "PetalsCmd\\|enum PetalsCmd\\|Petals(" crates/bloom/src/main.rs`
Expected: locates the `PetalsCmd` enum definition and the `run_petals` function.

- [ ] **Step 2: Add `--mode` flag, `Uninstall`, `Replay` variants**

In `crates/bloom/src/main.rs`, modify the `PetalsCmd` enum (around the current `Install`/`Run`/`Ls`/`Name` block):

```rust
#[derive(Subcommand, Debug)]
enum PetalsCmd {
    Install {
        path: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long = "cap", value_name = "CAP")]
        caps: Vec<String>,
        #[arg(long, default_value = "local", value_parser = ["local", "onchain"])]
        mode: String,
    },
    Run {
        name_or_hash: String,
        #[arg(long)]
        input: Option<String>,
        #[arg(long = "cap", value_name = "CAP")]
        cap_mask: Vec<String>,
    },
    Ls,
    Name {
        name: String,
        hash: Option<String>,
    },
    Uninstall {
        hash: String,
    },
    Replay {
        name_or_hash: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        expect: String,
    },
}
```

- [ ] **Step 3: Update `run_petals` to handle the new variants and forward `mode`**

In `crates/bloom/src/main.rs`, find the `match cmd { ... }` block inside `run_petals` and update/add arms. Show only the changed/added arms (preserve the existing ones in style):

```rust
        PetalsCmd::Install { path, name, caps, mode } => {
            let params = serde_json::json!({
                "path": path,
                "name": name,
                "caps": caps,
                "mode": mode,
            });
            let resp = client.call("petals.install", params).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
            Ok(())
        }
        PetalsCmd::Uninstall { hash } => {
            let resp = client.call("petals.uninstall", serde_json::json!({"hash": hash})).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
            Ok(())
        }
        PetalsCmd::Replay { name_or_hash, input, expect } => {
            let bytes = if input == "-" {
                let mut buf = Vec::new();
                use std::io::Read;
                std::io::stdin().read_to_end(&mut buf)?;
                buf
            } else {
                std::fs::read(&input)?
            };
            let params = serde_json::json!({
                "name_or_hash": name_or_hash,
                "input_b64": base64::engine::general_purpose::STANDARD.encode(&bytes),
                "expect_output_hash": expect,
            });
            let resp = client.call("petals.replay", params).await?;
            let matched = resp.get("match").and_then(|v| v.as_bool()).unwrap_or(false);
            let actual = resp.get("actual_output_hash").and_then(|v| v.as_str()).unwrap_or("");
            if matched {
                println!("match: {actual}");
                Ok(())
            } else {
                eprintln!("mismatch:\n  expected: {expect}\n  actual:   {actual}");
                std::process::exit(1);
            }
        }
```

- [ ] **Step 4: Add `mode` column to `Ls`**

Find the existing `PetalsCmd::Ls` arm and replace it to render a `mode` column. The current implementation likely calls a `petals.ls` IPC method and prints a table; pull the `mode` field out of each row:

```rust
        PetalsCmd::Ls => {
            let resp = client.call("petals.ls", serde_json::json!({})).await?;
            let items = resp.as_array().cloned().unwrap_or_default();
            println!("{:<16} {:<8} {:<22} {}", "HASH", "MODE", "CAPS", "NAME");
            for item in items {
                let hash = item.get("hash").and_then(|v| v.as_str()).unwrap_or("");
                let mode = item.get("mode").and_then(|v| v.as_str()).unwrap_or("local");
                let caps = item.get("caps").and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(","))
                    .unwrap_or_default();
                let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let short = &hash.get(..14).unwrap_or(hash);
                println!("{short:<16} {mode:<8} {caps:<22} {name}");
            }
            Ok(())
        }
```

Adapt to the actual `petals.ls` response shape. If `mode` isn't present (older response), add it on the daemon side by including `meta.mode_str()` in each row of the existing `do_petals_ls` handler. Locate it in `crates/bloom-daemon/src/ipc.rs` and add a `"mode": meta.mode_str(),` field to the per-row JSON.

- [ ] **Step 5: Build to verify**

Run: `cargo build -p bloom`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/bloom/src/main.rs crates/bloom-daemon/src/ipc.rs
git commit -m "bloom: CLI --mode, uninstall, replay, mode column in ls"
```

---

## Task 16: Integration tests for mode flow

**Files:**
- Create: `crates/bloom/tests/fixtures/onchain_echo.wat`
- Modify: `crates/bloom/tests/cli.rs`

- [ ] **Step 1: Add the onchain fixture**

Create `crates/bloom/tests/fixtures/onchain_echo.wat`:

```wat
(module
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $exit (param i32)))
  (memory (export "memory") 1)
  ;; Echo the first 16 bytes of stdin to stdout. Reads to address 32,
  ;; iovec at 0 (ptr=32, max=16), nread at 16. Then writes whatever
  ;; was actually read.
  (data (i32.const 0) "\20\00\00\00\10\00\00\00") ;; iovec: ptr=32, max=16
  (func (export "_start")
    (local $n i32)
    (call $fd_read
      (i32.const 0)  ;; stdin
      (i32.const 0)  ;; iovec ptr
      (i32.const 1)  ;; iovec count
      (i32.const 16)) ;; nread ptr
    drop
    (local.set $n (i32.load (i32.const 16)))
    ;; Stdout iovec at 64: ptr=32, len=$n.
    (i32.store (i32.const 64) (i32.const 32))
    (i32.store (i32.const 68) (local.get $n))
    (call $fd_write
      (i32.const 1)
      (i32.const 64)
      (i32.const 1)
      (i32.const 72))
    drop
    (call $exit (i32.const 0)))
)
```

- [ ] **Step 2: Add failing integration test**

In `crates/bloom/tests/cli.rs`, append:

```rust
#[test]
fn install_onchain_with_chain_read_cap_lists_mode() {
    let dir = tempfile::tempdir().unwrap();
    let socket = start_daemon(&dir).expect("daemon up");
    let wat = include_str!("fixtures/onchain_echo.wat");
    let wat_path = dir.path().join("echo.wat");
    std::fs::write(&wat_path, wat).unwrap();
    bloom_cmd(&socket)
        .args(["petals", "install", wat_path.to_str().unwrap(), "--name", "echo",
               "--cap", "chain.read", "--mode", "onchain"])
        .assert()
        .success();
    bloom_cmd(&socket)
        .args(["petals", "ls"])
        .assert()
        .success()
        .stdout(predicates::str::contains("onchain"))
        .stdout(predicates::str::contains("echo"));
}

#[test]
fn install_onchain_with_vfs_cap_fails_with_mode_cap_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let socket = start_daemon(&dir).expect("daemon up");
    let wat = include_str!("fixtures/onchain_echo.wat");
    let wat_path = dir.path().join("echo.wat");
    std::fs::write(&wat_path, wat).unwrap();
    bloom_cmd(&socket)
        .args(["petals", "install", wat_path.to_str().unwrap(), "--name", "x",
               "--cap", "vfs.read", "--mode", "onchain"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("mode/cap"));
}

#[test]
fn install_same_hash_two_modes_returns_mode_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let socket = start_daemon(&dir).expect("daemon up");
    let wat = include_str!("fixtures/onchain_echo.wat");
    let wat_path = dir.path().join("echo.wat");
    std::fs::write(&wat_path, wat).unwrap();
    // First install: local.
    bloom_cmd(&socket)
        .args(["petals", "install", wat_path.to_str().unwrap(), "--mode", "local"])
        .assert()
        .success();
    // Second install with same bytes, onchain mode: should fail.
    bloom_cmd(&socket)
        .args(["petals", "install", wat_path.to_str().unwrap(),
               "--cap", "chain.read", "--mode", "onchain"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("mode conflict"));
}

#[test]
fn replay_matches_then_mismatches_on_tampered_expect() {
    let dir = tempfile::tempdir().unwrap();
    let socket = start_daemon(&dir).expect("daemon up");
    let wat = include_str!("fixtures/onchain_echo.wat");
    let wat_path = dir.path().join("echo.wat");
    std::fs::write(&wat_path, wat).unwrap();
    bloom_cmd(&socket)
        .args(["petals", "install", wat_path.to_str().unwrap(), "--name", "echo",
               "--cap", "chain.read", "--mode", "onchain"])
        .assert()
        .success();
    let input_path = dir.path().join("in.bin");
    std::fs::write(&input_path, b"hello world!!!!!").unwrap();
    // First, capture the actual output hash by running and parsing.
    let out = bloom_cmd(&socket)
        .args(["petals", "run", "echo", "--input", input_path.to_str().unwrap()])
        .output()
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let actual_hash = resp.get("attestation").and_then(|a| a.get("output_hash"))
        .and_then(|v| v.as_str()).expect("attestation.output_hash").to_string();
    // Replay with the actual hash → match.
    bloom_cmd(&socket)
        .args(["petals", "replay", "echo",
               "--input", input_path.to_str().unwrap(),
               "--expect", &actual_hash])
        .assert()
        .success();
    // Replay with a tampered hash → mismatch.
    bloom_cmd(&socket)
        .args(["petals", "replay", "echo",
               "--input", input_path.to_str().unwrap(),
               "--expect", &"0".repeat(64)])
        .assert()
        .failure();
}
```

Note: assumes existing helpers `start_daemon(dir) -> socket_path` and `bloom_cmd(socket) -> Command`. Inspect the top of `crates/bloom/tests/cli.rs` and adapt the helper names if they differ.

- [ ] **Step 3: Run the integration tests**

Run: `cargo test -p bloom --test cli`
Expected: PASS for all four new tests.

- [ ] **Step 4: Commit**

```bash
git add crates/bloom/tests/cli.rs crates/bloom/tests/fixtures/onchain_echo.wat
git commit -m "bloom: integration tests for install --mode, replay, mode conflict"
```

---

## Task 17: Full-suite verification + manual smoke

**Files:** none (CI gate)

- [ ] **Step 1: Run the entire workspace test suite**

Run: `cargo test --workspace`
Expected: PASS (all crates).

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS (no warnings).

- [ ] **Step 3: Manual smoke test in `/tmp`**

```bash
rm -rf /tmp/bloom-petals-v1 && mkdir -p /tmp/bloom-petals-v1
cd /tmp/bloom-petals-v1
cargo run --manifest-path ~/code/beth/Cargo.toml -p bloom -- \
  --home . serve &
SERVE_PID=$!
sleep 1
echo 'check ls is empty' && cargo run --manifest-path ~/code/beth/Cargo.toml -p bloom -- --home . petals ls
echo 'install onchain' && cargo run --manifest-path ~/code/beth/Cargo.toml -p bloom -- \
  --home . petals install ~/code/beth/crates/bloom/tests/fixtures/onchain_echo.wat \
  --name echo --cap chain.read --mode onchain
echo 'ls' && cargo run --manifest-path ~/code/beth/Cargo.toml -p bloom -- --home . petals ls
echo 'try cross-mode install (should fail)' && cargo run --manifest-path ~/code/beth/Cargo.toml -p bloom -- \
  --home . petals install ~/code/beth/crates/bloom/tests/fixtures/onchain_echo.wat --mode local
kill $SERVE_PID
```

Expected:
- Initial `ls` is empty.
- Install succeeds, prints a JSON object with `"mode": "onchain"`.
- Second `ls` shows the petal with `MODE=onchain`.
- Cross-mode install fails with a `mode conflict` error in stderr.

- [ ] **Step 4: Commit final marker (if anything changed)**

If clippy fixed any lints, commit them:

```bash
git add -p
git commit -m "petals: clippy fixes from v1 mode-split"
```

---

## Spec Coverage Self-Check

| Spec section | Implemented in |
|---|---|
| §4.1 PetalMode + mode field | Tasks 1, 4 |
| §4.1 Capability rules (Local/Onchain) | Tasks 2, 3 |
| §4.1 Install invariant (ModeConflict, idempotency) | Task 4 |
| §4.1 Mode-branched linker / WasiCtx | Task 7 |
| §4.2 chain.read_at signature, OVERFLOW_BIAS, error codes | Tasks 6, 7 |
| §4.2 block=0 → ERR_BLOCK_NOT_PINNABLE | Task 7 (host fn body) |
| §4.3 On-disk store unchanged | (no change; spec deviation noted at top) |
| §4.3 VFS path-segmented layout | Task 9 |
| §4.3 Backward-compat for v0 installs (serde default) | Task 1 |
| §4.4 CLI --mode, uninstall, replay, ls mode column | Task 15 |
| §4.4 IPC additions, mode echoed in run response | Task 14 |
| §4.4 cap_mask narrowing | (inherited from v0; no change needed) |
| §4.5 Replay tooling, PetalAttestation | Tasks 10, 11, 13, 15 |
| §4.6 Determinism knobs | Task 8 |
| §4.7 Error variants | Tasks 3, 4, 6 |
| §5 Testing matrix | Distributed across all tasks + Task 16 |

## Out-of-scope confirmations (NOT implemented, per spec §7)

- Engine bit-exact determinism across wasmtime versions.
- Content-addressed cache for `chain_read_at`.
- `chain.view_call` host import.
- On-chain attestation contract / commit pipeline.
- `petal.call` cross-petal composition.
- Migration tooling for v0 installs (serde default handles read-side).
- Fuel-as-gas-schedule formalization.
- Deterministic WASI clock/random for onchain mode (v1 caveat: see Task 7 comment — replay surfaces the non-determinism as an output_hash mismatch; deterministic clock/RNG via `wall_clock(...)` / `secure_random(...)` is a follow-up).
- `--block` override flag on `replay` (mentioned as stretch in spec §4.5; deferred).
