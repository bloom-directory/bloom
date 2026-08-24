use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::Command,
};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf()
}

fn release_script(name: &str) -> PathBuf {
    workspace().join("packaging/triad/release").join(name)
}

#[test]
fn release_compatibility_declares_each_edge_without_a_global_protocol_range() {
    fn is_legacy_global_protocol_key(line: &str) -> bool {
        let line = line.trim_start();
        ["protocol_major", "protocol_minor_min", "protocol_minor_max"]
            .into_iter()
            .any(|key| {
                line.strip_prefix(key)
                    .is_some_and(|tail| tail.trim_start().starts_with('='))
            })
    }

    let release = workspace().join("packaging/triad/release");
    let compatibility = fs::read_to_string(release.join("compatibility-v1.toml")).unwrap();
    for exact_authority in ["machine_broker", "broker_signer"] {
        let block =
            format!("[protocols.{exact_authority}]\nmajor = 1\nminor_min = 3\nminor_max = 3");
        assert!(compatibility.contains(&block));
    }
    for compatible_support in ["signer_control", "session"] {
        let block =
            format!("[protocols.{compatible_support}]\nmajor = 1\nminor_min = 0\nminor_max = 1");
        assert!(compatibility.contains(&block));
    }
    assert!(!compatibility.lines().any(is_legacy_global_protocol_key));
    assert!(is_legacy_global_protocol_key("  protocol_major = 1"));
    assert!(is_legacy_global_protocol_key("\tprotocol_minor_min = 0"));

    let verifier = fs::read_to_string(release.join("verify-bundle.sh")).unwrap();
    assert!(verifier.contains("for authority_edge in machine_broker broker_signer"));
    assert!(verifier.contains("for support_edge in signer_control session"));
    assert!(verifier.contains("must not declare a global protocol range"));

    for revision in [
        "broker_commit",
        "signer_commit",
        "service_runtime_commit",
        "petal_contract_commit",
    ] {
        assert!(compatibility.contains(&format!("{revision} = \"")));
    }
    for component in ["machine", "broker", "signer"] {
        assert!(compatibility.contains(&format!("[state.{component}]")));
        assert!(compatibility.contains("downgrade_floor = 1"));
    }
}

#[test]
fn external_triad_dependencies_are_full_commit_pins() {
    let output = Command::new(release_script("check-external-pins.py"))
        .arg(workspace().join("Cargo.toml"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn default_petal_catalog_pins_artifacts_and_excludes_incompatible_defaults() {
    let output = Command::new(release_script("check-default-petal-releases.py"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn production_provenance_catalog_has_no_retired_native_hyperliquid_authority() {
    let catalog = fs::read_to_string(
        workspace().join("packaging/triad/macos/config/provenance-catalog.unsigned.json"),
    )
    .unwrap();
    assert!(!catalog.contains("hyperliquid."));
}

#[test]
fn machine_authority_boundary_is_directly_enforced_and_strict_release_is_blocked() {
    let release_dir = workspace().join("packaging/triad/release");
    let tested = Command::new(release_dir.join("test-machine-authority-boundary.sh"))
        .output()
        .unwrap();
    assert!(
        tested.status.success(),
        "{}",
        String::from_utf8_lossy(&tested.stderr)
    );

    let release_gate = fs::read_to_string(release_dir.join("triad-release-gate.sh")).unwrap();
    assert!(release_gate.contains("check-machine-authority-boundary.sh\" --require-clean"));
    assert!(release_gate.contains("--output-dir"));
    assert!(release_gate.contains("bloom-triad-test-unclaimed.tar.gz"));
    assert!(release_gate.contains("cargo test --workspace --locked -- --skip macos_"));
}

#[test]
fn tag_release_builds_the_locked_triad_and_isolates_production_signing() {
    let workflow = fs::read_to_string(workspace().join(".github/workflows/release.yml")).unwrap();
    assert!(workflow.contains("repository: bloom-directory/bloom-broker"));
    assert!(workflow.contains("ref: ${{ needs.prepare.outputs.broker_sha }}"));
    assert!(workflow.contains("repository: bloom-directory/bloom-signer"));
    assert!(workflow.contains("ref: ${{ needs.prepare.outputs.signer_sha }}"));
    assert!(workflow.contains("--test-signing-key"));
    assert!(!workflow.contains("--platform-claim linux"));
    assert!(workflow.contains("verify-release-candidate.sh"));
    assert!(workflow.contains("environment: production-release"));
    assert!(workflow.contains("sign-release-candidate.sh"));
    assert!(workflow.contains("packaging/triad/release/bloom-release-v1.pub"));
    assert!(workflow.contains("--prerelease"));
    assert!(workflow.contains("--latest=false"));
    assert!(workflow.contains("dry_run:"));
    assert!(workflow.contains("if: needs.prepare.outputs.dry_run != 'true'"));
    assert!(workflow.contains("release dry runs require workflow_dispatch"));
    assert!(!workflow.contains("--all-features"));
    assert!(!workflow.contains("--clobber"));
    assert!(workflow.contains("umask 077"));
    assert!(workflow.contains("unset RELEASE_SIGNING_KEY"));
    assert!(workflow.contains("published asset $name is immutable"));
    assert_eq!(
        workflow
            .matches("secrets.TRIAD_RELEASE_SIGNING_KEY")
            .count(),
        1,
        "the production key must be exposed to exactly one workflow step"
    );

    let proposal =
        fs::read_to_string(workspace().join(".github/workflows/propose-release.yml")).unwrap();
    assert!(proposal.contains("packaging/triad/release/compatibility-v1.toml"));
    assert!(proposal.contains("machine ="));
}

#[test]
fn legacy_hash_only_routes_are_checked_by_release_and_installed_acceptance() {
    let release_dir = workspace().join("packaging/triad/release");
    let release_gate = fs::read_to_string(release_dir.join("triad-release-gate.sh")).unwrap();
    assert!(release_gate.contains("check-legacy-hash-only-routes.py"));
    let bundle_gate = fs::read_to_string(release_dir.join("build-bundle.sh")).unwrap();
    assert!(bundle_gate.contains("check-legacy-hash-only-routes.py"));

    let legacy_routes = Command::new("python3")
        .arg(release_dir.join("check-legacy-hash-only-routes.py"))
        .output()
        .unwrap();
    assert!(
        legacy_routes.status.success(),
        "{}",
        String::from_utf8_lossy(&legacy_routes.stderr)
    );

    let installed_acceptance = fs::read_to_string(
        workspace().join("packaging/triad/macos/w0/run-installed-acceptance.sh"),
    )
    .unwrap();
    assert!(installed_acceptance.contains("-p bloom-petals"));
    assert!(installed_acceptance.contains("ac35_legacy_v0_1"));
    let tart_build =
        fs::read_to_string(workspace().join("packaging/triad/macos/w0/tart-build-guest.sh"))
            .unwrap();
    assert!(tart_build.contains("check-legacy-hash-only-routes.py"));
}

fn generate_ed25519_key(path: &Path) {
    assert!(
        Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
}

fn write_ed25519_public_key(private_key: &Path, public_key: &Path) {
    let output = Command::new(release_script("ssh-ed25519-public-key.sh"))
        .args([private_key, public_key])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn make_staging(root: &Path) -> PathBuf {
    let staging = root.join("staging");
    fs::create_dir_all(staging.join("bin")).unwrap();
    for binary in [
        "bloom",
        "bloom-broker",
        "bloom-signer",
        "bloom-signer-migrate",
    ] {
        let path = staging.join("bin").join(binary);
        let version = if binary == "bloom" {
            env!("CARGO_PKG_VERSION")
        } else {
            "0.1.0"
        };
        let version_output = if binary == "bloom" {
            format!(
                "echo '{binary} {version}'\necho 'bloom-daemon unavailable'\necho 'bloom-ipc 1 (not negotiated)'"
            )
        } else {
            format!("echo '{binary} {version}'")
        };
        fs::write(&path, format!("#!/bin/sh\n{version_output}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::write(staging.join("PLATFORM_CLAIM"), b"test-unclaimed\n").unwrap();
    staging
}

fn make_installer_payload(root: &Path) -> PathBuf {
    let payload = make_staging(root);
    fs::write(payload.join("SHA256SUMS"), b"test payload\n").unwrap();
    fs::copy(
        release_script("compatibility-v1.toml"),
        payload.join("compatibility-v1.toml"),
    )
    .unwrap();
    let macos = workspace().join("packaging/triad/macos");
    for relative in ["launchagents", "launchdaemons", "pf"] {
        let destination = payload.join("installer/macos").join(relative);
        fs::create_dir_all(&destination).unwrap();
        for entry in fs::read_dir(macos.join(relative)).unwrap() {
            let entry = entry.unwrap();
            fs::copy(entry.path(), destination.join(entry.file_name())).unwrap();
        }
    }
    let linux = workspace().join("packaging/triad/linux");
    for relative in [
        "config/edge-manifest.json.in",
        "config/broker.json.in",
        "config/signer.json.in",
        "config/provenance-catalog.unsigned.json",
        "config/nts-servers.conf",
        "bin/bloom",
        "systemd-user/bloom-session.service",
    ] {
        let destination = payload.join("installer/linux").join(relative);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::copy(linux.join(relative), destination).unwrap();
    }
    fs::create_dir_all(payload.join("config")).unwrap();
    for config in [
        "edge-manifest.json",
        "broker.json",
        "signer.json",
        "machine-identity.json",
        "broker-identity.json",
        "signer-identity.json",
        "revoke-identity.json",
        "session-identity.json",
        "installer-identity.json",
        "provenance-catalog.json",
    ] {
        fs::write(payload.join("config").join(config), b"{}").unwrap();
    }
    fs::write(
        payload.join("config/edge-manifest.json"),
        br#"{
  "machine_uid": @LOGIN_UID@,
  "broker_uid": @BLOOM_BROKER_UID@,
  "signer_uid": @BLOOM_SIGNER_UID@,
  "session_socket_gid": @SESSION_SOCKET_GID@
}"#,
    )
    .unwrap();
    fs::create_dir_all(payload.join("credentials")).unwrap();
    fs::write(
        payload.join("config/aws-kms-ip-allow.conf"),
        b"IPAddressAllow=192.0.2.0/24\n",
    )
    .unwrap();
    fs::write(
        payload.join("credentials/aws-credentials"),
        b"[default]\naws_access_key_id=test\n",
    )
    .unwrap();
    fs::write(
        payload.join("config/nts-servers.conf"),
        b"time.cloudflare.com\ntime.nist.gov\n",
    )
    .unwrap();
    payload
}

fn build(staging: &Path, output: &Path, key: &Path) -> std::process::Output {
    Command::new(release_script("build-bundle.sh"))
        .args([staging.as_os_str(), output.as_os_str(), key.as_os_str()])
        .arg("1700000000")
        .env("BLOOM_MACHINE_SHA", "11".repeat(20))
        .env("BLOOM_BROKER_SHA", "22".repeat(20))
        .env("BLOOM_SIGNER_SHA", "33".repeat(20))
        .env("BLOOM_ALLOW_TEST_UNCLAIMED", "true")
        .output()
        .unwrap()
}

#[test]
fn release_bundle_fails_closed_when_binary_format_scanner_fails() {
    let directory = tempfile::tempdir().unwrap();
    let staging = make_staging(directory.path());
    let key = directory.path().join("release-key");
    let archive = directory.path().join("bundle.tar.gz");
    generate_ed25519_key(&key);

    let tools = directory.path().join("scanner-failure-bin");
    fs::create_dir_all(&tools).unwrap();
    let file = tools.join("file");
    fs::write(&file, "#!/usr/bin/env bash\nexit 2\n").unwrap();
    let mut permissions = fs::metadata(&file).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&file, permissions).unwrap();
    let path = format!(
        "{}:{}",
        tools.display(),
        std::env::var("PATH").expect("PATH is set for release tooling")
    );

    let built = Command::new(release_script("build-bundle.sh"))
        .args([staging.as_os_str(), archive.as_os_str(), key.as_os_str()])
        .arg("1700000000")
        .env("BLOOM_MACHINE_SHA", "11".repeat(20))
        .env("BLOOM_BROKER_SHA", "22".repeat(20))
        .env("BLOOM_SIGNER_SHA", "33".repeat(20))
        .env("BLOOM_ALLOW_TEST_UNCLAIMED", "true")
        .env("PATH", path)
        .output()
        .unwrap();
    assert!(
        !built.status.success(),
        "a failed binary-format scanner must reject the release bundle"
    );
    assert!(
        String::from_utf8_lossy(&built.stderr)
            .contains("failed to inspect production binary format")
    );
}

#[test]
fn release_bundle_excludes_source_only_macos_w0_tooling() {
    let script = fs::read_to_string(release_script("build-bundle.sh")).unwrap();
    assert!(script.contains("macos_input"));
    assert!(script.contains("== \"w0\""));

    let directory = tempfile::tempdir().unwrap();
    let staging = make_staging(directory.path());
    let key = directory.path().join("release-key");
    let archive = directory.path().join("bundle.tar.gz");
    generate_ed25519_key(&key);
    let built = build(&staging, &archive, &key);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let listed = Command::new("tar")
        .args(["-tzf"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(listed.status.success());
    let entries = String::from_utf8(listed.stdout).unwrap();
    assert!(entries.contains("bloom-triad/installer/macos/README.md"));
    assert!(
        !entries
            .lines()
            .any(|entry| entry.starts_with("bloom-triad/installer/macos/w0/")),
        "source-only W0 tooling entered the production bundle:\n{entries}"
    );
}

#[test]
fn release_bundle_rejects_triad_developer_harness_artifacts() {
    let directory = tempfile::tempdir().unwrap();
    let staging = make_staging(directory.path());
    // This environment-variable name is intentionally present in every
    // dev-feature service binary: it selects the user-owned identity loader.
    // Put it in the executable fixture rather than an adjacent metadata file
    // so this test models the actual accidental-packaging failure mode.
    fs::write(
        staging.join("bin/bloom-broker"),
        b"#!/bin/sh\n# BLOOM_TRIAD_DEVELOPER_ROOT\necho bloom-broker 0.1.0\n",
    )
    .unwrap();
    let rejected = build(
        &staging,
        &directory.path().join("rejected.tar.gz"),
        &directory.path().join("unused-key"),
    );
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("forbidden production artifact marker: BLOOM_TRIAD_DEVELOPER_ROOT"),
        "{}",
        String::from_utf8_lossy(&rejected.stderr)
    );

    let launcher = fs::read_to_string(workspace().join("scripts/triad-dev-launch.sh")).unwrap();
    assert!(!launcher.contains("--local-integration"));
    assert!(!launcher.contains("--features local-integration"));
}

#[test]
fn triad_developer_launcher_supports_vfs_only_mode() {
    let launcher = fs::read_to_string(workspace().join("scripts/triad-dev-launch.sh")).unwrap();

    assert!(
        launcher.contains(
            "required_paths=(\"$developer_root\" \"$machine_socket\" \"$log_dir\" \"$ready_file\")"
        ),
        "the developer launcher must not require --mount"
    );
    assert!(
        launcher.contains("machine_home=\"${developer_root}/state/machine\"")
            && launcher.contains("Machine home must be inside the developer root"),
        "the persistent developer identity must not be paired with a disposable Machine journal"
    );
    assert!(
        launcher.contains("Bloom is ready without a kernel mount")
            && launcher
                .contains("Source triad.env to put the selected debug bloom binary first on PATH;")
            && launcher.contains("then use bloom directly in that terminal:")
            && launcher.contains("bloom vfs ls /")
            && launcher.contains("bloom vfs cat /next.md"),
        "VFS-only startup must tell the developer how to use the running Machine"
    );
    assert!(
        launcher.contains("wait_for_machine_ipc")
            && launcher.contains("BLOOM_RPC_ENDPOINT=\"unix:${machine_socket}\"")
            && launcher.contains("\"$bloom_bin\" --home \"$machine_home\" vfs ls /"),
        "VFS-only readiness must actively probe the exact launched endpoint"
    );
    assert!(
        launcher.contains("machine socket path already exists"),
        "the launcher must reject stale or foreign socket paths before startup"
    );
}

#[test]
fn triad_developer_launcher_exports_its_machine_connection() {
    let launcher = fs::read_to_string(workspace().join("scripts/triad-dev-launch.sh")).unwrap();

    assert!(
        launcher.contains("printf 'export BLOOM_RPC_ENDPOINT=%q\\n' \"unix:${machine_socket}\"")
            && launcher.contains("printf 'export BLOOM_BIN=%q\\n' \"$bloom_bin\""),
        "triad.env must select the launched Machine and exact bloom binary"
    );
}

#[test]
fn triad_developer_launcher_keeps_explicit_mounts_fail_closed() {
    let launcher = fs::read_to_string(workspace().join("scripts/triad-dev-launch.sh")).unwrap();

    assert!(
        launcher.contains("if [ -n \"$mount_dir\" ]; then")
            && launcher.contains("machine_args+=(--mount \"$mount_dir\")"),
        "an explicitly requested mount must still be passed to bloom serve"
    );
    assert!(
        launcher.contains("Machine exited before its requested kernel mount became ready")
            && launcher.contains("restart without --mount and use bloom vfs commands"),
        "a requested mount must fail with an actionable VFS-only fallback"
    );
    assert!(
        !launcher.contains("command ls \"$mount_dir\""),
        "mount readiness must not issue an unbounded filesystem operation"
    );
    assert!(
        launcher.contains("[ \"$attempts\" -lt 300 ] || {\n      if [ \"$label\" = machine ] && [ -n \"$mount_dir\" ]; then")
            && launcher.contains("die \"$label did not publish its socket\""),
        "a Machine socket timeout must retain the explicit-mount fallback hint"
    );
}

#[test]
fn triad_developer_launcher_can_leave_machine_developer_managed() {
    let launcher_path = workspace().join("scripts/triad-dev-launch.sh");
    let launcher = fs::read_to_string(&launcher_path).unwrap();

    assert!(launcher.contains("--services-only) services_only=1; shift ;;"));
    assert!(launcher.contains("if [ \"$services_only\" -eq 1 ]; then"));
    assert!(launcher.contains("Bloom triad services are ready; Machine is developer-managed."));
    assert!(
        launcher.contains("Source triad.env to put the selected debug bloom binary first on PATH;")
    );
    assert!(launcher.contains("then use bloom directly in that terminal:"));
    assert!(launcher.contains("supervise_services"));

    let directory = tempfile::tempdir().unwrap();
    let rejected = Command::new(launcher_path)
        .args([
            "--services-only",
            "--developer-root",
            directory.path().join("developer").to_str().unwrap(),
            "--machine-home",
            directory.path().join("machine").to_str().unwrap(),
            "--mount",
            directory.path().join("mount").to_str().unwrap(),
            "--machine-socket",
            directory.path().join("machine.sock").to_str().unwrap(),
            "--log-dir",
            directory.path().join("logs").to_str().unwrap(),
            "--ready-file",
            directory.path().join("ready").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("--services-only cannot be combined with --mount"),
        "{}",
        String::from_utf8_lossy(&rejected.stderr)
    );
}

#[test]
fn triad_developer_launcher_exports_debug_machine_on_path() {
    let launcher = fs::read_to_string(workspace().join("scripts/triad-dev-launch.sh")).unwrap();

    assert!(launcher.contains("bloom_bin_dir=\"$(cd \"$(dirname \"$bloom_bin\")\" && pwd -P)\""));
    assert!(launcher.contains("printf 'export PATH=%q:\"$PATH\"\\n' \"$bloom_bin_dir\""));
}

#[test]
fn triad_developer_launcher_owns_only_its_service_processes() {
    let launcher = fs::read_to_string(workspace().join("scripts/triad-dev-launch.sh")).unwrap();

    assert!(launcher.contains("trap cleanup EXIT INT TERM HUP"));
    assert!(
        launcher.contains(
            "for pid in \"$machine_pid\" \"$broker_pid\" \"$signer_pid\" \"$session_pid\""
        )
    );
    assert!(launcher.contains("rm -f -- \"$ready_file\""));
    assert!(launcher.contains("die \"$label exited while supervising triad services\""));
}

#[test]
fn serve_starts_audited_projection_refresh_after_fallible_setup() {
    let source = fs::read_to_string(workspace().join("crates/bloom/src/main.rs")).unwrap();
    let serve = source
        .rsplit("Cmd::Serve {")
        .next()
        .expect("serve command arm");
    let mount = serve.find("let mount_handle = mount_bloom").unwrap();
    let endpoint = serve
        .find("let endpoint = resolve_server_endpoint")
        .unwrap();
    let server = serve.find("let server = IpcServer::new").unwrap();
    let background = serve
        .find("let sweeper = d.spawn_background_tasks()")
        .unwrap();

    assert!(
        mount < background && endpoint < background && server < background,
        "audited background refresh must start only after fallible serve setup succeeds"
    );
}

#[test]
fn production_release_rejects_machine_audit_test_features() {
    let gate =
        fs::read_to_string(workspace().join("packaging/triad/release/triad-release-gate.sh"))
            .expect("read release gate");
    let bundle = fs::read_to_string(workspace().join("packaging/triad/release/build-bundle.sh"))
        .expect("read bundle builder");
    let checker = fs::read_to_string(
        workspace().join("packaging/triad/release/check-machine-authority-boundary.sh"),
    )
    .expect("read production feature-set checker");
    let checker_tests = fs::read_to_string(
        workspace().join("packaging/triad/release/test-machine-authority-boundary.sh"),
    )
    .expect("read production feature-set checker tests");
    for forbidden in ["unsigned-audit-test-seam", "audit-test-seam"] {
        assert!(gate.contains(forbidden));
        assert!(bundle.contains(forbidden));
        assert!(checker.contains(forbidden));
    }
    assert!(checker_tests.contains("for audit_feature in audit-test-seam"));
    assert!(checker_tests.contains("forbidden-unsigned-audit-seam"));
    assert!(checker_tests.contains("bloom-daemon:unsigned-audit-test-seam"));
    assert!(gate.contains("forbidden production Machine feature resolved"));
    assert!(gate.contains("cargo tree"));
    assert!(gate.contains("-e normal,build,features"));
    assert!(checker_tests.contains("BLOOM_MACHINE_METADATA_FIXTURE"));
    assert!(checker_tests.contains("BLOOM_MACHINE_FEATURE_TREE_FIXTURE"));
    assert!(checker_tests.contains("forbidden resolved Machine feature"));
}

#[test]
fn release_bundle_rejects_legacy_machine_authority_files() {
    let directory = tempfile::tempdir().unwrap();
    let staging = make_staging(directory.path());
    fs::create_dir_all(staging.join("machine/state/auth")).unwrap();
    fs::write(
        staging.join("machine/state/auth/auth.sqlite"),
        b"legacy authority",
    )
    .unwrap();

    let rejected = build(
        &staging,
        &directory.path().join("rejected.tar.gz"),
        &directory.path().join("unused-key"),
    );
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains(
            "forbidden production Machine artifact legacy authority file: machine/state/auth/auth.sqlite"
        ),
        "{}",
        String::from_utf8_lossy(&rejected.stderr)
    );
}

#[test]
fn release_bundle_rejects_legacy_machine_authority_symbols_or_strings() {
    let directory = tempfile::tempdir().unwrap();
    let staging = make_staging(directory.path());
    fs::write(
        staging.join("bin/bloom"),
        b"#!/bin/sh\n# KeystorePetalHost\necho bloom 0.1.3\n",
    )
    .unwrap();

    let rejected = build(
        &staging,
        &directory.path().join("rejected.tar.gz"),
        &directory.path().join("unused-key"),
    );
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("forbidden production Machine artifact marker: KeystorePetalHost"),
        "{}",
        String::from_utf8_lossy(&rejected.stderr)
    );
}

#[test]
fn release_bundle_allows_signer_authority_but_rejects_machine_owned_authority() {
    let directory = tempfile::tempdir().unwrap();
    let staging = make_staging(directory.path());
    fs::write(
        staging.join("bin/bloom-signer"),
        b"#!/bin/sh\n# PrivateKeySigner is conforming Signer authority\necho bloom-signer 0.1.0\n",
    )
    .unwrap();
    let key = directory.path().join("release-key");
    generate_ed25519_key(&key);
    let allowed = build(&staging, &directory.path().join("allowed.tar.gz"), &key);
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );

    fs::create_dir_all(staging.join("machine/plugins")).unwrap();
    fs::write(
        staging.join("machine/plugins/authority.txt"),
        b"KeystorePetalHost\n",
    )
    .unwrap();
    let rejected = build(
        &staging,
        &directory.path().join("rejected-machine.tar.gz"),
        &key,
    );
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("forbidden production Machine artifact marker: KeystorePetalHost"),
        "{}",
        String::from_utf8_lossy(&rejected.stderr)
    );
}

#[test]
fn installed_acceptance_runs_the_packaged_machine_runtime_negative() {
    let w0 = workspace().join("packaging/triad/macos/w0");
    let acceptance = fs::read_to_string(w0.join("run-installed-acceptance.sh")).unwrap();
    assert!(acceptance.contains("source cleanliness inspection failed"));
    assert!(acceptance.contains("if ! tracked_status=\"$("));
    assert!(acceptance.contains("run-packaged-machine-negative.sh"));
    assert!(
        acceptance.contains("installed payload unexpectedly has an alternate Machine executable")
    );

    let negative = fs::read_to_string(w0.join("run-packaged-machine-negative.sh")).unwrap();
    assert!(
        !negative.contains("ipc call write"),
        "MA-05 authority negatives must be driven only through the kernel mount"
    );
    for required in [
        "serve",
        "hostile-unix-listener",
        "BLOOM_BROKER_SOCKET",
        "default_chain = \"anvil\"",
        "[chains.anvil]",
        "rpc_urls = [",
        "$rpc_port",
        "allow_broadcast = true",
        "BLOOM_MA05_LEGACY_AUTHORITY_POISON",
        "legacy-before.manifest",
        "/usr/bin/fs_usage -w -f pathname >",
        "bloom\\.[0-9]+",
        "machine.effect.intent",
        "machine.effect.result",
        "payload_sha256",
        "result_details.get(\"outcome\") == \"error\"",
        "audit status",
        "bloom-broker-debug-driver",
        "wallet_id=\"$(jq -r '.wallet_id // empty'",
        "[[ \"$wallet_id\" == \"ma05-cached\" ]]",
        "wallet projection \"$wallet_id\"",
        "wallet commit-policy",
        "authenticated-projection-cache.json",
        "chown \"$login_uid\" \"$runtime/machine\"",
        "machine_socket=\"$runtime/machine/machine.sock\"",
        "system/com.bloom.signer.$login_uid",
        "/private/var/run/bloom/$login_uid/broker-signer/signer.sock",
        "launchctl bootout \"$signer_label\"",
        "launchctl bootstrap system \"$signer_plist\"",
        "signer_socket_dir_owner=\"$(stat -f '%u'",
        "signer_socket_dir_group=\"$(stat -f '%g'",
        "signer_socket_dir_mode=\"$(stat -f '%Lp'",
        "chmod 0711 \"$signer_socket_dir\"",
        "chown \"$signer_socket_dir_owner:$signer_socket_dir_group\"",
        "chmod \"$signer_socket_dir_mode\" \"$signer_socket_dir\"",
        "packaged production Machine service",
        "packaged Machine runtime negative failed at line",
        "lsof -nP -a -p",
        "-name auth",
        "-name auth.sqlite",
        "$clean_home/auth",
        "$clean_home/auth/challenges",
        "$clean_home/auth/grants",
        "for root in \"${legacy_poison_roots[@]}\"",
        "policy-session",
        "signer-cache",
        "did not preserve cached reads through its kernel mount",
        "did not expose a completed mounted simulation",
        "simulation did not return the deterministic fixture result",
        "did not identify the unavailable authenticated Broker edge",
        "accessed, migrated, or changed poisoned legacy authority state",
        "attempted to access poisoned legacy authority root",
        "connected directly to the hostile Signer sentinel",
    ] {
        assert!(
            negative.contains(required),
            "packaged runtime negative omits {required}"
        );
    }
    assert_eq!(
        negative.matches("ma05-cached").count(),
        2,
        "the requested wallet ID must be asserted at both registration input and Signer result"
    );
}

#[test]
fn tart_bundle_build_runs_strict_machine_boundary_before_compilation() {
    let w0 = workspace().join("packaging/triad/macos/w0");
    let source = fs::read_to_string(w0.join("tart-build-guest.sh")).unwrap();
    let boundary = source
        .find("check-machine-authority-boundary.sh")
        .expect("Tart build must invoke the strict Machine authority boundary");
    assert!(
        source[boundary..]
            .starts_with("check-machine-authority-boundary.sh\" \\\n      --require-clean")
    );
    let cargo_build = source
        .find("cargo build")
        .expect("Tart build must compile production binaries");
    let bundle_build = source
        .find("build-bundle.sh")
        .expect("Tart build must assemble the candidate bundle");
    assert!(
        boundary < cargo_build,
        "boundary check must precede compilation"
    );
    assert!(
        boundary < bundle_build,
        "boundary check must precede bundle assembly"
    );
    assert!(source.contains("for attempt in 1 2 3"));
    assert!(source.contains("if (( status <= 128 ))"));
    assert!(source.contains("terminated by signal"));
    assert!(source.contains("git clone --quiet \"$bundle\" \"$temporary\""));
    assert!(source.contains("git -C \"$temporary\" fsck --no-dangling"));
    assert!(source.contains("[[ ! -L \"$local_source_root\" ]]"));
    assert!(source.contains("for replacement_path in \"$temporary\" \"$target\""));
    assert!(!source.contains("readonly main_root=\"$shared_root/bloom\""));

    let runner = fs::read_to_string(w0.join("run-tart-local.sh")).unwrap();
    assert!(runner.contains("git -C \"$repository_root\" bundle create"));
    assert!(runner.contains("git -C \"$repository_root\" bundle verify \"$temporary\""));
    assert!(runner.contains("git -C \"$repository_root\" bundle list-heads \"$temporary\""));
    assert!(runner.contains("$bundled_revision\" != \"$revision"));
    assert!(runner.contains("--dir=\"output:$local_output_root\""));
    assert!(!runner.contains("--dir=\"bloom:$main_root:ro\""));
    assert!(runner.contains("sleep 60"));
    assert!(runner.contains("if printf '%s\\n'"));
    assert!(runner.contains("'set -e'"));
    assert!(runner.contains("for _fork_probe in {1..200}"));
    assert!(runner.contains("/usr/bin/python3 -c \"pass\""));
    assert!(runner.contains("\"admin@$guest_ip\" /bin/bash -s"));
    assert!(!runner.contains("/bin/bash -c"));

    let execution = fs::read_to_string(w0.join("tart-run-guest.sh")).unwrap();
    assert!(
        execution.contains("readonly local_source_root=\"$HOME/Library/Caches/bloom-w0-sources\"")
    );
    assert!(!execution.contains("readonly main_root=\"$shared_root/bloom\""));

    let acceptance = fs::read_to_string(w0.join("run-installed-acceptance.sh")).unwrap();
    assert_eq!(
        acceptance
            .matches("assert_source \"$main_root\" BLOOM_MACHINE_SHA")
            .count(),
        2,
        "installed acceptance must prove exact Machine source before and after tests"
    );
    assert_eq!(
        acceptance
            .matches("assert_source \"$broker_root\" BLOOM_BROKER_SHA")
            .count(),
        2,
        "installed acceptance must prove exact Broker source before and after tests"
    );
    assert_eq!(
        acceptance
            .matches("assert_source \"$signer_root\" BLOOM_SIGNER_SHA")
            .count(),
        2,
        "installed acceptance must prove exact Signer source before and after tests"
    );
}

fn macos_subject(payload: &Path) -> std::process::Output {
    Command::new(release_script("macos-conformance-subject.sh"))
        .arg(payload)
        .output()
        .unwrap()
}

fn stage_macos_install(installer: &Path, root: &Path, payload: &Path) -> std::process::Output {
    stage_macos_install_digest(installer, root, payload, &"11".repeat(32))
}

fn stage_macos_install_digest(
    installer: &Path,
    root: &Path,
    payload: &Path,
    digest: &str,
) -> std::process::Output {
    Command::new(installer)
        .args(["install"])
        .arg(root)
        .args(["501", "alice"])
        .arg(payload)
        .env("BLOOM_ALLOW_TEST_UNCLAIMED", "true")
        .env("BLOOM_MACOS_BROKER_UID", "250501")
        .env("BLOOM_MACOS_SIGNER_UID", "250502")
        .env("BLOOM_MACOS_BROKER_GID", "260499")
        .env("BLOOM_MACOS_SIGNER_GID", "260500")
        .env("BLOOM_MACOS_MACHINE_BROKER_GID", "260501")
        .env("BLOOM_MACOS_BROKER_SIGNER_GID", "260502")
        .env("BLOOM_MACOS_REVOKE_GID", "260503")
        .env("BLOOM_RELEASE_DIGEST", digest)
        .output()
        .unwrap()
}

#[test]
fn acceptance_rerun_is_bound_to_the_verified_bundle_when_present() {
    let Some(bundle) = std::env::var_os("BLOOM_ACCEPTANCE_BUNDLE_ROOT") else {
        return;
    };
    let bundle = PathBuf::from(bundle);
    let expected_claim = if std::env::var("BLOOM_ALLOW_TEST_UNCLAIMED").as_deref() == Ok("true") {
        "test-unclaimed"
    } else if std::env::var("BLOOM_ALLOW_MACOS_UNIX_W0").as_deref() == Ok("true") {
        "macos-unix-principals-w0"
    } else if cfg!(target_os = "macos") {
        "macos-unix-principals"
    } else {
        "linux"
    };
    assert_eq!(
        fs::read_to_string(bundle.join("PLATFORM_CLAIM"))
            .unwrap()
            .trim(),
        expected_claim
    );
    for (binary, expected_version) in [
        ("bloom", format!("bloom {}", env!("CARGO_PKG_VERSION"))),
        ("bloom-broker", "bloom-broker 0.1.0".to_owned()),
        ("bloom-signer", "bloom-signer 0.1.0".to_owned()),
    ] {
        let output = Command::new(bundle.join("bin").join(binary))
            .arg("--version")
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(stdout.lines().next().unwrap_or_default(), expected_version);
    }
}

#[test]
fn triad_bundle_is_reproducible_signed_and_self_verifying() {
    let directory = tempfile::tempdir().unwrap();
    let staging = make_staging(directory.path());
    let key = directory.path().join("release-key.pem");
    generate_ed25519_key(&key);
    let first = directory.path().join("first.tar.gz");
    let second = directory.path().join("second.tar.gz");
    let first_build = build(&staging, &first, &key);
    assert!(
        first_build.status.success(),
        "{}",
        String::from_utf8_lossy(&first_build.stderr)
    );
    let second_build = build(&staging, &second, &key);
    assert!(
        second_build.status.success(),
        "{}",
        String::from_utf8_lossy(&second_build.stderr)
    );
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());

    let checksum = PathBuf::from(format!("{}.sha256", first.display()));
    let signature = PathBuf::from(format!("{}.sig", first.display()));
    let public_key = PathBuf::from(format!("{}.pub", first.display()));
    let verified = Command::new(release_script("verify-bundle.sh"))
        .args([
            first.as_os_str(),
            checksum.as_os_str(),
            signature.as_os_str(),
            public_key.as_os_str(),
        ])
        .env("BLOOM_ALLOW_TEST_UNCLAIMED", "true")
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );

    let wrong_namespace = Command::new(release_script("ssh-ed25519-verify.sh"))
        .arg(&public_key)
        .arg("bloom-release-payload-v1")
        .arg(&checksum)
        .arg(&signature)
        .output()
        .unwrap();
    assert!(
        !wrong_namespace.status.success(),
        "an archive signature must not verify in the payload namespace"
    );
}

#[test]
fn production_candidate_signing_is_data_only_reproducible_and_key_pinned() {
    let directory = tempfile::tempdir().unwrap();
    let staging = make_staging(directory.path());
    let execution_marker = directory.path().join("candidate-executed");
    for binary in [
        "bloom",
        "bloom-broker",
        "bloom-signer",
        "bloom-signer-migrate",
    ] {
        let path = staging.join("bin").join(binary);
        let script = fs::read_to_string(&path).unwrap();
        fs::write(
            &path,
            script.replacen(
                "#!/bin/sh\n",
                &format!("#!/bin/sh\ntouch '{}'\n", execution_marker.display()),
                1,
            ),
        )
        .unwrap();
    }

    let candidate_key = directory.path().join("candidate-key");
    generate_ed25519_key(&candidate_key);
    let candidate = directory.path().join("candidate.tar.gz");
    let built = build(&staging, &candidate, &candidate_key);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    assert!(execution_marker.exists());
    fs::remove_file(&execution_marker).unwrap();

    let release_key = directory.path().join("release-key");
    let release_public_key = directory.path().join("release-key.pub.pinned");
    generate_ed25519_key(&release_key);
    write_ed25519_public_key(&release_key, &release_public_key);
    let first_dir = directory.path().join("signed-a");
    let second_dir = directory.path().join("signed-b");
    fs::create_dir(&first_dir).unwrap();
    fs::create_dir(&second_dir).unwrap();
    let first = first_dir.join("bloom-triad-linux-x86_64.tar.gz");
    let second = second_dir.join("bloom-triad-linux-x86_64.tar.gz");
    let expected_machine_sha = "11".repeat(20);
    let expected_broker_sha = "22".repeat(20);
    let expected_signer_sha = "33".repeat(20);
    for output in [&first, &second] {
        let signed = Command::new(release_script("sign-release-candidate.sh"))
            .args([
                candidate.as_os_str(),
                output.as_os_str(),
                release_key.as_os_str(),
                release_public_key.as_os_str(),
            ])
            .args([
                "1700000000",
                env!("CARGO_PKG_VERSION"),
                &expected_machine_sha,
                &expected_broker_sha,
                &expected_signer_sha,
            ])
            .output()
            .unwrap();
        assert!(
            signed.status.success(),
            "{}",
            String::from_utf8_lossy(&signed.stderr)
        );
    }
    assert!(!execution_marker.exists());
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());

    let first_checksum = PathBuf::from(format!("{}.sha256", first.display()));
    let first_signature = PathBuf::from(format!("{}.sig", first.display()));
    let verifier_tools = directory.path().join("verifier-tools");
    fs::create_dir(&verifier_tools).unwrap();
    let file = verifier_tools.join("file");
    fs::write(&file, "#!/bin/sh\necho 'ELF 64-bit LSB executable'\n").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
    let verified = Command::new(release_script("verify-bundle.sh"))
        .args([
            first.as_os_str(),
            first_checksum.as_os_str(),
            first_signature.as_os_str(),
            release_public_key.as_os_str(),
        ])
        .env(
            "PATH",
            format!(
                "{}:{}",
                verifier_tools.display(),
                std::env::var("PATH").unwrap()
            ),
        )
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );

    let wrong_key = directory.path().join("wrong-key");
    let wrong_public_key = directory.path().join("wrong-key.pub.pinned");
    generate_ed25519_key(&wrong_key);
    write_ed25519_public_key(&wrong_key, &wrong_public_key);
    let rejected = Command::new(release_script("sign-release-candidate.sh"))
        .args([
            candidate.as_os_str(),
            directory.path().join("wrong.tar.gz").as_os_str(),
            release_key.as_os_str(),
            wrong_public_key.as_os_str(),
        ])
        .args([
            "1700000000",
            env!("CARGO_PKG_VERSION"),
            &expected_machine_sha,
            &expected_broker_sha,
            &expected_signer_sha,
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("does not match the reviewed public key")
    );
}

#[test]
fn macos_conformance_subject_excludes_only_the_claim_and_signature_envelope() {
    let directory = tempfile::tempdir().unwrap();
    let payload = directory.path().join("payload");
    fs::create_dir_all(payload.join("installer/macos")).unwrap();
    fs::write(payload.join("bin"), b"machine-broker-signer").unwrap();
    fs::write(payload.join("installer/macos/profile"), b"uid-boundary").unwrap();
    fs::write(
        payload.join("PLATFORM_CLAIM"),
        b"macos-unix-principals-w0\n",
    )
    .unwrap();
    let baseline = macos_subject(&payload);
    assert!(
        baseline.status.success(),
        "{}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    let baseline = String::from_utf8(baseline.stdout).unwrap();

    for (name, bytes) in [
        ("PLATFORM_CLAIM", b"macos-unix-principals\n".as_slice()),
        ("MACOS_CONFORMANCE_REPORT.json", b"report".as_slice()),
        ("MACOS_CONFORMANCE_REPORT.sig", b"signature".as_slice()),
        ("MACOS_CONFORMANCE_REPORT.pub", b"public-key".as_slice()),
        ("RELEASE_PUBLIC_KEY.pem", b"release-key".as_slice()),
        ("RELEASE_SIGNATURE", b"release-signature".as_slice()),
        ("SHA256SUMS", b"release-manifest".as_slice()),
    ] {
        fs::write(payload.join(name), bytes).unwrap();
    }
    let envelope_changed = macos_subject(&payload);
    assert!(envelope_changed.status.success());
    assert_eq!(
        baseline,
        String::from_utf8(envelope_changed.stdout).unwrap()
    );

    fs::write(payload.join("installer/macos/profile"), b"changed-boundary").unwrap();
    let security_input_changed = macos_subject(&payload);
    assert!(security_input_changed.status.success());
    assert_ne!(
        baseline,
        String::from_utf8(security_input_changed.stdout).unwrap()
    );

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("profile", payload.join("installer/macos/substitution"))
            .unwrap();
        let substituted = macos_subject(&payload);
        assert!(!substituted.status.success());
        assert!(String::from_utf8_lossy(&substituted.stderr).contains("contains a symlink"));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_production_conformance_report_is_signed_complete_and_subject_bound() {
    let directory = tempfile::tempdir().unwrap();
    let payload = directory.path().join("payload");
    fs::create_dir_all(payload.join("installer/release")).unwrap();
    fs::write(payload.join("security-input"), b"exact-tested-content").unwrap();
    fs::write(
        payload.join("SOURCE_REVISIONS"),
        b"BLOOM_BROKER_SHA=2222222\nBLOOM_MACHINE_SHA=1111111\nBLOOM_SIGNER_SHA=3333333\n",
    )
    .unwrap();
    for script in [
        "macos-conformance-subject.sh",
        "sign-macos-conformance-report.sh",
        "verify-macos-conformance.sh",
    ] {
        let destination = payload.join("installer/release").join(script);
        fs::copy(release_script(script), &destination).unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let subject = macos_subject(&payload);
    assert!(subject.status.success());
    let subject = String::from_utf8(subject.stdout).unwrap();
    let private_key = directory.path().join("conformance.pem");
    let public_key = payload.join("MACOS_CONFORMANCE_REPORT.pub");
    let evidence = directory.path().join("evidence");
    fs::create_dir(&evidence).unwrap();
    for criterion in [
        "mui_01",
        "mui_02",
        "mui_03",
        "mui_04",
        "mui_05",
        "mui_06",
        "mui_07",
        "mui_08",
        "mui_09",
        "mui_10",
        "mui_11",
        "mui_12",
        "installed_ac_01_35",
        "negative_access",
    ] {
        fs::write(evidence.join(format!("{criterion}.pass")), &subject).unwrap();
    }
    generate_ed25519_key(&private_key);
    let missing = Command::new(release_script("sign-macos-conformance-report.sh"))
        .arg(&payload)
        .arg("44".repeat(32))
        .args(["2026-07-30T12:00:00Z", "25G86", "arm64", "w0-test-report"])
        .arg(&evidence)
        .arg(&private_key)
        .arg(&payload)
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("two_login_lifecycle"));
    fs::write(evidence.join("two_login_lifecycle.pass"), &subject).unwrap();
    let signed = Command::new(release_script("sign-macos-conformance-report.sh"))
        .arg(&payload)
        .arg("44".repeat(32))
        .args(["2026-07-30T12:00:00Z", "25G86", "arm64", "w0-test-report"])
        .arg(&evidence)
        .arg(&private_key)
        .arg(&payload)
        .output()
        .unwrap();
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let key_digest = Command::new("shasum")
        .args(["-a", "256"])
        .arg(&public_key)
        .output()
        .unwrap();
    assert!(key_digest.status.success());
    let key_digest = String::from_utf8(key_digest.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    let verified = Command::new(release_script("verify-macos-conformance.sh"))
        .arg(&payload)
        .arg(&key_digest)
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );

    fs::write(payload.join("security-input"), b"post-test-change").unwrap();
    let changed = Command::new(release_script("verify-macos-conformance.sh"))
        .arg(&payload)
        .arg(&key_digest)
        .output()
        .unwrap();
    assert!(!changed.status.success());
    assert!(
        String::from_utf8_lossy(&changed.stderr).contains("does not bind this release subject")
    );
}

#[test]
fn release_scan_rejects_debug_or_accepting_artifacts() {
    let directory = tempfile::tempdir().unwrap();
    let staging = make_staging(directory.path());
    fs::write(
        staging.join("bin/bloom-broker"),
        b"bloom-broker-debug-driver",
    )
    .unwrap();
    let key = directory.path().join("release-key.pem");
    generate_ed25519_key(&key);
    let built = build(&staging, &directory.path().join("forbidden.tar.gz"), &key);
    assert!(!built.status.success());
    assert!(String::from_utf8_lossy(&built.stderr).contains("forbidden production artifact"));
}

#[test]
fn release_scan_rejects_ma08_secret_artifact_probe() {
    let directory = tempfile::tempdir().unwrap();
    let staging = make_staging(directory.path());
    fs::write(
        staging.join("bin/bloom-machine"),
        b"assert-machine-secret-confinement",
    )
    .unwrap();
    let built = build(
        &staging,
        &directory.path().join("forbidden-ma08-probe.tar.gz"),
        &directory.path().join("unused-key"),
    );
    assert!(!built.status.success());
    assert!(
        String::from_utf8_lossy(&built.stderr)
            .contains("forbidden production artifact marker: assert-machine-secret-confinement")
    );
}

#[test]
fn release_scan_rejects_empty_debug_artifacts_globally() {
    let directory = tempfile::tempdir().unwrap();
    let staging = make_staging(directory.path());
    fs::create_dir_all(staging.join("signer/tools")).unwrap();
    fs::write(staging.join("signer/tools/bloom-broker-debug-driver"), b"").unwrap();
    let built = build(
        &staging,
        &directory.path().join("forbidden.tar.gz"),
        &directory.path().join("unused-key"),
    );
    assert!(!built.status.success());
    assert!(
        String::from_utf8_lossy(&built.stderr).contains(
            "forbidden production debug/test artifact: signer/tools/bloom-broker-debug-driver"
        ),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
}

#[test]
fn bundle_rejects_a_service_outside_the_current_only_matrix() {
    let directory = tempfile::tempdir().unwrap();
    let staging = make_staging(directory.path());
    fs::write(
        staging.join("bin/bloom-signer"),
        b"#!/bin/sh\necho bloom-signer 0.0.9\n",
    )
    .unwrap();
    let key = directory.path().join("release-key.pem");
    generate_ed25519_key(&key);
    let built = build(&staging, &directory.path().join("old-signer.tar.gz"), &key);
    assert!(!built.status.success());
    assert!(String::from_utf8_lossy(&built.stderr).contains("compatibility matrix"));

    let staging = make_staging(&directory.path().join("migration-skew"));
    fs::write(
        staging.join("bin/bloom-signer-migrate"),
        b"#!/bin/sh\necho bloom-signer-migrate 0.0.9\n",
    )
    .unwrap();
    let built = build(
        &staging,
        &directory.path().join("old-migration-tool.tar.gz"),
        &key,
    );
    assert!(!built.status.success());
    assert!(String::from_utf8_lossy(&built.stderr).contains("compatibility matrix"));
}

#[test]
fn linux_installer_upgrade_rotation_and_confirmed_uninstall_are_staged_safely() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    let payload = make_installer_payload(directory.path());
    let installer = release_script("install-linux.sh");
    let install = Command::new(&installer)
        .args(["install"])
        .arg(&root)
        .args(["1000", "alice"])
        .arg(&payload)
        .env("BLOOM_ALLOW_TEST_UNCLAIMED", "true")
        .output()
        .unwrap();
    assert!(
        install.status.success(),
        "{}",
        String::from_utf8_lossy(&install.stderr)
    );
    let broker_unit =
        fs::read_to_string(root.join("usr/lib/systemd/system/bloom-broker@.service")).unwrap();
    assert!(broker_unit.contains("ExecStart=/usr/libexec/bloom/bloom-broker"));
    assert!(!broker_unit.contains("@BLOOM_"));
    let sysusers = fs::read_to_string(root.join("usr/lib/sysusers.d/bloom-1000.conf")).unwrap();
    assert!(sysusers.contains("bloom-broker-1000"));
    assert!(sysusers.contains("alice"));
    let chrony = fs::read_to_string(root.join("etc/chrony/conf.d/bloom-nts.conf")).unwrap();
    assert!(chrony.contains("server time.cloudflare.com iburst nts"));
    assert!(chrony.contains("server nts.netnod.se iburst nts"));
    assert_eq!(
        fs::metadata(root.join("etc/bloom/1000/signer/config.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let aws_dropin = fs::read_to_string(
        root.join("usr/lib/systemd/system/bloom-signer@1000.service.d/50-aws-kms.conf"),
    )
    .unwrap();
    assert!(aws_dropin.contains("IPAddressDeny=any"));
    assert!(aws_dropin.contains("IPAddressAllow=192.0.2.0/24"));
    assert!(!aws_dropin.contains("@AWS_KMS_IP_ALLOW_DIRECTIVES@"));

    fs::remove_file(payload.join("credentials/aws-credentials")).unwrap();
    fs::remove_file(payload.join("config/aws-kms-ip-allow.conf")).unwrap();
    fs::write(payload.join("bin/bloom-broker"), b"upgraded-broker").unwrap();
    assert!(
        Command::new(&installer)
            .args(["install"])
            .arg(&root)
            .args(["1000", "alice"])
            .arg(&payload)
            .env("BLOOM_ALLOW_TEST_UNCLAIMED", "true")
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        fs::read(root.join("usr/libexec/bloom/bloom-broker")).unwrap(),
        b"upgraded-broker"
    );
    assert!(!root.join("etc/bloom/1000/signer/aws-credentials").exists());
    assert!(
        !root
            .join("usr/lib/systemd/system/bloom-signer@1000.service.d/50-aws-kms.conf")
            .exists()
    );

    fs::write(
        payload.join("config/broker-identity.json"),
        b"{\"changed\":true}",
    )
    .unwrap();
    let changed_identity = Command::new(&installer)
        .args(["install"])
        .arg(&root)
        .args(["1000", "alice"])
        .arg(&payload)
        .env("BLOOM_ALLOW_TEST_UNCLAIMED", "true")
        .output()
        .unwrap();
    assert!(changed_identity.status.success());
    assert_eq!(
        fs::read(root.join("etc/bloom/1000/broker/identity.json")).unwrap(),
        b"{}"
    );
    fs::write(payload.join("config/broker-identity.json"), b"{}").unwrap();

    let payload_manifest = fs::read(payload.join("config/edge-manifest.json")).unwrap();
    let installed_manifest = fs::read(root.join("etc/bloom/1000/edge-manifest.json")).unwrap();
    fs::write(
        payload.join("config/edge-manifest.json"),
        b"{\"changed\":true}",
    )
    .unwrap();
    let changed_manifest = Command::new(&installer)
        .args(["install"])
        .arg(&root)
        .args(["1000", "alice"])
        .arg(&payload)
        .env("BLOOM_ALLOW_TEST_UNCLAIMED", "true")
        .output()
        .unwrap();
    assert!(changed_manifest.status.success());
    assert_eq!(
        fs::read(root.join("etc/bloom/1000/edge-manifest.json")).unwrap(),
        installed_manifest
    );
    fs::write(payload.join("config/edge-manifest.json"), payload_manifest).unwrap();

    let rotated = directory.path().join("rotated.json");
    fs::write(&rotated, b"{\"maximum_connections\":63}").unwrap();
    assert!(
        Command::new(&installer)
            .args(["rotate-config"])
            .arg(&root)
            .args(["1000", "signer"])
            .arg(&rotated)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        fs::read(root.join("etc/bloom/1000/signer/config.json")).unwrap(),
        b"{\"maximum_connections\":63}"
    );

    for (principal, forbidden) in [
        ("broker", "{\"audit_key_id\":\"substituted\"}"),
        ("signer", "{\"audit_historical_public_keys\":[]}"),
    ] {
        let installed_config =
            fs::read(root.join(format!("etc/bloom/1000/{principal}/config.json"))).unwrap();
        let replacement = directory.path().join(format!("{principal}-forbidden.json"));
        fs::write(&replacement, forbidden).unwrap();
        let rejected = Command::new(&installer)
            .args(["rotate-config"])
            .arg(&root)
            .args(["1000", principal])
            .arg(&replacement)
            .output()
            .unwrap();
        assert!(!rejected.status.success());
        assert!(
            String::from_utf8_lossy(&rejected.stderr)
                .contains("may not change authority or identity field")
        );
        assert_eq!(
            fs::read(root.join(format!("etc/bloom/1000/{principal}/config.json"))).unwrap(),
            installed_config
        );
    }

    assert!(
        !Command::new(&installer)
            .args(["uninstall"])
            .arg(&root)
            .args(["1000", "wrong-confirmation"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&installer)
            .args(["uninstall"])
            .arg(&root)
            .args(["1000", "delete-bloom-login-1000"])
            .status()
            .unwrap()
            .success()
    );
    assert!(!root.join("etc/bloom/1000").exists());
    assert!(
        !root
            .join("usr/lib/systemd/system/bloom-signer@1000.service.d")
            .exists()
    );
    assert!(root.join("usr/libexec/bloom/bloom-broker").exists());
}

#[test]
fn linux_installer_accepts_the_native_or_portable_sha256_tool() {
    let installer = fs::read_to_string(release_script("install-linux.sh")).unwrap();
    assert!(installer.contains("command -v sha256sum"));
    assert!(installer.contains("sha256sum \"$input\" | awk '{print $1}'"));
    assert!(installer.contains("command -v shasum"));
    assert!(installer.contains("shasum -a 256 \"$input\" | awk '{print $1}'"));
    assert!(installer.contains("release_digest=\"$(sha256_digest \"$payload/SHA256SUMS\")\""));
    assert!(installer.contains("Linux installation requires sha256sum or shasum"));
}

#[test]
fn macos_installer_stages_unix_principals_launchdaemons_and_confirmed_uninstall() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    let payload = make_installer_payload(directory.path());
    let installer = release_script("install-macos.sh");
    let installed = stage_macos_install(&installer, &root, &payload);
    assert!(
        installed.status.success(),
        "status: {}; stderr: {}",
        installed.status,
        String::from_utf8_lossy(&installed.stderr)
    );
    let broker_plist = root.join("Library/LaunchDaemons/com.bloom.broker.501.plist");
    let signer_plist = root.join("Library/LaunchDaemons/com.bloom.signer.501.plist");
    for (service, plist) in [("broker", &broker_plist), ("signer", &signer_plist)] {
        let source = fs::read_to_string(plist).unwrap();
        assert!(!source.contains("@BLOOM_"));
        assert!(source.contains(&format!(
            "BLOOM_{}_AUDIT_CHECKPOINT_DIR",
            service.to_ascii_uppercase()
        )));
        assert!(source.contains("BLOOM_AUTHORITY_EDGE_HISTORY"));
        assert!(source.contains("<key>UserName</key>"));
        assert_eq!(
            fs::metadata(plist).unwrap().permissions().mode() & 0o777,
            0o644
        );
        if cfg!(target_os = "macos") {
            assert!(
                Command::new("plutil")
                    .args(["-lint"])
                    .arg(plist)
                    .status()
                    .unwrap()
                    .success()
            );
        }
    }
    let containment_plist = root.join("Library/LaunchDaemons/com.bloom.containment.plist");
    let containment_source = fs::read_to_string(&containment_plist).unwrap();
    assert!(containment_source.contains("<string>serve</string>"));
    assert!(containment_source.contains("<string>triad-pf-monitor-once</string>"));
    assert!(!containment_source.contains("@BLOOM_"));
    assert_eq!(
        fs::metadata(&containment_plist)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert_eq!(
        fs::metadata(root.join("var/db/bloom/501/signer/audit-checkpoints"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(root.join("var/db/bloom/501/machine/audit-checkpoints"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let authority_history = fs::read_to_string(
        root.join("Library/Application Support/BloomTriad/config/501/authority-edge-history.json"),
    )
    .unwrap();
    assert!(authority_history.contains("bloom.authority-edge-application-history.1"));
    let edge_manifest = fs::read_to_string(
        root.join("Library/Application Support/BloomTriad/config/501/edge-manifest.json"),
    )
    .unwrap();
    assert!(edge_manifest.contains("\"machine_uid\": 501"));
    assert!(edge_manifest.contains("\"broker_uid\": 250501"));
    assert!(edge_manifest.contains("\"signer_uid\": 250502"));
    assert!(edge_manifest.contains("\"session_socket_gid\": 260503"));
    let enrollment = fs::read_to_string(
        root.join("Library/Application Support/BloomTriad/enrollments/501.json"),
    )
    .unwrap();
    assert_eq!(
        fs::metadata(root.join("Library/Application Support/BloomTriad/enrollments/501.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert!(enrollment.contains("\"broker_gid\":260499"));
    assert!(enrollment.contains("\"state\":\"activating\""));
    assert!(enrollment.contains("\"signer_gid\":260500"));
    assert!(enrollment.contains("\"machine_broker_gid\":260501"));
    assert!(enrollment.contains("\"broker_signer_gid\":260502"));
    assert!(enrollment.contains("\"revoke_gid\":260503"));
    let pf = fs::read_to_string(root.join("etc/pf.anchors/com.bloom.triad.501")).unwrap();
    assert!(pf.contains("user 250501"));
    assert!(pf.contains("user 250502"));
    assert!(
        root.join("usr/local/libexec/bloom/current/bloom-broker")
            .exists()
    );
    assert!(
        root.join("Library/LaunchAgents/com.bloom.session.plist")
            .exists()
    );
    assert_eq!(
        fs::metadata(root.join("Library/Application Support/BloomTriad/config/501/session"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for relative in [
        "machine/identity.json",
        "machine/revoke-identity.json",
        "installer/identity.json",
        "provenance-catalog.json",
    ] {
        assert!(
            root.join("Library/Application Support/BloomTriad/config/501")
                .join(relative)
                .is_file(),
            "macOS install omitted {relative}"
        );
    }

    let signer_checkpoints = root.join("var/db/bloom/501/signer/audit-checkpoints");
    let substituted = directory.path().join("substituted-checkpoints");
    fs::create_dir(&substituted).unwrap();
    fs::set_permissions(&substituted, fs::Permissions::from_mode(0o777)).unwrap();
    fs::remove_dir(&signer_checkpoints).unwrap();
    std::os::unix::fs::symlink(&substituted, &signer_checkpoints).unwrap();
    let rejected = stage_macos_install(&installer, &root, &payload);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("security directory"));
    assert_eq!(
        fs::metadata(&substituted).unwrap().permissions().mode() & 0o777,
        0o777,
        "rejected symlink substitution must not chmod the target"
    );
    fs::remove_file(&signer_checkpoints).unwrap();
    fs::create_dir(&signer_checkpoints).unwrap();

    assert!(
        Command::new(&installer)
            .args(["uninstall"])
            .arg(&root)
            .args(["501", "delete-bloom-login-501"])
            .status()
            .unwrap()
            .success()
    );
    assert!(!broker_plist.exists());
    assert!(!signer_plist.exists());
    assert!(
        !root.join("usr/local/libexec/bloom").exists(),
        "the last permanent purge must remove the unreferenced shared release"
    );
}

#[test]
fn macos_installer_creates_enrollment_workspace_with_private_modes() {
    let installer = fs::read_to_string(release_script("install-macos.sh")).unwrap();
    assert!(
        installer.contains(r#"mkdir -m 0700 "$templates" "$material""#),
        "macOS enrollment generation directories must not inherit a permissive umask"
    );
}

#[test]
fn macos_staged_lifecycle_upgrades_repairs_retains_restores_and_rejects_downgrade() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    let baseline = make_installer_payload(&directory.path().join("baseline"));
    let candidate = make_installer_payload(&directory.path().join("candidate"));
    let installer = release_script("install-macos.sh");
    let old_digest = "11".repeat(32);
    let new_digest = "22".repeat(32);
    assert!(
        stage_macos_install_digest(&installer, &root, &baseline, &old_digest)
            .status
            .success()
    );
    let identity =
        root.join("Library/Application Support/BloomTriad/config/501/signer/identity.json");
    let identity_before = fs::read(&identity).unwrap();

    let upgraded = stage_macos_install_digest(&installer, &root, &candidate, &new_digest);
    assert!(
        upgraded.status.success(),
        "{}",
        String::from_utf8_lossy(&upgraded.stderr)
    );
    assert_eq!(
        fs::read_link(root.join("usr/local/libexec/bloom/current")).unwrap(),
        Path::new("releases").join(&new_digest)
    );
    assert_eq!(fs::read(&identity).unwrap(), identity_before);
    assert!(
        stage_macos_install_digest(&installer, &root, &candidate, &new_digest)
            .status
            .success(),
        "same-digest repair must be idempotent"
    );

    let retained = Command::new(&installer)
        .args(["uninstall", "--retain-custody"])
        .arg(&root)
        .arg("501")
        .output()
        .unwrap();
    assert!(
        retained.status.success(),
        "{}",
        String::from_utf8_lossy(&retained.stderr)
    );
    assert!(
        !root
            .join("Library/Application Support/BloomTriad/enrollments/501.json")
            .exists()
    );
    assert!(
        root.join("Library/Application Support/BloomTriad/retained/501.json")
            .is_file()
    );
    assert_eq!(fs::read(&identity).unwrap(), identity_before);

    let restored = Command::new(&installer)
        .args(["restore"])
        .arg(&root)
        .args(["501", "alice"])
        .arg(&candidate)
        .env("BLOOM_ALLOW_TEST_UNCLAIMED", "true")
        .env("BLOOM_MACOS_BROKER_UID", "250501")
        .env("BLOOM_MACOS_SIGNER_UID", "250502")
        .env("BLOOM_MACOS_BROKER_GID", "260499")
        .env("BLOOM_MACOS_SIGNER_GID", "260500")
        .env("BLOOM_MACOS_MACHINE_BROKER_GID", "260501")
        .env("BLOOM_MACOS_BROKER_SIGNER_GID", "260502")
        .env("BLOOM_MACOS_REVOKE_GID", "260503")
        .env("BLOOM_RELEASE_DIGEST", &new_digest)
        .output()
        .unwrap();
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert_eq!(fs::read(&identity).unwrap(), identity_before);

    fs::write(
        root.join("Library/Application Support/BloomTriad/state-schema"),
        b"machine=2\nbroker=1\nsigner=1\n",
    )
    .unwrap();
    let downgrade = stage_macos_install_digest(&installer, &root, &candidate, &new_digest);
    assert!(!downgrade.status.success());
    assert!(String::from_utf8_lossy(&downgrade.stderr).contains("downgrade rejected"));
    assert_eq!(fs::read(&identity).unwrap(), identity_before);

    fs::write(
        root.join("Library/Application Support/BloomTriad/state-schema"),
        b"machine=1\nbroker=1\nsigner=1\n",
    )
    .unwrap();
    fs::write(
        candidate.join("compatibility-v1.toml"),
        b"malformed = true\n",
    )
    .unwrap();
    let malformed = stage_macos_install_digest(&installer, &root, &candidate, &new_digest);
    assert!(!malformed.status.success());
    assert!(String::from_utf8_lossy(&malformed.stderr).contains("compatibility metadata"));
    assert_eq!(fs::read(&identity).unwrap(), identity_before);
}

#[test]
fn macos_restore_cannot_downgrade_the_release_shared_by_an_active_login() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    let baseline = make_installer_payload(&directory.path().join("baseline"));
    let candidate = make_installer_payload(&directory.path().join("candidate"));
    let installer = release_script("install-macos.sh");
    let old_digest = "11".repeat(32);
    let new_digest = "22".repeat(32);
    assert!(
        stage_macos_install_digest(&installer, &root, &baseline, &old_digest)
            .status
            .success()
    );
    assert!(
        Command::new(&installer)
            .args(["uninstall", "--retain-custody"])
            .arg(&root)
            .arg("501")
            .status()
            .unwrap()
            .success()
    );

    let second = Command::new(&installer)
        .args(["install"])
        .arg(&root)
        .args(["502", "bob"])
        .arg(&candidate)
        .env("BLOOM_ALLOW_TEST_UNCLAIMED", "true")
        .env("BLOOM_MACOS_BROKER_UID", "250511")
        .env("BLOOM_MACOS_SIGNER_UID", "250512")
        .env("BLOOM_MACOS_BROKER_GID", "260509")
        .env("BLOOM_MACOS_SIGNER_GID", "260510")
        .env("BLOOM_MACOS_MACHINE_BROKER_GID", "260511")
        .env("BLOOM_MACOS_BROKER_SIGNER_GID", "260512")
        .env("BLOOM_MACOS_REVOKE_GID", "260513")
        .env("BLOOM_RELEASE_DIGEST", &new_digest)
        .output()
        .unwrap();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );

    let rejected = Command::new(&installer)
        .args(["restore"])
        .arg(&root)
        .args(["501", "alice"])
        .arg(&baseline)
        .env("BLOOM_ALLOW_TEST_UNCLAIMED", "true")
        .env("BLOOM_MACOS_BROKER_UID", "250501")
        .env("BLOOM_MACOS_SIGNER_UID", "250502")
        .env("BLOOM_MACOS_BROKER_GID", "260499")
        .env("BLOOM_MACOS_SIGNER_GID", "260500")
        .env("BLOOM_MACOS_MACHINE_BROKER_GID", "260501")
        .env("BLOOM_MACOS_BROKER_SIGNER_GID", "260502")
        .env("BLOOM_MACOS_REVOKE_GID", "260503")
        .env("BLOOM_RELEASE_DIGEST", &old_digest)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("restore cannot change the shared release used by active enrollments")
    );
    assert!(
        root.join("Library/Application Support/BloomTriad/retained/501.json")
            .is_file()
    );
    assert!(
        !root
            .join("Library/Application Support/BloomTriad/enrollments/501.json")
            .exists()
    );
}

#[test]
fn macos_installer_silences_transient_health_failures_and_replays_the_last_error() {
    let installer = fs::read_to_string(release_script("install-macos.sh")).unwrap();
    assert!(
        installer.contains(r#"health_output="$(mktemp "$scratch/health-check.XXXXXX")""#),
        "health-check output must be captured privately during activation retries"
    );
    assert!(
        installer.contains(r#">"$health_output" 2>&1; then return"#),
        "a successful readiness retry must suppress earlier transient failures"
    );
    assert!(
        installer.contains(r#"cat "$health_output" >&2"#),
        "the final readiness diagnostic must be replayed when activation fails"
    );
}

#[test]
fn macos_installer_never_repairs_or_overwrites_a_digest_named_release() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    let payload = make_installer_payload(directory.path());
    let installer = release_script("install-macos.sh");
    assert!(
        stage_macos_install(&installer, &root, &payload)
            .status
            .success()
    );
    let installed_broker = root.join(format!(
        "usr/local/libexec/bloom/releases/{}/bloom-broker",
        "11".repeat(32)
    ));
    fs::write(&installed_broker, b"substituted").unwrap();

    let rejected = stage_macos_install(&installer, &root, &payload);
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("digest-named release does not match the verified payload")
    );
    assert_eq!(fs::read(installed_broker).unwrap(), b"substituted");
}
