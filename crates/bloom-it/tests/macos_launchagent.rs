use std::{
    fs,
    path::{Path, PathBuf},
};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("service activation crate is inside the workspace")
        .to_path_buf()
}

fn assert_ordered(source: &str, needles: &[&str]) {
    let mut offset = 0;
    for needle in needles {
        let position = source[offset..]
            .find(needle)
            .unwrap_or_else(|| panic!("missing ordered source fragment {needle}"));
        offset += position + needle.len();
    }
}

#[test]
fn broker_launchdaemon_selects_owned_unix_sockets_and_direct_ceremony_bind() {
    let source = fs::read_to_string(
        workspace().join("packaging/triad/macos/launchdaemons/com.bloom.broker.plist.in"),
    )
    .expect("read Broker LaunchDaemon source");

    assert!(source.contains("<key>UserName</key>"));
    assert!(source.contains("@BLOOM_BROKER_USER@"));
    assert!(source.contains("<key>GroupName</key>\n  <string>@BLOOM_BROKER_GROUP@</string>"));
    assert!(source.contains("<key>InitGroups</key>\n  <true/>"));
    assert!(source.contains("<key>BLOOM_BROKER_SOCKET</key>"));
    assert!(source.contains("@BLOOM_BROKER_SOCKET@"));
    assert!(source.contains("<key>BLOOM_BROKER_CONTROL_SOCKET</key>"));
    assert!(source.contains("@BLOOM_BROKER_CONTROL_SOCKET@"));
    assert!(!source.contains("<key>Sockets</key>"));
    assert!(!source.contains("SockPath"));
    assert!(
        !source.contains("broker-ceremony")
            && !source.contains("18734")
            && !source.contains("SockNodeName"),
        "Unix-principal Broker must bind the canonical TCP listener itself"
    );
    assert!(
        source.contains("<key>KeepAlive</key>")
            && source.contains("<key>SuccessfulExit</key>")
            && source.contains("<false/>")
            && source.contains("<key>ThrottleInterval</key>"),
        "fatal Broker startup is not configured for throttled launchd retry"
    );
    assert!(source.contains("<key>BLOOM_BROKER_STARTUP_STATUS</key>"));
    assert!(source.contains("@BLOOM_BROKER_STARTUP_STATUS@"));
    assert!(source.contains("<key>Core</key>\n    <integer>0</integer>"));
}

#[test]
fn signer_launchdaemon_exposes_only_broker_and_revoke_group_edges() {
    let source = fs::read_to_string(
        workspace().join("packaging/triad/macos/launchdaemons/com.bloom.signer.plist.in"),
    )
    .expect("read Signer LaunchDaemon source");

    assert!(source.contains("<key>UserName</key>"));
    assert!(source.contains("@BLOOM_SIGNER_USER@"));
    assert!(source.contains("<key>GroupName</key>\n  <string>@BLOOM_SIGNER_GROUP@</string>"));
    assert!(source.contains("<key>InitGroups</key>\n  <true/>"));
    assert!(source.contains("<key>BLOOM_SIGNER_SOCKET</key>"));
    assert!(source.contains("@BLOOM_SIGNER_SOCKET@"));
    assert!(source.contains("<key>BLOOM_SIGNER_CONTROL_SOCKET</key>"));
    assert!(source.contains("@BLOOM_SIGNER_CONTROL_SOCKET@"));
    assert!(source.contains("<key>BLOOM_SESSION_SOCKET</key>"));
    assert!(source.contains("@BLOOM_SESSION_SOCKET@"));
    assert!(!source.contains("<key>Sockets</key>"));
    assert!(!source.contains("SockPath"));
    assert!(!source.contains("com.apple.security.network"));
    assert!(!source.contains("broker-ceremony"));
}

#[test]
fn session_agent_has_no_service_authority_and_stops_with_the_login_domain() {
    let source = fs::read_to_string(
        workspace().join("packaging/triad/macos/launchagents/com.bloom.session.plist.in"),
    )
    .expect("read session LaunchAgent source");

    assert!(source.contains("@BLOOM_MACHINE_BINARY@"));
    assert!(source.contains("<string>serve</string>"));
    assert!(source.contains("<string>session-sentinel</string>"));
    assert!(source.contains("BLOOM_CONFIG_ROOT"));
    assert!(source.contains("/private/var/run/bloom"));
    assert!(source.contains("<string>Aqua</string>"));
    assert!(!source.contains("UserName"));
    assert!(!source.contains("Sockets"));
    assert!(!source.contains("BLOOM_BROKER_CONFIG"));
    assert!(!source.contains("BLOOM_SIGNER_CONFIG"));
}

#[test]
fn broker_requires_the_authenticated_session_socket_before_ceremonies() {
    let source = fs::read_to_string(
        workspace().join("packaging/triad/macos/launchdaemons/com.bloom.broker.plist.in"),
    )
    .expect("read Broker LaunchDaemon source");
    assert!(source.contains("<key>BLOOM_SESSION_SOCKET</key>"));
    assert!(source.contains("@BLOOM_SESSION_SOCKET@"));

    let machine = fs::read_to_string(workspace().join("crates/bloom/src/session_sentinel.rs"))
        .expect("read Machine session sentinel");
    assert!(machine.contains("authenticate_server"));
    assert!(machine.contains("bloom-session"));
    assert!(machine.contains("remove_owned_stale_socket"));
    assert!(machine.contains("session_socket_gid"));
    assert!(machine.contains("std::os::unix::fs::chown(&socket_path"));
    assert!(!machine.contains("fchown(&listener"));

    let cli = fs::read_to_string(workspace().join("crates/bloom/src/main.rs")).unwrap();
    assert!(cli.contains("/Library/Application Support/BloomTriad/enrollments/"));
    assert!(cli.contains("/private/var/run/bloom/{uid}/machine-broker/broker.sock"));
    assert!(cli.contains("observed_build={}, expected_build={}, state={:?}, conditions={}"));
}

#[test]
fn macos_packaging_pins_platform_time_checkpoint_and_future_rootless_separation() {
    let readme = fs::read_to_string(workspace().join("packaging/triad/macos/README.md")).unwrap();
    assert!(readme.contains("Unix-principal"));
    assert!(readme.contains("macos-rootless-code-identity"));
    assert!(readme.contains("future target"));
    assert!(readme.contains("checkpoint"));
    assert!(readme.contains("disposable macOS W0"));
}

#[test]
fn installed_acceptance_derives_the_signed_release_digest_and_reads_sources_as_login() {
    let source = fs::read_to_string(
        workspace().join("packaging/triad/macos/w0/run-installed-acceptance.sh"),
    )
    .unwrap();
    assert!(source.contains("shasum -a 256 \"$payload/SHA256SUMS\""));
    assert!(source.contains("\"$release_digest\" == \"$payload_release_digest\""));
    assert!(source.contains("sudo -H -u \"$login_user\" /usr/bin/git -C \"$root\" rev-parse HEAD"));
    assert!(source.contains("/usr/bin/git -C \"$root\" status --porcelain --untracked-files=no"));
    assert!(source.contains("BLOOM_MACOS_ACCEPTANCE_CARGO_TARGET_DIR"));
    assert!(source.contains("tool_environment+=(\"CARGO_TARGET_DIR=$cargo_target_dir\")"));
    assert!(!source.contains("$payload/RELEASE_DIGEST"));
}

#[test]
fn pf_source_denies_broker_and_signer_by_numeric_effective_uid() {
    let source =
        fs::read_to_string(workspace().join("packaging/triad/macos/pf/com.bloom.login.conf.in"))
            .expect("read packet-filter source");
    assert!(source.contains("user @BLOOM_SIGNER_UID@"));
    assert!(source.contains("user @BLOOM_BROKER_UID@"));
    assert!(source.contains("pass out quick on lo0 inet proto tcp"));
    assert!(source.contains("from 127.0.0.1 port 18734 to 127.0.0.1"));
    assert!(source.contains("flags A/A user @BLOOM_BROKER_UID@"));
    assert!(source.contains("block return out quick"));
    assert!(!source.contains("0.0.0.0/0"));
    assert!(!source.contains("::/0"));
}

#[test]
fn root_pf_monitor_has_no_rpc_or_custody_surface_and_services_require_its_attestation() {
    let plist = fs::read_to_string(
        workspace().join("packaging/triad/macos/launchdaemons/com.bloom.containment.plist.in"),
    )
    .unwrap();
    assert!(plist.contains("<string>root</string>"));
    assert!(plist.contains("<string>serve</string>"));
    assert!(plist.contains("<string>triad-pf-monitor-once</string>"));
    assert!(plist.contains("<key>StartInterval</key>"));
    assert!(!plist.contains("<key>Sockets</key>"));

    let monitor = fs::read_to_string(workspace().join("crates/bloom/src/pf_monitor.rs")).unwrap();
    assert!(monitor.contains("/sbin/pfctl"));
    assert!(monitor.contains("bloom.macos-platform-status.3"));
    assert!(monitor.contains("/usr/sbin/systemsetup"));
    assert!(monitor.contains("Network Time: On"));
    assert!(monitor.contains("system/com.apple.timed"));
    assert!(monitor.contains("x-bloom-ceremony-owner: bloom-broker-v1"));
    assert!(monitor.contains("ceremony_listener_bloom_shaped"));
    assert!(monitor.contains("status.json"));
    assert!(monitor.contains("restart_services_for_live_session"));
    assert!(monitor.contains("if enrollment_state == \"active\""));
    assert!(monitor.contains("gui/{login_uid}/com.bloom.session"));
    assert!(monitor.contains("session.sock"));
    assert!(monitor.contains("metadata.file_type().is_socket()"));
    assert!(monitor.contains("system/com.bloom.{service}.{login_uid}"));
    assert!(monitor.contains("[\"signer\", \"broker\"]"));
    assert!(monitor.contains("\"kickstart\""));
    assert!(!monitor.contains("signing_seed"));
    assert_ordered(
        &monitor,
        &[
            "gui/{login_uid}/com.bloom.session",
            "state = running",
            "session.sock",
            "[\"signer\", \"broker\"]",
        ],
    );

    for config in ["broker.json.in", "signer.json.in"] {
        let source = fs::read_to_string(
            workspace()
                .join("packaging/triad/macos/config")
                .join(config),
        )
        .unwrap();
        assert!(source.contains("\"network_containment\""));
        assert!(source.contains("@BLOOM_CONTAINMENT_STATUS@"));
    }
}

#[test]
fn live_installer_provisions_fail_closed_directory_service_records() {
    let source =
        fs::read_to_string(workspace().join("packaging/triad/release/install-macos.sh")).unwrap();
    for required in [
        "live installation requires root on macOS",
        "lock_installer",
        "next_id",
        "refusing to adopt pre-existing user",
        "refusing to adopt pre-existing group",
        "AuthenticationAuthority ';DisabledUser;'",
        "BLOOM_RELEASE_PUBLIC_KEY",
        "pinned release key must be root owned",
        "init triad-render-macos-enrollment",
        "$payload/installer/macos/config/",
        "dsmemberutil flushcache",
        "chown \"$broker_user:$machine_broker_group\" \"$runtime/machine-broker\"",
        "chown \"$signer_user:$broker_signer_group\" \"$runtime/broker-signer\"",
        "security directory is missing or substituted",
        "ssh-keygen -Y verify",
        "shasum -a 256 -c SHA256SUMS",
    ] {
        assert!(
            source.contains(required),
            "live installer is missing fail-closed input {required}"
        );
    }
    assert!(!source.contains("macos-rootless-code-identity"));
    assert!(!source.contains("com.apple.security.application-groups"));
    assert!(source.lines().count() < 500);
}

#[test]
fn macos_installer_has_an_explicit_small_lifecycle() {
    let source =
        fs::read_to_string(workspace().join("packaging/triad/release/install-macos.sh")).unwrap();
    assert!(source.lines().count() < 500);
    assert!(source.contains("install ROOT LOGIN_UID LOGIN_USER PAYLOAD_DIR"));
    assert!(source.contains("uninstall ROOT LOGIN_UID delete-bloom-login-LOGIN_UID"));
    assert!(source.contains("in-place upgrades were removed"));
    for removed in [
        "rotate-config",
        "rotate-identities",
        "upgrade-transaction",
        "rotation-transaction",
        "retain-bloom-login",
    ] {
        assert!(
            !source.contains(removed),
            "removed lifecycle leaked back into installer: {removed}"
        );
    }
}

#[test]
fn macos_installer_does_not_hide_removed_lifecycle_logic() {
    let source =
        fs::read_to_string(workspace().join("packaging/triad/release/install-macos.sh")).unwrap();
    for removed in [
        "init triad-render-macos-identity-rotation",
        "recover_interrupted",
        "retained_restore",
        "transaction_staging",
    ] {
        assert!(!source.contains(removed));
    }
    assert!(!source.contains("source "));
}

#[test]
fn macos_installer_is_self_contained_and_pipe_safe() {
    let source =
        fs::read_to_string(workspace().join("packaging/triad/release/install-macos.sh")).unwrap();
    assert!(source.contains("curl ... | sudo bash -s --"));
    assert!(!source.contains("BASH_SOURCE"));
    assert!(!source.contains("ssh-ed25519-verify.sh"));
    assert!(source.contains("ssh-keygen -Y verify"));
}

#[test]
fn macos_permanent_uninstall_is_explicit_and_small() {
    let source =
        fs::read_to_string(workspace().join("packaging/triad/release/install-macos.sh")).unwrap();
    for required in [
        "delete-bloom-login-LOGIN_UID",
        "uninstall confirmation mismatch",
        "Bloom macOS enrollment permanently removed",
    ] {
        assert!(
            source.contains(required),
            "macOS installer is missing uninstall behavior {required}"
        );
    }
}

#[test]
fn activating_enrollment_is_private_to_installer_health_and_session_bootstrap() {
    let machine = fs::read_to_string(workspace().join("crates/bloom/src/main.rs")).unwrap();
    assert!(machine.contains("allow_activating"));
    assert!(machine.contains("installed Bloom enrollment is not active"));
    for required in [
        "open_configured_machine_audit_with_activation",
        "configured_machine_checkpoint_path_with_activation",
        "configured_authority_edge_history_path_with_activation",
        "configured_machine_audit_history_path_with_activation",
    ] {
        assert!(
            machine.contains(required),
            "activation health does not carry its narrow enrollment allowance through {required}"
        );
    }
    let sentinel =
        fs::read_to_string(workspace().join("crates/bloom/src/session_sentinel.rs")).unwrap();
    assert!(sentinel.contains("Some(\"activating\" | \"active\")"));
    let installer =
        fs::read_to_string(workspace().join("packaging/triad/release/install-macos.sh")).unwrap();
    let health = installer.find("start_and_check").unwrap();
    let publish = installer.rfind("write_enrollment active").unwrap();
    assert!(health < publish);
}

#[test]
fn production_macos_bundle_forbids_archived_private_identity_material() {
    for script in ["build-bundle.sh", "verify-bundle.sh"] {
        let source =
            fs::read_to_string(workspace().join("packaging/triad/release").join(script)).unwrap();
        assert!(source.contains("macOS Unix-principal bundle contains private key material"));
        assert!(source.contains("private_key_seed_hex|signing_seed_hex"));
        assert!(source.contains("private identity-shaped file"));
        assert!(source.contains("verify-macos-conformance.sh"));
    }
    let builder =
        fs::read_to_string(workspace().join("packaging/triad/release/build-bundle.sh")).unwrap();
    assert!(builder.contains("BLOOM_MACOS_CONFORMANCE_KEY_SHA256"));
    assert!(builder.contains("BLOOM_MACOS_CONFORMANCE_REPORT"));
    let verifier =
        fs::read_to_string(workspace().join("packaging/triad/release/verify-macos-conformance.sh"))
            .unwrap();
    assert!(verifier.contains("bloom.macos-unix-conformance.1"));
    assert!(verifier.contains("installed_ac_01_35"));
    assert!(verifier.contains("two_login_lifecycle"));
    assert!(verifier.contains("release_subject_digest"));
    let templates = workspace().join("packaging/triad/macos/config");
    for entry in fs::read_dir(templates).unwrap() {
        let path = entry.unwrap().path();
        let bytes = fs::read_to_string(&path).unwrap();
        for line in bytes.lines().filter(|line| line.contains("seed_hex")) {
            assert!(
                line.contains('@'),
                "{} contains a concrete private seed",
                path.display()
            );
        }
    }
}

#[test]
fn privileged_w0_harness_requires_an_external_disposable_host_marker() {
    let source =
        fs::read_to_string(workspace().join("packaging/triad/macos/w0/run-disposable.sh")).unwrap();
    assert!(source.contains("BLOOM_RUN_MACOS_UNIX_W0"));
    assert!(source.contains("/private/var/db/bloom-w0-disposable-host"));
    assert!(source.contains("bloom-macos-unix-w0-disposable-v1"));
    assert!(source.contains("macos-unix-principals-w0"));
    assert!(!source.contains("UPGRADE_PAYLOAD"));
    assert!(!source.contains("upgrade-transaction"));
    assert!(!source.contains("rotation-transaction"));
    assert!(!source.contains("retain-bloom-login"));
    assert!(source.contains("/usr/bin/nc -lk 127.0.0.1 18734"));
    assert!(source.contains("no fallback port will be used"));
    assert!(source.contains("Broker opened a fallback TCP listener"));
    assert!(source.contains("foreign_or_unverifiable_process"));
    assert!(source.contains("Bloom Broker startup failed: a foreign or unverifiable process"));
    let foreign_bind = source
        .find("/usr/bin/nc -lk 127.0.0.1 18734")
        .expect("foreign listener bind");
    let freshness_wait = source[foreign_bind..]
        .find("network_containment.maximum_age_ms")
        .map(|offset| foreign_bind + offset)
        .expect("containment freshness wait after foreign bind");
    let broker_bootstrap = source[freshness_wait..]
        .find("launchctl bootstrap system \"$broker_plist\"")
        .map(|offset| freshness_wait + offset)
        .expect("Broker bootstrap after containment freshness wait");
    assert!(foreign_bind < freshness_wait && freshness_wait < broker_bootstrap);
    assert!(source.contains("Signer opened a forbidden IPv6 loopback TCP connection"));
    assert!(source.contains("assert_udp_blocked"));
    assert!(source.contains("forbidden non-loopback IPv4 TCP connection"));
    assert!(source.contains("unrelated local UID opened protected Unix endpoint"));
    assert!(source.contains("Machine login opened the Broker-to-Signer data endpoint"));
    assert!(source.contains("assert_principal_cannot_replace"));
    assert!(source.contains("run_reinstall_with_substitution"));
    assert!(source.contains("installer accepted $substitution edge-manifest tampering"));
    assert!(source.contains("task-access-probe"));
    assert!(source.contains("Machine login sampled"));
    assert!(source.contains("session sentinel did not reject an unauthorized login-UID peer"));
    assert!(source.contains("services did not drain after the login-session sentinel disappeared"));
    assert!(source.contains("Broker retained the ceremony listener after session logout"));
    assert!(source.contains("launchctl bootstrap \"gui/$login_uid\" \"$session_plist\""));
    assert!(source.contains("run-installed-acceptance.sh"));
    assert!(source.contains("BLOOM_MACOS_INSTALLED_ACCEPTANCE_MAIN_ROOT"));
    assert!(
        !source.contains("touch \"$marker\"")
            && !source.contains("install -m 0600 /dev/null \"$marker\""),
        "the repository must not self-authorize a host as disposable"
    );

    let two_login =
        fs::read_to_string(workspace().join("packaging/triad/macos/w0/run-two-login.sh")).unwrap();
    assert!(two_login.contains("active GUI domains for both selected users"));
    assert!(two_login.contains("another_login_session"));
    assert!(two_login.contains("second Broker opened a fallback TCP listener"));
    assert!(two_login.contains("launchctl bootout \"gui/$login_uid_b\""));
    assert!(two_login.contains("through failure-only KeepAlive"));
    assert!(two_login.contains("before any new Machine request"));
    assert!(two_login.contains("two_login_lifecycle"));
    assert!(two_login.contains("failing upgrade unexpectedly committed"));
    assert!(two_login.contains("two-login upgrade rollback split the installed release"));
    assert!(two_login.contains("mui_09.pass"));
    assert!(two_login.contains("macos-conformance-subject.sh"));
    assert!(two_login.contains("shasum -a 256 \"$manifest\""));
    assert!(!two_login.contains("RELEASE_DIGEST"));
    assert!(
        !two_login.contains("touch \"$marker\"")
            && !two_login.contains("install -m 0600 /dev/null \"$marker\""),
        "the two-login harness must not self-authorize a host as disposable"
    );

    let installed_acceptance = fs::read_to_string(
        workspace().join("packaging/triad/macos/w0/run-installed-acceptance.sh"),
    )
    .unwrap();
    assert!(installed_acceptance.contains("installed_ac_01_35"));
    assert!(installed_acceptance.contains("mui_01"));
    assert!(installed_acceptance.contains("mui_11"));
    assert!(installed_acceptance.contains("mui_12"));
    assert!(installed_acceptance.contains("TeamIdentifier="));
    assert!(installed_acceptance.contains("release gate emitted a production macOS claim"));
    assert!(installed_acceptance.contains("BLOOM_ACCEPTANCE_BUNDLE_ROOT"));
    assert!(installed_acceptance.contains("assert_installed_process bloom-broker"));
    assert!(installed_acceptance.contains("assert_installed_process bloom-signer"));
    assert!(installed_acceptance.contains("-p bloom-machine-client"));
    assert!(!installed_acceptance.contains("-p bloom-rpc-wire"));
    assert!(installed_acceptance.contains("--workspace"));
    assert!(
        !installed_acceptance.contains("touch \"$marker\"")
            && !installed_acceptance.contains("install -m 0600 /dev/null \"$marker\""),
        "the installed-acceptance harness must not self-authorize a host as disposable"
    );

    let ci = fs::read_to_string(workspace().join(".github/workflows/ci.yml")).unwrap();
    assert!(ci.contains("macos_unix_principal_disposable_w0"));
    assert!(ci.contains("github.event_name == 'workflow_dispatch'"));
    assert!(ci.contains("github.ref_name == 'triad-architecture'"));
    assert!(ci.contains("uses: ./.github/workflows/macos-unix-w0.yml"));

    let workflow =
        fs::read_to_string(workspace().join(".github/workflows/macos-unix-w0.yml")).unwrap();
    assert!(workflow.contains("workflow_call:"));

    let two_login_workflow =
        fs::read_to_string(workspace().join(".github/workflows/macos-two-login-w0.yml")).unwrap();
    assert!(two_login_workflow.contains("bloom-two-login-disposable"));
    assert!(two_login_workflow.contains("test \"$(id -u)\" !="));
    assert!(two_login_workflow.contains("failing-broker.c"));
    assert!(two_login_workflow.contains("run-two-login.sh"));
    assert!(two_login_workflow.contains("macos-two-login-evidence/*.pass"));
}
