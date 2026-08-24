use std::{fs, path::Path};

fn packaging_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("service activation crate is inside the workspace")
        .join("packaging/triad/linux")
}

fn source(relative: &str) -> String {
    fs::read_to_string(packaging_root().join(relative))
        .unwrap_or_else(|error| panic!("read Linux packaging source {relative}: {error}"))
}

#[test]
fn systemd_owns_only_the_tcp_listener_and_services_own_authenticated_unix_sockets() {
    let ceremony = source("systemd/bloom-broker-ceremony@.socket");
    for required in [
        "ListenStream=127.0.0.1:18734",
        "FileDescriptorName=broker-ceremony",
        "Service=bloom-broker@%i.service",
        "Accept=no",
        "FreeBind=no",
        "ReusePort=no",
        "IPAddressDeny=any",
        "IPAddressAllow=localhost",
    ] {
        assert!(
            ceremony.contains(required),
            "canonical listener is missing {required}"
        );
    }
    assert!(!ceremony.contains("18735") && !ceremony.contains("Accept=yes"));

    let broker = source("systemd/bloom-broker@.service.in");
    let signer = source("systemd/bloom-signer@.service.in");
    for required in [
        "Environment=BLOOM_BROKER_SOCKET=/run/bloom/%i/broker/rpc/broker.sock",
        "Environment=BLOOM_BROKER_CONTROL_SOCKET=/run/bloom/%i/broker/control/broker-control.sock",
    ] {
        assert!(broker.contains(required));
    }
    for required in [
        "Environment=BLOOM_SIGNER_SOCKET=/run/bloom/%i/signer/rpc/signer.sock",
        "Environment=BLOOM_SIGNER_CONTROL_SOCKET=/run/bloom/%i/signer/control/signer-control.sock",
    ] {
        assert!(signer.contains(required));
    }
    assert!(!broker.contains("BLOOM_BROKER_ACTIVATION_NAME"));
    assert!(!signer.contains("BLOOM_SIGNER_ACTIVATION_NAME"));

    let session_path = source("systemd/bloom-session@.path");
    assert!(session_path.contains("PathExists=/run/bloom/%i/session/session.sock"));
    assert!(session_path.contains("Unit=bloom-broker@%i.service"));
}

#[test]
fn principals_groups_state_and_socket_acls_are_non_transitive() {
    let users = source("sysusers.d/bloom-login.conf.in");
    for required in [
        "u bloom-broker-@LOGIN_UID@",
        "u bloom-signer-@LOGIN_UID@",
        "m @LOGIN_USER@ bloom-machine-broker-@LOGIN_UID@",
        "m bloom-broker-@LOGIN_UID@ bloom-machine-broker-@LOGIN_UID@",
        "m bloom-broker-@LOGIN_UID@ bloom-broker-signer-@LOGIN_UID@",
        "m bloom-signer-@LOGIN_UID@ bloom-broker-signer-@LOGIN_UID@",
        "m bloom-broker-@LOGIN_UID@ bloom-revoke-@LOGIN_UID@",
        "m bloom-signer-@LOGIN_UID@ bloom-revoke-@LOGIN_UID@",
        "m @LOGIN_USER@ bloom-session-@LOGIN_UID@",
        "m bloom-broker-@LOGIN_UID@ bloom-session-@LOGIN_UID@",
        "m bloom-signer-@LOGIN_UID@ bloom-session-@LOGIN_UID@",
    ] {
        assert!(
            users.contains(required),
            "sysusers source is missing {required}"
        );
    }
    assert!(
        !users.contains("m @LOGIN_USER@ bloom-broker-signer-"),
        "Machine login principal must not join the Broker--Signer group"
    );

    let temporary_paths = source("tmpfiles.d/bloom-login.conf.in");
    for principal in ["broker", "signer"] {
        assert!(
            temporary_paths.contains(&format!(
                "d /var/lib/bloom/@LOGIN_UID@/{principal} 0700 bloom-{principal}-@LOGIN_UID@"
            )),
            "{principal} state root is not private to its effective principal"
        );
        assert!(
            temporary_paths.contains(&format!(
                "d /etc/bloom/@LOGIN_UID@/{principal} 0700 bloom-{principal}-@LOGIN_UID@"
            )),
            "{principal} configuration root is not private to its effective principal"
        );
    }

    for required in [
        "d /run/bloom/@LOGIN_UID@/broker/rpc 0710 bloom-broker-@LOGIN_UID@ bloom-machine-broker-@LOGIN_UID@ -",
        "d /run/bloom/@LOGIN_UID@/broker/control 0710 bloom-broker-@LOGIN_UID@ bloom-revoke-@LOGIN_UID@ -",
        "d /run/bloom/@LOGIN_UID@/signer/rpc 0710 bloom-signer-@LOGIN_UID@ bloom-broker-signer-@LOGIN_UID@ -",
        "d /run/bloom/@LOGIN_UID@/signer/control 0710 bloom-signer-@LOGIN_UID@ bloom-revoke-@LOGIN_UID@ -",
    ] {
        assert!(temporary_paths.contains(required), "missing {required}");
    }
}

#[test]
fn login_session_sentinel_is_installed_with_persistent_machine_paths() {
    let temporary_paths = source("tmpfiles.d/bloom-login.conf.in");
    assert!(temporary_paths.contains(
        "d /run/bloom/@LOGIN_UID@/session 0710 @LOGIN_USER@ bloom-session-@LOGIN_UID@ -"
    ));
    assert!(
        temporary_paths
            .contains("d /etc/bloom/@LOGIN_UID@/machine 0700 @LOGIN_USER@ @LOGIN_USER@ -")
    );
    assert!(
        temporary_paths
            .contains("d /etc/bloom/@LOGIN_UID@/session 0700 @LOGIN_USER@ @LOGIN_USER@ -")
    );

    let sentinel = source("systemd-user/bloom-session.service");
    assert!(sentinel.contains("ExecStart=/usr/libexec/bloom/bloom serve session-sentinel"));
    assert!(sentinel.contains("NoNewPrivileges=yes"));
    assert!(sentinel.contains("RestrictAddressFamilies=AF_UNIX"));
    assert!(!sentinel.contains("ProtectSystem=") && !sentinel.contains("ReadWritePaths="));
    for principal in ["broker", "signer"] {
        let service = source(&format!("systemd/bloom-{principal}@.service.in"));
        assert!(
            service.contains("Environment=BLOOM_SESSION_SOCKET=/run/bloom/%i/session/session.sock")
        );
    }

    let wrapper = source("bin/bloom");
    for required in [
        "BLOOM_BROKER_SOCKET",
        "BLOOM_MACHINE_IDENTITY",
        "BLOOM_EDGE_MANIFEST",
        "BLOOM_PROVENANCE_CATALOG",
        "BLOOM_MACHINE_AUDIT_CHECKPOINT_DIR",
        "BLOOM_MACHINE_AUDIT_HISTORY",
        "BLOOM_AUTHORITY_EDGE_HISTORY",
    ] {
        assert!(
            wrapper.contains(required),
            "installed wrapper omits {required}"
        );
    }
}

#[test]
fn service_sandboxes_remove_machine_and_network_authority() {
    let broker = source("systemd/bloom-broker@.service.in");
    let signer = source("systemd/bloom-signer@.service.in");
    for (name, unit) in [("Broker", &broker), ("Signer", &signer)] {
        for required in [
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "ProtectProc=invisible",
            "RestrictNamespaces=yes",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "LimitCORE=0",
        ] {
            assert!(
                unit.contains(required),
                "{name} sandbox is missing {required}"
            );
        }
        assert!(
            !unit.contains("ProtectClock="),
            "{name} must be able to make the read-only adjtimex synchronization query"
        );
        assert!(
            unit.contains("CapabilityBoundingSet=") && unit.contains("AmbientCapabilities="),
            "{name} must still lack CAP_SYS_TIME after ProtectClock is removed"
        );
    }
    assert!(broker.contains("User=bloom-broker-%i"));
    assert!(broker.contains("RestrictAddressFamilies=AF_UNIX AF_INET"));
    assert!(broker.contains("IPAddressAllow=localhost"));
    assert!(signer.contains("User=bloom-signer-%i"));
    assert!(signer.contains("PrivateNetwork=yes"));
    assert!(signer.contains("RestrictAddressFamilies=AF_UNIX"));
    assert!(!signer.contains("IPAddressAllow="));

    let aws_path = "systemd/instance-dropins/bloom-signer@LOGIN_UID.service.d/50-aws-kms.conf.in";
    let aws = source(aws_path);
    assert!(
        aws_path.contains("bloom-signer@LOGIN_UID.service.d/"),
        "AWS drop-in source must render onto an instance of bloom-signer@.service"
    );
    assert!(aws.contains("IPAddressDeny=any"));
    assert!(aws.contains("PrivateNetwork=no"));
    assert!(aws.contains("@AWS_KMS_IP_ALLOW_DIRECTIVES@"));
    assert!(aws.contains("LoadCredential=aws-credentials:"));
    assert!(
        !aws.contains("IPAddressAllow=any"),
        "AWS profile must not permit wildcard egress"
    );
}

#[test]
fn linux_time_policy_requires_multiple_authenticated_sources() {
    let chrony = source("chrony/bloom-nts.conf.in");
    assert!(chrony.contains("authselectmode require"));
    assert!(chrony.contains("minsources 2"));
    assert_eq!(
        chrony.lines().filter(|line| line.contains(" nts")).count(),
        2,
        "packaging must render at least two authenticated NTS sources"
    );
    assert!(
        !chrony.lines().any(|line| {
            let line = line.trim_start();
            (line.starts_with("server ") || line.starts_with("pool ")) && !line.contains(" nts")
        }),
        "unauthenticated selectable time source is forbidden"
    );
}

#[test]
fn audit_checkpoint_roots_are_principal_private_and_explicitly_wired() {
    let temporary_paths = source("tmpfiles.d/bloom-login.conf.in");
    for principal in ["broker", "signer"] {
        let checkpoint = format!("/var/lib/bloom/@LOGIN_UID@/{principal}/audit-checkpoints");
        assert!(temporary_paths.contains(&format!(
            "d {checkpoint} 0700 bloom-{principal}-@LOGIN_UID@ bloom-{principal}-@LOGIN_UID@"
        )));
        let service = source(&format!("systemd/bloom-{principal}@.service.in"));
        assert!(service.contains(&format!(
            "Environment=BLOOM_{}_AUDIT_CHECKPOINT_DIR=/var/lib/bloom/%i/{principal}/audit-checkpoints",
            principal.to_ascii_uppercase()
        )));
        assert!(service.contains(
            "Environment=BLOOM_AUTHORITY_EDGE_HISTORY=/etc/bloom/%i/authority-edge-history.json"
        ));
        assert!(!service.contains("../"));
    }
    assert!(temporary_paths.contains(
        "d /var/lib/bloom/@LOGIN_UID@/machine/audit-checkpoints 0700 @LOGIN_USER@ @LOGIN_USER@ -"
    ));
}
