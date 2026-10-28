#![cfg(target_os = "linux")]
//! A real checkout process must fail when its browser dies, so the installed
//! service manager can restart it instead of leaving a permanently dead API.
use std::{fs, os::unix::fs::PermissionsExt, time::Duration};
use tokio::{process::Command, time::sleep};

#[tokio::test]
async fn checkout_exits_unsuccessfully_when_its_browser_exits() {
    let root = tempfile::tempdir().unwrap();
    let endpoint = root.path().join("endpoint");
    fs::create_dir(&endpoint).unwrap();
    fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o710)).unwrap();
    let chromium = std::env::var("BLOOM_CHECKOUT_TEST_CHROMIUM").unwrap_or_else(|_| {
        [
            "/usr/lib/chromium/chromium",
            "/usr/bin/google-chrome",
            "/usr/bin/chromium",
        ]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
        .expect("Checkout fixtures require Chromium; set BLOOM_CHECKOUT_TEST_CHROMIUM")
        .into()
    });
    let wrapper = root.path().join("chromium-test.sh");
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexec '{}' --no-sandbox \"$@\"\n",
            chromium.replace('\'', "'\\''")
        ),
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    let socket = endpoint.join("checkout.sock");
    let uid = unsafe { libc::geteuid() }.to_string();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
        .to_string();
    let mut checkout = Command::new(env!("CARGO_BIN_EXE_bloom-checkout"))
        .arg("--chromium")
        .arg(&wrapper)
        .arg("--profile")
        .arg(root.path().join("profile"))
        .arg("--state")
        .arg(root.path().join("operations.sqlite3"))
        .arg("--socket")
        .arg(&socket)
        .arg("--broker-socket")
        .arg(root.path().join("unused-broker.sock"))
        .args([
            "--broker-uid",
            &uid,
            "--machine-uid",
            &uid,
            "--view-port",
            &port,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pid = checkout.id().unwrap();
    let children_path = format!("/proc/{pid}/task/{pid}/children");
    let ready = tokio::time::timeout(Duration::from_secs(10), async {
        while !socket.exists() {
            assert!(
                checkout.try_wait().unwrap().is_none(),
                "checkout exited before readiness"
            );
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    // Only processes spawned by this test's checkout are eligible for killing.
    let children: Vec<i32> = fs::read_to_string(children_path)
        .unwrap_or_default()
        .split_whitespace()
        .map(|id| id.parse().unwrap())
        .collect();
    assert!(!children.is_empty(), "checkout browser was not spawned");
    for child in children {
        assert_eq!(unsafe { libc::kill(child, libc::SIGKILL) }, 0);
    }
    assert!(ready.is_ok(), "checkout did not become ready");
    let exit = tokio::time::timeout(Duration::from_secs(5), checkout.wait())
        .await
        .expect("checkout stayed alive after its browser died")
        .unwrap();
    assert!(
        !exit.success(),
        "browser loss must trigger service-manager restart"
    );
}
