#![cfg(target_os = "linux")]
//! A real checkout process must fail when its browser dies, so the installed
//! service manager can restart it instead of leaving a permanently dead API.
use std::{fs, os::unix::fs::PermissionsExt, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    process::Command,
    time::sleep,
};

async fn request(socket: &std::path::Path, body: serde_json::Value) -> serde_json::Value {
    let stream = UnixStream::connect(socket).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    writer
        .write_all(format!("{body}\n").as_bytes())
        .await
        .unwrap();
    let mut line = String::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        BufReader::new(reader).read_line(&mut line),
    )
    .await
    .unwrap()
    .unwrap();
    serde_json::from_str(&line).unwrap()
}

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
    let binary = std::env::var("NEXTEST_BIN_EXE_bloom_checkout")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_bloom-checkout").into());
    let spawn = || {
        Command::new(&binary)
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
            .unwrap()
    };
    let mut checkout = spawn();
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
    assert!(ready.is_ok(), "checkout did not become ready");
    // A known payment result must survive a fresh browser, even if cleanup
    // previously left shopping paused. This is this test's own synthetic store.
    let status = serde_json::json!({
        "operation_id": "restart-fixture", "state": "booked",
        "ceremony_url": null, "filled_fields": [], "paused": true,
        "outcome": {"state": "booked", "source": "fixture", "confirmation_reached": true,
            "order_id": "fixture-order", "merchant_reported_total_minor": 100, "currency": "USD"}
    });
    let conn = rusqlite::Connection::open(root.path().join("operations.sqlite3")).unwrap();
    conn.execute(
        "INSERT INTO operations(id,state,status,created,kind,description) VALUES('restart-fixture','booked',?1,0,'card','fixture')",
        [status.to_string()],
    ).unwrap();
    drop(conn);
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
    let exit = tokio::time::timeout(Duration::from_secs(5), checkout.wait())
        .await
        .expect("checkout stayed alive after its browser died")
        .unwrap();
    assert!(
        !exit.success(),
        "browser loss must trigger service-manager restart"
    );
    let mut restarted = spawn();
    let restored = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            assert!(
                restarted.try_wait().unwrap().is_none(),
                "checkout restart failed"
            );
            // The old socket can remain briefly; wait for the new listener.
            if UnixStream::connect(&socket).await.is_ok() {
                break request(
                    &socket,
                    serde_json::json!({"method":"status", "operation_id":"restart-fixture"}),
                )
                .await;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("checkout did not restart");
    assert_eq!(restored["state"], "booked");
    assert_eq!(restored["outcome"], status["outcome"]);
    assert_ne!(restored["paused"], true);
    let snapshot = request(
        &socket,
        serde_json::json!({"method":"browse", "request":{"action":"snapshot"}}),
    )
    .await;
    assert_eq!(snapshot["url"], "about:blank", "{snapshot}");
    assert_eq!(
        unsafe { libc::kill(restarted.id().unwrap() as i32, libc::SIGINT) },
        0
    );
    tokio::time::timeout(Duration::from_secs(5), restarted.wait())
        .await
        .unwrap()
        .unwrap();
}
