//! One-shot root packet-filter monitor for the macOS Unix-principal profile.

use std::{
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use rustix::{
    fs::{Gid, Uid, chown},
    process::geteuid,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

const STATUS_SCHEMA: &str = "bloom.macos-platform-status.3";
const TRUSTED_TIME_SOURCE: &str = "macos-managed-timed";
const CEREMONY_OWNER_MARKER: &str = "x-bloom-ceremony-owner: bloom-broker-v1";
const MONITOR_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Serialize)]
struct Status {
    schema: &'static str,
    login_uid: u32,
    build_digest: String,
    anchor_sha256: String,
    trusted_time_source: &'static str,
    automatic_time_enabled: bool,
    timed_service_loaded: bool,
    trusted_time_available: bool,
    ceremony_listener_bloom_shaped: bool,
    checked_at_unix_ms: u64,
    available: bool,
}

pub async fn run() -> Result<()> {
    if geteuid() != Uid::ROOT {
        bail!("the packet-filter monitor must run as root");
    }
    if std::env::consts::OS != "macos" {
        bail!("the packet-filter monitor requires macOS");
    }
    tracing::info!(event = "service.ready", monitor = "packet-filter");
    crate::native_lifecycle("containment-monitor", "ready");
    let mut interval = tokio::time::interval(MONITOR_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            result = crate::termination_signal() => {
                result.context("wait for containment shutdown signal")?;
                tracing::info!(event = "service.shutdown", reason = "signal");
                crate::native_lifecycle("containment-monitor", "shutdown");
                return Ok(());
            }
            _ = interval.tick() => {
                if let Err(error) = run_once() {
                    let _ = error;
                    tracing::warn!(
                        event = "containment.refresh_failed",
                        error_kind = "platform_status"
                    );
                }
            }
        }
    }
}

pub fn run_once() -> Result<()> {
    if geteuid() != Uid::ROOT {
        bail!("the packet-filter monitor must run as root");
    }
    if std::env::consts::OS != "macos" {
        bail!("the packet-filter monitor requires macOS");
    }
    let enrollment_root = Path::new("/Library/Application Support/BloomTriad/enrollments");
    require_directory(enrollment_root, 0o755)?;
    let pf_enabled = command_output("/sbin/pfctl", &["-s", "info"])
        .is_ok_and(|output| output.contains("Status: Enabled"));
    let (automatic_time_enabled, timed_service_loaded) = macos_managed_time_status();
    let trusted_time_available = automatic_time_enabled && timed_service_loaded;
    let ceremony_listener_bloom_shaped = canonical_listener_is_bloom_shaped();
    let checked_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time precedes the Unix epoch")?
        .as_millis()
        .try_into()
        .context("system time does not fit u64 milliseconds")?;

    let mut enrollments = fs::read_dir(enrollment_root)
        .context("read Bloom enrollment root")?
        .collect::<std::io::Result<Vec<_>>>()
        .context("enumerate Bloom enrollments")?;
    enrollments.sort_by_key(|entry| entry.file_name());
    let mut all_available = true;
    for entry in enrollments {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        require_file(&path, 0o644)?;
        let enrollment: serde_json::Value = serde_json::from_slice(
            &fs::read(&path).with_context(|| format!("read {}", path.display()))?,
        )
        .with_context(|| format!("decode {}", path.display()))?;
        let login_uid = required_u32(&enrollment, "login_uid")?;
        let enrollment_state = enrollment
            .get("state")
            .and_then(serde_json::Value::as_str)
            .context("enrollment state is not a string")?;
        if !matches!(enrollment_state, "activating" | "active") {
            bail!("enrollment is not activating or active");
        }
        if path.file_name().and_then(|value| value.to_str()) != Some(&format!("{login_uid}.json")) {
            bail!("enrollment filename does not match its login UID");
        }
        let broker_uid = required_u32(&enrollment, "broker_uid")?;
        let signer_uid = required_u32(&enrollment, "signer_uid")?;
        let revoke_gid = required_u32(&enrollment, "revoke_gid")?;
        let build_digest = required_digest(&enrollment, "release_digest")?;
        let anchor = PathBuf::from(format!("/etc/pf.anchors/com.bloom.triad.{login_uid}"));
        require_file_mode(&anchor, 0o600)?;
        let anchor_bytes =
            fs::read(&anchor).with_context(|| format!("read {}", anchor.display()))?;
        let anchor_sha256 = hex::encode(Sha256::digest(&anchor_bytes));
        let loaded = command_output(
            "/sbin/pfctl",
            &["-a", &format!("com.bloom.triad/{login_uid}"), "-sr"],
        );
        let available = pf_enabled
            && loaded.as_ref().is_ok_and(|rules| {
                rules.contains("block")
                    && (rules.contains(&broker_uid.to_string())
                        || rules.contains(&format!("bloom-broker-{login_uid}")))
                    && (rules.contains(&signer_uid.to_string())
                        || rules.contains(&format!("bloom-signer-{login_uid}")))
            });
        all_available &= available;
        let status = Status {
            schema: STATUS_SCHEMA,
            login_uid,
            build_digest,
            anchor_sha256,
            trusted_time_source: TRUSTED_TIME_SOURCE,
            automatic_time_enabled,
            timed_service_loaded,
            trusted_time_available,
            ceremony_listener_bloom_shaped,
            checked_at_unix_ms,
            available,
        };
        write_status(login_uid, &status)?;
        if enrollment_state == "active" {
            restart_services_for_live_session(login_uid, revoke_gid)?;
        }
    }
    if !all_available {
        bail!("Bloom packet-filter platform status is unavailable");
    }
    Ok(())
}

fn restart_services_for_live_session(login_uid: u32, revoke_gid: u32) -> Result<()> {
    let session_target = format!("gui/{login_uid}/com.bloom.session");
    let Ok(session_state) = command_output("/bin/launchctl", &["print", &session_target]) else {
        // An absent login job means this is a stale socket or a logged-out
        // session. Either case must not restart the service principals.
        return Ok(());
    };
    if !session_state
        .lines()
        .any(|line| line.trim() == "state = running")
    {
        return Ok(());
    }

    let session_directory = PathBuf::from(format!("/private/var/run/bloom/{login_uid}/session"));
    require_service_directory(&session_directory, login_uid, revoke_gid, 0o710)?;
    let session_socket = session_directory.join("session.sock");
    let metadata = match fs::symlink_metadata(&session_socket) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", session_socket.display()));
        }
    };
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.uid() != login_uid
        || metadata.gid() != revoke_gid
        || metadata.mode() & 0o7777 != 0o660
    {
        bail!(
            "unsafe login-session sentinel socket {}",
            session_socket.display()
        );
    }

    for service in ["signer", "broker"] {
        let target = format!("system/com.bloom.{service}.{login_uid}");
        let state = command_output("/bin/launchctl", &["print", &target])
            .with_context(|| format!("inspect loaded {service} job for login {login_uid}"))?;
        if !state.lines().any(|line| line.trim() == "state = running") {
            command_output("/bin/launchctl", &["kickstart", &target])
                .with_context(|| format!("restart {service} for live login {login_uid}"))?;
        }
    }
    Ok(())
}

fn macos_managed_time_status() -> (bool, bool) {
    let automatic_time_enabled = command_output("/usr/sbin/systemsetup", &["-getusingnetworktime"])
        .is_ok_and(|output| output.lines().any(|line| line.trim() == "Network Time: On"));
    let timed_service_loaded =
        command_output("/bin/launchctl", &["print", "system/com.apple.timed"]).is_ok();
    (automatic_time_enabled, timed_service_loaded)
}

fn canonical_listener_is_bloom_shaped() -> bool {
    let address: SocketAddr = match "127.0.0.1:18734".parse() {
        Ok(address) => address,
        Err(_) => return false,
    };
    let timeout = Duration::from_secs(1);
    let mut stream = match TcpStream::connect_timeout(&address, timeout) {
        Ok(stream) => stream,
        Err(_) => return false,
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    if stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost:18734\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 512];
    while response.len() < 4096 {
        let remaining = 4096 - response.len();
        let read_length = remaining.min(chunk.len());
        match stream.read(&mut chunk[..read_length]) {
            Ok(0) => break,
            Ok(count) => {
                response.extend_from_slice(&chunk[..count]);
                if response_has_bloom_owner_marker(&response) {
                    return true;
                }
            }
            Err(_) => return false,
        }
    }
    false
}

fn response_has_bloom_owner_marker(response: &[u8]) -> bool {
    String::from_utf8_lossy(response)
        .to_ascii_lowercase()
        .contains(CEREMONY_OWNER_MARKER)
}

fn write_status(login_uid: u32, status: &Status) -> Result<()> {
    let directory = PathBuf::from(format!("/private/var/run/bloom/{login_uid}/containment"));
    require_directory(&directory, 0o755)?;
    let destination = directory.join("status.json");
    match fs::symlink_metadata(&destination) {
        Ok(_) => require_file(&destination, 0o644)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect containment status"),
    }
    let temporary = directory.join(format!("status.json.new.{}", std::process::id()));
    let result = (|| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .context("create containment status")?;
        let bytes = serde_json::to_vec(status).context("encode containment status")?;
        output
            .write_all(&bytes)
            .context("write containment status")?;
        output.write_all(b"\n").context("terminate status record")?;
        output.sync_all().context("sync containment status")?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))
            .context("set containment status mode")?;
        chown(&temporary, Some(Uid::ROOT), Some(Gid::ROOT))
            .context("set containment status ownership")?;
        fs::rename(&temporary, &destination).context("publish containment status")?;
        fs::File::open(&directory)
            .context("open containment status directory")?
            .sync_all()
            .context("sync containment status directory")
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn command_output(program: &str, arguments: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .with_context(|| format!("execute {program}"))?;
    if !output.status.success() {
        bail!("{program} exited unsuccessfully");
    }
    String::from_utf8(output.stdout).context("packet-filter output is not UTF-8")
}

fn required_u32(value: &serde_json::Value, field: &str) -> Result<u32> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| value.try_into().ok())
        .filter(|value| *value != 0)
        .with_context(|| format!("enrollment field {field} is not a positive u32"))
}

fn required_digest(value: &serde_json::Value, field: &str) -> Result<String> {
    let digest = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .with_context(|| format!("enrollment field {field} is not a string"))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("enrollment field {field} is not a lowercase SHA-256 digest");
    }
    Ok(digest.to_owned())
}

fn require_directory(path: &Path, mode: u32) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != mode
    {
        bail!(
            "unsafe root packet-filter monitor directory {}",
            path.display()
        );
    }
    Ok(())
}

fn require_file(path: &Path, mode: u32) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != mode
        || metadata.nlink() != 1
    {
        bail!("unsafe root packet-filter monitor file {}", path.display());
    }
    Ok(())
}

fn require_file_mode(path: &Path, mode: u32) -> Result<()> {
    require_file(path, mode)
}

fn require_service_directory(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != mode
    {
        bail!(
            "unsafe root packet-filter monitor service directory {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceremony_owner_marker_is_case_insensitive_but_exact() {
        assert!(response_has_bloom_owner_marker(
            b"HTTP/1.1 404 Not Found\r\nX-Bloom-Ceremony-Owner: bloom-broker-v1\r\n\r\n"
        ));
        assert!(!response_has_bloom_owner_marker(
            b"HTTP/1.1 404 Not Found\r\nX-Bloom-Ceremony-Owner: other\r\n\r\n"
        ));
    }
}
