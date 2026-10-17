//! The Bloom browser extension: checkout's hands in the person's own browser.
//!
//! Some booking sites score the browser itself and reject every fresh or
//! automated one, including checkout's own Chromium. The extension acts in one
//! tab of the person's browser, on approved booking sites only, through content
//! scripts (no debugger). Chrome starts `bloom-extension-host` over native
//! messaging; it relays to checkout's extension socket as JSON lines.
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::browser::Browser;

pub use bloom_browser_extension::{EXTENSION_ID, HOST_NAME};

// Below Chrome's 1 MiB host-to-browser limit, including the JSON envelope.
// Deliberately use the same bound in both directions rather than accepting
// Chrome's much larger browser-to-host maximum.
const MESSAGE_LIMIT: usize = 1024 * 1024;
const QUEUE_LIMIT: usize = 32;

/// Use the pinned extension's own permissions to choose a transport. This does
/// not grant permission: the extension independently validates every command.
pub(crate) fn supports_url(url: &url::Url) -> bool {
    if url.scheme() != "https"
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    let Ok(manifest) = serde_json::from_str::<Value>(bloom_browser_extension::MANIFEST) else {
        return false;
    };
    manifest["host_permissions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|pattern| pattern.strip_prefix("https://")?.strip_suffix("/*"))
        .any(|pattern| match pattern.strip_prefix("*.") {
            Some(domain) => host == domain || host.ends_with(&format!(".{domain}")),
            None => host == pattern,
        })
}

pub struct ExtensionLink {
    commands: mpsc::Sender<String>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Value>>>,
    next: AtomicU64,
}

impl ExtensionLink {
    #[cfg(test)]
    pub(crate) fn fixture() -> (Arc<Self>, mpsc::Receiver<String>) {
        let (commands, receiver) = mpsc::channel(QUEUE_LIMIT);
        (
            Arc::new(Self {
                commands,
                pending: Mutex::new(HashMap::new()),
                next: AtomicU64::new(1),
            }),
            receiver,
        )
    }

    #[cfg(test)]
    pub(crate) async fn answer_fixture(&self, id: u64, value: Value) {
        if let Some(reply) = self.pending.lock().await.remove(&id) {
            let _ = reply.send(json!({"ok":true,"value":value}));
        }
    }

    pub async fn call(&self, command: Value) -> Result<Value> {
        self.call_within(command, Duration::from_secs(90)).await
    }

    pub async fn call_within(&self, mut command: Value, limit: Duration) -> Result<Value> {
        let command_name = command["action"].as_str().unwrap_or("?").to_owned();
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        command["id"] = json!(id);
        let message = serde_json::to_string(&command)?;
        if message.len() >= MESSAGE_LIMIT {
            bail!("Extension command exceeds message limit");
        }
        let (reply, answer) = oneshot::channel();
        {
            let mut pending = self.pending.lock().await;
            if pending.len() >= QUEUE_LIMIT {
                bail!("The Bloom extension has too many pending requests");
            }
            pending.insert(id, reply);
        }
        if self.commands.try_send(message).is_err() {
            self.pending.lock().await.remove(&id);
            bail!("The Bloom extension is unavailable or busy");
        }
        let result = tokio::time::timeout(limit, answer).await;
        self.pending.lock().await.remove(&id);
        let result = result
            .context("The Bloom extension did not answer")?
            .context("The Bloom extension disconnected")?;
        if result["ok"] != true {
            let error = result["error"]
                .as_str()
                .unwrap_or("The Bloom extension refused");
            // The extension's own fixed messages, for diagnosing the link.
            eprintln!(
                "extension {}: {}",
                command_name,
                error.chars().take(160).collect::<String>()
            );
            bail!("{error}");
        }
        Ok(result["value"].clone())
    }
}

/// Accepts the extension host (same user only). The newest connection wins;
/// New supported journeys may select it; existing journeys retain their link.
pub async fn serve_extension(path: &Path, browser: Arc<Browser>) -> Result<()> {
    let listener = bloom_service_activation::bind_owned_unix_listener(path)?;
    let listener = tokio::net::UnixListener::from_std(listener)?;
    let own_uid = unsafe { libc::geteuid() };
    loop {
        let (stream, _) = listener.accept().await?;
        if stream.peer_cred()?.uid() != own_uid {
            continue;
        }
        let (reader, mut writer) = stream.into_split();
        let (commands, mut outgoing) = mpsc::channel::<String>(QUEUE_LIMIT);
        let link = Arc::new(ExtensionLink {
            commands,
            pending: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        });
        browser.attach_extension(link.clone());
        // An extension older than the installed files reloads them.
        let checked = link.clone();
        tokio::spawn(async move {
            if checked.call(json!({"action":"version"})).await.ok() != Some(json!(version())) {
                let _ = checked.call(json!({"action":"reload"})).await;
            }
        });
        let writer_task = tokio::spawn(async move {
            while let Some(line) = outgoing.recv().await {
                if writer
                    .write_all(format!("{line}\n").as_bytes())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let browser = browser.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(reader);
            loop {
                use tokio::io::AsyncReadExt;
                let mut line = String::new();
                let read = (&mut reader)
                    .take((MESSAGE_LIMIT + 1) as u64)
                    .read_line(&mut line)
                    .await;
                if !matches!(read, Ok(size) if size > 0 && size <= MESSAGE_LIMIT)
                    || !line.ends_with('\n')
                {
                    break;
                }
                let Ok(result) = serde_json::from_str::<Value>(&line) else {
                    break;
                };
                let Some(id) = result["id"].as_u64() else {
                    continue;
                };
                if let Some(reply) = link.pending.lock().await.remove(&id) {
                    let _ = reply.send(result);
                }
            }
            writer_task.abort();
            // Wake every in-flight caller immediately on disconnect, without
            // retaining its private command until a ninety-second timeout.
            link.pending.lock().await.clear();
            browser.detach_extension(&link);
        });
    }
}

/// Native messaging host: Chrome's length-prefixed messages on stdin/stdout,
/// checkout's JSON lines on the socket.
pub fn relay(socket: &Path) -> Result<()> {
    let stream =
        std::os::unix::net::UnixStream::connect(socket).context("Bloom checkout is not running")?;
    let mut to_checkout = stream.try_clone()?;
    let mut from_checkout = std::io::BufReader::new(stream);
    std::thread::spawn(move || {
        let result = relay_to_browser(&mut from_checkout, &mut std::io::stdout().lock());
        // A failed writer must terminate the host too: leaving stdin blocked
        // would make Chrome believe a dead bridge was still connected.
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    });
    let mut input = std::io::stdin().lock();
    relay_from_browser(&mut input, &mut to_checkout)
}

fn relay_to_browser(input: &mut impl BufRead, output: &mut impl Write) -> Result<()> {
    loop {
        let mut message = Vec::new();
        let length =
            Read::take(&mut *input, (MESSAGE_LIMIT + 1) as u64).read_until(b'\n', &mut message)?;
        if length == 0 {
            return Ok(());
        }
        if length > MESSAGE_LIMIT || message.pop() != Some(b'\n') {
            bail!("Invalid checkout message length");
        }
        serde_json::from_slice::<Value>(&message).context("Malformed checkout message")?;
        output.write_all(&u32::try_from(message.len())?.to_ne_bytes())?;
        output.write_all(&message)?;
        output.flush()?;
    }
}

fn relay_from_browser(input: &mut impl Read, output: &mut impl Write) -> Result<()> {
    loop {
        let mut length = [0u8; 4];
        // EOF between messages is clean; a truncated header/body is not.
        if input.read(&mut length[..1])? == 0 {
            return Ok(());
        }
        input.read_exact(&mut length[1..])?;
        let length = u32::from_ne_bytes(length) as usize;
        if length == 0 || length >= MESSAGE_LIMIT {
            bail!("Extension message too large");
        }
        let mut message = vec![0; length];
        input.read_exact(&mut message)?;
        // JSON from Chrome never contains a raw newline.
        if message.contains(&b'\n') {
            bail!("Malformed extension message");
        }
        serde_json::from_slice::<Value>(&message).context("Malformed extension message")?;
        message.push(b'\n');
        output.write_all(&message)?;
    }
}

/// The extension's files. `page.js` carries checkout's own page scripts, so
/// both browsers run the same code.
fn scripts() -> Vec<(&'static str, String)> {
    vec![
        (
            "snapshot",
            format!("() => {}", include_str!("snapshot.js").trim()),
        ),
        ("act", include_str!("act.js").trim().into()),
        (
            "travelerDiscover",
            format!(
                "nonce => {{ globalThis.__bloomTravelerNonce = nonce; return {}; }}",
                include_str!("traveler-discover.js").trim()
            ),
        ),
        (
            "travelerFill",
            format!(
                "(nonce, origin, mapped, values) => {}",
                include_str!("traveler-fill.js").trim()
            ),
        ),
        (
            "facts",
            format!("() => {}", include_str!("facts.js").trim()),
        ),
        (
            "fields",
            format!("() => {}", include_str!("fields.js").trim()),
        ),
        (
            "submit",
            format!("() => {}", include_str!("submit.js").trim()),
        ),
        (
            "orderFields",
            format!("() => {}", include_str!("order-fields.js").trim()),
        ),
        (
            "confirmContact",
            format!("() => {}", include_str!("confirm-contact.js").trim()),
        ),
        (
            "attention",
            format!(
                "() => {{ {}; return globalThis.__bloomAttention(); }}",
                include_str!("form-attention.js").trim()
            ),
        ),
        (
            "attentionOutcome",
            format!(
                "() => {{ {}; return {}; }}",
                include_str!("form-attention.js").trim(),
                include_str!("outcome.js").trim()
            ),
        ),
        ("valid", include_str!("payment-valid.js").trim().into()),
        ("fill", include_str!("payment-fill.js").trim().into()),
    ]
}

pub fn bundle() -> Vec<(&'static str, String)> {
    bloom_browser_extension::bundle(&scripts())
}

/// Includes both the external transport assets and checkout's DOM scripts.
pub fn version() -> String {
    bloom_browser_extension::version(&scripts())
}

/// Native messaging manifest naming `host` (an executable) for the extension.
pub fn host_manifest(host: &Path) -> Value {
    json!({
        "name": HOST_NAME,
        "description": "Bloom checkout",
        "path": host,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{EXTENSION_ID}/")],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_relay_round_trips_bounded_json() {
        let message = br#"{"action":"version","id":1}"#;
        let mut input = std::io::Cursor::new([message.as_slice(), b"\n"].concat());
        let mut framed = Vec::new();
        relay_to_browser(&mut input, &mut framed).unwrap();
        assert_eq!(
            u32::from_ne_bytes(framed[..4].try_into().unwrap()),
            message.len() as u32
        );
        let mut output = Vec::new();
        relay_from_browser(&mut framed.as_slice(), &mut output).unwrap();
        assert_eq!(output, [message.as_slice(), b"\n"].concat());
    }

    #[test]
    fn native_relay_rejects_oversized_truncated_and_malformed_frames() {
        for bytes in [
            vec![b'x'; MESSAGE_LIMIT + 1],
            b"{}".to_vec(),
            b"not json\n".to_vec(),
        ] {
            let mut output = Vec::new();
            assert!(relay_to_browser(&mut bytes.as_slice(), &mut output).is_err());
            assert!(output.is_empty());
        }
        for bytes in [
            (MESSAGE_LIMIT as u32).to_ne_bytes().to_vec(),
            vec![1, 0],
            [3u32.to_ne_bytes().as_slice(), b"{}"].concat(),
            [3u32.to_ne_bytes().as_slice(), b"{\n}"].concat(),
            [3u32.to_ne_bytes().as_slice(), b"bad"].concat(),
        ] {
            let mut output = Vec::new();
            assert!(relay_from_browser(&mut bytes.as_slice(), &mut output).is_err());
            assert!(output.is_empty());
        }
    }

    #[tokio::test]
    async fn unavailable_and_full_connections_do_not_retain_pending_replies() {
        let (link, receiver) = ExtensionLink::fixture();
        for _ in 0..QUEUE_LIMIT {
            link.commands.try_send("{}".into()).unwrap();
        }
        assert!(link.call(json!({"action":"version"})).await.is_err());
        assert!(link.pending.lock().await.is_empty());
        drop(receiver);
        assert!(link.call(json!({"action":"version"})).await.is_err());
        assert!(link.pending.lock().await.is_empty());
        assert!(
            link.call(json!({"action":"type","value":"x".repeat(MESSAGE_LIMIT)}))
                .await
                .is_err()
        );
        assert!(link.pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn pending_reply_count_is_bounded_even_if_callers_stop_waiting() {
        let (link, _receiver) = ExtensionLink::fixture();
        for id in 100..100 + QUEUE_LIMIT as u64 {
            let (reply, _answer) = oneshot::channel();
            link.pending.lock().await.insert(id, reply);
        }
        assert!(link.call(json!({"action":"version"})).await.is_err());
        assert_eq!(link.pending.lock().await.len(), QUEUE_LIMIT);
    }

    #[test]
    fn transport_selection_uses_only_approved_https_hosts() {
        for value in [
            "https://www.aerolineas.com.ar/",
            "https://jetsmart.com/",
            "https://booking.jetsmart.com/",
            "https://jetsmart.com:443/",
        ] {
            assert!(supports_url(&url::Url::parse(value).unwrap()), "{value}");
        }
        for value in [
            "https://serpapi.com/users/sign_up",
            "https://buy.stripe.com/",
            "http://jetsmart.com/",
            "https://jetsmart.com:444/",
            "https://jetsmart.com.evil.example/",
            "https://eviljetsmart.com/",
            "https://user@jetsmart.com/",
            "file:///tmp/jetsmart.com",
        ] {
            assert!(!supports_url(&url::Url::parse(value).unwrap()), "{value}");
        }
    }

    #[test]
    fn extension_id_matches_the_manifest_key() {
        use base64::Engine;
        let manifest: Value = serde_json::from_str(bloom_browser_extension::MANIFEST).unwrap();
        let key = base64::engine::general_purpose::STANDARD
            .decode(manifest["key"].as_str().unwrap())
            .unwrap();
        use sha2::Digest;
        let digest = sha2::Sha256::digest(&key);
        let id: String = digest[..16]
            .iter()
            .flat_map(|b| [b >> 4, b & 15])
            .map(|n| (b'a' + n) as char)
            .collect();
        assert_eq!(id, EXTENSION_ID);
    }

    #[test]
    fn page_bundle_parses_as_javascript() {
        let page = bundle()
            .into_iter()
            .find(|(name, _)| *name == "page.js")
            .unwrap()
            .1;
        let dir = std::env::temp_dir().join(format!("bloom-ext-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("page.js");
        std::fs::write(&file, page).unwrap();
        let status = std::process::Command::new("node")
            .arg("--check")
            .arg(&file)
            .status();
        std::fs::remove_file(&file).ok();
        std::fs::remove_dir(&dir).ok();
        if let Ok(status) = status {
            assert!(status.success());
        }
    }
}
