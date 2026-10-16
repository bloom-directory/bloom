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

/// Native messaging host name; Chrome lets only the extension id below use it.
pub const HOST_NAME: &str = "directory.bloom.checkout";
/// Fixed by the public key in `extension/manifest.json`.
pub const EXTENSION_ID: &str = "ngpolgaijmajlonmjmcndcjajgnfcpom";

pub struct ExtensionLink {
    commands: mpsc::UnboundedSender<String>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Value>>>,
    next: AtomicU64,
}

impl ExtensionLink {
    pub async fn call(&self, mut command: Value) -> Result<Value> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        command["id"] = json!(id);
        let (reply, answer) = oneshot::channel();
        self.pending.lock().await.insert(id, reply);
        self.commands
            .send(serde_json::to_string(&command)?)
            .map_err(|_| anyhow::anyhow!("The Bloom extension disconnected"))?;
        let result = tokio::time::timeout(Duration::from_secs(90), answer).await;
        self.pending.lock().await.remove(&id);
        let result = result
            .context("The Bloom extension did not answer")?
            .context("The Bloom extension disconnected")?;
        if result["ok"] != true {
            bail!(
                "{}",
                result["error"]
                    .as_str()
                    .unwrap_or("The Bloom extension refused")
            );
        }
        Ok(result["value"].clone())
    }
}

/// Accepts the extension host (same user only). The newest connection wins;
/// browsing uses the person's browser while one is connected.
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
        let (commands, mut outgoing) = mpsc::unbounded_channel::<String>();
        let link = Arc::new(ExtensionLink {
            commands,
            pending: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        });
        browser.attach_extension(link.clone());
        tokio::spawn(async move {
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
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(result) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                let Some(id) = result["id"].as_u64() else {
                    continue;
                };
                if let Some(reply) = link.pending.lock().await.remove(&id) {
                    let _ = reply.send(result);
                }
            }
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
    let from_checkout = std::io::BufReader::new(stream);
    std::thread::spawn(move || -> Result<()> {
        let mut out = std::io::stdout().lock();
        for line in from_checkout.lines() {
            let line = line?;
            out.write_all(&u32::try_from(line.len())?.to_ne_bytes())?;
            out.write_all(line.as_bytes())?;
            out.flush()?;
        }
        // Checkout went away: end the host so the extension reconnects later.
        std::process::exit(0);
    });
    let mut input = std::io::stdin().lock();
    loop {
        let mut length = [0u8; 4];
        if input.read_exact(&mut length).is_err() {
            return Ok(());
        }
        let length = u32::from_ne_bytes(length) as usize;
        if length > 8 << 20 {
            bail!("Extension message too large");
        }
        let mut message = vec![0; length];
        input.read_exact(&mut message)?;
        // JSON from Chrome never contains a raw newline.
        if message.contains(&b'\n') {
            bail!("Malformed extension message");
        }
        message.push(b'\n');
        to_checkout.write_all(&message)?;
    }
}

/// The extension's files. `page.js` carries checkout's own page scripts, so
/// both browsers run the same code.
pub fn bundle() -> Vec<(&'static str, String)> {
    let page = format!(
        "const BLOOM_SCRIPTS = {{\n  snapshot: () => {},\n  act: {},\n}};\n{}",
        include_str!("snapshot.js").trim(),
        include_str!("act.js").trim(),
        include_str!("../extension/page.js")
    );
    vec![
        (
            "manifest.json",
            include_str!("../extension/manifest.json").into(),
        ),
        (
            "background.js",
            include_str!("../extension/background.js").into(),
        ),
        ("page.js", page),
    ]
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
    fn extension_id_matches_the_manifest_key() {
        use base64::Engine;
        let manifest: Value =
            serde_json::from_str(include_str!("../extension/manifest.json")).unwrap();
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
