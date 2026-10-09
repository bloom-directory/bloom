use anyhow::{Context, Result, bail};
use parking_lot::Mutex;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::process::CommandExt,
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::oneshot;

type Replies = Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>;

pub(crate) struct FrameContext {
    pub session: String,
    pub world: i64,
    pub frame_id: String,
    pub url: String,
    pub parent_id: Option<String>,
}

fn tree_frames(
    tree: &Value,
    session: &str,
    parent: Option<&str>,
    frames: &mut Vec<(String, String, String, Option<String>)>,
) {
    if let (Some(id), Some(url)) = (tree["frame"]["id"].as_str(), tree["frame"]["url"].as_str()) {
        if let Some(frame) = frames.iter_mut().find(|(known, _, _, _)| known == id) {
            frame.2 = session.into();
        } else {
            frames.push((
                id.into(),
                url.into(),
                session.into(),
                parent.map(str::to_owned),
            ));
        }
    }
    if let Some(children) = tree["childFrames"].as_array() {
        for child in children {
            tree_frames(child, session, tree["frame"]["id"].as_str(), frames);
        }
    }
}

/// Chrome's debugging channel is inherited pipe descriptors, never a TCP port.
pub(crate) struct Cdp {
    child: Mutex<Child>,
    writer: Mutex<File>,
    replies: Replies,
    sequence: AtomicU64,
}

fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // Both descriptors remain private through exec except the deliberate child mapping.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let pair = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [&pair.0, &pair.1] {
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(pair)
}

fn child_fd(fd: &OwnedFd) -> Result<OwnedFd> {
    // Keep sources above the destination pair so dup2 cannot clobber a source.
    let copy = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if copy < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}

impl Cdp {
    /// Include only frames belonging to this tab, including Chromium's OOPIFs.
    pub async fn contexts(
        &self,
        root_session: &str,
        world_name: &str,
    ) -> Result<Vec<FrameContext>> {
        let tree = self
            .call(Some(root_session), "Page.getFrameTree", json!({}))
            .await?;
        let targets = self.call(None, "Target.getTargets", json!({})).await?;
        let infos = targets["targetInfos"]
            .as_array()
            .context("Missing browser targets")?;
        let mut frames = Vec::new();
        tree_frames(&tree["frameTree"], root_session, None, &mut frames);
        let mut attached = std::collections::HashSet::new();
        loop {
            let before = attached.len();
            for target in infos {
                let Some(id) = target["targetId"].as_str() else {
                    continue;
                };
                let Some(parent) = target["parentId"].as_str() else {
                    continue;
                };
                if target["type"] != "iframe"
                    || attached.contains(id)
                    || !frames.iter().any(|(known, _, _, _)| known == parent)
                    || infos.iter().any(|t| {
                        t["type"] == "iframe"
                            && t["targetId"] == parent
                            && !attached.contains(parent)
                    })
                {
                    continue;
                }
                let attachment = self
                    .call(
                        None,
                        "Target.attachToTarget",
                        json!({"targetId":id,"flatten":true}),
                    )
                    .await?;
                let session = attachment["sessionId"]
                    .as_str()
                    .context("Missing iframe session")?;
                if let Some(frame) = frames.iter_mut().find(|(known, _, _, _)| known == id) {
                    frame.2 = session.into();
                }
                let tree = self
                    .call(Some(session), "Page.getFrameTree", json!({}))
                    .await?;
                tree_frames(&tree["frameTree"], session, Some(parent), &mut frames);
                attached.insert(id.to_owned());
            }
            if attached.len() == before {
                break;
            }
        }
        let mut contexts = Vec::new();
        for (frame_id, url, session, parent_id) in frames {
            let isolated = self
                .call(
                    Some(&session),
                    "Page.createIsolatedWorld",
                    json!({
                        "frameId":frame_id,"worldName":world_name,"grantUniveralAccess":false
                    }),
                )
                .await?;
            let world = isolated["executionContextId"]
                .as_i64()
                .context("Missing frame context")?;
            // Frame-tree URLs may be empty while an OOPIF is already loaded.
            // Read identity from this exact isolated document, never guess its URL.
            let identity = self
                .call(
                    Some(&session),
                    "Runtime.evaluate",
                    json!({"contextId":world,"expression":"location.href","returnByValue":true}),
                )
                .await?;
            let url = identity["result"]["value"]
                .as_str()
                .unwrap_or(&url)
                .to_owned();
            contexts.push(FrameContext {
                session,
                world,
                frame_id,
                url,
                parent_id,
            });
        }
        Ok(contexts)
    }
    pub fn launch(executable: &Path, profile: &Path, test_flags: &[String]) -> Result<Arc<Self>> {
        let (command_read, command_write) = pipe()?;
        let (event_read, event_write) = pipe()?;
        let child_read = child_fd(&command_read)?;
        let child_write = child_fd(&event_write)?;
        let mut command = Command::new(executable);
        command.args(["--headless=new","--remote-debugging-pipe","--no-first-run",
            "--no-default-browser-check","--disable-sync","--disable-breakpad",
            "--disable-crash-reporter","--disable-extensions","--disable-component-extensions-with-background-pages",
            "--force-device-scale-factor=1","--window-size=1280,900",
            "--disable-features=BackForwardCache,AutofillServerCommunication,AutofillEnableAccountWalletStorage",
            "--password-store=basic","--disable-save-password-bubble"])
            .arg(format!("--user-data-dir={}",profile.display()))
            .env("XDG_CONFIG_HOME",profile.join("config"))
            .env("XDG_CACHE_HOME",profile.join("cache"))
            .args(test_flags).arg("about:blank")
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        let input = child_read.as_raw_fd();
        let output = child_write.as_raw_fd();
        // The child executes only dup2 before exec; no allocation or logging here.
        unsafe {
            command.pre_exec(move || {
                crate::crash_protection::install()?;
                let limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::dup2(input, 3) < 0 || libc::dup2(output, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().context("Cannot launch checkout browser")?;
        drop(child_read);
        drop(child_write);
        drop(command_read);
        drop(event_write);
        let replies: Replies = Arc::new(Mutex::new(HashMap::new()));
        let browser = Arc::new(Self {
            child: Mutex::new(child),
            writer: Mutex::new(File::from(command_write)),
            replies: replies.clone(),
            sequence: AtomicU64::new(1),
        });
        let mut reader = File::from(event_read);
        std::thread::Builder::new()
            .name("checkout-cdp".into())
            .spawn(move || {
                let mut frame = Vec::new();
                let mut bytes = [0; 8192];
                while let Ok(size) = reader.read(&mut bytes) {
                    if size == 0 {
                        break;
                    }
                    for &byte in &bytes[..size] {
                        if byte == 0 {
                            if let Ok(value) = serde_json::from_slice::<Value>(&frame) {
                                if let Some(id) = value["id"].as_u64() {
                                    if let Some(reply) = replies.lock().remove(&id) {
                                        let _ = reply.send(value);
                                    }
                                }
                            }
                            frame.clear();
                        } else if frame.len() < 8 * 1024 * 1024 {
                            frame.push(byte);
                        } else {
                            return;
                        }
                    }
                }
                replies.lock().clear();
            })?;
        Ok(browser)
    }

    pub async fn call(&self, session: Option<&str>, method: &str, params: Value) -> Result<Value> {
        let id = self.sequence.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = oneshot::channel();
        self.replies.lock().insert(id, sender);
        let mut message = json!({"id":id,"method":method,"params":params});
        if let Some(session) = session {
            message["sessionId"] = json!(session);
        }
        let mut bytes = serde_json::to_vec(&message)?;
        bytes.push(0);
        if self.writer.lock().write_all(&bytes).is_err() {
            self.replies.lock().remove(&id);
            bail!("Checkout browser disconnected");
        }
        let response = tokio::time::timeout(Duration::from_secs(30), receiver).await;
        self.replies.lock().remove(&id);
        let value = response
            .context("Checkout browser timed out")?
            .context("Checkout browser disconnected")?;
        if value.get("error").is_some() {
            bail!("Checkout browser command failed");
        }
        Ok(value["result"].clone())
    }

    #[cfg(test)]
    pub fn exited(&self) -> bool {
        self.child.lock().try_wait().unwrap().is_some()
    }

    #[cfg(test)]
    pub async fn evaluate(&self, session: &str, expression: String) -> Result<Value> {
        let result = self
            .call(
                Some(session),
                "Runtime.evaluate",
                json!({"expression":expression,
            "returnByValue":true,"awaitPromise":true}),
            )
            .await?;
        if result.get("exceptionDetails").is_some() {
            bail!("Checkout document changed");
        }
        Ok(result["result"]["value"].clone())
    }
}

impl Drop for Cdp {
    fn drop(&mut self) {
        let child = self.child.get_mut();
        let _ = child.kill();
        let _ = child.wait();
    }
}
