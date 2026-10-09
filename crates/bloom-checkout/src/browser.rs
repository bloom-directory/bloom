use crate::cdp::Cdp;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::Mutex;

pub use bloom_checkout_api::BrowseRequest;

#[derive(Clone)]
struct ElementRef {
    session: String,
    world: i64,
    index: usize,
}

struct Tab {
    target: String,
    session: String,
    refs: Vec<ElementRef>,
    generation: u64,
}

pub struct Browser {
    cdp: Arc<Cdp>,
    tab: Mutex<Tab>,
    revoked: AtomicBool,
}

/// Private checkout access exists only after the public API has drained.
pub(crate) struct PrivateTab {
    pub cdp: Arc<Cdp>,
    pub session: String,
    pub target: String,
}

impl Browser {
    pub async fn launch(
        executable: &Path,
        profile: &Path,
        test_flags: &[String],
    ) -> Result<Arc<Self>> {
        if profile.exists() {
            let metadata = std::fs::symlink_metadata(profile)?;
            if !metadata.is_dir()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                bail!("Checkout profile must be a private directory owned by this process");
            }
        } else {
            std::fs::create_dir(profile)?;
            std::fs::set_permissions(profile, std::fs::Permissions::from_mode(0o700))?;
        }
        let preferences = profile.join("Default");
        if !preferences.exists() {
            std::fs::create_dir(&preferences)?;
        }
        // Chrome respects these preferences alongside the launch flags.
        let path = preferences.join("Preferences");
        let mut prefs: Value = if path.exists() {
            serde_json::from_slice(&std::fs::read(&path)?)?
        } else {
            json!({})
        };
        prefs["autofill"] = json!({"credit_card_enabled":false,"profile_enabled":false});
        prefs["credentials_enable_service"] = json!(false);
        prefs["profile"]["password_manager_enabled"] = json!(false);
        std::fs::write(path, serde_json::to_vec(&prefs)?)?;
        let cdp = Cdp::launch(executable, profile, test_flags)?;
        let tab = new_tab(&cdp, 1).await?;
        Ok(Arc::new(Self {
            cdp,
            tab: Mutex::new(tab),
            revoked: AtomicBool::new(false),
        }))
    }

    pub async fn browse(&self, request: BrowseRequest) -> Result<Value> {
        self.available()?;
        let mut tab = self.tab.lock().await;
        self.available()?;
        match request {
            BrowseRequest::Open { url } => {
                let parsed = url::Url::parse(&url).context("Invalid browsing URL")?;
                if !matches!(parsed.scheme(), "http" | "https")
                    || !parsed.username().is_empty()
                    || parsed.password().is_some()
                {
                    bail!("Only ordinary HTTP(S) shopping URLs are supported");
                }
                self.cdp
                    .call(Some(&tab.session), "Page.navigate", json!({"url":url}))
                    .await?;
                tab.refs.clear();
                tab.generation += 1;
                Ok(json!({"state":"opened"}))
            }
            BrowseRequest::Snapshot => {
                tab.generation += 1;
                tab.refs.clear();
                let contexts = self.cdp.contexts(&tab.session, "bloom-shopping").await?;
                let mut elements = Vec::new();
                let mut text = String::new();
                let mut url = String::new();
                for (position, frame) in contexts.into_iter().enumerate() {
                    let parsed = url::Url::parse(&frame.url)?;
                    if !matches!(parsed.scheme(), "http" | "https") && frame.url != "about:blank" {
                        if position == 0 {
                            bail!("Only ordinary shopping documents can be observed");
                        }
                        continue;
                    }
                    let result=self.cdp.call(Some(&frame.session),"Runtime.evaluate",json!({
                        "contextId":frame.world,"returnByValue":true,"expression":include_str!("snapshot.js")
                    })).await?;
                    if result.get("exceptionDetails").is_some() {
                        bail!("Shopping document changed; request a new snapshot");
                    }
                    let snapshot = &result["result"]["value"];
                    if position == 0 {
                        url = snapshot["url"].as_str().unwrap_or("").into();
                    }
                    let tree = self
                        .cdp
                        .call(
                            Some(&frame.session),
                            "Accessibility.getFullAXTree",
                            json!({"frameId":frame.frame_id}),
                        )
                        .await?;
                    text.push_str(&accessibility_text(&tree)?);
                    text.push('\n');
                    for (index, element) in snapshot["elements"]
                        .as_array()
                        .context("Missing shopping elements")?
                        .iter()
                        .enumerate()
                    {
                        if elements.len() >= 300 {
                            break;
                        }
                        let mut element = element.clone();
                        element["ref"] = json!(format!("{}:{}", tab.generation, tab.refs.len()));
                        element["frame_origin"] = json!(parsed.origin().ascii_serialization());
                        tab.refs.push(ElementRef {
                            session: frame.session.clone(),
                            world: frame.world,
                            index,
                        });
                        elements.push(element);
                    }
                }
                Ok(
                    json!({"url":url,"text":text.chars().take(30000).collect::<String>(),"elements":elements}),
                )
            }
            BrowseRequest::Back => {
                let history = self
                    .cdp
                    .call(Some(&tab.session), "Page.getNavigationHistory", json!({}))
                    .await?;
                let index = history["currentIndex"].as_u64().unwrap_or(0);
                if index > 0 {
                    self.cdp
                        .call(
                            Some(&tab.session),
                            "Page.navigateToHistoryEntry",
                            json!({"entryId":history["entries"][index as usize-1]["id"]}),
                        )
                        .await?;
                }
                tab.refs.clear();
                tab.generation += 1;
                Ok(json!({"state":"navigated"}))
            }
            BrowseRequest::Click { element_ref } => {
                self.act(&mut tab, &element_ref, "click", "").await
            }
            BrowseRequest::Type { element_ref, text } => {
                self.act(&mut tab, &element_ref, "type", &text).await
            }
            BrowseRequest::Select { element_ref, value } => {
                self.act(&mut tab, &element_ref, "select", &value).await
            }
        }
    }

    async fn act(&self, tab: &mut Tab, reference: &str, kind: &str, value: &str) -> Result<Value> {
        let (generation, index) = reference
            .split_once(':')
            .context("Invalid element reference")?;
        if generation.parse::<u64>()? != tab.generation {
            bail!("Stale element reference; request a new snapshot");
        }
        let index = index.parse::<usize>()?;
        if value.len() > 8192 {
            bail!("Input exceeds limit");
        }
        let binding = tab
            .refs
            .get(index)
            .context("Stale element reference; request a new snapshot")?
            .clone();
        let index = binding.index;
        let world = binding.world;
        let expression = format!(
            r#"(()=>{{const e=globalThis.__bloomRefs?.[{index}];
            if(!e||!e.isConnected||e.disabled||!e.getClientRects().length)throw Error('stale');
            const kind={kind},value={value};
            const label=(e.innerText||e.value||e.getAttribute('aria-label')||'').trim();
            if(kind==='click' && /^(pay|place order|complete purchase|submit payment|pagar)\b/i.test(label))throw Error('payment requires approval');
            if(kind==='click')e.click();else{{
                if((e.autocomplete||'').split(' ').some(s=>s.startsWith('cc-')))throw Error('private payment input');
                if(kind==='select'&&e.tagName!=='SELECT')throw Error('wrong field');
                if(kind==='type'&&!['INPUT','TEXTAREA'].includes(e.tagName))throw Error('wrong field');
                const p=e.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:e.tagName==='SELECT'?HTMLSelectElement.prototype:HTMLInputElement.prototype;
                Object.getOwnPropertyDescriptor(p,'value').set.call(e,value);
                e.dispatchEvent(new Event('input',{{bubbles:true}}));e.dispatchEvent(new Event('change',{{bubbles:true}}));
            }}return {{state:'acted'}};}})()"#,
            kind = serde_json::to_string(kind)?,
            value = serde_json::to_string(value)?
        );
        let response = self
            .cdp
            .call(
                Some(&binding.session),
                "Runtime.evaluate",
                json!({"contextId":world,"expression":expression,"returnByValue":true}),
            )
            .await?;
        if response.get("exceptionDetails").is_some() {
            bail!("Shopping document changed; request a new snapshot");
        }
        // Every action invalidates refs, including same-document replacement.
        tab.generation += 1;
        Ok(json!({"state":"acted"}))
    }

    fn available(&self) -> Result<()> {
        if self.revoked.load(Ordering::SeqCst) {
            bail!("Checkout has private control; shopping is paused");
        }
        Ok(())
    }

    pub(crate) async fn handoff(&self) -> Result<PrivateTab> {
        if self.revoked.swap(true, Ordering::SeqCst) {
            bail!("Checkout is already private");
        }
        let mut tab = self.tab.lock().await; // Drain the one in-flight command.
        tab.refs.clear();
        tab.generation += 1;
        Ok(PrivateTab {
            cdp: self.cdp.clone(),
            session: tab.session.clone(),
            target: tab.target.clone(),
        })
    }

    pub(crate) async fn return_control(&self) -> Result<()> {
        let mut tab = self.tab.lock().await;
        // The entire browser belongs to checkout, including script-opened popups.
        let targets = self.cdp.call(None, "Target.getTargets", json!({})).await?;
        for target in targets["targetInfos"]
            .as_array()
            .context("Missing browser targets")?
        {
            if target["type"] == "page" {
                self.cdp
                    .call(
                        None,
                        "Target.closeTarget",
                        json!({"targetId":target["targetId"]}),
                    )
                    .await?;
            }
        }
        *tab = new_tab(&self.cdp, tab.generation + 1).await?;
        self.revoked.store(false, Ordering::SeqCst);
        Ok(())
    }
}

async fn new_tab(cdp: &Cdp, generation: u64) -> Result<Tab> {
    let created = cdp
        .call(None, "Target.createTarget", json!({"url":"about:blank"}))
        .await?;
    let target = created["targetId"]
        .as_str()
        .context("Missing tab")?
        .to_owned();
    let attached = cdp
        .call(
            None,
            "Target.attachToTarget",
            json!({"targetId":target,"flatten":true}),
        )
        .await?;
    let session = attached["sessionId"]
        .as_str()
        .context("Missing browser session")?
        .to_owned();
    cdp.call(Some(&session), "Page.enable", json!({})).await?;
    cdp.call(Some(&session), "Network.enable", json!({}))
        .await?;
    cdp.call(
        Some(&session),
        "Emulation.setDeviceMetricsOverride",
        json!({"width":1280,"height":900,"deviceScaleFactor":1,"mobile":false}),
    )
    .await?;
    cdp.call(Some(&session), "Runtime.enable", json!({}))
        .await?;
    Ok(Tab {
        target,
        session,
        refs: Vec::new(),
        generation,
    })
}

fn accessibility_text(tree: &Value) -> Result<String> {
    let nodes = tree["nodes"]
        .as_array()
        .context("Missing accessibility tree")?;
    let mut hidden = std::collections::HashSet::new();
    let mut queue = nodes
        .iter()
        .filter(|n| {
            matches!(
                n["role"]["value"].as_str(),
                Some("textbox" | "searchbox" | "Iframe" | "IframePresentational")
            )
        })
        .filter_map(|n| n["nodeId"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    while let Some(id) = queue.pop() {
        if !hidden.insert(id.clone()) {
            continue;
        }
        if let Some(node) = nodes.iter().find(|n| n["nodeId"] == id) {
            if let Some(children) = node["childIds"].as_array() {
                queue.extend(
                    children
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_owned)),
                );
            }
        }
    }
    let text = nodes
        .iter()
        .filter(|n| n["ignored"] != true)
        .filter(|n| !hidden.contains(n["nodeId"].as_str().unwrap_or("")))
        .filter_map(|n| {
            let role = n["role"]["value"].as_str()?;
            let name = n["name"]["value"].as_str()?;
            if name.is_empty() || matches!(role, "textbox" | "Iframe" | "IframePresentational") {
                None
            } else {
                Some(format!("{role}: {name}"))
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, response::Html, routing::get};

    #[tokio::test]
    #[ignore = "real public Shopify cart, no card or purchase; requires network"]
    async fn shopify_public_cart_remains_browsable() {
        let root = tempfile::tempdir().unwrap().keep();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.join("profile"),
            &["--no-sandbox".into()],
        )
        .await
        .unwrap();
        browser
            .browse(BrowseRequest::Open {
                url: "https://shop.simplyonpurpose.org/products/story-starters".into(),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let button = snapshot["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|element| element["label"] == "Add to Cart")
            .unwrap();
        browser
            .browse(BrowseRequest::Click {
                element_ref: button["ref"].as_str().unwrap().into(),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
        browser.browse(BrowseRequest::Snapshot).await.unwrap();
    }
    use std::time::Duration;

    #[tokio::test]
    async fn renderer_and_browser_crashes_leave_no_memory_dumps() {
        fn assert_no_dump(path: &Path) {
            for entry in std::fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    assert_no_dump(&entry.path());
                } else {
                    assert_ne!(
                        entry.path().extension().and_then(|v| v.to_str()),
                        Some("dmp")
                    );
                    assert!(!entry.file_name().to_string_lossy().starts_with("core."));
                }
            }
        }
        for method in ["Page.crash", "Browser.crash"] {
            let root = tempfile::tempdir().unwrap().keep();
            let browser = Browser::launch(
                &crate::test_chromium(),
                &root.join("profile"),
                &["--no-sandbox".into()],
            )
            .await
            .unwrap();
            let tab = browser.handoff().await.unwrap();
            tab.cdp.evaluate(&tab.session,
                "document.body.innerHTML='<input autocomplete=cc-number>';document.querySelector('input').value='4242424242424242'".into(),
            ).await.unwrap();
            let session = if method == "Browser.crash" {
                None
            } else {
                Some(tab.session.as_str())
            };
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                tab.cdp.call(session, method, json!({})),
            )
            .await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            if method == "Browser.crash" {
                assert!(
                    tab.cdp.exited(),
                    "Browser crash command must terminate the browser"
                );
            } else {
                assert!(
                    tab.cdp.evaluate(&tab.session, "1".into()).await.is_err(),
                    "Renderer crash command must terminate the renderer"
                );
            }
            assert_no_dump(&root);
        }
    }

    #[tokio::test]
    async fn real_pipe_browser_revokes_drains_and_closes_popups() {
        let executable = crate::test_chromium();
        let root = tempfile::tempdir().unwrap().keep();
        let browser = Browser::launch(&executable, &root.join("profile"), &["--no-sandbox".into()])
            .await
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    Html(
                        r#"<!doctype html><h1>Fixture shop</h1>
            <input aria-label="Private fixture" value="do-not-project-input-value">
            <button onclick="window.open('/popup')">Open popup</button>"#,
                    )
                }),
            )
            .route("/popup", get(|| async { Html("<h1>Payment popup</h1>") }));
        let fixture = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        browser.browse(BrowseRequest::Open { url }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        assert!(snapshot["text"].as_str().unwrap().contains("Fixture shop"));
        assert!(!snapshot.to_string().contains("do-not-project-input-value"));
        let reference = snapshot["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == "Open popup")
            .unwrap()["ref"]
            .as_str()
            .unwrap()
            .to_owned();
        browser
            .browse(BrowseRequest::Click {
                element_ref: reference.clone(),
            })
            .await
            .unwrap();
        assert!(
            browser
                .browse(BrowseRequest::Click {
                    element_ref: reference
                })
                .await
                .is_err()
        );
        let session = browser.tab.lock().await.session.clone();
        let cdp = browser.cdp.clone();
        let busy = tokio::spawn(async move {
            cdp.evaluate(
                &session,
                "(()=>{const t=Date.now()+600;while(Date.now()<t){};return true})()".into(),
            )
            .await
            .unwrap();
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        let b = browser.clone();
        let snapshot = tokio::spawn(async move { b.browse(BrowseRequest::Snapshot).await });
        tokio::time::sleep(Duration::from_millis(30)).await;
        let b = browser.clone();
        let handoff = tokio::spawn(async move { b.handoff().await.unwrap() });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(browser.browse(BrowseRequest::Snapshot).await.is_err());
        busy.await.unwrap();
        snapshot.await.unwrap().unwrap();
        let private = handoff.await.unwrap();
        assert!(!private.target.is_empty());
        assert_eq!(private.session, browser.tab.lock().await.session);
        assert!(
            private
                .cdp
                .call(None, "Target.getTargets", json!({}))
                .await
                .unwrap()["targetInfos"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|t| t["type"] == "page")
                .count()
                >= 2
        );
        browser.return_control().await.unwrap();
        let targets = browser
            .cdp
            .call(None, "Target.getTargets", json!({}))
            .await
            .unwrap();
        let pages = targets["targetInfos"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t["type"] == "page")
            .collect::<Vec<_>>();
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0]["url"], "about:blank");
        assert!(browser.browse(BrowseRequest::Snapshot).await.is_ok());
        fixture.abort();
        // Retained profile is evidence; no recursive removal.
    }
}
