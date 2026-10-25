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
    /// Origin of the frame holding the element when it was read.
    origin: String,
}

struct Tab {
    /// Shopping runs in a disposable browser context, never the profile's
    /// default one, so a finished checkout discards its cookies and storage.
    context: String,
    target: String,
    session: String,
    refs: Vec<ElementRef>,
    generation: u64,
    journey: u64,
}

pub struct Browser {
    cdp: Arc<Cdp>,
    tab: Mutex<Tab>,
    revoked: AtomicBool,
    #[cfg(test)]
    fixture_payment_hosts: bool,
    /// Unlocked traveler values and their placeholders, removed from snapshots.
    redactions: std::sync::RwLock<Vec<(zeroize::Zeroizing<String>, String)>>,
}

/// Private checkout access exists only after the public API has drained.
#[derive(Clone)]
pub(crate) struct PrivateTab {
    pub cdp: Arc<Cdp>,
    pub session: String,
    pub target: String,
    /// Local fixture merchants count as payment providers (tests only).
    #[cfg(test)]
    pub fixture_payment_hosts: bool,
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
        // Tests accept card fields served by local fixture merchants.
        #[cfg(test)]
        let fixture_payment_hosts = test_flags
            .iter()
            .any(|f| f == "--ignore-certificate-errors");
        let cdp = Cdp::launch(executable, profile, test_flags)?;
        let tab = new_tab(&cdp, None, 1).await?;
        Ok(Arc::new(Self {
            cdp,
            tab: Mutex::new(tab),
            #[cfg(test)]
            fixture_payment_hosts,
            revoked: AtomicBool::new(false),
            redactions: std::sync::RwLock::new(Vec::new()),
        }))
    }

    pub async fn browse(&self, mut request: BrowseRequest) -> Result<Value> {
        self.available()?;
        let mut tab = self.tab.lock().await;
        self.available()?;
        if let BrowseRequest::Open { url } = &mut request {
            let parsed = shopping_url(url)?;
            *url = parsed.to_string();
            // An explicit open starts a new public journey.
            tab.journey += 1;
            tab.refs.clear();
            tab.generation += 1;
        }
        match request {
            BrowseRequest::Open { url } => {
                self.cdp
                    .call(Some(&tab.session), "Page.navigate", json!({"url":url}))
                    .await?;
                tab.refs.clear();
                tab.generation += 1;
                Ok(json!({"state":"opened"}))
            }
            BrowseRequest::Snapshot => {
                // Booking sites may create the tab after the click has returned.
                self.follow_popup(&mut tab).await?;
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
                        "contextId":frame.world,"returnByValue":true,"expression":crate::scripts::prepare(include_str!("snapshot.js"))
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
                        // A long page must not crowd out its payment and
                        // other embedded frames, which get their own share.
                        if index >= if position == 0 { 300 } else { 20 } || elements.len() >= 400 {
                            break;
                        }
                        let mut element = element.clone();
                        element["ref"] = json!(format!("{}:{}", tab.generation, tab.refs.len()));
                        element["frame_origin"] = json!(parsed.origin().ascii_serialization());
                        tab.refs.push(ElementRef {
                            session: frame.session.clone(),
                            world: frame.world,
                            index,
                            origin: parsed.origin().ascii_serialization(),
                        });
                        elements.push(element);
                    }
                }
                self.redacted(json!({"url":url,"text":text.chars().take(30000).collect::<String>(),"elements":elements}))
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
                self.act(&mut tab, &element_ref, "click", "", None).await
            }
            BrowseRequest::Type { element_ref, text } => {
                self.act(&mut tab, &element_ref, "type", &text, None).await
            }
            BrowseRequest::Select { element_ref, value } => {
                self.act(&mut tab, &element_ref, "select", &value, None)
                    .await
            }
            BrowseRequest::FillTraveler { .. } | BrowseRequest::TypeTraveler { .. } => {
                bail!("Unlock a saved traveler first")
            }
        }
    }

    /// Replace each saved value, in any ASCII letter case, with its placeholder.
    fn redacted(&self, value: Value) -> Result<Value> {
        let redactions = self.redactions.read().unwrap();
        let mut text = serde_json::to_string(&value)?;
        for (secret, label) in redactions.iter() {
            let escaped = serde_json::to_string(secret.as_str())?;
            let needle = escaped[1..escaped.len() - 1].to_ascii_lowercase();
            for variant in [needle.clone(), secret.to_uppercase()] {
                let mut out = String::with_capacity(text.len());
                let lower = text.to_ascii_lowercase();
                let mut last = 0;
                for (start, _) in lower.match_indices(&variant.to_ascii_lowercase()) {
                    if start >= last {
                        out.push_str(&text[last..start]);
                        out.push_str(label);
                        last = start + variant.len();
                    }
                }
                out.push_str(&text[last..]);
                text = out;
            }
        }
        Ok(serde_json::from_str(&text)?)
    }

    pub(crate) fn redact(&self, values: impl IntoIterator<Item = (String, String)>) {
        self.redact_min(values, 3);
    }

    /// `min_chars` is 3 for saved values. A birth year is the exception: a
    /// two-digit year is still the person's year.
    pub(crate) fn redact_min(
        &self,
        values: impl IntoIterator<Item = (String, String)>,
        min_chars: usize,
    ) {
        let mut redactions = self.redactions.write().unwrap();
        redactions.extend(
            values
                .into_iter()
                .filter(|(secret, _)| secret.chars().count() >= min_chars)
                .map(|(secret, label)| (zeroize::Zeroizing::new(secret), label)),
        );
        // Longer values first, so a full name is replaced before its parts.
        redactions.sort_by_key(|(secret, _)| std::cmp::Reverse(secret.len()));
    }

    /// Form errors the shopping page shows, read before payment is requested.
    /// Copies the page's contact email and phone into its re-entry fields,
    /// then reports what the page still asks of the human.
    pub(crate) async fn page_attention(&self) -> Result<Value> {
        let tab = self.tab.lock().await;
        let evaluate = |expression: &str| {
            self.cdp.call(
                Some(&tab.session),
                "Runtime.evaluate",
                json!({"expression":expression,"returnByValue":true}),
            )
        };
        evaluate(include_str!("confirm-contact.js")).await?;
        let result = evaluate(concat!(
            include_str!("form-attention.js"),
            ";globalThis.__bloomAttention()"
        ))
        .await?;
        Ok(result["result"]["value"].clone())
    }

    /// Distinguishes explicit journeys, including two opens on the same origin.
    #[cfg(test)]
    pub(crate) async fn shopping_context(&self) -> String {
        let tab = self.tab.lock().await;
        journey_context(&tab)
    }

    #[cfg(test)]
    pub(crate) async fn shopping_origin(&self) -> Result<String> {
        let tab = self.tab.lock().await;
        self.origin(&tab).await
    }

    pub(crate) async fn shopping_scope(&self) -> Result<(String, String)> {
        let tab = self.tab.lock().await;
        Ok((journey_context(&tab), self.origin(&tab).await?))
    }

    pub(crate) async fn private_shopping_scope(&self) -> Result<(String, String)> {
        let tab = self.tab.lock().await;
        self.available()?;
        Ok((journey_context(&tab), self.origin(&tab).await?))
    }

    async fn origin(&self, tab: &Tab) -> Result<String> {
        let info = self
            .cdp
            .call(None, "Target.getTargetInfo", json!({"targetId":tab.target}))
            .await?;
        let url = url::Url::parse(info["targetInfo"]["url"].as_str().unwrap_or(""))?;
        Ok(url.origin().ascii_serialization())
    }

    async fn check_traveler_scope(&self, tab: &Tab, context: &str, origin: &str) -> Result<()> {
        if journey_context(tab) != context || self.origin(tab).await? != origin {
            bail!("Saved traveler details are unlocked for another booking or website");
        }
        Ok(())
    }

    /// Saved values go only into frames of the unlocked website, never into
    /// an embedded chat, ad or other third-party frame.
    fn check_traveler_frame(tab: &Tab, reference: &str, origin: &str) -> Result<()> {
        let index = reference
            .split_once(':')
            .and_then(|(_, index)| index.parse::<usize>().ok());
        if let Some(binding) = index.and_then(|index| tab.refs.get(index))
            && binding.origin != origin
        {
            bail!(
                "That field is in an embedded frame from another website; type it in the private view"
            );
        }
        Ok(())
    }

    pub(crate) async fn type_traveler(
        &self,
        reference: &str,
        field: &str,
        value: &str,
        context: &str,
        origin: &str,
    ) -> Result<()> {
        self.available()?;
        let mut tab = self.tab.lock().await;
        self.available()?;
        self.check_traveler_scope(&tab, context, origin).await?;
        Self::check_traveler_frame(&tab, reference, origin)?;
        self.act(&mut tab, reference, "type", value, Some(field))
            .await?;
        Ok(())
    }

    /// Choose a saved traveler value in a list the agent picked (a select or a
    /// site-drawn dropdown). The value never comes back; failure says so.
    pub(crate) async fn choose_traveler(
        &self,
        reference: &str,
        field: &str,
        value: &str,
        context: &str,
        origin: &str,
    ) -> Result<()> {
        self.available()?;
        let mut tab = self.tab.lock().await;
        self.available()?;
        self.check_traveler_scope(&tab, context, origin).await?;
        Self::check_traveler_frame(&tab, reference, origin)?;
        let (generation, index) = reference
            .split_once(':')
            .context("Invalid element reference")?;
        if generation.parse::<u64>()? != tab.generation {
            bail!("Stale element reference; request a new snapshot");
        }
        let binding = tab
            .refs
            .get(index.parse::<usize>()?)
            .context("Stale element reference; request a new snapshot")?
            .clone();
        tab.refs.clear();
        tab.generation += 1;
        // Open the list the way a shopping click does: synchronously, with a
        // user gesture. Some lists ignore clicks from later script turns.
        let open = format!(
            "(()=>{{const e=globalThis.__bloomRefs?.[{}];if(!e?.isConnected)throw Error('stale');e.focus();e.click();return true;}})()",
            binding.index
        );
        self.cdp
            .call(
                Some(&binding.session),
                "Runtime.evaluate",
                json!({"contextId":binding.world,"expression":open,"returnByValue":true,"userGesture":true}),
            )
            .await?;
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let view = PrivateTab {
            cdp: self.cdp.clone(),
            session: binding.session.clone(),
            target: tab.target.clone(),
            #[cfg(test)]
            fixture_payment_hosts: self.fixture_payment_hosts,
        };
        let filled = crate::travelers::TravelerDiscovery::fill_opened(
            &view,
            &binding.session,
            binding.world,
            binding.index,
            field,
            value,
            origin,
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!("That list did not take the saved value; choose it in the private view")
        })?;
        if !filled.iter().any(|filled_field| filled_field == field) {
            bail!("That list did not take the saved value; choose it in the private view");
        }
        Ok(())
    }

    /// Fill unlocked traveler values into the shopping page. Only field names
    /// come back; the values are never part of a response.
    pub(crate) async fn fill_traveler(
        &self,
        origin: &str,
        context: &str,
        fields: &[bloom_signer_api::TravelerField],
        values: &std::collections::BTreeMap<String, zeroize::Zeroizing<String>>,
    ) -> Result<Vec<String>> {
        self.available()?;
        let mut tab = self.tab.lock().await;
        self.available()?;
        self.check_traveler_scope(&tab, context, origin).await?;
        let view = PrivateTab {
            cdp: self.cdp.clone(),
            session: tab.session.clone(),
            target: tab.target.clone(),
            #[cfg(test)]
            fixture_payment_hosts: self.fixture_payment_hosts,
        };
        tab.refs.clear();
        tab.generation += 1;
        let mut filled = Vec::new();
        for pass in 0..2 {
            let discovery = match crate::travelers::TravelerDiscovery::read(&view, fields).await {
                Ok(discovery) => discovery,
                Err(_) if pass > 0 => break,
                Err(error) => return Err(error),
            };
            if discovery.scope.origin != origin {
                bail!("Saved traveler details are unlocked for another website");
            }
            let wanted: std::collections::BTreeMap<_, _> = discovery
                .field_names()
                .into_iter()
                .filter_map(|f| values.get(&f).map(|v| (f, v.clone())))
                .collect();
            for field in discovery.fill(&view, &wanted).await? {
                if !filled.contains(&field) {
                    filled.push(field);
                }
            }
        }
        Ok(filled)
    }

    async fn act(
        &self,
        tab: &mut Tab,
        reference: &str,
        kind: &str,
        value: &str,
        saved_field: Option<&str>,
    ) -> Result<Value> {
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
            "({})({index},{},{},{})",
            crate::scripts::prepare(include_str!("act.js")),
            serde_json::to_string(kind)?,
            serde_json::to_string(value)?,
            serde_json::to_string(&saved_field)?
        );
        let response = self
            .cdp
            .call(
                Some(&binding.session),
                "Runtime.evaluate",
                json!({"contextId":world,"expression":expression,"returnByValue":true,"userGesture":true}),
            )
            .await?;
        if let Some(details) = response.get("exceptionDetails") {
            let description = details["exception"]["description"].as_str().unwrap_or("");
            let text = details["text"].as_str().unwrap_or("");
            let reason = if description.is_empty() {
                text
            } else {
                description
            };
            if reason
                .lines()
                .next()
                .unwrap_or("")
                .contains("payment requires approval")
            {
                bail!("payment requires approval");
            }
            bail!("Shopping document changed; request a new snapshot");
        }
        // Every action invalidates refs, including same-document replacement.
        tab.generation += 1;
        if kind == "click" {
            self.follow_popup(tab).await?;
        }
        Ok(json!({"state":"acted"}))
    }

    async fn follow_popup(&self, tab: &mut Tab) -> Result<()> {
        let targets = self.cdp.call(None, "Target.getTargets", json!({})).await?;
        let pages = targets["targetInfos"]
            .as_array()
            .context("Missing browser targets")?;
        let children = pages
            .iter()
            .filter(|page| page["type"] == "page" && page["openerId"] == tab.target)
            .collect::<Vec<_>>();
        let child = match children.as_slice() {
            [] => return Ok(()),
            [child] => child,
            _ => bail!("Multiple shopping pages opened; choose the page in private control"),
        };
        let url = child["url"].as_str().context("Missing popup URL")?;
        // Chromium reports an empty URL while a newly opened page initializes.
        // Snapshot independently checks its eventual document URL.
        if !matches!(url, "" | "about:blank")
            && !matches!(url::Url::parse(url)?.scheme(), "http" | "https")
        {
            bail!("Only ordinary HTTP(S) shopping popups are supported");
        }
        let target = child["targetId"].as_str().context("Missing popup target")?;
        let journey = tab.journey;
        *tab = attach_tab(
            &self.cdp,
            tab.context.clone(),
            target.to_owned(),
            tab.generation + 1,
        )
        .await?;
        tab.journey = journey;
        Ok(())
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
            #[cfg(test)]
            fixture_payment_hosts: self.fixture_payment_hosts,
        })
    }

    #[cfg(test)]
    pub(crate) async fn lose_shopping_context(&self) {
        self.tab.lock().await.context = "missing-context".into();
    }

    /// Discards the checkout's browsing context, including cookies and storage
    /// the merchant kept, so shopping never reopens a private session and may
    /// return to the booking site.
    pub(crate) async fn return_control(&self) -> Result<()> {
        let mut tab = self.tab.lock().await;
        self.cdp
            .call(
                None,
                "Target.disposeBrowserContext",
                json!({"browserContextId":tab.context}),
            )
            .await?;
        // The entire browser belongs to checkout, including script-opened popups.
        // closeTarget acknowledges a request, not destruction. Keep shopping
        // revoked until every private page has disappeared, including popups
        // created while the initial pages were closing.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let targets = self.cdp.call(None, "Target.getTargets", json!({})).await?;
            let pages = targets["targetInfos"]
                .as_array()
                .context("Missing browser targets")?
                .iter()
                .filter(|target| target["type"] == "page")
                .collect::<Vec<_>>();
            if pages.is_empty() {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("Private pages did not close; shopping remains revoked");
            }
            for target in pages {
                self.cdp
                    .call(
                        None,
                        "Target.closeTarget",
                        json!({"targetId":target["targetId"]}),
                    )
                    .await?;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        *tab = new_tab(&self.cdp, None, tab.generation + 1).await?;
        // Old private pages are gone. Until then these patterns must remain so
        // an expired traveler still present in the DOM cannot enter a snapshot.
        self.redactions.write().unwrap().clear();
        self.revoked.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// After a take-over, shopping continues on the page the human left.
    pub(crate) async fn return_control_at(&self, target: &str, url: Option<String>) -> Result<()> {
        let Some(url) = url.filter(|u| u.starts_with("https://") || u.starts_with("http://"))
        else {
            return self.return_control().await;
        };
        let mut tab = self.tab.lock().await;
        let mut resumed = attach_tab(
            &self.cdp,
            tab.context.clone(),
            target.to_owned(),
            tab.generation + 1,
        )
        .await?;
        resumed.journey = tab.journey;
        // Navigate away before returning, so Chrome cannot restore private
        // form values as it might during a reload of the same history entry.
        self.cdp
            .call(
                Some(&resumed.session),
                "Page.navigate",
                json!({"url":"about:blank"}),
            )
            .await?;
        let tree = self
            .cdp
            .call(Some(&resumed.session), "Page.getFrameTree", json!({}))
            .await?;
        let previous = tree["frameTree"]["frame"]["loaderId"]
            .as_str()
            .context("Missing private document")?;
        let navigation = self
            .cdp
            .call(Some(&resumed.session), "Page.navigate", json!({"url":url}))
            .await?;
        let loader = navigation["loaderId"]
            .as_str()
            .filter(|id| *id != previous)
            .context("Private document was not replaced; shopping remains paused")?;
        // A new document clears private DOM and execution contexts while the
        // tab's sessionStorage keeps the airline's booking session alive.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if tokio::time::Instant::now() >= deadline {
                bail!("Private document replacement timed out; shopping remains paused");
            }
            let tree = self
                .cdp
                .call(Some(&resumed.session), "Page.getFrameTree", json!({}))
                .await?;
            let targets = self.cdp.call(None, "Target.getTargets", json!({})).await?;
            let other_pages = targets["targetInfos"]
                .as_array()
                .context("Missing browser targets")?
                .iter()
                .filter(|page| page["type"] == "page" && page["targetId"] != target)
                .collect::<Vec<_>>();
            if tree["frameTree"]["frame"]["loaderId"] == loader && other_pages.is_empty() {
                break;
            }
            for page in other_pages {
                self.cdp
                    .call(
                        None,
                        "Target.closeTarget",
                        json!({"targetId":page["targetId"]}),
                    )
                    .await?;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        self.cdp
            .call(
                Some(&resumed.session),
                "Page.resetNavigationHistory",
                json!({}),
            )
            .await?;
        resumed.refs.clear();
        *tab = resumed;
        self.revoked.store(false, Ordering::SeqCst);
        Ok(())
    }
}

async fn new_tab(cdp: &Cdp, context: Option<String>, generation: u64) -> Result<Tab> {
    let context = match context {
        Some(context) => context,
        None => cdp
            .call(None, "Target.createBrowserContext", json!({}))
            .await?["browserContextId"]
            .as_str()
            .context("Missing browser context")?
            .to_owned(),
    };
    let created = cdp
        .call(
            None,
            "Target.createTarget",
            json!({"url":"about:blank","browserContextId":context}),
        )
        .await?;
    let target = created["targetId"]
        .as_str()
        .context("Missing tab")?
        .to_owned();
    attach_tab(cdp, context, target, generation).await
}

async fn attach_tab(cdp: &Cdp, context: String, target: String, generation: u64) -> Result<Tab> {
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
        context,
        target,
        session,
        refs: Vec::new(),
        generation,
        journey: 0,
    })
}

fn shopping_url(url: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(url).context("Invalid browsing URL")?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        bail!("Only ordinary HTTP(S) shopping URLs are supported");
    }
    Ok(parsed)
}

fn journey_context(tab: &Tab) -> String {
    format!("{}:{}", tab.context, tab.journey)
}

fn accessibility_text(tree: &Value) -> Result<String> {
    let nodes = tree["nodes"]
        .as_array()
        .context("Missing accessibility tree")?;
    let mut hidden = std::collections::HashSet::new();
    // Values and select options come from the controlled element projection.
    // AX can repeat a selected birth month outside that value's redaction.
    let mut queue = nodes
        .iter()
        .filter(|n| {
            matches!(
                n["role"]["value"].as_str(),
                Some("textbox" | "searchbox" | "combobox" | "Iframe" | "IframePresentational")
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
    async fn comprar_and_kaufen_require_payment_approval() {
        let root = tempfile::tempdir().unwrap();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.path().join("profile"),
            &["--no-sandbox".into()],
        )
        .await
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let site = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/",
                    get(|| async {
                        Html(r#"<button>Comprar</button><button>Kaufen</button><button onclick="document.title='unsafe booking'">Book Now</button><button onclick="document.title='unsafe purchase'">PURCHASE &amp; ACCEPT</button><button onclick="document.title='unsafe Turkish payment'">Öde</button><button onclick="document.title='unsafe Vietnamese payment'">Thanh toán Ngay</button><span id="pay-name">Pay now</span><button aria-labelledby="pay-name" onmousedown="document.title='unsafe down'">Next</button><button onmousedown="this.textContent='Pay now'" onclick="document.title='unsafe click'">Proceed</button><button>Ödeme Sayfasına Devam Et</button><button>Tiếp theo: Thanh toán &gt;</button>"#)
                    }),
                ),
            )
            .await
            .unwrap();
        });
        browser.browse(BrowseRequest::Open { url }).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let reference = |label: &str| {
            snapshot["elements"]
                .as_array()
                .unwrap()
                .iter()
                .find(|element| element["label"] == label)
                .unwrap()["ref"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        for label in [
            "Comprar",
            "Kaufen",
            "Book Now",
            "PURCHASE & ACCEPT",
            "Öde",
            "Thanh toán Ngay",
            "Pay now",
            "Proceed",
        ] {
            let error = browser
                .browse(BrowseRequest::Click {
                    element_ref: reference(label),
                })
                .await
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("payment requires approval"),
                "{label}: {error}"
            );
        }
        browser
            .browse(BrowseRequest::Click {
                element_ref: reference("Ödeme Sayfasına Devam Et"),
            })
            .await
            .unwrap();
        let after = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let reference = after["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == "Tiếp theo: Thanh toán >")
            .unwrap()["ref"]
            .as_str()
            .unwrap()
            .to_owned();
        browser
            .browse(BrowseRequest::Click {
                element_ref: reference,
            })
            .await
            .unwrap();
        assert!(!after["text"].as_str().unwrap().contains("unsafe"));
        site.abort();
    }

    #[tokio::test]
    async fn opening_another_booking_on_the_same_origin_invalidates_traveler_scope() {
        let root = tempfile::tempdir().unwrap();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.path().join("profile"),
            &["--no-sandbox".into()],
        )
        .await
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let origin = url.trim_end_matches('/');
        let site = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/",
                    get(|| async { Html("<label>Given name<input name='first_name'></label>") }),
                ),
            )
            .await
            .unwrap();
        });
        browser
            .browse(BrowseRequest::Open { url: url.clone() })
            .await
            .unwrap();
        let old_context = browser.shopping_context().await;
        browser
            .browse(BrowseRequest::Open { url: url.clone() })
            .await
            .unwrap();
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let reference = snapshot["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["kind"] == "textbox" || e["tag"] == "input")
            .or_else(|| snapshot["elements"].as_array().unwrap().first())
            .unwrap()["ref"]
            .as_str()
            .unwrap();
        let error = browser
            .type_traveler(
                reference,
                "given_name",
                "PRIVATE-FIXTURE",
                &old_context,
                origin,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("another booking"));
        assert!(
            browser
                .fill_traveler(origin, &old_context, &[], &Default::default())
                .await
                .is_err()
        );
        let value = browser
            .cdp
            .call(
                Some(&browser.tab.lock().await.session),
                "Runtime.evaluate",
                json!({"expression":"document.querySelector('input').value","returnByValue":true}),
            )
            .await
            .unwrap();
        assert_eq!(value["result"]["value"], "");
        site.abort();
        let _ = site.await;
    }

    #[tokio::test]
    async fn saved_traveler_values_never_go_into_another_origins_frame() {
        let root = tempfile::tempdir().unwrap();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.path().join("profile"),
            &["--no-sandbox".into()],
        )
        .await
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/");
        let origin = url.trim_end_matches('/').to_owned();
        let page = format!(
            "<label>Given name<input name='first_name'></label>\
             <iframe src='http://localhost:{port}/chat' width=400 height=200></iframe>"
        );
        let site = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/", get(move || async move { Html(page) }))
                    .route(
                        "/chat",
                        get(|| async { Html("<label>Chat message<input name='chat'></label>") }),
                    ),
            )
            .await
            .unwrap();
        });
        browser
            .browse(BrowseRequest::Open { url: url.clone() })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let context = browser.shopping_context().await;
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let chat = snapshot["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["frame_origin"] != origin.as_str() && e["role"] == "input")
            .unwrap_or_else(|| panic!("no child frame input in {snapshot}"))["ref"]
            .as_str()
            .unwrap()
            .to_owned();
        let error = browser
            .type_traveler(&chat, "given_name", "PRIVATE-FIXTURE", &context, &origin)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("embedded frame from another website"),
            "{error}"
        );
        site.abort();
        let _ = site.await;
    }

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
    #[ignore = "public airline airport picker only; no passengers, card or purchase"]
    async fn aerolineas_public_airport_autocomplete() {
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
                url: "https://www.aerolineas.com.ar/".into(),
            })
            .await
            .unwrap();
        let mut before = json!({});
        let mut reference = None;
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let Ok(snapshot) = browser.browse(BrowseRequest::Snapshot).await else {
                continue;
            };
            before = snapshot;
            reference = before["elements"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| matches!(e["label"].as_str(), Some("Origen" | "Origin")))
                .and_then(|e| e["ref"].as_str())
                .map(str::to_owned);
            if reference.is_some() {
                break;
            }
        }
        let reference =
            reference.unwrap_or_else(|| panic!("Airline origin field absent: {before}"));
        if let Some(cookie) = before["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == "Aceptar solo las esenciales")
        {
            browser
                .browse(BrowseRequest::Click {
                    element_ref: cookie["ref"].as_str().unwrap().into(),
                })
                .await
                .unwrap();
            let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
            let origin = snapshot["elements"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["label"] == "Origen")
                .unwrap()["ref"]
                .as_str()
                .unwrap()
                .to_owned();
            browser
                .browse(BrowseRequest::Type {
                    element_ref: origin,
                    text: "Cordoba".into(),
                })
                .await
                .unwrap();
        } else {
            browser
                .browse(BrowseRequest::Type {
                    element_ref: reference,
                    text: "Cordoba".into(),
                })
                .await
                .unwrap();
        }
        let mut after = json!({});
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Ok(snapshot) = browser.browse(BrowseRequest::Snapshot).await {
                after = snapshot;
                if after["text"].as_str().unwrap().contains("COR") {
                    break;
                }
            }
        }
        let labels = after["elements"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e["label"].as_str())
            .collect::<Vec<_>>();
        assert!(
            after["text"].as_str().unwrap().contains("COR"),
            "Expected Córdoba airport suggestion; got labels {labels:?}, text {}",
            after["text"]
        );
        let airport = after["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| {
                e["label"]
                    .as_str()
                    .is_some_and(|label| label.contains("COR"))
            })
            .expect("Clickable Córdoba airport suggestion");
        browser
            .browse(BrowseRequest::Click {
                element_ref: airport["ref"].as_str().unwrap().into(),
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn shopping_type_triggers_autocomplete_and_click_follows_popup() {
        let root = tempfile::tempdir().unwrap().keep();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.join("profile"),
            &["--no-sandbox".into()],
        )
        .await
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let fixture = tokio::spawn(async move {
            axum::serve(listener, Router::new()
                .route("/", get(|| async { Html(r#"<!doctype html>
                  <input aria-label="Origin" onkeyup="document.getElementById('suggestion').hidden=this.value!=='Cordoba'">
                  <div id="suggestion" role="option" hidden onclick="setTimeout(()=>window.open('/flight'),100)">Córdoba COR</div>
                  <div role="gridcell" aria-label="Sun Oct 25 2026" onclick="this.innerText='Date selected'">25</div>
                  <div role="gridcell" aria-disabled="true">Unavailable date</div>
                  <div ng-click="selectFlight()" onclick="this.innerText='Flight selected'">Select itinerary</div>
                  <div data-ng-click="disabled()" aria-disabled="true">Disabled itinerary</div>
                  <div ng-click="hidden()" hidden>Hidden itinerary</div>
                  <div ng-click="pay()" onclick="document.body.innerHTML='Unexpected payment'">Pagar</div>
                  <input aria-label="Private card" autocomplete="cc-number">
                  <button>Pay</button>"#) }))
                .route("/flight", get(|| async { Html("<h1>Flight AR1554</h1>") })))
                .await.unwrap();
        });
        browser.browse(BrowseRequest::Open { url }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let before = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let reference = |snapshot: &Value, label: &str| {
            snapshot["elements"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["label"] == label)
                .unwrap()["ref"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        assert!(!before.to_string().contains("Córdoba COR"));
        for label in ["Disabled itinerary", "Hidden itinerary"] {
            assert!(
                !before["elements"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|e| e["label"] == label)
            );
        }
        assert!(
            browser
                .browse(BrowseRequest::Click {
                    element_ref: reference(&before, "Pagar"),
                })
                .await
                .is_err()
        );
        browser
            .browse(BrowseRequest::Click {
                element_ref: reference(&before, "Select itinerary"),
            })
            .await
            .unwrap();
        let before = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        assert!(before["text"].as_str().unwrap().contains("Flight selected"));
        assert!(
            !before["elements"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["label"] == "Unavailable date")
        );
        browser
            .browse(BrowseRequest::Click {
                element_ref: reference(&before, "Sun Oct 25 2026"),
            })
            .await
            .unwrap();
        let before = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        assert!(before["text"].as_str().unwrap().contains("Date selected"));
        browser
            .browse(BrowseRequest::Type {
                element_ref: reference(&before, "Origin"),
                text: "Cordoba".into(),
            })
            .await
            .unwrap();
        let after = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        assert!(after.to_string().contains("Córdoba COR"));
        assert!(
            browser
                .browse(BrowseRequest::Type {
                    element_ref: reference(&after, "Private card"),
                    text: "4242424242424242".into(),
                })
                .await
                .is_err()
        );
        assert!(
            browser
                .browse(BrowseRequest::Click {
                    element_ref: reference(&after, "Pay"),
                })
                .await
                .is_err()
        );
        browser
            .browse(BrowseRequest::Click {
                element_ref: reference(&after, "Córdoba COR"),
            })
            .await
            .unwrap();
        let popup = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(snapshot) = browser.browse(BrowseRequest::Snapshot).await {
                    if snapshot["url"]
                        .as_str()
                        .is_some_and(|url| url.ends_with("/flight"))
                        && snapshot["text"]
                            .as_str()
                            .is_some_and(|text| text.contains("Flight AR1554"))
                    {
                        break snapshot;
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("shopping popup never became ready");
        assert!(popup["url"].as_str().unwrap().ends_with("/flight"));
        assert!(popup["text"].as_str().unwrap().contains("Flight AR1554"));
        fixture.abort();
    }

    #[tokio::test]
    async fn dense_seat_map_keeps_the_native_continue_control() {
        let (url, fixture) = crate::discovery::tests::fixture(format!(
            "<!doctype html><style>.seat{{cursor:pointer}}</style>{}<input type='button' value='Continue without seats' onclick=\"document.title='continued'\">",
            "<div class='seat' role='button' onclick=\"document.title='seat selected'\">Seat selection</div>".repeat(350)
        ))
        .await;
        let root = tempfile::tempdir().unwrap();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.path().join("profile"),
            &["--no-sandbox".into(), "--ignore-certificate-errors".into()],
        )
        .await
        .unwrap();
        browser.browse(BrowseRequest::Open { url }).await.unwrap();
        let snapshot = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
                if snapshot["text"]
                    .as_str()
                    .unwrap()
                    .contains("Continue without seats")
                {
                    break snapshot;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        let elements = snapshot["elements"].as_array().unwrap();
        assert!(elements.len() <= 300);
        let next = elements
            .iter()
            .find(|e| e["label"] == "Continue without seats")
            .expect("seat-map controls must not crowd out the native Continue button");
        browser
            .browse(BrowseRequest::Click {
                element_ref: next["ref"].as_str().unwrap().to_owned(),
            })
            .await
            .unwrap();
        assert!(
            browser.browse(BrowseRequest::Snapshot).await.unwrap()["text"]
                .as_str()
                .unwrap()
                .contains("continued")
        );
        fixture.abort();
    }

    #[tokio::test]
    async fn script_styled_controls_are_projected_with_their_card() {
        let root = tempfile::tempdir().unwrap().keep();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.join("profile"),
            &["--no-sandbox".into()],
        )
        .await
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        // Shaped like JetSMART: listeners attached by script, a pointer cursor
        // from the stylesheet, a pointer panel around day cells, identical
        // fare buttons told apart only by their card, and a restyled radio.
        let external_style = format!(
            "http://localhost:{}/external.css",
            listener.local_addr().unwrap().port()
        );
        let fixture = tokio::spawn(async move {
            let page = r#"<!doctype html>
              <link rel="stylesheet" href="EXTERNAL_STYLE">
              <style>.pick{cursor:pointer}.faded{opacity:0}</style>
              <div id="previous-step" style="height:0;overflow:hidden"></div>
              <input aria-label="Passenger name" value="First passenger">
              <div id="earlier-step"></div>
              <div class="external"><span>Remote fare</span></div>
              <input aria-label="Passenger name" value="Second passenger">
              <div id="component"></div>
              <div id="slotted"><span slot="label">Continue as guest</span></div>
              <div id="slotted-pay"><span slot="label">Pay now</span></div>
              <label>Styled month<select aria-label="Styled month" style="opacity:0"><option value="">Month</option><option value="1">January</option></select></label>
              <select aria-label="Hidden styled month" aria-hidden="true" style="opacity:0"><option>Month</option></select>
              <div style="opacity:0"><select aria-label="Inactive month"><option>Month</option></select></div>
              <span id="birth-month-label">Birth month</span>
              <div id="birth-month" role="combobox" tabindex="0" aria-labelledby="birth-month-label">Choose month</div>
              <ul><li class="pick" id="city">Cordoba COR</li><li class="pick faded">Hidden city</li></ul>
              <div class="pick"><div>Noviembre 2026</div><div class="pick" id="day">04</div></div>
              <div class="card">08:06 Cordoba 16:17 Bariloche<div class="pick fare">Tarifa desde $127.664,00</div></div>
              <div class="card">14:11 Cordoba 21:16 Bariloche<div class="pick fare">Tarifa desde $116.058,00</div></div>
              <label onclick="if(event.target===this) event.preventDefault()"><input type="radio" name="pass" style="display:none">Llevaré mi tarjeta de embarque<span class="pick">?</span></label>
              <div class="pick" id="pay">Pagar</div>
              <script>
                document.getElementById('birth-month').addEventListener('mousedown', e => e.currentTarget.innerHTML = '<div role="option">January</div>');
                for (const id of ['slotted', 'slotted-pay']) document.getElementById(id).attachShadow({mode:'open'}).innerHTML = '<button onclick="document.title=\'slotted clicked\'"><slot name="label"></slot></button>';
                document.getElementById('component').attachShadow({mode:'open'}).innerHTML = '<label>Component passenger<input oninput="document.title=this.value"></label><button onclick="document.title=\'component continued\'">Component continue</button><input aria-label="Component card" autocomplete="cc-number" value="4242424242424242">';
                document.getElementById('previous-step').innerHTML = '<button>Old seat</button>'.repeat(310);
                document.getElementById('earlier-step').innerHTML = '<button>Previous seat</button><br>'.repeat(310);
                document.querySelector('.external').scrollIntoView();
                for (const e of document.querySelectorAll('.pick,.external'))
                  e.addEventListener('click', () => document.title = 'clicked ' + e.innerText);
              </script>"#.replace("EXTERNAL_STYLE", &external_style);
            axum::serve(
                listener,
                Router::new()
                    .route(
                        "/",
                        get(move || {
                            let page = page.clone();
                            async move { Html(page) }
                        }),
                    )
                    .route(
                        "/external.css",
                        get(|| async {
                            ([("content-type", "text/css")], ".external {cursor:pointer}")
                        }),
                    ),
            )
            .await
            .unwrap();
        });
        browser.browse(BrowseRequest::Open { url }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let elements = snapshot["elements"].as_array().unwrap();
        let find = |label: &str| {
            elements
                .iter()
                .filter(|e| e["label"] == label)
                .collect::<Vec<_>>()
        };
        assert_eq!(find("Cordoba COR").len(), 1);
        assert!(find("January").is_empty());
        assert!(find("Hidden styled month").is_empty());
        assert!(find("Inactive month").is_empty());
        assert_eq!(
            find("Styled month")
                .iter()
                .filter(|e| e["role"] == "select")
                .count(),
            1
        );
        assert_eq!(
            find("Continue as guest").len(),
            1,
            "slotted button needs its visible label"
        );
        assert_eq!(
            find("Birth month").len(),
            1,
            "custom combobox must be exposed with its accessible name"
        );
        assert_eq!(
            find("Component passenger")
                .iter()
                .filter(|e| e["role"] == "input")
                .count(),
            1
        );
        assert!(find("Old seat").is_empty());
        assert_eq!(
            find("Passenger name")
                .iter()
                .map(|e| e["value"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["First passenger", "Second passenger"],
            "scrolling must not reorder repeated passenger fields"
        );
        assert_eq!(
            find("Remote fare").len(),
            1,
            "cross-origin CSS control must be projected once, without its inherited span"
        );
        assert_eq!(find("Remote fare")[0]["role"], "div");
        assert!(find("Hidden city").is_empty());
        assert_eq!(find("04")[0]["context"], "Noviembre 2026 04");
        // The panel around the day is layout, not a control.
        assert!(!elements.iter().any(|e| e["label"] == "Noviembre 2026 04"));
        let early = elements
            .iter()
            .find(|e| {
                e["context"]
                    .as_str()
                    .is_some_and(|c| c.starts_with("08:06"))
            })
            .unwrap();
        assert_eq!(early["label"], "Tarifa desde $127.664,00");
        assert_eq!(find("Llevaré mi tarjeta de embarque?").len(), 1);
        assert_eq!(find("Llevaré mi tarjeta de embarque?")[0]["checked"], false);
        browser
            .browse(BrowseRequest::Click {
                element_ref: early["ref"].as_str().unwrap().into(),
            })
            .await
            .unwrap();
        let after = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        assert!(
            after["text"]
                .as_str()
                .unwrap()
                .contains("clicked Tarifa desde $127.664,00")
        );
        let remote = after["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == "Remote fare")
            .unwrap()["ref"]
            .as_str()
            .unwrap()
            .to_owned();
        browser
            .browse(BrowseRequest::Click {
                element_ref: remote,
            })
            .await
            .unwrap();
        let after = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        assert!(
            after["text"]
                .as_str()
                .unwrap()
                .contains("clicked Remote fare")
        );
        let radio = after["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == "Llevaré mi tarjeta de embarque?")
            .unwrap()["ref"]
            .as_str()
            .unwrap()
            .to_owned();
        browser
            .browse(BrowseRequest::Click { element_ref: radio })
            .await
            .unwrap();
        let after = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        assert_eq!(
            after["elements"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["label"] == "Llevaré mi tarjeta de embarque?")
                .unwrap()["checked"],
            true
        );
        for label in ["Pagar", "Pay now"] {
            let pay = after["elements"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["label"] == label)
                .unwrap()["ref"]
                .as_str()
                .unwrap()
                .to_owned();
            assert!(
                browser
                    .browse(BrowseRequest::Click { element_ref: pay })
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("payment requires approval")
            );
        }
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let card = snapshot["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == "Component card")
            .unwrap();
        assert!(card.get("value").is_none());
        assert!(
            browser
                .browse(BrowseRequest::Type {
                    element_ref: card["ref"].as_str().unwrap().into(),
                    text: "4242424242424242".into(),
                })
                .await
                .is_err()
        );
        for (label, typed, expected) in [
            (
                "Component passenger",
                Some("FixtureShadow"),
                "FixtureShadow",
            ),
            ("Component continue", None, "component continued"),
            ("Birth month", None, "January"),
            ("Continue as guest", None, "slotted clicked"),
        ] {
            let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
            let element_ref = snapshot["elements"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["label"] == label && e["role"] != "label")
                .unwrap()["ref"]
                .as_str()
                .unwrap()
                .to_owned();
            let action = match typed {
                Some(text) => BrowseRequest::Type {
                    element_ref,
                    text: text.into(),
                },
                None => BrowseRequest::Click { element_ref },
            };
            browser.browse(action).await.unwrap();
            let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
            assert!(
                snapshot["text"].as_str().unwrap().contains(expected)
                    || snapshot["elements"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|e| e["label"] == expected),
                "{label} did not expose {expected}: {snapshot}"
            );
        }
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let month = snapshot["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["role"] == "select" && e["label"] == "Styled month")
            .unwrap();
        browser
            .browse(BrowseRequest::Select {
                element_ref: month["ref"].as_str().unwrap().into(),
                value: "1".into(),
            })
            .await
            .unwrap();
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        assert_eq!(
            snapshot["elements"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["role"] == "select" && e["label"] == "Styled month")
                .unwrap()["value"],
            "1"
        );
        fixture.abort();
    }

    #[tokio::test]
    async fn returning_control_discards_the_merchant_session() {
        let root = tempfile::tempdir().unwrap().keep();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.join("profile"),
            &["--no-sandbox".into()],
        )
        .await
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        // The page shows whatever a previous visit stored, then stores a passenger.
        let fixture = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/", get(|| async { Html(r#"<!doctype html>
              <h1 id="seen"></h1>
              <script>
                seen.textContent = 'stored:' + (localStorage.passenger || '') + '|' + document.cookie;
                localStorage.passenger = 'SyntheticPassenger';
                document.cookie = 'booking=SyntheticBooking; max-age=3600';
              </script>"#) })))
                .await.unwrap();
        });
        let visit = || async {
            browser
                .browse(BrowseRequest::Open { url: url.clone() })
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            browser.browse(BrowseRequest::Snapshot).await.unwrap()["text"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        visit().await;
        // Within one shopping session the merchant keeps its state.
        assert!(visit().await.contains("SyntheticPassenger"));
        browser.handoff().await.unwrap();
        browser.return_control().await.unwrap();
        let after = visit().await;
        assert!(after.contains("stored:|"), "{after}");
        assert!(!after.contains("Synthetic"));
        fixture.abort();
    }

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
                let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                while !tab.cdp.exited() && tokio::time::Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
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
            <input aria-label="Ordinary fixture" value="shown-input-value">
            <input autocomplete="cc-number" value="do-not-project-card-value">
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
        assert!(snapshot.to_string().contains("shown-input-value"));
        assert!(!snapshot.to_string().contains("do-not-project-card-value"));
        let session = browser.tab.lock().await.session.clone();
        let agent = browser
            .cdp
            .evaluate(&session, "navigator.userAgent".into())
            .await
            .unwrap();
        let agent = agent.as_str().unwrap();
        assert!(agent.contains(" HeadlessChrome/"));
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
