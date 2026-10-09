use crate::browser::PrivateTab;
use anyhow::{Context, Result, bail};
use bloom_signer_api::CheckoutFacts;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct CardInput {
    number: String,
    expiry_month: u8,
    expiry_year: u16,
    name: String,
    cvc: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct Field {
    pub kind: String,
    pub index: usize,
}
pub(crate) struct Frame {
    pub session: String,
    pub world: i64,
    pub origin: String,
    pub fields: Vec<Field>,
}
pub(crate) struct Discovery {
    pub facts: CheckoutFacts,
    pub frames: Vec<Frame>,
    pub main_world: i64,
}

async fn evaluate(
    tab: &PrivateTab,
    session: &str,
    world: i64,
    expression: String,
) -> Result<Value> {
    let response = tab
        .cdp
        .call(
            Some(session),
            "Runtime.evaluate",
            json!({
                "contextId":world,"expression":expression,"returnByValue":true,"awaitPromise":true
            }),
        )
        .await?;
    if response.get("exceptionDetails").is_some() {
        bail!("Payment document changed");
    }
    Ok(response["result"]["value"].clone())
}

fn flatten_frames(tree: &Value, frames: &mut Vec<(String, String)>) {
    if let (Some(id), Some(url)) = (tree["frame"]["id"].as_str(), tree["frame"]["url"].as_str()) {
        frames.push((id.to_owned(), url.to_owned()));
    }
    if let Some(children) = tree["childFrames"].as_array() {
        for child in children {
            flatten_frames(child, frames);
        }
    }
}

impl Discovery {
    pub async fn read(tab: &PrivateTab) -> Result<Self> {
        let tree = tab
            .cdp
            .call(Some(&tab.session), "Page.getFrameTree", json!({}))
            .await?;
        let targets = tab.cdp.call(None, "Target.getTargets", json!({})).await?;
        let mut frame_ids = Vec::new();
        flatten_frames(&tree["frameTree"], &mut frame_ids);
        // Chromium omits out-of-process child frames from the parent's tree.
        // Include only targets whose parent chain belongs to this checkout tab.
        let infos = targets["targetInfos"]
            .as_array()
            .context("Missing browser targets")?;
        loop {
            let before = frame_ids.len();
            for target in infos {
                let Some(id) = target["targetId"].as_str() else {
                    continue;
                };
                let Some(parent) = target["parentId"].as_str() else {
                    continue;
                };
                if target["type"] == "iframe"
                    && !frame_ids.iter().any(|(known, _)| known == id)
                    && frame_ids.iter().any(|(known, _)| known == parent)
                {
                    frame_ids.push((id.into(), target["url"].as_str().unwrap_or("").into()));
                }
            }
            if before == frame_ids.len() {
                break;
            }
        }
        let mut frames = Vec::new();
        let mut main_world = None;
        let mut main_facts = Value::Null;
        for (position, (id, url)) in frame_ids.into_iter().enumerate() {
            let origin = url::Url::parse(&url)?.origin().ascii_serialization();
            let remote = targets["targetInfos"]
                .as_array()
                .context("Missing browser targets")?
                .iter()
                .find(|t| t["targetId"] == id && t["type"] == "iframe");
            let session = if remote.is_some() {
                let result = tab
                    .cdp
                    .call(
                        None,
                        "Target.attachToTarget",
                        json!({"targetId":id,"flatten":true}),
                    )
                    .await?;
                result["sessionId"]
                    .as_str()
                    .context("Missing iframe session")?
                    .to_owned()
            } else {
                tab.session.clone()
            };
            let isolated = tab
                .cdp
                .call(
                    Some(&session),
                    "Page.createIsolatedWorld",
                    json!({
                        "frameId":id,"worldName":"bloom-payment","grantUniveralAccess":false
                    }),
                )
                .await?;
            let world = isolated["executionContextId"]
                .as_i64()
                .context("Missing payment context")?;
            if position == 0 {
                main_world = Some(world);
                main_facts =
                    evaluate(tab, &session, world, include_str!("facts.js").into()).await?;
            }
            let fields = evaluate(tab, &session, world, include_str!("fields.js").into()).await?;
            let fields: Vec<Field> =
                serde_json::from_value(fields).context("Ambiguous payment fields")?;
            if !fields.is_empty() {
                frames.push(Frame {
                    session,
                    world,
                    origin,
                    fields,
                });
            }
        }
        let mut facts: CheckoutFacts =
            serde_json::from_value(main_facts).context("Payment facts require human review")?;
        facts.payment_frame_origins = frames.iter().map(|f| f.origin.clone()).collect();
        facts.payment_frame_origins.sort();
        facts.payment_frame_origins.dedup();
        facts
            .validate()
            .map_err(|_| anyhow::anyhow!("Payment facts require human review"))?;
        let count = |kind: &str| {
            frames
                .iter()
                .flat_map(|f| &f.fields)
                .filter(|f| f.kind == kind)
                .count()
        };
        if count("number") != 1
            || count("cvc") != 1
            || count("name") > 1
            || !((count("expiry") == 1 && count("month") == 0 && count("year") == 0)
                || (count("expiry") == 0 && count("month") == 1 && count("year") == 1))
        {
            bail!("Payment fields require human review");
        }
        Ok(Self {
            facts,
            frames,
            main_world: main_world.context("Missing payment document")?,
        })
    }

    pub async fn recheck(&self, tab: &PrivateTab) -> Result<()> {
        let target = tab
            .cdp
            .call(None, "Target.getTargetInfo", json!({"targetId":tab.target}))
            .await?;
        let url = target["targetInfo"]["url"]
            .as_str()
            .context("Payment tab disappeared")?;
        if url::Url::parse(url)?.origin().ascii_serialization() != self.facts.origin {
            bail!("Payment tab origin changed");
        }
        let mut current: CheckoutFacts = serde_json::from_value(
            evaluate(
                tab,
                &tab.session,
                self.main_world,
                include_str!("facts.js").into(),
            )
            .await?,
        )
        .context("Payment facts changed")?;
        current.payment_frame_origins = self.frames.iter().map(|f| f.origin.clone()).collect();
        current.payment_frame_origins.sort();
        current.payment_frame_origins.dedup();
        if current != self.facts {
            bail!("Payment facts changed");
        }
        for frame in &self.frames {
            let current = evaluate(
                tab,
                &frame.session,
                frame.world,
                "({origin:location.origin,valid:globalThis.__bloomPaymentValid?.()===true})".into(),
            )
            .await?;
            if current["origin"] != frame.origin || current["valid"] != true {
                bail!("Payment targets changed");
            }
        }
        Ok(())
    }

    /// Each completed insertion is tracked; a failed insertion may already have disclosed.
    pub async fn fill(
        &self,
        tab: &PrivateTab,
        card: &CardInput,
        filled: &mut Vec<String>,
    ) -> Result<()> {
        for frame in &self.frames {
            for field in &frame.fields {
                self.recheck(tab).await?;
                let value = zeroize::Zeroizing::new(match field.kind.as_str() {
                    "number" => card.number.clone(),
                    "cvc" => card.cvc.clone(),
                    "name" => card.name.clone(),
                    "expiry" => format!("{:02}/{:02}", card.expiry_month, card.expiry_year % 100),
                    "month" => format!("{:02}", card.expiry_month),
                    "year" => card.expiry_year.to_string(),
                    _ => bail!("Unknown payment field"),
                });
                evaluate(tab,&frame.session,frame.world,format!("(()=>{{if(!__bloomPaymentValid())throw Error('changed');const e=__bloomPaymentNodes[{}];e.focus();e.select();return true}})()",field.index)).await?;
                tab.cdp
                    .call(
                        Some(&frame.session),
                        "Input.insertText",
                        json!({"text":value.as_str()}),
                    )
                    .await?;
                filled.push(field.kind.clone());
            }
        }
        Ok(())
    }

    pub async fn submit(&self, tab: &PrivateTab) -> Result<()> {
        self.recheck(tab).await?;
        let response = evaluate(
            tab,
            &tab.session,
            self.main_world,
            include_str!("submit.js").into(),
        )
        .await?;
        if response != true {
            bail!("Payment needs human submission");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::{BrowseRequest, Browser};
    use axum::{Router, response::Html, routing::get};
    use std::{path::Path, sync::Arc, time::Duration};

    async fn fixture(html: String) -> (String, tokio::task::JoinHandle<()>) {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let config = axum_server::tls_rustls::RustlsConfig::from_pem(
            certificate.cert.pem().into_bytes(),
            certificate.signing_key.serialize_pem().into_bytes(),
        )
        .await
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = Router::new().route(
            "/",
            get(move || {
                let html = html.clone();
                async move { Html(html) }
            }),
        );
        let task = tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, config)
                .unwrap()
                .serve(app.into_make_service())
                .await
                .unwrap();
        });
        (format!("https://localhost:{port}/"), task)
    }
    fn inputs() -> String {
        "<input autocomplete='cc-number'><input autocomplete='cc-exp'><input autocomplete='cc-csc'>"
            .into()
    }
    fn merchant(fields: &str, extra: &str, outcome: &str) -> String {
        format!(
            "<!doctype html><h1>Fixture merchant</h1><div id='total' data-bloom-total-minor='399' data-bloom-currency='USD'>Total USD 3.99</div>{fields}{extra}<button onclick=\"document.body.innerHTML='{outcome}'\">Pay</button>"
        )
    }
    async fn browser() -> Arc<Browser> {
        let root = tempfile::tempdir().unwrap().keep();
        Browser::launch(
            Path::new("/usr/lib/chromium/chromium"),
            &root.join("profile"),
            &["--no-sandbox".into(), "--ignore-certificate-errors".into()],
        )
        .await
        .unwrap()
    }
    async fn open(browser: &Browser, url: String) -> PrivateTab {
        browser.browse(BrowseRequest::Open { url }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        browser.handoff().await.unwrap()
    }
    fn card() -> CardInput {
        CardInput {
            number: "4242424242424242".into(),
            expiry_month: 12,
            expiry_year: 2034,
            name: "Synthetic Card".into(),
            cvc: "937".into(),
        }
    }

    #[tokio::test]
    async fn fixture_plain_installments_confirmation_and_decline() {
        let browser = browser().await;
        for (outcome, expected) in [
            ("Order confirmed. Order ID FIXTURE-01", "paid"),
            ("Your card was declined", "declined"),
        ] {
            let (url,server)=fixture(merchant(&inputs(),"<label>Installments<select name='installments'><option>6 x installments</option></select></label>",outcome)).await;
            let tab = open(&browser, url).await;
            let discovery = Discovery::read(&tab).await.unwrap();
            assert_eq!(discovery.facts.installments, 6);
            assert_eq!(discovery.facts.total_minor, 399);
            discovery.recheck(&tab).await.unwrap();
            let mut filled = Vec::new();
            discovery.fill(&tab, &card(), &mut filled).await.unwrap();
            assert_eq!(filled.len(), 3);
            discovery.submit(&tab).await.unwrap();
            let outcome = tab
                .cdp
                .evaluate(&tab.session, include_str!("outcome.js").into())
                .await
                .unwrap();
            assert_eq!(outcome["state"], expected);
            browser.return_control().await.unwrap();
            server.abort();
        }
    }

    #[tokio::test]
    async fn fixture_cross_origin_secure_fields_and_changed_total() {
        let browser = browser().await;
        let (frame_url, frame_server) = fixture(inputs()).await;
        let frame_url = frame_url.replace("localhost", "127.0.0.1");
        let (url, server) = fixture(merchant(
            &format!("<iframe src='{frame_url}'></iframe>"),
            "",
            "Order confirmed",
        ))
        .await;
        let tab = open(&browser, url).await;
        let discovery = Discovery::read(&tab).await.unwrap();
        assert_eq!(discovery.facts.payment_frame_origins.len(), 1);
        assert!(discovery.facts.payment_frame_origins[0].contains("127.0.0.1"));
        let mut filled = Vec::new();
        discovery.fill(&tab, &card(), &mut filled).await.unwrap();
        assert_eq!(filled.len(), 3);
        tab.cdp
            .evaluate(
                &tab.session,
                "document.getElementById('total').dataset.bloomTotalMinor='799'".into(),
            )
            .await
            .unwrap();
        assert!(discovery.recheck(&tab).await.is_err());
        assert!(discovery.submit(&tab).await.is_err());
        browser.return_control().await.unwrap();
        server.abort();
        frame_server.abort();
    }

    #[tokio::test]
    async fn fixture_hidden_duplicate_and_navigation_fail_closed() {
        let browser = browser().await;
        for extra in [
            "<input autocomplete='cc-number' hidden>",
            "<input autocomplete='cc-number'>",
        ] {
            let (url, server) = fixture(merchant(&inputs(), extra, "Order confirmed")).await;
            let tab = open(&browser, url).await;
            assert!(Discovery::read(&tab).await.is_err());
            browser.return_control().await.unwrap();
            server.abort();
        }
        let fields = inputs().replacen(
            "<input autocomplete='cc-number'>",
            "<input autocomplete='cc-number' oninput=\"location.href='about:blank'\">",
            1,
        );
        let (url, server) = fixture(merchant(&fields, "", "Order confirmed")).await;
        let tab = open(&browser, url).await;
        let discovery = Discovery::read(&tab).await.unwrap();
        let mut filled = Vec::new();
        assert!(discovery.fill(&tab, &card(), &mut filled).await.is_err());
        assert!(filled.len() <= 1);
        browser.return_control().await.unwrap();
        server.abort();
    }
}
