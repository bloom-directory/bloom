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
    owners: Vec<(String, String)>,
}
pub(crate) struct Discovery {
    pub facts: CheckoutFacts,
    pub frames: Vec<Frame>,
    pub main_world: i64,
    pub facts_session: String,
}

/// Card number, expiry and CVC go only into documents a payment provider
/// serves, so a look-alike shop never receives them; other pages fall back to
/// the private view. Origins are taken from each provider's published SDK
/// (checked 2026-10-10). The cardholder name may stay on the merchant page.
const PROVIDER_FIELD_ORIGINS: &[&str] = &[
    "https://js.stripe.com",
    "https://checkout.pci.shopifyinc.com",
    "https://assets.braintreegateway.com",
    "https://checkoutshopper-live.adyen.com",
    "https://checkoutshopper-live-us.adyen.com",
    "https://checkoutshopper-live-au.adyen.com",
    "https://checkoutshopper-live-apse.adyen.com",
    "https://checkoutshopper-live-in.adyen.com",
    "https://checkoutshopper-live.cdn.adyen.com",
    "https://checkoutshopper-live-us.cdn.adyen.com",
    "https://checkoutshopper-live-au.cdn.adyen.com",
    "https://checkoutshopper-live-apse.cdn.adyen.com",
    "https://checkoutshopper-live-in.cdn.adyen.com",
    "https://js.checkout.com",
    "https://web.squarecdn.com",
    "https://api-static.mercadopago.com",
    "https://js.mollie.com",
    "https://www.paypal.com",
    "https://api.recurly.com",
    "https://api.eu.recurly.com",
    "https://js.chargebee.com",
];
/// Provider-hosted checkout pages whose own document holds the card fields.
const PROVIDER_PAGE_ORIGINS: &[&str] = &[
    "https://checkout.stripe.com",
    "https://buy.stripe.com",
    "https://www.paypal.com",
    "https://checkoutshopper-live.adyen.com",
    "https://checkoutshopper-live-us.adyen.com",
    "https://www.mercadopago.com.ar",
    "https://www.mercadopago.com.br",
    "https://www.mercadopago.com.mx",
    "https://www.mercadopago.cl",
    "https://www.mercadopago.com.co",
    "https://www.mercadopago.com.uy",
    "https://www.mercadopago.com.pe",
];

fn provider_hosts_card_fields(frame_origin: &str, top_origin: &str, fixture: bool) -> bool {
    PROVIDER_FIELD_ORIGINS.contains(&frame_origin)
        || (frame_origin == top_origin && PROVIDER_PAGE_ORIGINS.contains(&frame_origin))
        || (fixture
            && url::Url::parse(frame_origin)
                .is_ok_and(|u| matches!(u.host_str(), Some("localhost" | "127.0.0.1"))))
}

/// JPEG of the merchant's checkout page for the approval page, captured before
/// any card field is filled. None when it cannot fit in 1 MiB.
pub(crate) async fn order_preview(tab: &PrivateTab) -> Option<String> {
    use base64::Engine;
    let metrics = tab
        .cdp
        .call(Some(&tab.session), "Page.getLayoutMetrics", json!({}))
        .await
        .ok()?;
    let width = metrics["cssContentSize"]["width"].as_f64()?.min(1280.0);
    let height = metrics["cssContentSize"]["height"].as_f64()?.min(3000.0);
    for (quality, scale) in [(70, 1.0), (45, 0.6)] {
        let shot = tab
            .cdp
            .call(
                Some(&tab.session),
                "Page.captureScreenshot",
                json!({
            "format":"jpeg","quality":quality,"captureBeyondViewport":true,
            "clip":{"x":0,"y":0,"width":width,"height":height,"scale":scale}}),
            )
            .await
            .ok()?;
        let jpeg = base64::engine::general_purpose::STANDARD
            .decode(shot["data"].as_str()?)
            .ok()?;
        if jpeg.len() <= 1 << 20 {
            return Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(jpeg));
        }
    }
    None
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

async fn check_frame_owners(tab: &PrivateTab, owners: &[(String, String)]) -> Result<()> {
    for (session, object) in owners {
        let response=tab.cdp.call(Some(session),"Runtime.callFunctionOn",json!({"objectId":object,"returnByValue":true,"functionDeclaration":"function(){if(!this.isConnected || !this.getClientRects().length)return false;for(let n=this;n;n=n.parentElement){const s=getComputedStyle(n);if(s.visibility!=='visible'||s.display==='none'||Number(s.opacity)===0)return false;}return true;}"})).await?;
        if response["result"]["value"] != true {
            bail!("Receiving iframe is hidden or replaced");
        }
    }
    Ok(())
}

impl Discovery {
    pub async fn read(tab: &PrivateTab) -> Result<Self> {
        let mut last_error = None;
        for _ in 0..3 {
            match Self::read_once(tab).await {
                Ok(discovery) => return Ok(discovery),
                Err(error) => last_error = Some(error),
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        Err(last_error.unwrap())
    }

    async fn read_once(tab: &PrivateTab) -> Result<Self> {
        let contexts = tab.cdp.contexts(&tab.session, "bloom-payment").await?;
        let mut frames = Vec::new();
        let mut candidates = Vec::new();
        let mut top_origin = None;
        for (position, context) in contexts.iter().enumerate() {
            let url = &context.url;
            let origin = url::Url::parse(url)?.origin().ascii_serialization();
            let session = context.session.clone();
            let world = context.world;
            if position == 0 {
                top_origin = Some(origin.clone());
                if origin == "https://buy.stripe.com" {
                    let facts = tab
                        .cdp
                        .hosted_stripe_facts(&session, &context.frame_id, url)
                        .await?;
                    evaluate(tab,&session,world,format!("(()=>{{const facts={facts};if(globalThis.__bloomHostedStripeFacts){{if(JSON.stringify(globalThis.__bloomHostedStripeFacts)!==JSON.stringify(facts))throw Error('Facts changed');}}else Object.defineProperty(globalThis,'__bloomHostedStripeFacts',{{value:Object.freeze(facts),writable:false,configurable:false}});return true;}})()")).await?;
                }
            }
            if position == 0
                || (origin == "https://js.stripe.com"
                    && url::Url::parse(url)?.path() == "/v3/embedded-checkout-inner.html")
            {
                let candidate =
                    evaluate(tab, &session, world, include_str!("facts.js").into()).await?;
                if let Ok(facts) = serde_json::from_value::<CheckoutFacts>(candidate) {
                    candidates.push((session.clone(), world, facts));
                }
            }
            let fields = evaluate(tab, &session, world, include_str!("fields.js").into()).await?;
            let fields: Vec<Field> =
                serde_json::from_value(fields).context("Ambiguous payment fields")?;
            if !fields.is_empty() {
                let mut owners = Vec::new();
                let mut child = context;
                while let Some(parent_id) = &child.parent_id {
                    let parent = contexts
                        .iter()
                        .find(|c| &c.frame_id == parent_id)
                        .context("Unbound payment frame parent")?;
                    let owner = tab
                        .cdp
                        .call(
                            Some(&parent.session),
                            "DOM.getFrameOwner",
                            json!({"frameId":child.frame_id}),
                        )
                        .await?;
                    let node=tab.cdp.call(Some(&parent.session),"DOM.resolveNode",json!({"backendNodeId":owner["backendNodeId"],"executionContextId":parent.world})).await?;
                    let object = node["object"]["objectId"]
                        .as_str()
                        .context("Unbound receiving iframe")?
                        .to_owned();
                    owners.push((parent.session.clone(), object));
                    child = parent;
                }
                check_frame_owners(tab, &owners).await?;
                frames.push(Frame {
                    session,
                    world,
                    origin,
                    fields,
                    owners,
                });
            }
        }
        if candidates.len() != 1 {
            bail!("Payment facts require human review");
        }
        let (facts_session, main_world, mut facts) = candidates.remove(0);
        facts.origin = top_origin.context("Missing merchant origin")?;
        if frames.iter().any(|frame| {
            frame.fields.iter().any(|field| field.kind != "name")
                && !provider_hosts_card_fields(
                    &frame.origin,
                    &facts.origin,
                    tab.fixture_payment_hosts,
                )
        }) {
            bail!("Card fields are not hosted by a known payment provider");
        }
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
            main_world,
            facts_session,
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
                &self.facts_session,
                self.main_world,
                include_str!("facts.js").into(),
            )
            .await?,
        )
        .context("Payment facts changed")?;
        current.origin = self.facts.origin.clone();
        current.payment_frame_origins = self.frames.iter().map(|f| f.origin.clone()).collect();
        current.payment_frame_origins.sort();
        current.payment_frame_origins.dedup();
        if current != self.facts {
            bail!("Payment facts changed");
        }
        for frame in &self.frames {
            check_frame_owners(tab, &frame.owners).await?;
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
        self.recheck(tab).await?;
        for frame in &self.frames {
            for field in &frame.fields {
                let value = zeroize::Zeroizing::new(match field.kind.as_str() {
                    "number" => card.number.clone(),
                    "cvc" => card.cvc.clone(),
                    "name" => card.name.clone(),
                    "expiry" => format!("{:02}/{:02}", card.expiry_month, card.expiry_year % 100),
                    "month" => format!("{:02}", card.expiry_month),
                    "year" => card.expiry_year.to_string(),
                    _ => bail!("Unknown payment field"),
                });
                // One renderer call binds the insertion to the approved document.
                // A focus-driven navigation cannot redirect a later Input.insertText.
                let expression = zeroize::Zeroizing::new(format!(
                    r#"(()=>{{
                    if(location.origin!=={origin}||!__bloomPaymentValid())throw Error('changed');
                    const e=__bloomPaymentNodes[{index}],value={value};
                    e.focus();if(!e.isConnected||!__bloomPaymentValid())throw Error('changed');
                    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,value);
                    e.dispatchEvent(new Event('input',{{bubbles:true}}));
                    e.dispatchEvent(new Event('change',{{bubbles:true}}));return true;
                }})()"#,
                    origin = serde_json::to_string(&frame.origin)?,
                    index = field.index,
                    value = serde_json::to_string(value.as_str())?
                ));
                evaluate(tab, &frame.session, frame.world, expression.to_string()).await?;
                filled.push(field.kind.clone());
            }
        }
        Ok(())
    }

    pub async fn submit(&self, tab: &PrivateTab) -> Result<()> {
        self.recheck(tab).await?;
        let response = evaluate(
            tab,
            &self.facts_session,
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
    use std::{sync::Arc, time::Duration};

    #[tokio::test]
    #[ignore = "real public hosted Stripe sandbox discovery; requires network"]
    async fn stripe_hosted_public_sandbox_discovery() {
        let browser = browser().await;
        browser
            .browse(BrowseRequest::Open {
                url: "https://buy.stripe.com/test_28o7u4eQMcaUgWk8ww".into(),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(8)).await;
        let mut tab = browser.handoff().await.unwrap();
        tab.fixture_payment_hosts = false; // Real provider pages need no fixture trust.
        let discovery = Discovery::read(&tab).await.unwrap();
        assert_eq!(discovery.facts.currency, "USD");
        assert_eq!(discovery.facts.total_minor, 2000);
        assert!(discovery.facts.recurring);
        discovery.recheck(&tab).await.unwrap();
        browser.return_control().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "real hosted Stripe test payments, no money; requires network"]
    async fn stripe_hosted_public_sandbox_payments() {
        for (case, (number, bank_action, expected)) in [
            ("4242424242424242", None, "paid"),
            ("4000000000000002", None, "declined"),
            ("4000000000003220", Some("complete"), "paid"),
            ("4000002760003184", Some("fail"), "declined"),
        ]
        .into_iter()
        .enumerate()
        {
            if std::env::var("BLOOM_CHECKOUT_TEST_CASE")
                .ok()
                .is_some_and(|v| v != case.to_string())
            {
                continue;
            }
            let browser = browser().await;
            browser
                .browse(BrowseRequest::Open {
                    url: "https://buy.stripe.com/test_28o7u4eQMcaUgWk8ww".into(),
                })
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
            let mut tab = browser.handoff().await.unwrap();
            tab.fixture_payment_hosts = false; // Real provider pages need no fixture trust.
            let tree = tab
                .cdp
                .call(Some(&tab.session), "Page.getFrameTree", json!({}))
                .await
                .unwrap();
            let facts = tab
                .cdp
                .hosted_stripe_facts(
                    &tab.session,
                    tree["frameTree"]["frame"]["id"].as_str().unwrap(),
                    "https://buy.stripe.com/test_28o7u4eQMcaUgWk8ww",
                )
                .await
                .unwrap();
            assert_eq!(
                facts["livemode"], false,
                "Never fill or submit a live checkout in this test"
            );
            // Synthetic non-card billing fields through the private test driver.
            tab.cdp.evaluate(&tab.session,r#"(()=>{
                const set=(selector,value)=>{const e=document.querySelector(selector);if(!e)throw Error('Missing fixture field');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,value);e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));};
                set('input[name=email]','fixture-buyer@example.com');
                set('input[name=billingPostalCode]','12345');
                const save=document.querySelector('input[type=checkbox]');if(save?.checked)save.click();return true;
            })()"#.into()).await.unwrap();
            let discovery = Discovery::read(&tab).await.unwrap();
            let mut test_card = card();
            test_card.number = number.into();
            discovery
                .fill(&tab, &test_card, &mut Vec::new())
                .await
                .unwrap();
            discovery.submit(&tab).await.unwrap();
            let mut confirmed = false;
            let mut bank_handled = false;
            for attempt in 0..60 {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if let Some(action) = bank_action {
                    if !bank_handled {
                        for frame in tab
                            .cdp
                            .contexts(&tab.session, "bloom-test-bank")
                            .await
                            .unwrap_or_default()
                        {
                            if !url::Url::parse(&frame.url).is_ok_and(|url| {
                                url.host_str()
                                    .is_some_and(|host| host.ends_with(".stripe.com"))
                            }) {
                                continue;
                            }
                            let expression = format!(
                                "(()=>{{const b=[...document.querySelectorAll('button,input[type=submit]')].find(e=>/^{action}|^{alternate}/i.test((e.innerText||e.value).trim()));if(!b)return false;b.click();return true;}})()",
                                alternate = if action == "complete" {
                                    "authorize"
                                } else {
                                    "fail"
                                }
                            );
                            if evaluate(&tab, &frame.session, frame.world, expression)
                                .await
                                .is_ok_and(|v| v == true)
                            {
                                bank_handled = true;
                            }
                        }
                    }
                }
                let Ok(result) = tab
                    .cdp
                    .evaluate(&tab.session, include_str!("outcome.js").into())
                    .await
                else {
                    continue;
                };
                if result["state"] == expected {
                    confirmed = true;
                    break;
                }
                if attempt == 15 || attempt == 59 {
                    // Fixed diagnostic flags, never field values or response bodies.
                    let diagnostic = tab
                        .cdp
                        .evaluate(&tab.session, "({subscriptionConfirmed:/Thanks for subscribing/.test(document.body.innerText),authenticationFailed:/We are unable to authenticate your payment method/.test(document.body.innerText),cardDeclined:/card.*declined/i.test(document.body.innerText)})".into())
                        .await
                        .unwrap_or(Value::Null);
                    eprintln!("Hosted fixture case {case}: {diagnostic}");
                }
            }
            browser.return_control().await.unwrap();
            assert!(
                confirmed,
                "Hosted Stripe case {case}, bank handled {bank_handled}"
            );
            assert_eq!(bank_handled, bank_action.is_some());
            eprintln!("Hosted Stripe case {case}: {expected}, bank interaction {bank_handled}");
        }
    }

    #[tokio::test]
    #[ignore = "real Shopify checkout discovery, no card or purchase; requires network"]
    async fn shopify_public_checkout_discovery() {
        let browser = browser().await;
        browser
            .browse(BrowseRequest::Open {
                url: "https://shop.simplyonpurpose.org/products/story-starters".into(),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(12)).await;
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let button = snapshot["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|element| {
                element["label"]
                    .as_str()
                    .is_some_and(|label| label.eq_ignore_ascii_case("Add to Cart"))
            })
            .unwrap();
        browser
            .browse(BrowseRequest::Click {
                element_ref: button["ref"].as_str().unwrap().into(),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        browser
            .browse(BrowseRequest::Open {
                url: "https://shop.simplyonpurpose.org/cart".into(),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let button = snapshot["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|element| element["label"] == "Checkout")
            .unwrap();
        browser
            .browse(BrowseRequest::Click {
                element_ref: button["ref"].as_str().unwrap().into(),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
        let mut tab = browser.handoff().await.unwrap();
        tab.fixture_payment_hosts = false; // Real provider pages need no fixture trust.
        let discovery = Discovery::read(&tab).await.unwrap();
        assert_eq!(discovery.facts.currency, "USD");
        assert!((100..=200).contains(&discovery.facts.total_minor));
        assert_eq!(discovery.facts.installments, 1);
        discovery.recheck(&tab).await.unwrap();
        browser.return_control().await.unwrap();
    }

    async fn fixture(html: String) -> (String, tokio::task::JoinHandle<()>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
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
            &crate::test_chromium(),
            &root.join("profile"),
            &["--no-sandbox".into(), "--ignore-certificate-errors".into()],
        )
        .await
        .unwrap()
    }
    async fn open(browser: &Browser, url: String) -> PrivateTab {
        browser.browse(BrowseRequest::Open { url }).await.unwrap();
        let tab = browser.handoff().await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tab
            .cdp
            .evaluate(&tab.session, "document.readyState".into())
            .await
            .unwrap()
            == "loading"
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "page was not parsed"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tab
    }
    async fn initialized_processor(tab: &PrivateTab) -> Discovery {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            match Discovery::read(tab).await {
                Ok(discovery) => return discovery,
                Err(error) if tokio::time::Instant::now() >= deadline => {
                    panic!("Processor did not initialize: {error}")
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        }
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
    #[ignore = "real Stripe public test checkout; requires network"]
    async fn stripe_elements_public_backend_test_purchase() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap();
        let base = "https://stripe-payments-demo.appspot.com";
        let config: Value = client
            .get(format!("{base}/config"))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let key = config["stripePublishableKey"].as_str().unwrap();
        assert!(
            key.starts_with("pk_test_"),
            "Only a public test-mode demo may back this fixture"
        );
        let products: Value = client
            .get(format!("{base}/products"))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let sku = &products["data"][0]["skus"]["data"][0];
        for (case, (number, bank_action, expected)) in [
            ("4242424242424242", None, "paid"),
            ("4000000000000002", None, "declined"),
            ("4000000000003220", Some("complete"), "paid"),
            ("4000002760003184", Some("fail"), "declined"),
        ]
        .into_iter()
        .enumerate()
        {
            if std::env::var("BLOOM_CHECKOUT_TEST_CASE")
                .ok()
                .is_some_and(|value| value != case.to_string())
            {
                continue;
            }
            let response: Value = client.post(format!("{base}/payment_intents"))
            .json(&json!({"currency":config["currency"],"items":[{"type":"sku","parent":sku["id"],"quantity":1}]}))
            .send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
            let intent = &response["paymentIntent"];
            assert_eq!(intent["livemode"], false);
            let amount = intent["amount"].as_u64().unwrap();
            let currency = intent["currency"].as_str().unwrap().to_uppercase();
            let secret = intent["client_secret"]
                .as_str()
                .expect("Public demo must return its test client secret");
            // No account, secret API key, or production checkout. The public demo's
            // documented backend creates this test intent for its existing sample SKU.
            let html = format!(
                r#"<!doctype html><h1>Stripe test fixture</h1>
          <div data-bloom-total-minor='{amount}' data-bloom-currency='{currency}'>Total {currency} {major}.{minor:02}</div>
          <form><div id='card'></div><button type='submit'>Pay</button></form>
          <script src='https://js.stripe.com/v3/'></script><script>
          const stripe=Stripe({key}),element=stripe.elements().create('card',{{hidePostalCode:true}});element.mount('#card');
          document.querySelector('form').onsubmit=async event=>{{event.preventDefault();
            const result=await stripe.confirmCardPayment({secret},{{payment_method:{{card:element,billing_details:{{name:'Fixture Buyer'}}}}}});
            globalThis.__fixtureDiagnostic={{error_code:['card_declined','payment_intent_authentication_failure','incomplete_number','incomplete_expiry','incomplete_cvc','invalid_request_error'].includes(result.error?.code)?result.error.code:result.error?'other':null,status:result.paymentIntent?.status==='succeeded'?'succeeded':'other'}};
            document.body.innerText=result.error?['card_declined','payment_intent_authentication_failure'].includes(result.error.code)?'Payment failed':'Test input rejected':result.paymentIntent.status==='succeeded'?'Payment successful':'Payment outcome uncertain';
          }};</script>"#,
                major = amount / 100,
                minor = amount % 100,
                key = serde_json::to_string(key).unwrap(),
                secret = serde_json::to_string(secret).unwrap()
            );
            let (url, server) = fixture(html).await;
            let browser = browser().await;
            let tab = open(&browser, url).await;
            tokio::time::sleep(Duration::from_secs(8)).await;
            let discovery = initialized_processor(&tab).await;
            let mut filled = Vec::new();
            let mut test_card = card();
            test_card.number = number.into();
            discovery.fill(&tab, &test_card, &mut filled).await.unwrap();
            discovery.submit(&tab).await.unwrap();
            let mut confirmed = false;
            let mut bank_handled = false;
            for attempt in 0..60 {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if let Some(action) = bank_action {
                    if !bank_handled {
                        for frame in tab
                            .cdp
                            .contexts(&tab.session, "bloom-test-bank")
                            .await
                            .unwrap_or_default()
                        {
                            let origin = url::Url::parse(&frame.url)
                                .unwrap()
                                .origin()
                                .ascii_serialization();
                            if !origin.ends_with(".stripe.com") {
                                continue;
                            }
                            if attempt == 5 {
                                let diagnostic = evaluate(&tab, &frame.session, frame.world, "({buttons:document.querySelectorAll('button,input[type=submit]').length,iframes:document.querySelectorAll('iframe').length,complete:[...document.querySelectorAll('button,input[type=submit]')].some(e=>/complete|authorize/i.test(e.innerText||e.value)),fail:[...document.querySelectorAll('button,input[type=submit]')].some(e=>/fail/i.test(e.innerText||e.value))})".into()).await.unwrap();
                                eprintln!("Bank frame {origin}: {diagnostic}");
                            }
                            let expression = format!(
                                r#"(()=>{{
                          const button=[...document.querySelectorAll('button,input[type=submit]')].find(e=>/^{action}|^{alternate}/i.test((e.innerText||e.value).trim()));
                          if(!button)return false;button.click();return true;
                        }})()"#,
                                alternate = if action == "complete" {
                                    "authorize"
                                } else {
                                    "fail"
                                }
                            );
                            if evaluate(&tab, &frame.session, frame.world, expression)
                                .await
                                .is_ok_and(|value| value == true)
                            {
                                bank_handled = true;
                            }
                        }
                    }
                }
                let Ok(result) = tab
                    .cdp
                    .evaluate(&tab.session, include_str!("outcome.js").into())
                    .await
                else {
                    continue;
                };
                if result["state"] == expected {
                    confirmed = true;
                    break;
                }
            }
            let diagnostic = tab
                .cdp
                .evaluate(
                    &tab.session,
                    "globalThis.__fixtureDiagnostic || null".into(),
                )
                .await
                .unwrap_or(Value::Null);
            browser.return_control().await.unwrap();
            server.abort();
            assert!(
                confirmed,
                "Stripe fixture case {case}, bank handled {bank_handled}, diagnostic {diagnostic}"
            );
            assert_eq!(bank_handled, bank_action.is_some());
            eprintln!("Stripe fixture case {case}: {expected}, bank interaction {bank_handled}");
        }
    }

    #[tokio::test]
    #[ignore = "real Stripe public test checkout; requires network"]
    async fn stripe_public_demo_reads_real_fields_and_processor_facts() {
        let browser = browser().await;
        browser
            .browse(BrowseRequest::Open {
                url: "https://checkout.stripe.dev/checkout".into(),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(12)).await;
        let mut tab = browser.handoff().await.unwrap();
        tab.fixture_payment_hosts = false; // Real provider pages need no fixture trust.
        let discovery = Discovery::read(&tab).await.unwrap();
        assert_eq!(discovery.facts.currency, "USD");
        assert!(discovery.facts.total_minor > 0);
        assert_eq!(discovery.facts.origin, "https://checkout.stripe.dev");
        assert!(
            discovery
                .frames
                .iter()
                .any(|f| f.origin == "https://js.stripe.com")
        );
        discovery.recheck(&tab).await.unwrap();
        browser.return_control().await.unwrap();
    }

    #[tokio::test]
    async fn fixture_shopify_proxy_fields_are_narrow_and_rechecked() {
        let html = "<!doctype html><style>input{width:200px;height:40px}.proxy{position:absolute;left:-2px;width:2px;height:2px;border:0;padding:0}</style><input id=number autocomplete=cc-number><input id=name class=proxy autocomplete=cc-name><input id=expiry class=proxy autocomplete=cc-exp><input id=verification_value class=proxy autocomplete=cc-csc>";
        let (url, server) = fixture(html.into()).await;
        let browser = browser().await;
        let tab = open(&browser, url).await;
        // An ordinary merchant cannot opt into the PCI exception by copying ids.
        assert!(
            tab.cdp
                .evaluate(&tab.session, include_str!("fields.js").into())
                .await
                .unwrap()
                .is_null()
        );
        let expression=include_str!("fields.js").replacen("(() => {", "(() => { const location={origin:'https://checkout.pci.shopifyinc.com',pathname:'/build/09497de/number-ltr.html'};",1);
        let fields = tab.cdp.evaluate(&tab.session, expression).await.unwrap();
        assert_eq!(fields, json!([{"kind":"number","index":0}]));
        assert_eq!(
            tab.cdp
                .evaluate(&tab.session, "__bloomPaymentValid()".into())
                .await
                .unwrap(),
            true
        );
        tab.cdp
            .evaluate(
                &tab.session,
                "document.querySelector('#name').className='';true".into(),
            )
            .await
            .unwrap();
        assert_eq!(
            tab.cdp
                .evaluate(&tab.session, "!!__bloomPaymentValid()".into())
                .await
                .unwrap(),
            false
        );
        browser.return_control().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn fixture_total_currency_amount_on_separate_lines() {
        let browser = browser().await;
        let (url, server) = fixture(format!(
            "<!doctype html><p>Total</p><p>USD</p><p>$1.00</p>{}<button>Buy Now</button>",
            inputs()
        ))
        .await;
        let tab = open(&browser, url).await;
        let discovery = Discovery::read(&tab).await.unwrap();
        assert_eq!(discovery.facts.total_minor, 100);
        assert_eq!(discovery.facts.currency, "USD");
        browser.return_control().await.unwrap();
        server.abort();
    }

    /// Lines and buttons as captured from live checkouts on 2026-10-10
    /// (Shopify de-CH, fr-CH, es-ES, pt-BR, en-US), plus formats used in
    /// Argentina, Chile, Switzerland and the UK, and cases that stay manual.
    #[tokio::test]
    async fn fixture_totals_in_european_and_american_formats() {
        let browser = browser().await;
        let lines = |lang: &str, head: &str, lines: &[&str], button: &str| {
            let body: String = lines.iter().map(|l| format!("<div>{l}</div>")).collect();
            format!(
                "<!doctype html><html lang='{lang}'><head>{head}</head><body>{body}{}<button>{button}</button></body></html>",
                inputs()
            )
        };
        let cases = [
            (
                lines(
                    "de-CH",
                    "",
                    &[
                        "Zwischensumme",
                        "CHF\u{a0}39.90",
                        "Versand",
                        "Lieferadresse eingeben",
                        "Gesamt",
                        "CHF\u{a0}39.90",
                        "inkl. CHF\u{a0}2.99 MwSt",
                    ],
                    "Jetzt kaufen",
                ),
                Some((3990, "CHF")),
            ),
            (
                lines(
                    "fr-CH",
                    "",
                    &[
                        "Sous-total",
                        "39.90\u{a0}CHF",
                        "Total",
                        "39.90 CHF",
                        "Taxes de 2.99 CHF incluses",
                    ],
                    "Payer maintenant",
                ),
                Some((3990, "CHF")),
            ),
            (
                lines(
                    "es-ES",
                    "",
                    &[
                        "Subtotal",
                        "14,90\u{a0}€",
                        "Total",
                        "EUR",
                        "14,90\u{a0}€",
                        "Incluye 2,59\u{a0}€ de impuestos",
                    ],
                    "Pagar ahora",
                ),
                Some((1490, "EUR")),
            ),
            (
                lines(
                    "pt-BR",
                    "",
                    &["Total", "BRL", "R$\u{a0}359,00"],
                    "Pagar agora",
                ),
                Some((35900, "BRL")),
            ),
            (
                lines(
                    "en-US",
                    "",
                    &["Subtotal", "$48.00", "Total", "USD", "$48.00"],
                    "Pay now",
                ),
                Some((4800, "USD")),
            ),
            (
                lines("es-AR", "", &["Total", "$ 12.345,67"], "Pagar"),
                Some((1234567, "ARS")),
            ),
            (
                lines("es-CL", "", &["Total: $12.990"], "Pagar"),
                Some((12990, "CLP")),
            ),
            (
                lines(
                    "de-CH",
                    "",
                    &["Total CHF 1'234.50"],
                    "Zahlungspflichtig bestellen",
                ),
                Some((123450, "CHF")),
            ),
            (
                lines("en-GB", "", &["Order total £4.99"], "Place order"),
                Some((499, "GBP")),
            ),
            (
                lines(
                    "en",
                    "<script type='application/ld+json'>{\"offers\":{\"priceCurrency\":\"USD\"}}</script>",
                    &["Total $10.00"],
                    "Place order",
                ),
                Some((1000, "USD")),
            ),
            (
                lines(
                    "en",
                    "",
                    &["Total savings $5.00", "Total USD $10.00"],
                    "Pay",
                ),
                Some((1000, "USD")),
            ),
            // Decimal commas are unambiguous: grouping always has three digits.
            (
                lines("pt-BR", "", &["Total BRL 57,00"], "Pay"),
                Some((5700, "BRL")),
            ),
            // A bare dollar with no declared currency or page region is unknown.
            (lines("en", "", &["Total $10.00"], "Pay"), None),
            // Three-decimal currencies make "1.234" ambiguous.
            (lines("ar-KW", "", &["Total KWD 1.234"], "Pay"), None),
            (lines("en", "", &["Total EUR $5.00"], "Pay"), None),
            (
                lines("en", "", &["Total USD 10.00", "Total USD 12.00"], "Pay"),
                None,
            ),
            // An ambiguous continue button is not the final payment button.
            (
                lines("it", "", &["Totale", "USD", "90,00\u{a0}$"], "PROCEDI"),
                None,
            ),
        ];
        for (html, expected) in cases {
            let (url, server) = fixture(html.clone()).await;
            let tab = open(&browser, url).await;
            let found = Discovery::read(&tab)
                .await
                .ok()
                .map(|d| (d.facts.total_minor, d.facts.currency.clone()));
            assert_eq!(
                found,
                expected.map(|(total, currency)| (total, currency.to_owned())),
                "{html}"
            );
            browser.return_control().await.unwrap();
            server.abort();
        }
    }

    #[tokio::test]
    async fn fixture_card_fields_outside_payment_providers_require_manual() {
        assert!(provider_hosts_card_fields(
            "https://js.stripe.com",
            "https://shop.example",
            false
        ));
        assert!(provider_hosts_card_fields(
            "https://checkout.stripe.com",
            "https://checkout.stripe.com",
            false
        ));
        assert!(!provider_hosts_card_fields(
            "https://checkout.stripe.com",
            "https://shop.example",
            false
        ));
        assert!(!provider_hosts_card_fields(
            "https://shop.example",
            "https://shop.example",
            false
        ));
        assert!(!provider_hosts_card_fields(
            "https://js.stripe.com.evil.example",
            "https://shop.example",
            false
        ));
        let browser = browser().await;
        let (url, server) = fixture(merchant(&inputs(), "", "Order confirmed")).await;
        let mut tab = open(&browser, url).await;
        assert!(Discovery::read(&tab).await.is_ok());
        tab.fixture_payment_hosts = false;
        let error = Discovery::read(&tab).await.err().unwrap();
        assert!(
            error.to_string().contains("known payment provider"),
            "{error}"
        );
        browser.return_control().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn fixture_plain_installments_confirmation_and_decline() {
        let browser = browser().await;
        for (outcome, expected) in [
            (
                "Order confirmed. Order ID FIXTURE-01 Total USD 3.99",
                "paid",
            ),
            ("Your card was declined", "declined"),
            (
                "Thank you, Kyle! Your order is confirmed. Confirmation #FIX01 Total USD 3.99",
                "paid",
            ),
            (
                "Your payment details couldn’t be verified. Check your card details and try again.",
                "declined",
            ),
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
            if expected == "paid" {
                assert_eq!(outcome["merchant_reported_total_minor"], 399);
                assert_eq!(outcome["currency"], "USD");
            }
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
        // The approval screenshot must not disturb the bound payment frames.
        use base64::Engine;
        let preview = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(order_preview(&tab).await.unwrap())
            .unwrap();
        assert!(preview.starts_with(&[0xff, 0xd8, 0xff]) && preview.len() <= 1 << 20);
        discovery.recheck(&tab).await.unwrap();
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
    async fn fixture_hidden_payment_frame_and_replaced_owner_fail_closed() {
        let browser = browser().await;
        let (frame_url, frame_server) = fixture(inputs()).await;
        let frame_url = frame_url.replace("localhost", "127.0.0.1");
        for style in ["display:none", "opacity:0", "visibility:hidden"] {
            let (url, server) = fixture(merchant(
                &format!("<div style='{style}'><iframe src='{frame_url}'></iframe></div>"),
                "",
                "Order confirmed",
            ))
            .await;
            let tab = open(&browser, url).await;
            assert!(Discovery::read(&tab).await.is_err());
            browser.return_control().await.unwrap();
            server.abort();
        }
        let (url, server) = fixture(merchant(
            &format!("<iframe src='{frame_url}'></iframe>"),
            "",
            "Order confirmed",
        ))
        .await;
        let tab = open(&browser, url).await;
        let discovery = Discovery::read(&tab).await.unwrap();
        tab.cdp
            .evaluate(
                &tab.session,
                "const f=document.querySelector('iframe');f.replaceWith(f.cloneNode(true))".into(),
            )
            .await
            .unwrap();
        assert!(discovery.recheck(&tab).await.is_err());
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
