use crate::browser::PrivateTab;
use crate::cdp::Cdp;
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
#[derive(Clone)]
pub(crate) struct Frame {
    pub session: String,
    pub world: i64,
    pub origin: String,
    pub fields: Vec<Field>,
    owners: Vec<(String, String)>,
}
#[derive(Clone)]
pub(crate) struct Discovery {
    pub facts: CheckoutFacts,
    pub frames: Vec<Frame>,
    pub main_world: i64,
    pub facts_session: String,
}

/// Card number, expiry and CVC go into documents a payment provider serves,
/// or into the approved merchant's own HTTPS page; other frames fall back to
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
    // Booking.com's own payment component (seen on its final page 2026-10-11).
    "https://paymentcomponent.booking.com",
    // Yuno secure fields (JetSMART's payment page, SDK checked 2026-10-14).
    "https://sdk-web-card.prod.y.uno",
    // Etraveli secure fields observed on Gotogate's final payment page 2026-10-24.
    "https://frontend-payments.payment-prod.etraveligroup.net",
    // Jetabroad number/CVC frames, observed 2026-10-24; Spreedly's documented iframe SDK origin.
    "https://core.spreedly.com",
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
/// Merchants that collect the card on their own checkout page, checked by
/// hand. The approval names the origin the card is entered on.
const MERCHANT_CARD_ORIGINS: &[&str] = &[
    // Aerolíneas Argentinas' inline card form (card research 2026-10-13).
    "https://www.aerolineas.com.ar",
    // Jetabroad Singapore keeps expiry on its own reviewed payment page.
    "https://www.jetabroad.com.sg",
    // Frontier's inline card fields on its final payment page, observed 2026-10-24.
    "https://booking.flyfrontier.com",
    // Jettzy Hong Kong's inline card form, observed on Cathay Pacific review 2026-10-25.
    "https://en.jettzy.com.hk",
    // Same inline form on the Malaysia site, observed on AirAsia review 2026-10-25.
    "https://www.jettzy.com.my",
];

/// Test browsers may read fixture merchants' declared totals; release builds never.
fn fixture_totals(tab: &PrivateTab) -> bool {
    #[cfg(test)]
    return tab.fixture_payment_hosts;
    #[cfg(not(test))]
    {
        let _ = tab;
        false
    }
}

fn provider_hosts_card_fields(frame_origin: &str, top_origin: &str, fixture: bool) -> bool {
    let known = PROVIDER_FIELD_ORIGINS.contains(&frame_origin)
        || (frame_origin == top_origin
            && (PROVIDER_PAGE_ORIGINS.contains(&frame_origin)
                || MERCHANT_CARD_ORIGINS.contains(&frame_origin)));
    // Local fixture merchants are a test seam. Release builds never treat
    // localhost as a payment provider.
    #[cfg(test)]
    let fixture_host = fixture
        && url::Url::parse(frame_origin)
            .is_ok_and(|u| matches!(u.host_str(), Some("localhost" | "127.0.0.1")));
    #[cfg(not(test))]
    let fixture_host = {
        let _ = fixture;
        false
    };
    known || fixture_host
}

/// Read the already-received Stripe bootstrap, never initialize a second
/// Checkout Session. Bind it to this exact frame and document loader.
pub(crate) async fn hosted_stripe_facts(
    cdp: &Cdp,
    session: &str,
    frame: &str,
    url: &str,
) -> Result<Value> {
    let url = url::Url::parse(url)?;
    if url.origin().ascii_serialization() != "https://buy.stripe.com" {
        bail!("Not a Stripe Payment Link");
    }
    let link = url.path().trim_start_matches('/');
    let tree = cdp
        .call(Some(session), "Page.getFrameTree", json!({}))
        .await?;
    let loader = tree["frameTree"]["frame"]["loaderId"]
        .as_str()
        .context("Missing checkout document identity")?;
    let request = cdp
        .processor_responses
        .lock()
        .iter()
        .rev()
        .find(|response| {
            response.session == session
                && response.frame == frame
                && response.loader == loader
                && response.link == link
        })
        .map(|response| response.request.clone())
        .context("Missing current Stripe bootstrap")?;
    let response = cdp
        .call(
            Some(session),
            "Network.getResponseBody",
            json!({"requestId":request}),
        )
        .await?;
    if response["base64Encoded"] == true {
        bail!("Unsupported Stripe bootstrap encoding");
    }
    let page: Value = serde_json::from_str(
        response["body"]
            .as_str()
            .context("Missing Stripe bootstrap body")?,
    )?;
    if !matches!(page["mode"].as_str(), Some("payment" | "subscription"))
        || !page["session_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("cs_"))
    {
        bail!("Unbound Stripe checkout facts");
    }
    Ok(
        json!({"total_minor":page["total_summary"]["due"],"currency":page["currency"].as_str().map(str::to_uppercase),"recurring":page["mode"]=="subscription","livemode":page["livemode"]}),
    )
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
    let height = metrics["cssContentSize"]["height"].as_f64()?;
    // Show the human what was entered: the part of the page holding the
    // filled fields (names, contact, card holder), not the page top.
    let filled = tab
        .cdp
        .call(
            Some(&tab.session),
            "Runtime.evaluate",
            json!({"expression":include_str!("filled-region.js"),"returnByValue":true}),
        )
        .await
        .ok()
        .map(|r| r["result"]["value"].clone())
        .filter(|r| r["height"].as_f64().is_some_and(|h| h > 0.0));
    let (y, height) = match &filled {
        Some(region) => {
            let top = (region["top"].as_f64()? - 80.0).max(0.0);
            let bottom = (region["top"].as_f64()? + region["height"].as_f64()? + 80.0).min(height);
            // Keep the end nearest the payment form when the region is tall.
            ((bottom - 3000.0).max(top), (bottom - top).min(3000.0))
        }
        None => (0.0, height.min(3000.0)),
    };
    for (quality, scale) in [(70, 1.0), (45, 0.6)] {
        let shot = tab
            .cdp
            .call(
                Some(&tab.session),
                "Page.captureScreenshot",
                json!({
            "format":"jpeg","quality":quality,"captureBeyondViewport":true,
            "clip":{"x":0,"y":y,"width":width,"height":height,"scale":scale}}),
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

/// Labels and values of every filled field on the merchant page, except
/// card and password fields, for the human's review page only.
pub(crate) async fn order_fields(tab: &PrivateTab) -> Value {
    let fields = tab
        .cdp
        .call(
            Some(&tab.session),
            "Runtime.evaluate",
            json!({"expression":include_str!("order-fields.js"),"returnByValue":true}),
        )
        .await
        .ok()
        .map(|r| r["result"]["value"].clone());
    fields
        .and_then(|r| r.as_array().cloned())
        .map_or_else(|| json!([]), Value::Array)
}

/// Page scripts checkout evaluates in its own browser.
pub(crate) enum Script<'a> {
    /// `fixture` honours the test-only total attribute on localhost pages.
    Facts {
        fixture: bool,
    },
    Fields,
    Submit,
    Valid,
    Fill {
        origin: &'a str,
        index: usize,
        value: &'a str,
    },
}

impl Script<'_> {
    fn expression(&self) -> Result<String> {
        Ok(match self {
            Script::Facts { fixture } => crate::scripts::prepare(include_str!("facts.js"))
                .replace("BLOOM_FIXTURE_TOTALS", &fixture.to_string()),
            Script::Fields => crate::scripts::prepare(include_str!("fields.js")),
            Script::Submit => include_str!("submit.js").into(),
            Script::Valid => format!("({})()", include_str!("payment-valid.js").trim()),
            Script::Fill {
                origin,
                index,
                value,
            } => format!(
                "({})({},{index},{})",
                include_str!("payment-fill.js").trim(),
                serde_json::to_string(origin)?,
                serde_json::to_string(value)?
            ),
        })
    }
}

/// Run a page script in the payment document, in checkout's browser `world`.
pub(crate) async fn run(
    tab: &PrivateTab,
    session: &str,
    world: i64,
    script: Script<'_>,
) -> Result<Value> {
    // A fill expression carries a card value: wipe it after use.
    let expression = zeroize::Zeroizing::new(script.expression()?);
    evaluate(tab, session, world, expression.to_string()).await
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
        Self::read_retrying(tab, false).await
    }

    /// Facts and the pay button only: the merchant charges the payment method
    /// saved in the buyer's account, so no card field is read or filled.
    pub async fn read_site(tab: &PrivateTab) -> Result<Self> {
        Self::read_retrying(tab, true).await
    }

    async fn read_retrying(tab: &PrivateTab, site: bool) -> Result<Self> {
        let mut last_error = None;
        for _ in 0..3 {
            match Self::read_once(tab, site).await {
                Ok(discovery) => return Ok(discovery),
                Err(error) => last_error = Some(error),
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        Err(last_error.unwrap())
    }

    async fn read_once(tab: &PrivateTab, site: bool) -> Result<Self> {
        let mut frames = Vec::new();
        let mut candidates = Vec::new();
        let mut top_origin = None;
        let contexts = tab.cdp.contexts(&tab.session, "bloom-payment").await?;
        for (position, context) in contexts.iter().enumerate() {
            let url = &context.url;
            let origin = url::Url::parse(url)?.origin().ascii_serialization();
            let session = context.session.clone();
            let world = context.world;
            if position == 0 {
                top_origin = Some(origin.clone());
                if origin == "https://buy.stripe.com" {
                    let facts =
                        hosted_stripe_facts(&tab.cdp, &session, &context.frame_id, url).await?;
                    evaluate(tab,&session,world,format!("(()=>{{const facts={facts};if(globalThis.__bloomHostedStripeFacts){{if(JSON.stringify(globalThis.__bloomHostedStripeFacts)!==JSON.stringify(facts))throw Error('Facts changed');}}else Object.defineProperty(globalThis,'__bloomHostedStripeFacts',{{value:Object.freeze(facts),writable:false,configurable:false}});return true;}})()")).await?;
                }
            }
            if position == 0
                || (origin == "https://js.stripe.com"
                    && url::Url::parse(url)?.path() == "/v3/embedded-checkout-inner.html")
            {
                let candidate = run(
                    tab,
                    &session,
                    world,
                    Script::Facts {
                        fixture: fixture_totals(tab),
                    },
                )
                .await?;
                if let Ok(facts) = serde_json::from_value::<CheckoutFacts>(candidate) {
                    candidates.push((session.clone(), world, facts));
                }
            }
            if site {
                continue;
            }
            let fields = run(tab, &session, world, Script::Fields).await?;
            let fields: Vec<Field> = serde_json::from_value(fields)
                .with_context(|| format!("Ambiguous payment fields in {origin}"))?;
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
                && !provider_hosts_card_fields(&frame.origin, &facts.origin, {
                    #[cfg(test)]
                    {
                        tab.fixture_payment_hosts
                    }
                    #[cfg(not(test))]
                    {
                        false
                    }
                })
        }) {
            let found: Vec<String> = frames
                .iter()
                .map(|f| {
                    let kinds: Vec<&str> = f.fields.iter().map(|x| x.kind.as_str()).collect();
                    format!("{} {}", f.origin, kinds.join(","))
                })
                .collect();
            eprintln!("card fields found: {}", found.join("; "));
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
        if !site
            && (count("number") != 1
                || count("cvc") != 1
                || count("name") > 1
                || !((count("expiry") == 1 && count("month") == 0 && count("year") == 0)
                    || (count("expiry") == 0 && count("month") == 1 && count("year") == 1)))
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
            .context("Payment tab disappeared")?
            .to_owned();
        if url::Url::parse(&url)?.origin().ascii_serialization() != self.facts.origin {
            bail!("Payment tab origin changed");
        }
        let mut current: CheckoutFacts = serde_json::from_value(
            run(
                tab,
                &self.facts_session,
                self.main_world,
                Script::Facts {
                    fixture: fixture_totals(tab),
                },
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
            let current = run(tab, &frame.session, frame.world, Script::Valid).await?;
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
                let script = Script::Fill {
                    origin: &frame.origin,
                    index: field.index,
                    value: value.as_str(),
                };
                run(tab, &frame.session, frame.world, script).await?;
                filled.push(field.kind.clone());
            }
        }
        Ok(())
    }

    /// True only when the pay control was clicked. False is a known local
    /// validation stop, not an ambiguous payment attempt.
    pub async fn submit(&self, tab: &PrivateTab) -> Result<bool> {
        self.recheck(tab).await?;
        let response = run(tab, &self.facts_session, self.main_world, Script::Submit).await?;
        response
            .as_bool()
            .context("Payment submission result unavailable")
    }

    /// Whether private-view coordinates point at the exact pay control that
    /// discovery bound. Used to persist a manual retry before dispatching it.
    pub async fn is_submit_point(&self, tab: &PrivateTab, x: f64, y: f64) -> Result<bool> {
        let result = evaluate(
            tab,
            &self.facts_session,
            self.main_world,
            format!(
                "(()=>{{const n=document.elementFromPoint({x},{y});return !!n&&(n===globalThis.__bloomPayButton||globalThis.__bloomPayButton?.contains(n));}})()"
            ),
        )
        .await?;
        Ok(result == true)
    }
}

#[cfg(test)]
pub(crate) mod tests {
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
            ("4242424242424242", None, "payment_phrase"),
            ("4000000000000002", None, "declined"),
            ("4000000000003220", Some("complete"), "payment_phrase"),
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
            let facts = hosted_stripe_facts(
                &tab.cdp,
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

    pub(crate) async fn fixture(html: String) -> (String, tokio::task::JoinHandle<()>) {
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
            ("4242424242424242", None, "payment_phrase"),
            ("4000000000000002", None, "declined"),
            ("4000000000003220", Some("complete"), "payment_phrase"),
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
        // Off-screen alternatives are not receivers. Without the PCI exception
        // this document exposes only a number field, not a complete card form.
        assert_eq!(
            tab.cdp
                .evaluate(
                    &tab.session,
                    crate::scripts::prepare(include_str!("fields.js"))
                )
                .await
                .unwrap(),
            json!([{"kind":"number","index":0}])
        );
        let expression=crate::scripts::prepare(include_str!("fields.js")).replacen("(() => {", "(() => { const location={origin:'https://checkout.pci.shopifyinc.com',pathname:'/build/09497de/number-ltr.html'};",1);
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

    /// A logged-in merchant charging its own saved card shows no card fields.
    #[tokio::test]
    async fn fixture_site_checkout_reads_facts_without_card_fields_and_submits_once() {
        let browser = browser().await;
        let (url, server) = fixture(
            "<!doctype html><html lang='de-CH'><p id='total'>Gesamtbetrag CHF 49.90</p>\
             <p>Visa ••4242 (in your account)</p>\
             <button onclick=\"document.body.innerHTML='Vielen Dank für Ihre Bestellung'\">Jetzt kaufen</button>"
                .into(),
        )
        .await;
        let tab = open(&browser, url).await;
        assert!(Discovery::read(&tab).await.is_err());
        let discovery = Discovery::read_site(&tab).await.unwrap();
        assert_eq!(
            (
                discovery.facts.total_minor,
                discovery.facts.currency.as_str()
            ),
            (4990, "CHF")
        );
        assert!(discovery.facts.payment_frame_origins.is_empty());
        assert!(discovery.frames.is_empty());
        tab.cdp
            .evaluate(
                &tab.session,
                "document.getElementById('total').textContent='Gesamtbetrag CHF 59.90'".into(),
            )
            .await
            .unwrap();
        assert!(discovery.submit(&tab).await.is_err());
        tab.cdp
            .evaluate(
                &tab.session,
                "document.getElementById('total').textContent='Gesamtbetrag CHF 49.90'".into(),
            )
            .await
            .unwrap();
        discovery.submit(&tab).await.unwrap();
        let text = tab
            .cdp
            .evaluate(&tab.session, "document.body.innerText".into())
            .await
            .unwrap();
        assert_eq!(text, "Vielen Dank für Ihre Bestellung");
        browser.return_control().await.unwrap();
        server.abort();
    }

    /// A merchant page cannot pick the reviewed total with the fixture attribute.
    #[tokio::test]
    async fn merchant_total_attribute_is_ignored_outside_fixtures() {
        let browser = browser().await;
        let (url, server) = fixture(
            "<!doctype html><p data-bloom-total-minor='1' data-bloom-currency='USD'>Total USD 399.00</p>\
             <button>Pay</button>"
                .into(),
        )
        .await;
        let mut tab = open(&browser, url).await;
        tab.fixture_payment_hosts = false;
        let discovery = Discovery::read_site(&tab).await.unwrap();
        assert_eq!(
            (
                discovery.facts.total_minor,
                discovery.facts.currency.as_str()
            ),
            (39900, "USD")
        );
        browser.return_control().await.unwrap();
        server.abort();
    }

    /// Lines and buttons as captured from live checkouts on 2026-10-10
    /// (Shopify de-CH, fr-CH, es-ES, pt-BR, en-US), plus formats used in
    /// Argentina, Chile, Switzerland and the UK, and cases that stay manual.
    #[tokio::test]
    async fn fixture_totals_in_localized_formats() {
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
                lines("en-SG", "", &["Total", "SGD 977.27"], "Book Now"),
                Some((97727, "SGD")),
            ),
            (
                lines("en-HK", "", &["Amount to pay:", "HK$", "5804.47"], "Pay Now"),
                Some((580447, "HKD")),
            ),
            (
                lines("en", "", &["Total HK$5804.47"], "Pay Now"),
                Some((580447, "HKD")),
            ),
            (
                lines("en-US", "", &["Total amount due (All passengers)", "$178.40"], "Pay now"),
                Some((17840, "USD")),
            ),
            (
                lines(
                    "en-US",
                    "",
                    &["Total Payment Due: $56.98"],
                    "PURCHASE & ACCEPT",
                )
                .replace("<button>", "<a href='#'>")
                .replace("</button>", "</a>")
                .replace("<body>", "<body><a href='#' aria-label='Logo' style='display:block;width:20px;height:20px'></a>"),
                Some((5698, "USD")),
            ),
            // Final pages seen on 2026-10-11: Booking.com, Ryanair,
            // Aerolíneas Argentinas and Zalando.
            (
                lines(
                    "en-GB",
                    "",
                    &["Total", "CHF 37.70", "Includes taxes and fees"],
                    "Complete\u{a0}booking",
                ),
                Some((3770, "CHF")),
            ),
            (
                lines("en-GB", "", &["Total to pay", "SFr 24.23"], "Pay now"),
                Some((2423, "CHF")),
            ),
            (
                lines(
                    "es-AR",
                    "",
                    &["Precio total final", "ARS 55.553,05"],
                    "Comprar",
                ),
                Some((5555305, "ARS")),
            ),
            (
                lines(
                    "de-CH",
                    "",
                    &["Gesamtsummeinkl. MwSt.", "CHF 31.90"],
                    "Jetzt kaufen",
                ),
                Some((3190, "CHF")),
            ),
            (
                lines("en-US", "", &["Total", "USD", "$297.51"], "Confirm and pay"),
                Some((29751, "USD")),
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
            // Gotogate displays a converted total but charges the stated USD amount.
            (
                lines(
                    "es-AR",
                    "",
                    &[
                        "Importe total",
                        "AR$1,322,517.54",
                        "El precio se cobrará en:",
                        "\u{202a}853USD\u{202c}",
                    ],
                    "Pagar",
                ),
                Some((85300, "USD")),
            ),
            (
                lines(
                    "es-AR",
                    "",
                    &[
                        "Importe total AR$1,322,517.54",
                        "El precio se cobrará en:",
                        "importe pendiente",
                    ],
                    "Pagar",
                ),
                None,
            ),
            (
                lines(
                    "es-AR",
                    "",
                    &[
                        "Importe total AR$1,322,517.54",
                        "El precio se cobrará en: 853USD",
                        "El precio se cobrará en: 854USD",
                    ],
                    "Pagar",
                ),
                None,
            ),
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
    async fn jettzy_expiry_aliases_are_scoped_and_inactive_alternatives_are_rechecked() {
        let browser = browser().await;
        let fields = "<label>Card Number<input autocomplete='cc-number'></label><div>Expiration Date<select name='validity_begin'><option value=''>Month</option><option value='12'>December</option></select><select name='validity_end'><option value=''>Year</option><option value='34'>2034</option></select></div><label>Security code<input autocomplete='cc-csc'></label>";
        let (url, server) = fixture(merchant(
            fields,
            "<div id='alternative' hidden><input autocomplete='cc-number'></div>",
            "Confirmed",
        ))
        .await;
        let tab = open(&browser, url).await;
        // Other merchants cannot opt into Jettzy's expiry aliases.
        assert!(Discovery::read(&tab).await.is_err());
        for (origin, count) in [
            ("https://en.jettzy.com.hk.evil.example", 2),
            ("http://en.jettzy.com.hk", 2),
            ("https://www.jettzy.com.my.evil.example", 2),
            ("http://www.jettzy.com.my", 2),
            ("https://www.jettzy.com.my", 4),
            ("https://en.jettzy.com.hk", 4),
        ] {
            let expression = crate::scripts::prepare(include_str!("fields.js")).replacen(
                "(() => {",
                &format!("(() => {{ const location={{origin:'{origin}'}};"),
                1,
            );
            let fields = tab.cdp.evaluate(&tab.session, expression).await.unwrap();
            assert_eq!(fields.as_array().unwrap().len(), count, "{origin}");
        }
        let fill = crate::scripts::prepare(include_str!("payment-fill.js"));
        for (index, value) in ["4242424242424242", "12", "2034", "937"].iter().enumerate() {
            tab.cdp
                .evaluate(
                    &tab.session,
                    format!("({fill})(location.origin,{index},'{value}')"),
                )
                .await
                .unwrap();
        }
        let selected = tab
            .cdp
            .evaluate(
                &tab.session,
                "[...document.querySelectorAll('select')].map(e=>e.value)".into(),
            )
            .await
            .unwrap();
        assert_eq!(selected, json!(["12", "34"]));
        tab.cdp
            .evaluate(
                &tab.session,
                "document.getElementById('alternative').hidden=false".into(),
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
    async fn native_expiry_selects_use_the_displayed_year_and_refuse_ambiguity() {
        let browser = browser().await;
        let months = (1..=12)
            .map(|n| format!("<option value='{n}'>{n}</option>"))
            .collect::<String>();
        let (url, server) = fixture(merchant(
            &format!("<input autocomplete='cc-number'><label>Expiration Date<select id='month'><option value='0'>month</option>{months}</select></label><label>Expiration year<select id='year'><option value='0'>year</option><option value='34'>2034</option></select></label><input autocomplete='cc-csc'>"),
            "",
            "Confirmed",
        )).await;
        let tab = open(&browser, url).await;
        let discovery = Discovery::read(&tab).await.unwrap();
        let mut input = card();
        input.expiry_month = 3;
        discovery.fill(&tab, &input, &mut Vec::new()).await.unwrap();
        let selected = tab
            .cdp
            .evaluate(
                &tab.session,
                "[document.getElementById('month').value,document.getElementById('year').value]"
                    .into(),
            )
            .await
            .unwrap();
        assert_eq!(selected, json!(["3", "34"]));
        tab.cdp
            .evaluate(
                &tab.session,
                "document.getElementById('year').add(new Option('2034','duplicate'))".into(),
            )
            .await
            .unwrap();
        assert!(
            discovery.fill(&tab, &input, &mut Vec::new()).await.is_err(),
            "ambiguous expiry choice must not be guessed"
        );
        browser.return_control().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn card_fields_go_to_payment_providers_or_the_merchant_page() {
        for (frame, top, allowed) in [
            ("https://js.stripe.com", "https://shop.example", true),
            (
                "https://www.jettzy.com.my",
                "https://www.jettzy.com.my",
                true,
            ),
            ("https://www.jettzy.com.my", "https://shop.example", false),
            (
                "https://www.jettzy.com.my.evil.example",
                "https://www.jettzy.com.my.evil.example",
                false,
            ),
            (
                "http://www.jettzy.com.my",
                "http://www.jettzy.com.my",
                false,
            ),
            ("https://en.jettzy.com.hk", "https://en.jettzy.com.hk", true),
            ("https://en.jettzy.com.hk", "https://shop.example", false),
            (
                "https://en.jettzy.com.hk.evil.example",
                "https://en.jettzy.com.hk.evil.example",
                false,
            ),
            ("http://en.jettzy.com.hk", "http://en.jettzy.com.hk", false),
            (
                "https://booking.flyfrontier.com",
                "https://booking.flyfrontier.com",
                true,
            ),
            (
                "https://booking.flyfrontier.com",
                "https://shop.example",
                false,
            ),
            (
                "https://booking.flyfrontier.com.evil.example",
                "https://booking.flyfrontier.com.evil.example",
                false,
            ),
            (
                "http://booking.flyfrontier.com",
                "http://booking.flyfrontier.com",
                false,
            ),
            (
                "https://core.spreedly.com",
                "https://www.jetabroad.com.sg",
                true,
            ),
            (
                "https://core.spreedly.com.evil.example",
                "https://www.jetabroad.com.sg",
                false,
            ),
            (
                "http://core.spreedly.com",
                "https://www.jetabroad.com.sg",
                false,
            ),
            (
                "https://www.jetabroad.com.sg",
                "https://www.jetabroad.com.sg",
                true,
            ),
            (
                "https://www.jetabroad.com.sg",
                "https://shop.example",
                false,
            ),
            (
                "https://www.jetabroad.com.sg.evil.example",
                "https://www.jetabroad.com.sg.evil.example",
                false,
            ),
            (
                "https://frontend-payments.payment-prod.etraveligroup.net",
                "https://ar.gotogate.com",
                true,
            ),
            (
                "https://frontend-payments.payment-prod.etraveligroup.net.evil.example",
                "https://ar.gotogate.com",
                false,
            ),
            (
                "http://frontend-payments.payment-prod.etraveligroup.net",
                "https://ar.gotogate.com",
                false,
            ),
            (
                "https://checkout.stripe.com",
                "https://checkout.stripe.com",
                true,
            ),
            // A listed merchant's own page, but not any HTTPS shop.
            (
                "https://www.aerolineas.com.ar",
                "https://www.aerolineas.com.ar",
                true,
            ),
            ("https://shop.example", "https://shop.example", false),
            ("http://shop.example", "http://shop.example", false),
            // A frame from anywhere else, including a look-alike provider.
            ("https://checkout.stripe.com", "https://shop.example", false),
            ("https://cards.other.example", "https://shop.example", false),
            (
                "https://js.stripe.com.evil.example",
                "https://shop.example",
                false,
            ),
        ] {
            assert_eq!(
                provider_hosts_card_fields(frame, top, false),
                allowed,
                "{frame} in {top}"
            );
        }
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

    async fn outcome_of(browser: &Browser, html: &str) -> Value {
        let (url, server) = fixture(html.into()).await;
        let tab = open(browser, url).await;
        let outcome = tab
            .cdp
            .evaluate(
                &tab.session,
                concat!(
                    include_str!("form-attention.js"),
                    ";",
                    include_str!("outcome.js")
                )
                .into(),
            )
            .await
            .unwrap();
        browser.return_control().await.unwrap();
        server.abort();
        outcome
    }

    #[tokio::test]
    async fn airline_outcomes_read_booking_codes_and_requests_for_attention() {
        let browser = browser().await;
        // A synthetic merchant confirmation, not live JetSMART acceptance.
        let booked = outcome_of(
            &browser,
            "<h1>Pago aprobado</h1><p>Código de reserva</p><p>QX7T2M</p>",
        )
        .await;
        assert_eq!(booked["state"], "booked");
        assert_eq!(booked["order_id"], "QX7T2M");
        let unpaid = outcome_of(&browser,
            "<h1>Itinerario de vuelo</h1><p>Código de reserva QX7T2M</p><p>Reserva confirmada</p><button>Pagar</button>",
        ).await;
        assert_eq!(unpaid["state"], "waiting");
        assert_eq!(unpaid["reason"], "reservation_reference_only");
        // Form text requests attention; it does not establish a bank outcome.
        let refused = outcome_of(&browser, "<input aria-label='Nombres *' value='Karen'><div class='error'>Debes completar todos los campos.</div>").await;
        assert_eq!(refused["state"], "needs_input");
        assert_eq!(refused["reason"], "form_errors");
        let legend = outcome_of(&browser, "<p>All fields are required.</p><input required>").await;
        assert_eq!(legend["state"], "waiting");
        let required_error = outcome_of(
            &browser,
            "<p role='alert'>All fields are required.</p><input required>",
        )
        .await;
        assert_eq!(required_error["state"], "needs_input");
        // A label that names a booking code field is not a confirmation.
        let form = outcome_of(
            &browser,
            "<label>Código de reserva <input></label><p>Apellido</p>",
        )
        .await;
        assert_eq!(form["state"], "waiting");
        browser.return_control().await.ok();
    }

    #[tokio::test]
    async fn contact_reentry_is_copied_from_the_page_for_the_human_to_confirm() {
        let browser = browser().await;
        let (url, server) = fixture("<div><div>Correo electrónico *</div><input name='email' value='fixture@example.com'></div>
            <input name='prefix' value='Argentina (+54)'><div><div>Teléfono *</div><input name='phone' value='2944808829'></div>
            <div role='dialog'><p>Por favor reingresa tu correo y teléfono para confirmarlos.</p>
              <input name='confirmEmail' placeholder='Correo'><input name='confirmPhone' placeholder='Teléfono'><button>Confirmar</button></div>".into()).await;
        let tab = open(&browser, url).await;
        let outcome = tab
            .cdp
            .evaluate(
                &tab.session,
                concat!(
                    include_str!("form-attention.js"),
                    ";",
                    include_str!("outcome.js")
                )
                .into(),
            )
            .await
            .unwrap();
        assert_eq!(outcome["reason"], "confirm_contact");
        let copied = tab
            .cdp
            .evaluate(&tab.session, include_str!("confirm-contact.js").into())
            .await
            .unwrap();
        assert_eq!(copied["copied"], 2);
        let values = tab
            .cdp
            .evaluate(
                &tab.session,
                "[...document.querySelectorAll('[role=dialog] input')].map(e=>e.value)".into(),
            )
            .await
            .unwrap();
        assert_eq!(values, json!(["fixture@example.com", "2944808829"]));
        browser.return_control().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn read_only_and_contact_boxes_are_not_card_fields() {
        let browser = browser().await;
        let html = merchant(
            &format!(
                "<div><div>Código de seguridad</div><input readonly></div>
                 <div><div>Confirma correo electrónico</div><input autocomplete='cc-csc'></div>{}",
                inputs()
            ),
            "",
            "Order confirmed",
        );
        let (url, server) = fixture(html).await;
        let tab = open(&browser, url).await;
        let discovery = Discovery::read(&tab).await.unwrap();
        assert_eq!(discovery.facts.total_minor, 399);
        browser.return_control().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn inline_contact_confirmation_is_copied_and_is_not_a_form_error() {
        // JetSMART's payment page asks for the re-entry before Pay, inline.
        let browser = browser().await;
        let (url, server) = fixture("<div><div>Correo electrónico *</div><input name='e1' value='fixture@example.com'></div>
            <div><div>Teléfono *</div><input name='contact.emailaddress' value='2944808829'></div>
            <p class='error'>Por favor reingresa tu correo y teléfono para confirmarlos. Deben coincidir con los anteriores.</p>
            <div><div>Confirma correo electrónico</div><input name='e2'></div>
            <div><div>Confirma teléfono</div><input name='p2'></div>".into()).await;
        let tab = open(&browser, url).await;
        let copied = tab
            .cdp
            .evaluate(&tab.session, include_str!("confirm-contact.js").into())
            .await
            .unwrap();
        assert_eq!(copied["copied"], 2);
        let attention = tab
            .cdp
            .evaluate(
                &tab.session,
                concat!(
                    include_str!("form-attention.js"),
                    ";[globalThis.__bloomAttention(),...['e2','p2'].map(n=>document.querySelector(`[name=${n}]`).value)]"
                )
                .into(),
            )
            .await
            .unwrap();
        assert_eq!(attention[0]["errors"], json!([]));
        assert_eq!(attention[1], "fixture@example.com");
        assert_eq!(attention[2], "2944808829");
        browser.return_control().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn approval_preview_shows_the_filled_fields() {
        // An airline page: earlier steps above, filled contact fields far down.
        let html = "<!doctype html><div style='height:2400px'>Seat map</div>
            <div><div>Nombres *</div><input value='Synthetic'></div>
            <div><div>Correo *</div><input value='fixture@example.com'></div><input>
            <div><div>Confirma correo</div><input autocomplete='cc-csc' value='fixture@example.com'></div>
            <input autocomplete='cc-number' value='4242'><p>Total USD 3.99</p><button>Pay</button>";
        let browser = browser().await;
        let (url, server) = fixture(html.into()).await;
        let tab = open(&browser, url).await;
        let region = tab
            .cdp
            .evaluate(&tab.session, include_str!("filled-region.js").into())
            .await
            .unwrap();
        let top = region["top"].as_f64().unwrap();
        assert!((2400.0..2500.0).contains(&top), "{region}");
        assert!(region["height"].as_f64().unwrap() < 200.0, "{region}");
        assert!(order_preview(&tab).await.is_some());
        // The review lists what was entered, never the card number.
        assert_eq!(
            order_fields(&tab).await,
            json!([
                {"label":"Nombres *","value":"Synthetic"},
                {"label":"Correo *","value":"fixture@example.com"},
                {"label":"Confirma correo","value":"fixture@example.com"}
            ])
        );
        browser.return_control().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn total_split_from_its_currency_code_is_read() {
        // JetSMART's summary: label, colon, amount and code on separate lines,
        // on a page whose language names no region.
        let html = "<!doctype html><html lang='es'><div>Total equipaje</div><div>:</div><div>$0,00</div>
            <div>Total</div><div>:</div><div>$371.805,17</div><div>ARS</div><div>© 2026 JetSMART</div>
            <input autocomplete='cc-number'><input autocomplete='cc-exp'><input autocomplete='cc-csc'>
            <button>Pagar Ahora</button></html>";
        let browser = browser().await;
        let (url, server) = fixture(html.into()).await;
        let tab = open(&browser, url).await;
        let discovery = Discovery::read(&tab).await.unwrap();
        assert_eq!(discovery.facts.total_minor, 37180517);
        assert_eq!(discovery.facts.currency, "ARS");
        browser.return_control().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn spanish_card_form_captioned_beside_its_fields_is_supported() {
        // Shaped like an airline's own payment page: no autocomplete, captions in divs.
        let html = "<!doctype html><html lang='es-AR'><h1>Pago</h1><p>Total $371.805,17</p>
            <div><div>Número de tarjeta</div><input name='f1'></div>
            <div><div>Vencimiento (MM/AA)</div><input name='f2'></div>
            <div><div>Código de seguridad</div><input name='f3'></div>
            <div><div>Nombre del titular como figura en la tarjeta</div><input name='f4'></div>
            <button>Pagar</button></html>";
        let browser = browser().await;
        let (url, server) = fixture(html.into()).await;
        let tab = open(&browser, url).await;
        let discovery = Discovery::read(&tab).await.unwrap();
        assert_eq!(discovery.facts.total_minor, 37180517);
        assert_eq!(discovery.facts.currency, "ARS");
        let kinds: Vec<_> = discovery.frames[0]
            .fields
            .iter()
            .map(|f| f.kind.as_str())
            .collect();
        assert_eq!(kinds, ["number", "expiry", "cvc", "name"]);
        browser.return_control().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn selected_installments_are_distinguished_from_other_offers() {
        // Aerolíneas keeps every installment offer in the page after one is chosen.
        let html = "<!doctype html><html lang='es-AR'><p>Precio total final ARS 57.823,35</p>
            <p>Seleccionaste 1 cuota sin interés con Visa</p><p>3 Cuotas sin interés</p>
            <p>6 Cuotas sin interés</p><input autocomplete='cc-number'>
            <input autocomplete='cc-exp'><input autocomplete='cc-csc'>
            <button>Finalizar Compra</button></html>";
        let browser = browser().await;
        let (url, server) = fixture(html.into()).await;
        let tab = open(&browser, url).await;
        let discovery = Discovery::read(&tab).await.unwrap();
        assert_eq!(discovery.facts.total_minor, 5_782_335);
        assert_eq!(discovery.facts.currency, "ARS");
        assert_eq!(discovery.facts.installments, 1);
        browser.return_control().await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn fixture_plain_installments_confirmation_and_decline() {
        let browser = browser().await;
        for (outcome, expected) in [
            (
                "Order confirmed. Order ID FIXTURE-01 Total USD 3.99",
                "payment_phrase",
            ),
            ("Your card was declined", "declined"),
            (
                "Thank you, Kyle! Your order is confirmed. Confirmation #FIX01 Total USD 3.99",
                "payment_phrase",
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
            assert!(discovery.submit(&tab).await.unwrap());
            let outcome = tab
                .cdp
                .evaluate(&tab.session, include_str!("outcome.js").into())
                .await
                .unwrap();
            assert_eq!(outcome["state"], expected);
            if expected == "payment_phrase" {
                assert_eq!(outcome["merchant_reported_total_minor"], 399);
                assert_eq!(outcome["currency"], "USD");
            }
            browser.return_control().await.unwrap();
            server.abort();
        }
    }

    #[tokio::test]
    async fn an_invalid_field_stops_the_pay_click() {
        let browser = browser().await;
        let html = merchant(
            &format!("<label>Email<input id='email'></label>{}", inputs()),
            "",
            "Order confirmed",
        );
        let (url, server) = fixture(html).await;
        let tab = open(&browser, url).await;
        let discovery = Discovery::read(&tab).await.unwrap();
        tab.cdp
            .evaluate(
                &tab.session,
                "email.setAttribute('aria-invalid','true')".into(),
            )
            .await
            .unwrap();
        assert!(!discovery.submit(&tab).await.unwrap());
        browser.return_control().await.unwrap();
        server.abort();
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
    async fn fixture_visible_duplicate_and_navigation_fail_closed() {
        let browser = browser().await;
        let (url, server) = fixture(merchant(
            &inputs(),
            "<input autocomplete='cc-number'>",
            "Order confirmed",
        ))
        .await;
        let tab = open(&browser, url).await;
        assert!(Discovery::read(&tab).await.is_err());
        browser.return_control().await.unwrap();
        server.abort();
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
