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
            let discovery = Discovery::read(&tab).await.unwrap();
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
        let tab = browser.handoff().await.unwrap();
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
    async fn fixture_ambiguous_decimal_comma_requires_manual_review() {
        let browser = browser().await;
        let (url, server) = fixture(format!(
            "<!doctype html><p>Total BRL 57,00</p>{}<button>Pay</button>",
            inputs()
        ))
        .await;
        let tab = open(&browser, url).await;
        assert!(Discovery::read(&tab).await.is_err());
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
