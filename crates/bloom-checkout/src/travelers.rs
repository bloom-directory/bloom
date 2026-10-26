use crate::browser::PrivateTab;
use anyhow::{Context, Result, bail};
use bloom_signer_api::{Digest32, TravelerField, TravelerFillScope};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub(crate) struct TravelerDiscovery {
    pub scope: TravelerFillScope,
    session: String,
    world: i64,
    mapped: Value,
}

/// The saved phone in international format, grouped by the country's
/// numbering plan ("+54 9 294 412-3456"), so a form's area-code and number
/// fields can each take their part. None when the number does not parse.
pub(crate) fn formatted_phone(raw: &str) -> Option<String> {
    let number = phonenumber::parse(None, raw).ok()?;
    phonenumber::is_valid(&number).then(|| {
        number
            .format()
            .mode(phonenumber::Mode::International)
            .to_string()
    })
}

/// A saved value, or a form of it that booking forms ask for separately.
pub(crate) fn derived_traveler_value(
    values: &BTreeMap<String, Zeroizing<String>>,
    field: &str,
) -> Option<Zeroizing<String>> {
    let date = |range: std::ops::Range<usize>| {
        values
            .get("born_on")
            .and_then(|v| v.get(range))
            .map(|s| Zeroizing::new(s.to_owned()))
    };
    match field {
        "phone_national" => {
            let digits: String = values
                .get("phone")?
                .chars()
                .filter(|c| c.is_ascii_digit())
                .collect();
            let international = values.get("phone")?.trim_start().starts_with('+');
            let code = if international {
                phonenumber::parse(None, values.get("phone")?)
                    .ok()?
                    .country()
                    .code()
                    .to_string()
            } else {
                String::new()
            };
            Some(Zeroizing::new(digits.strip_prefix(&code)?.to_owned()))
        }
        "phone_area" | "phone_local" => {
            let formatted = formatted_phone(values.get("phone")?)?;
            let mut groups: Vec<&str> = formatted.split(' ').skip(1).collect();
            if groups.first() == Some(&"9") && groups.len() > 2 {
                groups.remove(0);
            }
            let area = groups.first()?.to_string();
            let local: String = groups[1..]
                .concat()
                .chars()
                .filter(|c| c.is_ascii_digit())
                .collect();
            Some(Zeroizing::new(if field == "phone_area" {
                area
            } else {
                local
            }))
        }
        "born_on_year" => date(0..4),
        "born_on_month" => date(5..7),
        "born_on_day" => date(8..10),
        "born_on_dmy" => {
            let born = values.get("born_on")?;
            Some(Zeroizing::new(format!(
                "{}/{}/{}",
                born.get(8..10)?,
                born.get(5..7)?,
                born.get(0..4)?
            )))
        }
        _ => values.get(field).cloned(),
    }
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
            json!({"contextId":world,"expression":expression,
        "returnByValue":true,"awaitPromise":true,"userGesture":true}),
        )
        .await?;
    if let Some(details) = response.get("exceptionDetails") {
        // Only the script's own fixed message: the first line, no page content.
        let reason = details["exception"]["description"].as_str().unwrap_or("");
        eprintln!(
            "traveler form not filled: {}",
            reason
                .lines()
                .next()
                .unwrap_or("")
                .chars()
                .take(120)
                .collect::<String>()
        );
        bail!("Traveler form needs private input");
    }
    Ok(response["result"]["value"].clone())
}

/// The fields the page asks for that the saved traveler has, bound to the
/// document the discovery script marked with `binding`.
fn scope_of(
    result: &Value,
    available: &[TravelerField],
    binding: Digest32,
) -> Result<(TravelerFillScope, Value)> {
    let origin = result["origin"]
        .as_str()
        .context("Traveler origin unavailable")?
        .to_owned();
    #[derive(Deserialize)]
    struct Mapping {
        field: TravelerField,
    }
    let mapped: Vec<Value> = result["mapped"]
        .as_array()
        .context("Traveler fields unavailable")?
        .iter()
        .filter(|m| {
            serde_json::from_value::<Mapping>((*m).clone())
                .is_ok_and(|m| available.contains(&m.field))
        })
        .cloned()
        .collect();
    let mut fields = Vec::new();
    for m in &mapped {
        let m: Mapping = serde_json::from_value(m.clone())?;
        if !fields.contains(&m.field) {
            fields.push(m.field);
        }
    }
    let scope = TravelerFillScope {
        origin: origin.clone(),
        frame_origins: vec![origin],
        document_binding: binding,
        fields,
    };
    scope
        .validate()
        .map_err(|_| anyhow::anyhow!("No supported traveler fields on a secure booking page"))?;
    Ok((scope, json!(mapped)))
}

impl TravelerDiscovery {
    pub async fn read(tab: &PrivateTab, available: &[TravelerField]) -> Result<Self> {
        use rand::RngCore;
        let mut nonce = [0; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let binding = Digest32::from_bytes(nonce);
        // Share private field annotations with snapshots in an isolated world;
        // neither the merchant's scripts nor the agent can read this map.
        let contexts = tab.cdp.contexts(&tab.session, "bloom-shopping").await?;
        let root = contexts
            .iter()
            .find(|c| c.parent_id.is_none())
            .context("Traveler document unavailable")?;
        let expression = format!(
            "globalThis.__bloomTravelerNonce={};{}",
            serde_json::to_string(binding.as_str())?,
            include_str!("traveler-discover.js")
        );
        let result = evaluate(tab, &root.session, root.world, expression).await?;
        let (scope, mapped) = scope_of(&result, available, binding)?;
        Ok(Self {
            scope,
            session: root.session.clone(),
            world: root.world,
            mapped,
        })
    }
    pub fn field_names(&self) -> Vec<String> {
        self.scope
            .fields
            .iter()
            .map(|f| {
                serde_json::to_value(f)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }
    /// Fill one list the agent already opened. The page decides whether the
    /// control is a typed combobox; checkout does not format the fill script.
    pub async fn fill_opened(
        tab: &PrivateTab,
        session: &str,
        world: i64,
        index: usize,
        field: &str,
        value: &str,
        origin: &str,
    ) -> Result<Vec<String>> {
        use rand::RngCore;
        let mut nonce = [0; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let binding = Digest32::from_bytes(nonce);
        let field_name: TravelerField = serde_json::from_value(json!(field))
            .context("That saved traveler field is not available")?;
        let prelude = format!(
            "(()=>{{const e=globalThis.__bloomRefs?.[{index}];if(!e?.isConnected)throw Error('stale');globalThis.__bloomTravelerRefs={{document,refs:[e],nonce:{}}};return true;}})()",
            serde_json::to_string(binding.as_str())?
        );
        evaluate(tab, session, world, prelude).await?;
        let discovery = Self {
            scope: TravelerFillScope {
                origin: origin.to_owned(),
                frame_origins: vec![origin.to_owned()],
                document_binding: binding,
                fields: vec![field_name],
            },
            session: session.to_owned(),
            world,
            mapped: json!([{ "field": field, "choose": true, "index": 0 }]),
        };
        let mut values = BTreeMap::new();
        values.insert(field.to_owned(), Zeroizing::new(value.to_owned()));
        discovery.fill(tab, &values).await
    }

    pub async fn fill(
        &self,
        tab: &PrivateTab,
        values: &BTreeMap<String, Zeroizing<String>>,
    ) -> Result<Vec<String>> {
        let expected = self.field_names();
        let derived = ["phone_national", "phone_area", "phone_local"];
        let mut values = values.clone();
        if values.contains_key("phone") {
            for field in derived {
                if !values.contains_key(field) {
                    if let Some(part) = derived_traveler_value(&values, field) {
                        values.insert(field.to_owned(), part);
                    }
                }
            }
        }
        if expected.iter().any(|field| !values.contains_key(field))
            || values
                .keys()
                .any(|key| !expected.contains(key) && !derived.contains(&key.as_str()))
        {
            bail!("Traveler release field mismatch");
        }
        let expression = format!(
            "(()=>{{const nonce={},origin={},mapped={},values={};return {};}})()",
            serde_json::to_string(self.scope.document_binding.as_str())?,
            serde_json::to_string(&self.scope.origin)?,
            self.mapped,
            serde_json::to_string(&values)?,
            include_str!("traveler-fill.js")
        );
        let result = evaluate(tab, &self.session, self.world, expression).await?;
        let filled: Vec<String> =
            serde_json::from_value(result["filled"].clone()).context("Traveler fill incomplete")?;
        // Field names and fixed reasons only, for diagnosing site lists.
        for skipped in result["skipped"].as_array().into_iter().flatten() {
            eprintln!(
                "traveler field left for the agent: {}",
                skipped.as_str().unwrap_or("")
            );
        }
        // A skipped site list is reported by omission; nothing else may appear.
        if filled.iter().any(|f| !expected.contains(f)) {
            bail!("Traveler fill incomplete");
        }
        Ok(filled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        browser::{BrowseRequest, Browser},
        discovery::tests::fixture,
    };
    async fn browser_at(
        html: &str,
    ) -> (std::sync::Arc<Browser>, tokio::task::JoinHandle<()>, String) {
        let (url, server) = fixture(html.into()).await;
        let root = tempfile::tempdir().unwrap().keep();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.join("profile"),
            &["--no-sandbox".into(), "--ignore-certificate-errors".into()],
        )
        .await
        .unwrap();
        browser
            .browse(BrowseRequest::Open { url: url.clone() })
            .await
            .unwrap();
        let expected_origin = url::Url::parse(&url)
            .unwrap()
            .origin()
            .ascii_serialization();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let snapshot = browser.browse(BrowseRequest::Snapshot).await;
                if snapshot.is_ok_and(|snapshot| {
                    snapshot["elements"]
                        .as_array()
                        .is_some_and(|elements| !elements.is_empty())
                }) && browser
                    .shopping_origin()
                    .await
                    .is_ok_and(|origin| origin == expected_origin)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("traveler fixture never became ready");
        (browser, server, url)
    }
    #[tokio::test]
    async fn private_filling_handles_dates_choices_and_reflections_without_public_access() {
        let (browser,server,url)=browser_at(r#"<!doctype html><html lang='es'><title>Fixture</title>
          <input autocomplete='given-name'><input autocomplete='family-name'>
          <input autocomplete='bday' type='date'><select aria-label='Nationality'><option value=''>Elige</option><option value='CAN'>Canadá</option></select>
          <select aria-label='Gender'><option value=''>Elige</option><option value='F'>Femenino</option></select>
          <input type='email'><input autocomplete='cc-number'><input type='password'>
          <h1 id='echo'></h1><script>document.addEventListener('input',()=>{
            const name=document.querySelector('[autocomplete=given-name]').value;
            echo.textContent=name;document.title=name;history.replaceState({},'', '/?person='+encodeURIComponent(name));
          });</script>"#).await;
        let before = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let stale = before["elements"][0]["ref"].as_str().unwrap().to_owned();
        let tab = browser.handoff().await.unwrap();
        let fields = [
            TravelerField::GivenName,
            TravelerField::FamilyName,
            TravelerField::BornOn,
            TravelerField::Nationality,
            TravelerField::Gender,
            TravelerField::Email,
        ];
        let discovery = TravelerDiscovery::read(&tab, &fields).await.unwrap();
        assert_eq!(discovery.scope.fields.len(), 6);
        let values: BTreeMap<String, Zeroizing<String>> = [
            ("given_name", "SyntheticPrivateName"),
            ("family_name", "FixtureFamily"),
            ("born_on", "1992-02-29"),
            ("nationality", "CA"),
            ("gender", "female"),
            ("email", "fixture@example.com"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), Zeroizing::new(v.into())))
        .collect();
        assert_eq!(discovery.fill(&tab, &values).await.unwrap().len(), 6);
        let checked=tab.cdp.evaluate(&tab.session,"({born:document.querySelector('[autocomplete=bday]').value,nation:document.querySelector('select').value,card:document.querySelector('[autocomplete=cc-number]').value,password:document.querySelector('[type=password]').value})".into()).await.unwrap();
        assert_eq!(
            checked,
            json!({"born":"1992-02-29","nation":"CAN","card":"","password":""})
        );
        assert!(browser.browse(BrowseRequest::Snapshot).await.is_err());
        assert!(
            browser
                .browse(BrowseRequest::Type {
                    element_ref: stale,
                    text: "attempt".into()
                })
                .await
                .is_err()
        );
        browser.return_control().await.unwrap();
        browser.browse(BrowseRequest::Open { url }).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        // The filled session was discarded, so the site is ordinary shopping again.
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        assert!(!snapshot.to_string().contains("SyntheticPrivateName"));
        assert!(!snapshot["elements"].as_array().unwrap().is_empty());
        server.abort();
    }
    #[tokio::test]
    async fn fields_captioned_by_nearby_text_are_found() {
        // Shaped like JetSMART: captions are plain divs beside unlabeled inputs.
        let (browser, server, _) = browser_at(
            "<div class='row'><div><div>Nombres</div><input></div><div><div>Apellidos</div><input></div>
             <div><div>Número AAdvantage® (Opcional)</div><input></div></div>",
        )
        .await;
        let tab = browser.handoff().await.unwrap();
        let fields = [TravelerField::GivenName, TravelerField::FamilyName];
        let discovery = TravelerDiscovery::read(&tab, &fields).await.unwrap();
        assert_eq!(discovery.scope.fields.len(), 2);
        let values = [
            ("given_name".into(), Zeroizing::new("SyntheticName".into())),
            ("family_name".into(), Zeroizing::new("Fixture".into())),
        ]
        .into_iter()
        .collect();
        assert_eq!(discovery.fill(&tab, &values).await.unwrap().len(), 2);
        let filled = tab
            .cdp
            .evaluate(
                &tab.session,
                "[...document.querySelectorAll('input')].map(e=>e.value)".into(),
            )
            .await
            .unwrap();
        assert_eq!(filled, json!(["SyntheticName", "Fixture", ""]));
        server.abort();
    }
    #[tokio::test]
    async fn text_fields_are_touched_and_confirmation_email_is_repeated() {
        let (browser, server, _) = browser_at(
            "<div><div>Nombres</div><input id='name' required></div>
             <label>Correo electrónico<input id='email' type='email' required></label>
             <label>Confirmar correo electrónico<input id='confirm' type='email' required></label>
             <button id='next' disabled>Continuar</button>
             <script>const nameField=document.getElementById('name'),emailField=document.getElementById('email'),confirmField=document.getElementById('confirm'),nextButton=document.getElementById('next');
               const fields=[nameField,emailField,confirmField];
               const update=()=>nextButton.disabled=!(fields.every(e=>e.dataset.touched==='yes')&&nameField.value&&emailField.value===confirmField.value);
               for(const e of fields){e.addEventListener('input',update);e.addEventListener('focusout',()=>{e.dataset.touched='yes';update();});}</script>",
        )
        .await;
        let tab = browser.handoff().await.unwrap();
        let discovery =
            TravelerDiscovery::read(&tab, &[TravelerField::GivenName, TravelerField::Email])
                .await
                .unwrap();
        let values = [
            ("given_name".into(), Zeroizing::new("Synthetic".into())),
            ("email".into(), Zeroizing::new("fixture@example.com".into())),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            discovery.fill(&tab, &values).await.unwrap(),
            ["given_name", "email"]
        );
        let state = tab
            .cdp
            .evaluate(
                &tab.session,
                "(()=>{const fields=['name','email','confirm'].map(id=>document.getElementById(id));return {same:fields[1].value===fields[2].value,touched:fields.every(e=>e.dataset.touched==='yes'),ready:!document.getElementById('next').disabled};})()".into(),
            )
            .await
            .unwrap();
        assert_eq!(state, json!({"same":true,"touched":true,"ready":true}));
        server.abort();
    }
    #[tokio::test]
    async fn site_drawn_dropdowns_are_chosen_by_clicking_their_option() {
        // Shaped like JetSMART: gender is a read-only input whose options appear on click.
        let (browser, server, _) = browser_at(
            "<div><div>Nombres</div><input name='firstName-0'></div>
             <div><div>Género</div><input name='gender-0' readonly></div>
             <div><div>Número AAdvantage® (Opcional)</div><input name='ff-0' readonly></div>
             <div>Seats <span>A</span><span>F</span><span>M</span></div>
             <div id='list' hidden><div class='opt' data-test-value='Male'>Masculino</div>
               <div class='opt' data-test-value='Female'>Femenino</div></div>
             <script>const g=document.querySelector('[name=gender-0]');
               g.addEventListener('click',()=>setTimeout(()=>list.hidden=false,150));
               for(const o of document.querySelectorAll('.opt'))o.addEventListener('click',()=>{g.value=o.innerText;list.hidden=true;});</script>",
        )
        .await;
        let tab = browser.handoff().await.unwrap();
        let fields = [TravelerField::GivenName, TravelerField::Gender];
        let discovery = TravelerDiscovery::read(&tab, &fields).await.unwrap();
        assert_eq!(discovery.scope.fields, fields);
        let values = [
            ("given_name".into(), Zeroizing::new("SyntheticName".into())),
            ("gender".into(), Zeroizing::new("female".into())),
        ]
        .into_iter()
        .collect();
        assert_eq!(discovery.fill(&tab, &values).await.unwrap().len(), 2);
        let filled = tab
            .cdp
            .evaluate(
                &tab.session,
                "[...document.querySelectorAll('input')].map(e=>e.value)".into(),
            )
            .await
            .unwrap();
        assert_eq!(filled, json!(["SyntheticName", "Femenino", ""]));
        server.abort();
    }

    #[tokio::test]
    async fn document_expiry_parts_are_chosen_from_site_drawn_lists() {
        let (browser, server, _) = browser_at(
            r#"<html lang='es'><div id='expiry'>Fecha de Caducidad
              <label>Día<input id='day' aria-label='Día de vencimiento' aria-autocomplete='list' readonly></label>
              <label>Mes<input id='month' aria-label='Mes de vencimiento' aria-autocomplete='list' readonly></label>
              <label>Año<input id='year' aria-label='Año de vencimiento' aria-autocomplete='list' readonly></label>
            </div><div id='options' hidden></div><p id='accepted'></p>
            <script>
              const values={day:['31','31'],month:['12','Diciembre'],year:['2035','2035']};
              for(const input of expiry.querySelectorAll('input')) input.addEventListener('click',()=>{
                const [value,label]=values[input.id];options.innerHTML='<div role="option">'+label+'</div>';
                options.hidden=false;options.firstChild.addEventListener('click',()=>{
                  input.value=value;input.dataset.accepted='yes';options.hidden=true;
                  accepted.textContent=[...expiry.querySelectorAll('input')].every(e=>e.dataset.accepted==='yes')?'accepted':'';
                });
              });
            </script></html>"#,
        )
        .await;
        let tab = browser.handoff().await.unwrap();
        let discovery = TravelerDiscovery::read(&tab, &[TravelerField::DocumentExpiry])
            .await
            .unwrap();
        let values = [(
            "document_expiry".into(),
            Zeroizing::new("2035-12-31".into()),
        )]
        .into_iter()
        .collect();
        assert_eq!(
            discovery.fill(&tab, &values).await.unwrap(),
            ["document_expiry"]
        );
        let accepted = tab
            .cdp
            .evaluate(&tab.session, "accepted.textContent".into())
            .await
            .unwrap();
        assert_eq!(accepted, json!("accepted"));
        server.abort();
    }

    #[tokio::test]
    async fn a_choice_revealing_dependent_fields_is_filled_in_one_request() {
        let (browser, server, url) = browser_at(
            r#"<html lang='es'><label>Tipo de Documento<select id='kind'>
              <option value=''>Seleccionar</option><option value='national_id'>DNI</option>
            </select></label><div id='expiry' hidden>Fecha de Caducidad
              <label>Día<input id='day' aria-label='Día de vencimiento' aria-autocomplete='list' readonly></label>
              <label>Mes<input id='month' aria-label='Mes de vencimiento' aria-autocomplete='list' readonly></label>
              <label>Año<input id='year' aria-label='Año de vencimiento' aria-autocomplete='list' readonly></label>
            </div><div id='options' hidden></div><p id='accepted'></p>
            <script>
              kind.addEventListener('input',()=>expiry.hidden=false);
              const values={day:['31','31'],month:['12','Diciembre'],year:['2035','2035']};
              for(const input of expiry.querySelectorAll('input')) input.addEventListener('click',()=>{
                const [value,label]=values[input.id];options.innerHTML='<div role="option">'+label+'</div>';
                options.hidden=false;options.firstChild.addEventListener('click',()=>{
                  input.value=value;input.dataset.accepted='yes';options.hidden=true;
                  accepted.textContent=[...expiry.querySelectorAll('input')].every(e=>e.dataset.accepted==='yes')?'accepted':'';
                });
              });
            </script></html>"#,
        )
        .await;
        let origin = url::Url::parse(&url)
            .unwrap()
            .origin()
            .ascii_serialization();
        let values = [
            ("document_kind".into(), Zeroizing::new("national_id".into())),
            (
                "document_expiry".into(),
                Zeroizing::new("2035-12-31".into()),
            ),
        ]
        .into_iter()
        .collect();
        let filled = browser
            .fill_traveler(
                &origin,
                &browser.shopping_context().await,
                &[TravelerField::DocumentKind, TravelerField::DocumentExpiry],
                &values,
            )
            .await
            .unwrap();
        assert_eq!(filled, ["document_kind", "document_expiry"]);
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        assert!(snapshot["text"].as_str().unwrap().contains("accepted"));
        server.abort();
    }
    #[tokio::test]
    async fn unlocked_traveler_fills_shopping_pages_and_stays_out_of_snapshots() {
        // The merchant echoes the name into the page, title and URL as typed.
        let (browser, server, url) = browser_at(
            "<div><div>Nombres</div><input name='firstName-0'></div>
             <div><div>Apellidos</div><input name='lastName-0'></div>
             <input type='email'><h1 id='echo'></h1><button>Continuar</button>
             <p id='keys'></p><script>let keys=0;document.addEventListener('keyup',()=>{keys++;document.getElementById('keys').textContent='key releases '+keys;});</script>
             <script>document.addEventListener('input',()=>{const n=document.querySelector('[name=firstName-0]').value.toUpperCase();
               echo.textContent='Hola '+n;document.title=n;history.replaceState({},'','/?n='+n);});</script>",
        )
        .await;
        let origin = url::Url::parse(&url)
            .unwrap()
            .origin()
            .ascii_serialization();
        assert_eq!(browser.shopping_origin().await.unwrap(), origin);
        let values: BTreeMap<String, Zeroizing<String>> = [
            ("given_name", "Syntheticname"),
            ("family_name", "Fixturefamily"),
            ("email", "fixture@example.com"),
            ("phone", "5491100000000"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), Zeroizing::new(v.into())))
        .collect();
        browser.redact(
            values
                .iter()
                .map(|(k, v)| (v.to_string(), format!("[saved {k}]"))),
        );
        let fields = [
            TravelerField::GivenName,
            TravelerField::FamilyName,
            TravelerField::Email,
            TravelerField::Phone,
        ];
        assert!(
            browser
                .fill_traveler(
                    "https://elsewhere.example",
                    &browser.shopping_context().await,
                    &fields,
                    &values
                )
                .await
                .is_err()
        );
        let filled = browser
            .fill_traveler(&origin, &browser.shopping_context().await, &fields, &values)
            .await
            .unwrap();
        assert_eq!(filled, ["given_name", "family_name", "email"]);
        // Forms that accept a value only on a key release see one per field.
        let keys = browser.browse(BrowseRequest::Snapshot).await.unwrap()["text"].to_string();
        assert!(keys.contains("key releases 3"), "{keys}");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        // Machine accepts only the closed public response shapes.
        serde_json::from_value::<bloom_checkout_api::BrowseResponse>(snapshot.clone()).unwrap();
        serde_json::from_value::<bloom_checkout_api::BrowseResponse>(
            json!({"state":"filled","filled_fields":filled}),
        )
        .unwrap();
        let snapshot = snapshot.to_string();
        assert!(snapshot.contains("Hola [saved given_name]"), "{snapshot}");
        // Captioned fields show which saved value went where.
        assert!(
            snapshot.contains(
                r#""label":"Apellidos","role":"input","type":"text","value":"[saved family_name]""#
            ) || snapshot.contains("[saved family_name]"),
            "{snapshot}"
        );
        for secret in ["syntheticname", "fixturefamily", "fixture@example.com"] {
            assert!(
                !snapshot.to_ascii_lowercase().contains(secret),
                "{snapshot}"
            );
        }
        // Shopping continues on the same page with fresh refs.
        assert!(snapshot.contains("Continuar"));
        server.abort();
    }
    #[tokio::test]
    async fn saved_accented_names_stay_private_when_the_merchant_changes_case() {
        for (name, shown, render) in [
            ("Élodie", "élodie", "value.toLowerCase()"),
            ("Straße", "STRASSE", "value.toUpperCase()"),
            ("İpek", "i\u{307}pek", "value.toLowerCase()"),
            (
                "élodie zoë",
                "Élodie Zoë",
                "value.split(' ').map(word=>word[0].toUpperCase()+word.slice(1)).join(' ')",
            ),
        ] {
            let (browser, server, url) = browser_at(&format!(
                "<label>First name<input autocomplete='given-name'></label>
                 <p id='echo'></p><button id='next'>Continue</button>
                 <script>document.querySelector('input').addEventListener('input',event=>{{
                   const value=event.target.value, shown={render};
                   echo.textContent='Passenger '+shown;document.title=shown;
                   document.getElementById('next').setAttribute('aria-label','Continue for '+shown);
                 }});</script>"
            ))
            .await;
            let origin = url::Url::parse(&url)
                .unwrap()
                .origin()
                .ascii_serialization();
            let values = [("given_name".into(), Zeroizing::new(name.to_owned()))].into();
            browser.redact([(name.to_owned(), "[saved given_name]".into())]);
            let filled = browser
                .fill_traveler(
                    &origin,
                    &browser.shopping_context().await,
                    &[TravelerField::GivenName],
                    &values,
                )
                .await
                .unwrap();
            assert_eq!(filled, ["given_name"]);
            let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
            serde_json::from_value::<bloom_checkout_api::BrowseResponse>(snapshot.clone()).unwrap();
            let snapshot = snapshot.to_string();
            assert!(
                !snapshot.contains(shown),
                "Saved name escaped redaction: {snapshot}"
            );
            assert!(
                snapshot.contains("Passenger [saved given_name]"),
                "{snapshot}"
            );
            assert!(
                snapshot.contains("Continue for [saved given_name]"),
                "{snapshot}"
            );
            server.abort();
        }
    }
    #[tokio::test]
    async fn passport_or_id_captions_fill_only_traveler_document_fields() {
        for number_label in [
            "Passport No.",
            "Passport or ID number",
            "Passport or lD number",
        ] {
            let (browser, server, _) = browser_at(&format!(
                "<div>{number_label}<input></div>
                 <div>Country of passport or lD<select><option value=''></option><option value='US'>United States</option></select></div>
                 <div>Passport or lD expiration date<input type='date'></div>
                 <fieldset><legend>Cardholder</legend><label>{number_label}<input></label></fieldset>"
            ))
            .await;
            let tab = browser.handoff().await.unwrap();
            let discovery = TravelerDiscovery::read(
                &tab,
                &[
                    TravelerField::DocumentNumber,
                    TravelerField::DocumentCountry,
                    TravelerField::DocumentExpiry,
                ],
            )
            .await
            .unwrap();
            assert_eq!(
                discovery.field_names(),
                ["document_number", "document_country", "document_expiry"],
                "{number_label}"
            );
            let values = [
                ("document_number", "X00000000"),
                ("document_country", "US"),
                ("document_expiry", "2034-01-01"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), Zeroizing::new(v.to_owned())))
            .collect();
            assert_eq!(discovery.fill(&tab, &values).await.unwrap().len(), 3);
            let filled = tab
                .cdp
                .evaluate(
                    &tab.session,
                    "[...document.querySelectorAll('input,select')].map(e=>e.value)".into(),
                )
                .await
                .unwrap();
            assert_eq!(filled, json!(["X00000000", "US", "2034-01-01", ""]));
            server.abort();
        }
    }

    #[tokio::test]
    async fn split_dates_radios_and_typeahead_lists_are_filled() {
        // Shaped like Aerolíneas Argentinas' passenger form.
        let (browser, server, _) = browser_at(
            "<a href='#'>Argentina</a>
             <div><div>Fecha de Nacimiento</div><div><input aria-label='Día'><input aria-label='Mes'><input aria-label='Año'></div></div>
             <div><div>Género</div><label><input type='radio' name='g' value='F'>Femenino</label><label><input type='radio' name='g' value='M'>Masculino</label></div>
             <div><div>nro documento</div><input name='doc'></div>
             <div><div>Nacionalidad</div><input id='nat'><ul id='list'></ul></div>
             <script>nat.addEventListener('input',()=>{list.innerHTML='';for(const c of ['Argentina','Armenia'])
               if(c.toLowerCase().startsWith(nat.value.toLowerCase())){const li=document.createElement('li');li.textContent=c;
               li.onclick=()=>{nat.value=c;list.innerHTML='';};list.append(li);}});</script>",
        )
        .await;
        let tab = browser.handoff().await.unwrap();
        let fields = [
            TravelerField::BornOn,
            TravelerField::Gender,
            TravelerField::DocumentNumber,
            TravelerField::Nationality,
        ];
        let discovery = TravelerDiscovery::read(&tab, &fields).await.unwrap();
        let values = [
            ("born_on", "1990-05-07"),
            ("gender", "female"),
            ("document_number", "12345678"),
            ("nationality", "AR"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), Zeroizing::new(v.to_owned())))
        .collect();
        assert_eq!(discovery.fill(&tab, &values).await.unwrap().len(), 4);
        let filled = tab
            .cdp
            .evaluate(
                &tab.session,
                "[...document.querySelectorAll('input:not([type=radio])')].map(e=>e.value).concat(document.querySelector('[value=F]').checked)".into(),
            )
            .await
            .unwrap();
        assert_eq!(
            filled,
            json!(["7", "5", "1990", "12345678", "Argentina", true])
        );
        server.abort();
    }
    #[tokio::test]
    async fn a_single_digit_day_is_picked_from_a_site_list() {
        // Shaped like Aerolíneas Argentinas' birth day: a search box whose
        // options are 1..31, and the choice shown beside an emptied box.
        let (browser, server, _) = browser_at(
            "<div><div>Fecha de Nacimiento</div><div>
               <div><div id='shown'></div><input aria-label='Día' id='day' role='combobox'><div id='list'></div></div>
               <input aria-label='Mes'><input aria-label='Año'></div></div>
             <script>day.addEventListener('input',()=>{list.innerHTML='';for(let d=1;d<=31;d++)
               if(day.value&&String(d).startsWith(day.value)){const o=document.createElement('div');o.className='option';o.textContent=d;
               o.onclick=()=>{shown.textContent=d;day.value='';list.innerHTML='';};list.append(o);}});</script>",
        )
        .await;
        let tab = browser.handoff().await.unwrap();
        let discovery = TravelerDiscovery::read(&tab, &[TravelerField::BornOn])
            .await
            .unwrap();
        let values = [(
            "born_on".to_owned(),
            Zeroizing::new("1990-05-07".to_owned()),
        )]
        .into_iter()
        .collect();
        assert_eq!(discovery.fill(&tab, &values).await.unwrap().len(), 1);
        let shown = tab
            .cdp
            .evaluate(&tab.session, "shown.textContent".into())
            .await
            .unwrap();
        assert_eq!(shown, json!("7"));
        server.abort();
    }
    #[tokio::test]
    async fn earlier_filled_steps_do_not_count_as_a_second_person() {
        // Shaped like JetSMART's payment page: the filled passenger step stays
        // in the document above the empty contact form.
        let (browser, server, _) = browser_at(
            "<div><div>Nombres</div><input value='Filled'></div><div><div>Apellidos</div><input value='Filled'></div>
             <div><div>Nombres *</div><input></div><div><div>Apellidos *</div><input></div>
             <div><div>Correo electrónico *</div><input></div>
             <div><input value='Argentina (+54)' readonly><div><div>Teléfono *</div><input></div></div>",
        )
        .await;
        let tab = browser.handoff().await.unwrap();
        let fields = [
            TravelerField::GivenName,
            TravelerField::FamilyName,
            TravelerField::Email,
            TravelerField::Phone,
        ];
        let discovery = TravelerDiscovery::read(&tab, &fields).await.unwrap();
        assert_eq!(discovery.scope.fields, fields);
        let values = [
            ("given_name", "Synthetic"),
            ("family_name", "Fixture"),
            ("email", "fixture@example.com"),
            ("phone", "+54 9 11 0000-0000"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), Zeroizing::new(v.to_owned())))
        .collect();
        assert_eq!(discovery.fill(&tab, &values).await.unwrap().len(), 4);
        let phone = tab
            .cdp
            .evaluate(
                &tab.session,
                "document.querySelectorAll('input')[6].value".into(),
            )
            .await
            .unwrap();
        // The prefix field already says +54.
        assert_eq!(phone, json!("91100000000"));
        server.abort();
    }
    #[tokio::test]
    async fn card_holder_fields_are_left_for_the_payer() {
        let (browser, server, _) = browser_at(
            "<div><div>Nombres *</div><input></div><div><div>Apellidos *</div><input></div>
             <div><div>Correo *</div><input></div><div><div>Teléfono *</div><input></div>
             <section><h3>Tarjeta de débito o crédito</h3><div><div>Nombre del titular de la tarjeta</div><input></div>
               <div><div>Documento</div><input type='hidden'><input type='hidden'><input type='hidden'>
                 <div><div><div><div><div><div><div>Número</div><input name='documentNumber'></div></div></div></div></div></div></div>
               <div><div>Correo electrónico</div><input></div></section>",
        )
        .await;
        let tab = browser.handoff().await.unwrap();
        let fields = [
            TravelerField::GivenName,
            TravelerField::DocumentNumber,
            TravelerField::Email,
        ];
        let discovery = TravelerDiscovery::read(&tab, &fields).await.unwrap();
        assert_eq!(
            discovery.mapped.as_array().unwrap().len(),
            2,
            "only the contact name and email"
        );
        // The contact email is filled; the card holder's is not.
        assert_eq!(
            discovery.scope.fields,
            [TravelerField::GivenName, TravelerField::Email]
        );
        assert_eq!(discovery.field_names().len(), 2);
        server.abort();
    }
    #[tokio::test]
    async fn long_pages_leave_room_for_embedded_frames() {
        // Shaped like JetSMART's payment page: earlier steps stay in the DOM.
        let (browser, server, _) = browser_at(
            "<body><script>if (location.search) document.body.innerHTML = \"<input aria-label='Frame field'>\";
             else { for (let i = 0; i < 350; i++) document.body.insertAdjacentHTML('beforeend', '<button>Step ' + i + '</button>');
               document.body.insertAdjacentHTML('beforeend', \"<iframe src='/?frame'></iframe>\"); }</script></body>",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let elements = snapshot["elements"].as_array().unwrap();
        assert!(elements.iter().any(|e| e["label"] == "Frame field"));
        assert_eq!(
            elements.iter().filter(|e| e["role"] == "button").count(),
            300
        );
        server.abort();
    }
    #[tokio::test]
    async fn duplicate_people_and_stale_document_bindings_fail_before_reuse() {
        let (browser,server,_)=browser_at("<input autocomplete='given-name'><input autocomplete='family-name'><input autocomplete='given-name'><input autocomplete='family-name'>").await;
        let tab = browser.handoff().await.unwrap();
        let fields = [TravelerField::GivenName, TravelerField::FamilyName];
        assert!(TravelerDiscovery::read(&tab, &fields).await.is_err());
        tab.cdp.evaluate(&tab.session,"document.querySelectorAll('input')[2].remove();document.querySelectorAll('input')[2].remove()".into()).await.unwrap();
        let first = TravelerDiscovery::read(&tab, &fields).await.unwrap();
        let _second = TravelerDiscovery::read(&tab, &fields).await.unwrap();
        let values = [
            ("given_name".into(), Zeroizing::new("SyntheticName".into())),
            ("family_name".into(), Zeroizing::new("Fixture".into())),
        ]
        .into_iter()
        .collect();
        assert!(first.fill(&tab, &values).await.is_err());
        server.abort();
    }
}
