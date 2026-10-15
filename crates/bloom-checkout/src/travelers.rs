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

impl TravelerDiscovery {
    pub async fn read(tab: &PrivateTab, available: &[TravelerField]) -> Result<Self> {
        use rand::RngCore;
        let mut nonce = [0; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let binding = Digest32::from_bytes(nonce);
        let contexts = tab
            .cdp
            .contexts(&tab.session, "bloom-traveler-private")
            .await?;
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
        scope.validate().map_err(|_| {
            anyhow::anyhow!("No supported traveler fields on a secure booking page")
        })?;
        Ok(Self {
            scope,
            session: root.session.clone(),
            world: root.world,
            mapped: json!(mapped),
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
    pub async fn fill(
        &self,
        tab: &PrivateTab,
        values: &BTreeMap<String, Zeroizing<String>>,
    ) -> Result<Vec<String>> {
        let expected = self.field_names();
        if values.len() != expected.len() || expected.iter().any(|f| !values.contains_key(f)) {
            bail!("Traveler release field mismatch");
        }
        let expression = format!(
            "(()=>{{const nonce={},origin={},mapped={},values={};return {};}})()",
            serde_json::to_string(self.scope.document_binding.as_str())?,
            serde_json::to_string(&self.scope.origin)?,
            self.mapped,
            serde_json::to_string(values)?,
            include_str!("traveler-fill.js")
        );
        let result = evaluate(tab, &self.session, self.world, expression).await?;
        let filled: Vec<String> =
            serde_json::from_value(result["filled"].clone()).context("Traveler fill incomplete")?;
        if filled.len() != expected.len() || filled.iter().any(|f| !expected.contains(f)) {
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
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
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
        browser
            .protect_origin(discovery.scope.origin.clone())
            .unwrap();
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
    async fn unlocked_traveler_fills_shopping_pages_and_stays_out_of_snapshots() {
        // The merchant echoes the name into the page, title and URL as typed.
        let (browser, server, url) = browser_at(
            "<div><div>Nombres</div><input name='firstName-0'></div>
             <div><div>Apellidos</div><input name='lastName-0'></div>
             <input type='email'><h1 id='echo'></h1><button>Continuar</button>
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
                .fill_traveler("https://elsewhere.example", &fields, &values)
                .await
                .is_err()
        );
        let filled = browser
            .fill_traveler(&origin, &fields, &values)
            .await
            .unwrap();
        assert_eq!(filled, ["given_name", "family_name", "email"]);
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
                 <div><div>Número</div><input name='documentNumber'></div></div>
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
