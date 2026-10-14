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
        "returnByValue":true,"userGesture":true}),
        )
        .await?;
    if response.get("exceptionDetails").is_some() {
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
    pub async fn fill(
        &self,
        tab: &PrivateTab,
        values: &BTreeMap<String, Zeroizing<String>>,
    ) -> Result<Vec<String>> {
        let expected: Vec<String> = self
            .scope
            .fields
            .iter()
            .map(|f| {
                serde_json::to_value(f)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
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
