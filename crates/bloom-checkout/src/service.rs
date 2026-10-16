use crate::{
    browser::{Browser, PrivateTab},
    discovery::Discovery,
    hpke::Recipient,
};
use anyhow::{Context, Result, bail};
use bloom_checkout_api::BrowseRequest;
use bloom_signer_api::{
    CardOperationState, CardOperationStatus, CustodyOutputHpkeAad, CustodyResult, Digest32,
    OperationId, Token, TravelerFillScope,
};
use parking_lot::Mutex;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    sync::Mutex as AsyncMutex,
};

pub use bloom_checkout_api::{HistoryEntry, Request, Status};

struct Store(Mutex<Connection>);
impl Store {
    fn open(path: &Path) -> Result<Self> {
        if path.exists() {
            let meta = std::fs::symlink_metadata(path)?;
            if !meta.is_file()
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.mode() & 0o077 != 0
            {
                bail!("Checkout state must be a private file owned by checkout");
            }
        } else {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(path)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,state TEXT NOT NULL,status TEXT NOT NULL,created INTEGER NOT NULL,kind TEXT NOT NULL,description TEXT NOT NULL,shop TEXT,total_minor INTEGER,currency TEXT);")?;
        // A lost recipient cannot be reconstructed. Interrupted disclosure is never retried.
        conn.execute("UPDATE operations SET state='uncertain',status=json_set(status,'$.state','uncertain','$.ceremony_url',NULL) WHERE state='submitted'",[])?;
        conn.execute("UPDATE operations SET state='not_submitted',status=json_set(status,'$.state','not_submitted','$.ceremony_url',NULL) WHERE state='needs_input'",[])?;
        conn.execute("UPDATE operations SET state='disclosure_unknown',status=json_set(status,'$.state','disclosure_unknown','$.ceremony_url',NULL) WHERE state IN ('release_started','filled','partially_filled')",[])?;
        conn.execute("UPDATE operations SET state='failed_before_release',status=json_set(status,'$.state','failed_before_release','$.ceremony_url',NULL) WHERE state IN ('requested','preparing','awaiting_approval','manual_required','human_control')",[])?;
        Ok(Self(Mutex::new(conn)))
    }
    fn get(&self, id: &str) -> Result<Status> {
        let text: String = self
            .0
            .lock()
            .query_row("SELECT status FROM operations WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .context("Unknown checkout request")?;
        Ok(serde_json::from_str(&text)?)
    }
    fn insert(&self, status: &Status, kind: &str, description: &str) -> Result<()> {
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        self.0
            .lock()
            .execute(
                "INSERT INTO operations(id,state,status,created,kind,description) VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    status.operation_id,
                    status.state,
                    serde_json::to_string(status)?,
                    created,
                    kind,
                    description
                ],
            )
            .context("Checkout request already exists; use status, never retry automatically")?;
        Ok(())
    }
    /// The shop and, when Bloom read one, the total the human approved.
    fn record_order(&self, id: &str, shop: Option<&str>, total: Option<(u64, &str)>) -> Result<()> {
        self.0.lock().execute(
            "UPDATE operations SET shop=?2,total_minor=?3,currency=?4 WHERE id=?1",
            params![id, shop, total.map(|t| t.0), total.map(|t| t.1)],
        )?;
        Ok(())
    }
    fn history(&self) -> Result<Vec<HistoryEntry>> {
        let conn = self.0.lock();
        let mut query = conn.prepare(
            "SELECT created,kind,description,shop,total_minor,currency,status FROM operations ORDER BY created DESC,rowid DESC LIMIT 50",
        )?;
        let rows = query.query_map([], |r| {
            Ok((
                HistoryEntry {
                    created: r.get(0)?,
                    kind: r.get(1)?,
                    description: r.get(2)?,
                    shop: r.get(3)?,
                    total_minor: r.get(4)?,
                    currency: r.get(5)?,
                    status: None,
                },
                r.get::<_, String>(6)?,
            ))
        })?;
        rows.map(|row| {
            let (mut entry, status) = row?;
            entry.status = Some(serde_json::from_str(&status)?);
            Ok(entry)
        })
        .collect()
    }
    fn update(&self, status: &Status) -> Result<()> {
        self.0.lock().execute(
            "UPDATE operations SET state=?2,status=?3 WHERE id=?1",
            params![
                status.operation_id,
                status.state,
                serde_json::to_string(status)?
            ],
        )?;
        Ok(())
    }
    fn consume(&self, id: &str) -> Result<Status> {
        let mut status = self.get(id)?;
        status.state = "release_started".into();
        status.ceremony_url = None;
        let changed=self.0.lock().execute("UPDATE operations SET state='release_started',status=?2 WHERE id=?1 AND state='awaiting_approval'",
            params![id,serde_json::to_string(&status)?])?;
        if changed != 1 {
            bail!("Checkout release already consumed or cancelled");
        }
        Ok(status)
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// Fill a saved Bloom card.
    Card,
    /// Click the merchant's pay button; the merchant charges its saved method.
    Site,
    /// The human takes over the browser and hands it back; nothing is bought.
    TakeOver,
}

struct PrivateCheckout {
    operation_id: String,
    mode: Mode,
    tab: PrivateTab,
    discovery: Option<Discovery>,
    recipient: Option<Recipient>,
    capability: String,
    claimed: bool,
    approved: bool,
    view_target: String,
    view_session: String,
    seen_pages: std::collections::HashSet<String>,
    /// A human retry is an attempted payment even if the old validation text
    /// remains visible while the merchant processes it.
    manual_submission: bool,
}

struct PendingUnlock {
    operation_id: String,
    recipient: Recipient,
    origin: String,
    fields: Vec<bloom_signer_api::TravelerField>,
}

struct UnlockedTraveler {
    origin: String,
    /// The unlock ends with the booking's browsing context.
    context: String,
    fields: Vec<bloom_signer_api::TravelerField>,
    values: BTreeMap<String, zeroize::Zeroizing<String>>,
    expires: tokio::time::Instant,
}

/// Country calling codes, longest first, for numbers sites want without one.
const CALLING_CODES: &[&str] = &[
    "598", "595", "593", "591", "506", "507", "502", "503", "504", "505", "351", "353", "54", "55",
    "56", "57", "58", "51", "52", "53", "34", "44", "49", "33", "39", "41", "31", "32", "61", "64",
    "81", "82", "86", "91", "1", "7",
];

/// The saved phone in international format, grouped by the country's
/// numbering plan ("+54 9 294 412-3456"), so a form's area-code and number
/// fields can each take their part. None when the number does not parse.
fn formatted_phone(raw: &str) -> Option<String> {
    let number = phonenumber::parse(None, raw).ok()?;
    phonenumber::is_valid(&number).then(|| {
        number
            .format()
            .mode(phonenumber::Mode::International)
            .to_string()
    })
}

/// A saved value, or a form of it that booking forms ask for separately.
fn derived_traveler_value(
    values: &BTreeMap<String, zeroize::Zeroizing<String>>,
    field: &str,
) -> Option<zeroize::Zeroizing<String>> {
    let date = |range: std::ops::Range<usize>| {
        values
            .get("born_on")
            .and_then(|v| v.get(range))
            .map(|s| zeroize::Zeroizing::new(s.to_owned()))
    };
    match field {
        "phone_national" => {
            let digits: String = values
                .get("phone")?
                .chars()
                .filter(|c| c.is_ascii_digit())
                .collect();
            let international = values.get("phone")?.trim_start().starts_with('+');
            let code = CALLING_CODES
                .iter()
                .find(|code| international && digits.starts_with(**code))
                .map_or(0, |code| code.len());
            Some(zeroize::Zeroizing::new(digits[code..].to_owned()))
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
            Some(zeroize::Zeroizing::new(if field == "phone_area" {
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
            Some(zeroize::Zeroizing::new(format!(
                "{}/{}/{}",
                born.get(8..10)?,
                born.get(5..7)?,
                born.get(0..4)?
            )))
        }
        _ => values.get(field).cloned(),
    }
}

struct CompletedView {
    capability: String,
    claimed: bool,
    status: Status,
}

pub struct CheckoutService {
    pub browser: Arc<Browser>,
    store: Store,
    private: AsyncMutex<Option<PrivateCheckout>>,
    unlocking: AsyncMutex<Option<PendingUnlock>>,
    traveler: AsyncMutex<Option<UnlockedTraveler>>,
    completed: Mutex<Option<CompletedView>>,
    broker_socket: PathBuf,
    broker_uid: u32,
    pub view_port: u16,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum IntakeResponse {
    Traveler {
        traveler: bloom_signer_api::TravelerPublic,
    },
    Prepared {
        ceremony_url: String,
    },
    Result {
        status: CardOperationStatus,
        receipt: Option<Box<CustodyResult>>,
        output_aad: Option<CustodyOutputHpkeAad>,
    },
    Error {
        #[serde(rename = "message")]
        _message: String,
    },
}

impl CheckoutService {
    /// One approval unlocks a saved traveler for the shopping website. The
    /// values stay in this process, are filled on request and are replaced by
    /// placeholders in everything the agent reads.
    async fn start_traveler(
        self: &Arc<Self>,
        operation_id: String,
        traveler_id: String,
    ) -> Result<Value> {
        OperationId::new(&operation_id).map_err(|_| anyhow::anyhow!("Invalid operation ID"))?;
        Token::new(&traveler_id).map_err(|_| anyhow::anyhow!("Invalid traveler ID"))?;
        let mut unlocking = self.unlocking.lock().await;
        if self.private.lock().await.is_some() || unlocking.is_some() {
            bail!("A checkout already has private control");
        }
        let metadata = match self
            .intake(json!({"method":"traveler_info","traveler_id":traveler_id}))
            .await?
        {
            IntakeResponse::Traveler { traveler }
                if traveler.traveler_id.as_str() == traveler_id =>
            {
                traveler
            }
            _ => bail!("Traveler metadata unavailable"),
        };
        let origin = self.browser.shopping_origin().await?;
        use rand::RngCore;
        let mut nonce = [0; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let scope = TravelerFillScope {
            origin: origin.clone(),
            frame_origins: vec![origin.clone()],
            document_binding: Digest32::from_bytes(nonce),
            fields: metadata.fields.clone(),
        };
        scope
            .validate()
            .map_err(|_| anyhow::anyhow!("Open the booking website before unlocking a traveler"))?;
        let mut status = Status {
            operation_id: operation_id.clone(),
            state: "requested".into(),
            ceremony_url: None,
            filled_fields: vec![],
            outcome: None,
        };
        self.store.insert(
            &status,
            "traveler",
            &format!("Unlock {} for {}", metadata.label, origin),
        )?;
        self.store
            .record_order(&operation_id, Some(&origin), None)?;
        let recipient = Recipient::generate();
        let challenge_url = format!("http://localhost:{}/unlocked", self.view_port);
        let response = self
            .intake(
                json!({"method":"traveler","operation_id":operation_id,"traveler_id":traveler_id,
            "scope":scope,"recipient_key":recipient.public,"challenge_url":challenge_url}),
            )
            .await;
        let Ok(IntakeResponse::Prepared { ceremony_url }) = response else {
            self.set_state(&operation_id, "failed_before_release");
            bail!("Traveler approval unavailable");
        };
        status.state = "awaiting_approval".into();
        status.ceremony_url = Some(ceremony_url);
        self.store.update(&status)?;
        *unlocking = Some(PendingUnlock {
            operation_id: operation_id.clone(),
            recipient,
            origin,
            fields: metadata.fields,
        });
        let service = self.clone();
        tokio::spawn(async move { service.finish_unlock(operation_id).await });
        Ok(serde_json::to_value(status)?)
    }

    async fn finish_unlock(self: Arc<Self>, operation_id: String) {
        // Approval links last fifteen minutes; wait a little past that.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(930);
        loop {
            tokio::time::sleep(Duration::from_millis(300)).await;
            if tokio::time::Instant::now() >= deadline {
                self.set_state(&operation_id, "expired");
                *self.unlocking.lock().await = None;
                return;
            }
            let state = match self
                .intake(json!({"method":"result","operation_id":operation_id}))
                .await
            {
                Ok(IntakeResponse::Result {
                    status,
                    receipt,
                    output_aad,
                }) => match status.state {
                    CardOperationState::Succeeded => {
                        let pending = self.unlocking.lock().await.take();
                        match self.open_unlock(pending, receipt, output_aad).await {
                            Ok(()) => return,
                            // Released but unusable: nothing reached a page.
                            Err(_) => "failed",
                        }
                    }
                    CardOperationState::Cancelled
                    | CardOperationState::Expired
                    | CardOperationState::Failed
                    | CardOperationState::Missing => "failed_before_release",
                    _ => continue,
                },
                _ => continue,
            };
            self.set_state(&operation_id, state);
            *self.unlocking.lock().await = None;
            return;
        }
    }

    async fn open_unlock(
        &self,
        pending: Option<PendingUnlock>,
        receipt: Option<Box<CustodyResult>>,
        aad: Option<CustodyOutputHpkeAad>,
    ) -> Result<()> {
        let pending = pending.context("Traveler unlock unavailable")?;
        let mut status = self.store.consume(&pending.operation_id)?;
        let receipt = receipt.context("Traveler release unavailable")?;
        let aad = aad.context("Traveler release binding unavailable")?;
        if receipt.custody_operation_id.as_str() != pending.operation_id
            || aad.custody_operation_id.as_str() != pending.operation_id
            || receipt.surface.as_ref() != Some(&aad.surface)
        {
            bail!("Traveler release binding mismatch");
        }
        let plaintext = zeroize::Zeroizing::new(
            pending.recipient.open(
                receipt
                    .encrypted_browser_result
                    .as_ref()
                    .context("Traveler release unavailable")?,
                &aad.canonical_bytes()
                    .map_err(|_| anyhow::anyhow!("Traveler release binding invalid"))?,
            )?,
        );
        let values: BTreeMap<String, zeroize::Zeroizing<String>> =
            serde_json::from_slice(&plaintext)
                .map_err(|_| anyhow::anyhow!("Invalid private traveler release"))?;
        // Choices such as gender are not identifying; names, numbers and
        // contact details are.
        self.browser.redact(
            values
                .iter()
                .filter(|(field, _)| !matches!(field.as_str(), "gender" | "document_kind"))
                .map(|(field, value)| (value.to_string(), format!("[saved {field}]")))
                .chain(
                    ["phone_national", "phone_local", "born_on_dmy"]
                        .into_iter()
                        .filter_map(|field| {
                            derived_traveler_value(&values, field)
                                .map(|value| (value.to_string(), format!("[saved {field}]")))
                        }),
                ),
        );
        status.filled_fields = values.keys().cloned().collect();
        *self.traveler.lock().await = Some(UnlockedTraveler {
            origin: pending.origin,
            context: self.browser.shopping_context().await,
            fields: pending.fields,
            values,
            expires: tokio::time::Instant::now() + Duration::from_secs(1800),
        });
        status.state = "unlocked".into();
        self.store.update(&status)?;
        Ok(())
    }

    async fn type_traveler(&self, element_ref: String, field: &str) -> Result<Value> {
        if self.private.lock().await.is_some() {
            bail!("A checkout already has private control");
        }
        let mut traveler = self.traveler.lock().await;
        let context = self.browser.shopping_context().await;
        // A finished checkout discards the context; the unlock goes with it.
        if traveler
            .as_ref()
            .is_some_and(|t| t.context != context || tokio::time::Instant::now() >= t.expires)
        {
            *traveler = None;
        }
        let traveler = traveler.as_ref().context("Unlock a saved traveler first")?;
        if self.browser.shopping_origin().await? != traveler.origin {
            bail!("Saved traveler details are unlocked for another website");
        }
        let text = derived_traveler_value(&traveler.values, field)
            .context("That saved traveler field is not available")?;
        if matches!(
            field,
            "gender" | "nationality" | "document_kind" | "document_country"
        ) {
            // A choice goes into a list: pick the option naming the saved value.
            self.browser
                .choose_traveler(&element_ref, field, &text)
                .await?;
        } else {
            self.browser
                .browse(BrowseRequest::Type {
                    element_ref,
                    text: text.to_string(),
                })
                .await?;
        }
        Ok(json!({"state":"typed","filled_fields":[field]}))
    }

    async fn fill_traveler(&self) -> Result<Value> {
        if self.private.lock().await.is_some() {
            bail!("A checkout already has private control");
        }
        let mut traveler = self.traveler.lock().await;
        let context = self.browser.shopping_context().await;
        // A finished checkout discards the context; the unlock goes with it.
        if traveler
            .as_ref()
            .is_some_and(|t| t.context != context || tokio::time::Instant::now() >= t.expires)
        {
            *traveler = None;
        }
        let traveler = traveler.as_ref().context("Unlock a saved traveler first")?;
        let mut values = traveler.values.clone();
        if let Some(phone) = values.get("phone").and_then(|p| formatted_phone(p)) {
            values.insert("phone".into(), zeroize::Zeroizing::new(phone));
        }
        let filled = self
            .browser
            .fill_traveler(&traveler.origin, &traveler.fields, &values)
            .await
            .inspect_err(|e| eprintln!("traveler fill refused: {e:#}"))?;
        Ok(json!({"state":"filled","filled_fields":filled}))
    }

    pub fn new(
        browser: Arc<Browser>,
        state: &Path,
        broker_socket: PathBuf,
        broker_uid: u32,
        view_port: u16,
    ) -> Result<Arc<Self>> {
        if view_port == 0 {
            bail!("Private view port must be explicit");
        }
        let store = Store::open(state)?;
        Ok(Arc::new(Self {
            browser,
            store,
            private: AsyncMutex::new(None),
            unlocking: AsyncMutex::new(None),
            traveler: AsyncMutex::new(None),
            completed: Mutex::new(None),
            broker_socket,
            broker_uid,
            view_port,
        }))
    }

    async fn intake(&self, request: Value) -> Result<IntakeResponse> {
        let stream = tokio::net::UnixStream::connect(&self.broker_socket)
            .await
            .context("Checkout authorization service unavailable")?;
        if stream.peer_cred()?.uid() != self.broker_uid {
            bail!("Checkout authorization peer rejected");
        }
        let (reader, mut writer) = stream.into_split();
        let mut bytes = serde_json::to_vec(&request)?;
        bytes.push(b'\n');
        writer.write_all(&bytes).await?;
        let mut line = String::new();
        tokio::time::timeout(
            Duration::from_secs(15),
            BufReader::new(reader.take(32769)).read_line(&mut line),
        )
        .await??;
        if line.len() > 32768 {
            bail!("Checkout authorization response exceeds limit");
        }
        let response: IntakeResponse = serde_json::from_str(&line)?;
        if let IntakeResponse::Error { .. } = response {
            bail!("Checkout authorization request rejected");
        }
        Ok(response)
    }

    pub async fn request(self: &Arc<Self>, request: Request) -> Result<Value> {
        match request {
            Request::Traveler {
                operation_id,
                traveler_id,
            } => self.start_traveler(operation_id, traveler_id).await,
            Request::Browse {
                request: BrowseRequest::FillTraveler,
            } => self.fill_traveler().await,
            Request::Browse {
                request: BrowseRequest::TypeTraveler { element_ref, field },
            } => self.type_traveler(element_ref, &field).await,
            Request::Browse { request } => self.browser.browse(request).await,
            Request::Status { operation_id } => {
                Ok(serde_json::to_value(self.store.get(&operation_id)?)?)
            }
            Request::History => Ok(serde_json::to_value(self.store.history()?)?),
            Request::Checkout {
                operation_id,
                card_id,
                agent_description,
                take_over,
            } => {
                OperationId::new(&operation_id)
                    .map_err(|_| anyhow::anyhow!("Invalid operation ID"))?;
                if let Some(card_id) = &card_id {
                    Token::new(card_id).map_err(|_| anyhow::anyhow!("Invalid card ID"))?;
                }
                let mode = match (&card_id, take_over) {
                    (Some(_), true) => bail!("A take-over does not use a card"),
                    (Some(_), false) => Mode::Card,
                    (None, false) => Mode::Site,
                    (None, true) => Mode::TakeOver,
                };
                if agent_description.len() > 1024 {
                    bail!("Description exceeds limit");
                }
                let mut private = self.private.lock().await;
                if private.is_some() {
                    bail!("A checkout already has private control");
                }
                let mut status = Status {
                    operation_id: operation_id.clone(),
                    state: "requested".into(),
                    ceremony_url: None,
                    filled_fields: Vec::new(),
                    outcome: None,
                };
                if matches!(mode, Mode::Card | Mode::Site) {
                    // Ask for payment only once the page accepts what was entered.
                    let attention = self.browser.page_attention().await.unwrap_or_default();
                    let errors: Vec<&str> = attention["errors"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .collect();
                    if !errors.is_empty() || attention["invalid"].as_u64().unwrap_or(0) > 0 {
                        eprintln!("payment refused over form errors: {attention}");
                        bail!(
                            "The page shows form errors; fix them before payment: {}",
                            if errors.is_empty() {
                                "a field is marked invalid".into()
                            } else {
                                errors.join(" / ")
                            }
                        );
                    }
                }
                let kind = match mode {
                    Mode::Card => "card",
                    Mode::Site => "site",
                    Mode::TakeOver => "take_over",
                };
                self.store.insert(&status, kind, &agent_description)?;
                let tab = self.browser.handoff().await?;
                status.state = "preparing".into();
                self.store.update(&status)?;
                let discovery = match mode {
                    Mode::Card => match Discovery::read(&tab).await {
                        Ok(discovery) => Some(discovery),
                        // The reason is generic text, never page or card content.
                        Err(error) => {
                            eprintln!("payment page needs the private view: {error:#}");
                            None
                        }
                    },
                    Mode::Site => Discovery::read_site(&tab).await.ok(),
                    Mode::TakeOver => None,
                };
                let shop = match &discovery {
                    Some(discovery) => Some(discovery.facts.origin.clone()),
                    None => tab_url(&tab)
                        .await
                        .and_then(|url| url::Url::parse(&url).ok())
                        .map(|url| url.origin().ascii_serialization()),
                };
                self.store.record_order(
                    &operation_id,
                    shop.as_deref(),
                    discovery
                        .as_ref()
                        .map(|d| (d.facts.total_minor, d.facts.currency.as_str())),
                )?;
                let recipient =
                    (mode == Mode::Card && discovery.is_some()).then(Recipient::generate);
                use rand::RngCore;
                let mut token = [0; 32];
                rand::thread_rng().fill_bytes(&mut token);
                let capability = hex_token(&token);
                let challenge_url =
                    challenge_url(self.view_port, &capability, tab.extension.is_some());
                let request = match (&discovery, &recipient) {
                    (Some(discovery), Some(recipient)) => {
                        json!({"method":"prepare","operation_id":operation_id,"card_id":card_id,
                        "facts":discovery.facts,"recipient_key":recipient.public,
                        "agent_description":agent_description,"challenge_url":challenge_url,
                        "order_preview":crate::discovery::order_preview(&tab).await,
                        "order_fields":crate::discovery::order_fields(&tab).await})
                    }
                    (Some(discovery), None) => {
                        json!({"method":"site","operation_id":operation_id,
                        "facts":discovery.facts,"agent_description":agent_description,
                        "challenge_url":challenge_url,
                        "order_preview":crate::discovery::order_preview(&tab).await,
                        "order_fields":crate::discovery::order_fields(&tab).await})
                    }
                    _ => json!({"method":"manual","operation_id":operation_id,"card_id":card_id,
                        "agent_description":agent_description,"challenge_url":challenge_url}),
                };
                match self.intake(request).await {
                    Ok(IntakeResponse::Prepared { ceremony_url }) => {
                        status.state = "awaiting_approval".into();
                        status.ceremony_url = Some(ceremony_url);
                        self.store.update(&status)?;
                        *private = Some(PrivateCheckout {
                            operation_id: operation_id.clone(),
                            mode,
                            view_target: tab.target.clone(),
                            view_session: tab.session.clone(),
                            seen_pages: std::collections::HashSet::from([tab.target.clone()]),
                            tab,
                            discovery,
                            recipient,
                            capability,
                            claimed: false,
                            approved: false,
                            manual_submission: false,
                        });
                        let service = self.clone();
                        tokio::spawn(async move {
                            service.finish_approved(operation_id).await;
                        });
                        Ok(serde_json::to_value(status)?)
                    }
                    _ => {
                        status.state = "failed_before_release".into();
                        self.store.update(&status)?;
                        self.browser.return_control().await?;
                        Ok(serde_json::to_value(status)?)
                    }
                }
            }
            Request::Cancel { operation_id } => {
                let mut private = self.private.lock().await;
                if private
                    .as_ref()
                    .is_none_or(|p| p.operation_id != operation_id)
                {
                    bail!("Checkout not active");
                }
                let status = self.store.get(&operation_id)?;
                if status.state != "awaiting_approval" {
                    bail!("Release may have started; inspect the private view instead");
                }
                let response = self
                    .intake(json!({"method":"cancel","operation_id":operation_id}))
                    .await?;
                if !matches!(
                    response,
                    IntakeResponse::Result {
                        status: CardOperationStatus {
                            state: CardOperationState::Cancelled,
                            ..
                        },
                        ..
                    }
                ) {
                    bail!("Approval may already have completed; cancellation is not confirmed");
                }
                let mut status = status;
                status.state = "cancelled".into();
                status.ceremony_url = None;
                self.store.update(&status)?;
                self.browser.return_control().await?;
                *private = None;
                Ok(serde_json::to_value(status)?)
            }
        }
    }

    async fn finish_approved(self: Arc<Self>, operation_id: String) {
        // Approval links last fifteen minutes; wait a little past that.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(930);
        loop {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let mut private = self.private.lock().await;
            let Some(checkout) = private.as_mut().filter(|p| p.operation_id == operation_id) else {
                return;
            };
            if let Ok(IntakeResponse::Result {
                status,
                receipt,
                output_aad,
            }) = self
                .intake(json!({"method":"result","operation_id":operation_id}))
                .await
            {
                match status.state {
                    CardOperationState::Succeeded => {
                        checkout.approved = true;
                        let result = self.consume_and_fill(checkout, receipt, output_aad).await;
                        if result.is_err() {
                            self.set_state(&operation_id, "disclosure_unknown");
                        }
                        drop(private);
                        self.watch_outcome(operation_id).await;
                        return;
                    }
                    CardOperationState::Cancelled
                    | CardOperationState::Expired
                    | CardOperationState::Failed
                    | CardOperationState::Missing => {
                        self.set_state(&operation_id, "failed_before_release");
                        if self.browser.return_control().await.is_ok() {
                            *private = None;
                        }
                        return;
                    }
                    _ => {}
                }
            }
            if tokio::time::Instant::now() >= deadline {
                self.set_state(&operation_id, "expired");
                if self.browser.return_control().await.is_ok() {
                    *private = None;
                }
                return;
            }
        }
    }

    fn set_state(&self, id: &str, state: &str) {
        if let Ok(mut status) = self.store.get(id) {
            status.state = state.into();
            status.ceremony_url = None;
            let _ = self.store.update(&status);
        }
    }

    async fn consume_and_fill(
        &self,
        checkout: &mut PrivateCheckout,
        receipt: Option<Box<CustodyResult>>,
        aad: Option<CustodyOutputHpkeAad>,
    ) -> Result<()> {
        let Some(discovery) = &checkout.discovery else {
            // Unclear payment facts leave the human to finish in the private view.
            let state = if checkout.mode == Mode::TakeOver {
                "human_control"
            } else {
                "manual_required"
            };
            self.set_state(&checkout.operation_id, state);
            return Ok(());
        };
        let mut status = self.store.consume(&checkout.operation_id)?; // Durable before plaintext.
        if checkout.mode == Mode::Site {
            // Record the submission attempt first; a lost response must not cause a second click.
            status.state = "submitted".into();
            self.store.update(&status)?;
            match discovery.submit(&checkout.tab).await {
                Ok(true) => {}
                Ok(false) => {
                    status.state = "needs_input".into();
                    self.store.update(&status)?;
                }
                Err(_) => {
                    status.state = "uncertain".into();
                    self.store.update(&status)?;
                }
            }
            return Ok(());
        }
        discovery.recheck(&checkout.tab).await?;
        let key = checkout
            .recipient
            .take()
            .context("Recipient already consumed")?;
        let receipt = receipt.context("Disclosure receipt unavailable; do not retry")?;
        let aad = aad.context("Missing release binding")?;
        if receipt.custody_operation_id.as_str() != checkout.operation_id
            || aad.custody_operation_id.as_str() != checkout.operation_id
            || receipt.surface.as_ref() != Some(&aad.surface)
        {
            bail!("Release binding mismatch");
        }
        let plaintext = key.open(
            receipt
                .encrypted_browser_result
                .as_ref()
                .context("Missing card release")?,
            &aad.canonical_bytes()
                .map_err(|_| anyhow::anyhow!("Invalid release binding"))?,
        )?;
        let card = serde_json::from_slice(&plaintext).context("Invalid card release")?;
        if discovery
            .fill(&checkout.tab, &card, &mut status.filled_fields)
            .await
            .is_err()
        {
            status.state = if status.filled_fields.is_empty() {
                "disclosure_unknown"
            } else {
                "partially_filled"
            }
            .into();
            self.store.update(&status)?;
            return Ok(());
        }
        drop(card);
        drop(plaintext);
        status.state = "filled".into();
        self.store.update(&status)?;
        // Rehearsals with made-up cards on live sites stop before paying.
        #[cfg(feature = "triad-dev-harness")]
        if std::env::var_os("BLOOM_CHECKOUT_REHEARSAL_NO_SUBMIT").is_some() {
            return Ok(());
        }
        // Record the submission attempt first; a lost response must not cause a second click.
        status.state = "submitted".into();
        self.store.update(&status)?;
        match discovery.submit(&checkout.tab).await {
            Ok(true) => {}
            Ok(false) => {
                status.state = "needs_input".into();
                self.store.update(&status)?;
            }
            Err(_) => {
                status.state = "uncertain".into();
                self.store.update(&status)?;
            }
        }
        // Outcome watching and private user interaction are handled by the view worker.
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ViewAction {
    Click { x: f64, y: f64 },
    Type { text: String },
    Key { key: String },
    Scroll { x: f64, y: f64, delta_y: f64 },
    SelectPage { target: String },
    Finish,
}

fn authorize_view(checkout: &PrivateCheckout, token: &str) -> Result<()> {
    if !checkout.approved || !checkout.claimed || !same_token(&checkout.capability, token) {
        bail!("Private user view rejected");
    }
    Ok(())
}
fn same_token(expected: &str, received: &str) -> bool {
    if expected.len() != received.len() {
        return false;
    }
    expected
        .bytes()
        .zip(received.bytes())
        .fold(0, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn challenge_url(view_port: u16, capability: &str, extension: bool) -> String {
    if extension {
        format!("http://localhost:{view_port}/extension")
    } else {
        format!("http://localhost:{view_port}/private?token={capability}")
    }
}

impl CheckoutService {
    fn retain_completed(&self, checkout: &PrivateCheckout, status: Status) {
        *self.completed.lock() = Some(CompletedView {
            capability: checkout.capability.clone(),
            claimed: checkout.claimed,
            status,
        });
    }

    // Only pages descended from the held checkout belong to the private view.
    // A bank may open a popup; never switch to unrelated browser targets.
    async fn list_private_pages(tab: &PrivateTab) -> Result<Vec<Value>> {
        let targets = tab.cdp.call(None, "Target.getTargets", json!({})).await?;
        let infos = targets["targetInfos"]
            .as_array()
            .context("Missing private pages")?;
        let mut owned = std::collections::HashSet::from([tab.target.clone()]);
        loop {
            let count = owned.len();
            for info in infos {
                if info["type"] == "page"
                    && info["openerId"].as_str().is_some_and(|p| owned.contains(p))
                {
                    if let Some(id) = info["targetId"].as_str() {
                        owned.insert(id.to_owned());
                    }
                }
            }
            if owned.len() == count {
                break;
            }
        }
        let mut pages = Vec::new();
        for info in infos {
            let Some(id) = info["targetId"].as_str().filter(|id| owned.contains(*id)) else {
                continue;
            };
            let origin = url::Url::parse(info["url"].as_str().unwrap_or(""))
                .ok()
                .map(|u| u.origin().ascii_serialization())
                .unwrap_or_else(|| "Loading".into());
            pages.push(json!({"target":id,"origin":origin}));
        }
        Ok(pages)
    }

    async fn prepare_private_page(tab: &PrivateTab, target: &str) -> Result<String> {
        let session = if target == tab.target {
            tab.session.clone()
        } else {
            let attachment = tab
                .cdp
                .call(
                    None,
                    "Target.attachToTarget",
                    json!({"targetId":target,"flatten":true}),
                )
                .await?;
            attachment["sessionId"]
                .as_str()
                .context("Private page closed")?
                .to_owned()
        };
        tab.cdp
            .call(Some(&session), "Page.enable", json!({}))
            .await?;
        tab.cdp
            .call(
                Some(&session),
                "Emulation.setDeviceMetricsOverride",
                json!({"width":1280,"height":900,"deviceScaleFactor":1,"mobile":false}),
            )
            .await?;
        tab.cdp
            .call(Some(&session), "Page.bringToFront", json!({}))
            .await?;
        Ok(session)
    }

    async fn watch_outcome(&self, id: String) {
        let started = tokio::time::Instant::now();
        let mut copied_contact = false;
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            // Outcome polling must not own the private-view lock while Chromium
            // is slow. Copy the stable browser handles, then do bounded calls.
            let (mode, tab, view_target) = {
                let private = self.private.lock().await;
                let Some(checkout) = private.as_ref().filter(|p| p.operation_id == id) else {
                    return;
                };
                (
                    checkout.mode,
                    checkout.tab.clone(),
                    checkout.view_target.clone(),
                )
            };
            let Ok(mut status) = self.store.get(&id) else {
                return;
            };
            // A take-over may include a login with an emailed or texted code;
            // a payment may need a bank check or a correction from the human.
            let deadline = started + Duration::from_secs(900);
            if matches!(
                status.state.as_str(),
                "submitted"
                    | "needs_input"
                    | "manual_required"
                    | "uncertain"
                    | "partially_filled"
                    | "disclosure_unknown"
            ) {
                let mut observed = Vec::new();
                if tab.extension.is_some() {
                    use crate::discovery::{Script, run};
                    let outcome = tokio::time::timeout(
                        Duration::from_secs(5),
                        run(&tab, "", 0, Script::AttentionOutcome),
                    )
                    .await
                    .ok()
                    .and_then(Result::ok);
                    if let Some(outcome) = outcome {
                        if outcome["reason"] == "confirm_contact" && !copied_contact {
                            copied_contact = true;
                            let _ = tokio::time::timeout(
                                Duration::from_secs(5),
                                run(&tab, "", 0, Script::ConfirmContact),
                            )
                            .await;
                        }
                        observed.push(outcome);
                    }
                }
                let contexts = if tab.extension.is_some() {
                    Vec::new()
                } else {
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        tab.cdp.contexts(&tab.session, "bloom-outcome"),
                    )
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or_default()
                };
                for context in contexts {
                    let expression = concat!(
                        include_str!("form-attention.js"),
                        ";",
                        include_str!("outcome.js")
                    );
                    let result = tokio::time::timeout(
                        Duration::from_secs(2),
                        tab.cdp.call(Some(&context.session),"Runtime.evaluate",json!({"contextId":context.world,"expression":expression,"returnByValue":true})),
                    ).await.ok().and_then(Result::ok);
                    let Some(result) = result else {
                        continue;
                    };
                    let outcome = result["result"]["value"].clone();
                    if outcome["reason"] == "confirm_contact" && !copied_contact {
                        // Copy the contact email and phone already on the page into
                        // the re-entry fields; the human checks them and confirms.
                        copied_contact = true;
                        let _ = tokio::time::timeout(
                            Duration::from_secs(2),
                            tab.cdp.call(Some(&context.session),"Runtime.evaluate",
                                json!({"contextId":context.world,"expression":include_str!("confirm-contact.js"),"returnByValue":true})),
                        ).await;
                    }
                    observed.push(outcome);
                }
                let outcome = observed
                    .iter()
                    .find(|outcome| {
                        matches!(
                            outcome["state"].as_str(),
                            Some("booked" | "paid" | "declined")
                        )
                    })
                    .or_else(|| {
                        observed
                            .iter()
                            .find(|outcome| outcome["state"] == "needs_input")
                    });
                if let Some(outcome) = outcome {
                    let state = outcome["state"].as_str().unwrap();
                    if state == "needs_input" {
                        // Not paid: the human corrects the page in the private view.
                        // Serialize with the manual retry marker: whichever
                        // happens last leaves the durable state conservative.
                        let private = self.private.lock().await;
                        let manually_retried = private
                            .as_ref()
                            .filter(|checkout| checkout.operation_id == id)
                            .is_some_and(|checkout| checkout.manual_submission);
                        if !manually_retried && status.state != state {
                            status.state = state.into();
                            status.ceremony_url = None;
                            let _ = self.store.update(&status);
                        }
                    } else {
                        status.state = state.into();
                        status.outcome = serde_json::from_value(outcome.clone()).ok();
                        status.ceremony_url = None;
                        if self.store.update(&status).is_ok()
                            && self.browser.return_control().await.is_ok()
                        {
                            let mut private = self.private.lock().await;
                            if let Some(checkout) =
                                private.as_ref().filter(|p| p.operation_id == id)
                            {
                                self.retain_completed(checkout, status);
                                *private = None;
                            }
                        }
                        return;
                    }
                }
            }
            if tokio::time::Instant::now() >= deadline {
                // Only a plain take-over resumes its page; a session that held
                // traveler data is discarded with its browsing context.
                let resume = if mode == Mode::TakeOver {
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        tab.cdp.call(
                            None,
                            "Target.getTargetInfo",
                            json!({"targetId":view_target}),
                        ),
                    )
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .and_then(|target| target["targetInfo"]["url"].as_str().map(str::to_owned))
                } else {
                    None
                };
                if self
                    .browser
                    .return_control_at(&view_target, resume)
                    .await
                    .is_ok()
                {
                    let final_state = if status.state == "needs_input" {
                        "not_submitted"
                    } else if mode == Mode::TakeOver {
                        "returned"
                    } else {
                        "uncertain"
                    };
                    self.set_state(&id, final_state);
                    if let Ok(status) = self.store.get(&id) {
                        let mut private = self.private.lock().await;
                        if let Some(checkout) = private.as_ref().filter(|p| p.operation_id == id) {
                            self.retain_completed(checkout, status);
                            *private = None;
                        }
                    }
                }
                return;
            }
        }
    }

    pub async fn private_claim(&self, token: &str) -> Result<()> {
        for _ in 0..20 {
            {
                let mut private = self.private.lock().await;
                let Some(checkout) = private.as_mut() else {
                    let mut completed = self.completed.lock();
                    let completed = completed.as_mut().context("No private checkout")?;
                    if !same_token(&completed.capability, token) || completed.claimed {
                        bail!("Private view capability rejected");
                    }
                    completed.claimed = true;
                    return Ok(());
                };
                if !same_token(&checkout.capability, token) || checkout.claimed {
                    bail!("Private view capability rejected");
                }
                if checkout.approved {
                    checkout.claimed = true;
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        bail!("Private checkout approval not complete")
    }

    fn completed_private_state(&self, token: &str) -> Result<Value> {
        let completed = self.completed.lock();
        let completed = completed
            .as_ref()
            .filter(|c| c.claimed && same_token(&c.capability, token))
            .context("Private view rejected")?;
        Ok(
            json!({"state":completed.status.state,"outcome":completed.status.outcome,"closed":true,"pages":[]}),
        )
    }

    pub async fn private_state(&self, token: &str) -> Result<Value> {
        let (operation_id, tab, original_target, original_session, seen_pages) = {
            let private = self.private.lock().await;
            let Some(checkout) = private.as_ref() else {
                return self.completed_private_state(token);
            };
            authorize_view(checkout, token)?;
            (
                checkout.operation_id.clone(),
                checkout.tab.clone(),
                checkout.view_target.clone(),
                checkout.view_session.clone(),
                checkout.seen_pages.clone(),
            )
        };
        let pages = tokio::time::timeout(Duration::from_secs(2), Self::list_private_pages(&tab))
            .await
            .map_err(|_| anyhow::anyhow!("Private page is still loading"))??;
        let mut selected = pages
            .iter()
            .filter(|page| page["origin"] != "Loading")
            .filter_map(|page| page["target"].as_str())
            .rfind(|target| !seen_pages.contains(*target))
            .map(str::to_owned);
        if !pages.iter().any(|page| page["target"] == original_target) {
            selected = Some(tab.target.clone());
        }
        let prepared = if let Some(target) = selected {
            let session = tokio::time::timeout(
                Duration::from_secs(2),
                Self::prepare_private_page(&tab, &target),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Private page is still loading"))??;
            Some((target, session))
        } else {
            None
        };
        let selected_page = {
            let mut private = self.private.lock().await;
            let Some(checkout) = private
                .as_mut()
                .filter(|checkout| checkout.operation_id == operation_id)
            else {
                return self.completed_private_state(token);
            };
            authorize_view(checkout, token)?;
            for page in &pages {
                if page["origin"] != "Loading"
                    && let Some(target) = page["target"].as_str()
                {
                    checkout.seen_pages.insert(target.to_owned());
                }
            }
            if checkout.view_target == original_target
                && checkout.view_session == original_session
                && let Some((target, session)) = prepared
            {
                checkout.view_target = target;
                checkout.view_session = session;
            }
            checkout.view_target.clone()
        };
        let status = self.store.get(&operation_id)?;
        Ok(
            json!({"state":status.state,"outcome":status.outcome,"pages":pages,"selected_page":selected_page,"closed":false}),
        )
    }

    pub async fn private_screenshot(&self, token: &str) -> Result<Vec<u8>> {
        // Copy what the capture needs and release the lock: a page that never
        // paints must not stall the rest of the private view.
        let (cdp, session) = {
            let private = self.private.lock().await;
            let checkout = private.as_ref().context("No active private checkout")?;
            authorize_view(checkout, token)?;
            (checkout.tab.cdp.clone(), checkout.view_session.clone())
        };
        let bounded = |method: &'static str, params: Value| {
            let (cdp, session) = (cdp.clone(), session.clone());
            async move {
                tokio::time::timeout(
                    Duration::from_secs(5),
                    cdp.call(Some(&session), method, params),
                )
                .await
                .map_err(|_| anyhow::anyhow!("Private page is still loading"))?
            }
        };
        // The initial handoff may not have switched pages. Activate the held
        // page before capture so a background headless tab paints as well.
        bounded("Page.bringToFront", json!({})).await?;
        let result = bounded(
            "Page.captureScreenshot",
            json!({"format":"png","captureBeyondViewport":false}),
        )
        .await?;
        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD.decode(
            result["data"]
                .as_str()
                .context("Missing private screenshot")?,
        )?)
    }

    pub async fn private_action(&self, token: &str, action: ViewAction) -> Result<()> {
        match action {
            ViewAction::Click { x, y } => {
                if !x.is_finite()
                    || !y.is_finite()
                    || !(0.0..=1280.0).contains(&x)
                    || !(0.0..=900.0).contains(&y)
                {
                    bail!("Invalid private pointer");
                }
                let (tab, session, operation_id, discovery) = {
                    let private = self.private.lock().await;
                    let checkout = private.as_ref().context("No active private checkout")?;
                    authorize_view(checkout, token)?;
                    (
                        checkout.tab.clone(),
                        checkout.view_session.clone(),
                        checkout.operation_id.clone(),
                        checkout.discovery.clone(),
                    )
                };
                if let Some(discovery) = discovery.filter(|d| d.facts_session == session) {
                    let payment = tokio::time::timeout(
                        Duration::from_secs(2),
                        discovery.is_submit_point(&tab, x, y),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("Private page is still loading"))??;
                    if payment {
                        let mut status = self.store.get(&operation_id)?;
                        if status.state != "needs_input" {
                            bail!("Payment was already attempted; do not click it again");
                        }
                        tokio::time::timeout(Duration::from_secs(2), discovery.recheck(&tab))
                            .await
                            .map_err(|_| anyhow::anyhow!("Private page is still loading"))??;
                        {
                            let mut private = self.private.lock().await;
                            let checkout = private
                                .as_mut()
                                .filter(|checkout| checkout.operation_id == operation_id)
                                .context("Private checkout changed")?;
                            authorize_view(checkout, token)?;
                            checkout.manual_submission = true;
                        }
                        // The next browser input may submit. Persist that fact first.
                        status.state = "submitted".into();
                        status.outcome = None;
                        self.store.update(&status)?;
                    }
                }
                for kind in ["mousePressed", "mouseReleased"] {
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        tab.cdp.call(
                            Some(&session),
                            "Input.dispatchMouseEvent",
                            json!({"type":kind,"x":x,"y":y,"button":"left","clickCount":1}),
                        ),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("Private page is still loading"))??;
                }
            }
            ViewAction::Type { text } => {
                if text.len() > 4096 {
                    bail!("Private input exceeds limit");
                }
                let (cdp, session) = {
                    let private = self.private.lock().await;
                    let checkout = private.as_ref().context("No active private checkout")?;
                    authorize_view(checkout, token)?;
                    (checkout.tab.cdp.clone(), checkout.view_session.clone())
                };
                let text = zeroize::Zeroizing::new(text);
                tokio::time::timeout(
                    Duration::from_secs(2),
                    cdp.call(
                        Some(&session),
                        "Input.insertText",
                        json!({"text":text.as_str()}),
                    ),
                )
                .await
                .map_err(|_| anyhow::anyhow!("Private page is still loading"))??;
            }
            ViewAction::Key { key } => {
                let key_code = match key.as_str() {
                    "Tab" => 9,
                    "Enter" => 13,
                    "Backspace" => 8,
                    "Escape" => 27,
                    "ArrowDown" => 40,
                    "ArrowUp" => 38,
                    _ => bail!("Unsupported private key"),
                };
                let (tab, session, operation_id, discovery) = {
                    let private = self.private.lock().await;
                    let checkout = private.as_ref().context("No active private checkout")?;
                    authorize_view(checkout, token)?;
                    (
                        checkout.tab.clone(),
                        checkout.view_session.clone(),
                        checkout.operation_id.clone(),
                        checkout.discovery.clone(),
                    )
                };
                if key == "Enter"
                    && discovery
                        .as_ref()
                        .is_some_and(|d| d.facts_session == session)
                {
                    let mut status = self.store.get(&operation_id)?;
                    if status.state != "needs_input" {
                        bail!("Payment was already attempted; do not submit it again");
                    }
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        discovery.as_ref().unwrap().recheck(&tab),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("Private page is still loading"))??;
                    {
                        let mut private = self.private.lock().await;
                        let checkout = private
                            .as_mut()
                            .filter(|checkout| checkout.operation_id == operation_id)
                            .context("Private checkout changed")?;
                        authorize_view(checkout, token)?;
                        checkout.manual_submission = true;
                    }
                    status.state = "submitted".into();
                    status.outcome = None;
                    self.store.update(&status)?;
                }
                for kind in ["keyDown", "keyUp"] {
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        tab.cdp.call(
                            Some(&session),
                            "Input.dispatchKeyEvent",
                            json!({"type":kind,"key":key,"code":key,
                                "windowsVirtualKeyCode":key_code,
                                "text":if key == "Enter" && kind == "keyDown" {"\r"} else {""}}),
                        ),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("Private page is still loading"))??;
                }
            }
            ViewAction::Scroll { x, y, delta_y } => {
                if !x.is_finite()
                    || !y.is_finite()
                    || !delta_y.is_finite()
                    || !(0.0..=1280.0).contains(&x)
                    || !(0.0..=900.0).contains(&y)
                    || delta_y.abs() > 3000.0
                {
                    bail!("Invalid private scroll");
                }
                let (cdp, session) = {
                    let private = self.private.lock().await;
                    let checkout = private.as_ref().context("No active private checkout")?;
                    authorize_view(checkout, token)?;
                    (checkout.tab.cdp.clone(), checkout.view_session.clone())
                };
                tokio::time::timeout(
                    Duration::from_secs(2),
                    cdp.call(
                        Some(&session),
                        "Input.dispatchMouseEvent",
                        json!({"type":"mouseWheel","x":x,"y":y,"deltaX":0,"deltaY":delta_y}),
                    ),
                )
                .await
                .map_err(|_| anyhow::anyhow!("Private page is still loading"))??;
            }
            ViewAction::SelectPage { target } => {
                let (operation_id, tab) = {
                    let private = self.private.lock().await;
                    let checkout = private.as_ref().context("No active private checkout")?;
                    authorize_view(checkout, token)?;
                    (checkout.operation_id.clone(), checkout.tab.clone())
                };
                let pages =
                    tokio::time::timeout(Duration::from_secs(2), Self::list_private_pages(&tab))
                        .await
                        .map_err(|_| anyhow::anyhow!("Private page is still loading"))??;
                if !pages.iter().any(|p| p["target"] == target) {
                    bail!("Unknown private page");
                }
                let session = tokio::time::timeout(
                    Duration::from_secs(2),
                    Self::prepare_private_page(&tab, &target),
                )
                .await
                .map_err(|_| anyhow::anyhow!("Private page is still loading"))??;
                let mut private = self.private.lock().await;
                let checkout = private
                    .as_mut()
                    .filter(|checkout| checkout.operation_id == operation_id)
                    .context("Private checkout changed")?;
                authorize_view(checkout, token)?;
                checkout.seen_pages.insert(target.clone());
                checkout.view_target = target;
                checkout.view_session = session;
            }
            ViewAction::Finish => {
                let (operation_id, mode, tab, view_target) = {
                    let private = self.private.lock().await;
                    let checkout = private.as_ref().context("No active private checkout")?;
                    authorize_view(checkout, token)?;
                    (
                        checkout.operation_id.clone(),
                        checkout.mode,
                        checkout.tab.clone(),
                        checkout.view_target.clone(),
                    )
                };
                if mode == Mode::TakeOver {
                    let resume = tokio::time::timeout(
                        Duration::from_secs(2),
                        tab.cdp.call(
                            None,
                            "Target.getTargetInfo",
                            json!({"targetId":view_target}),
                        ),
                    )
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .and_then(|target| target["targetInfo"]["url"].as_str().map(str::to_owned));
                    self.browser.return_control_at(&view_target, resume).await?;
                    self.set_state(&operation_id, "returned");
                } else {
                    let state = if mode == Mode::TakeOver {
                        "returned"
                    } else if self.store.get(&operation_id)?.state == "needs_input" {
                        "not_submitted"
                    } else {
                        "uncertain"
                    };
                    self.set_state(&operation_id, state);
                    self.browser.return_control().await?;
                }
                let mut private = self.private.lock().await;
                if let Some(checkout) = private
                    .as_ref()
                    .filter(|checkout| checkout.operation_id == operation_id)
                {
                    self.retain_completed(checkout, self.store.get(&operation_id)?);
                    *private = None;
                }
            }
        }
        Ok(())
    }
}

async fn tab_url(tab: &PrivateTab) -> Option<String> {
    if tab.extension.is_some() {
        return crate::discovery::extension_url(tab).await.ok();
    }
    let info = tab
        .cdp
        .call(None, "Target.getTargetInfo", json!({"targetId":tab.target}))
        .await
        .ok()?;
    info["targetInfo"]["url"].as_str().map(str::to_owned)
}

fn hex_token(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The login principal has this narrow API, never the private browser channel.
pub async fn serve_api(service: Arc<CheckoutService>, path: &Path, machine_uid: u32) -> Result<()> {
    let listener = bloom_service_activation::bind_owned_unix_listener(path)?;
    let listener = tokio::net::UnixListener::from_std(listener)?;
    let quota = Arc::new(tokio::sync::Semaphore::new(16));
    loop {
        let (stream, _) = listener.accept().await?;
        if stream.peer_cred()?.uid() != machine_uid {
            continue;
        }
        let Ok(slot) = quota.clone().try_acquire_owned() else {
            continue;
        };
        let service = service.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let (reader, mut writer) = stream.into_split();
            let mut line = String::new();
            if !matches!(
                tokio::time::timeout(
                    Duration::from_secs(10),
                    BufReader::new(reader.take(16385)).read_line(&mut line)
                )
                .await,
                Ok(Ok(_))
            ) || line.len() > 16384
            {
                return;
            }
            let response = match serde_json::from_str(&line) {
                Ok(request) => {
                    let browse = matches!(request, Request::Browse { .. });
                    match service.request(request).await {
                        Ok(value) => value,
                        // Browse errors are Bloom's own guidance strings; anything else
                        // (CDP or page-derived text) stays generic.
                        Err(error) if browse => {
                            let message = error.to_string();
                            json!({"error": if BROWSE_ERRORS.contains(&message.as_str()) {
                                message
                            } else {
                                "The page could not be read or changed; open it again or request a new snapshot".into()
                            }})
                        }
                        Err(_) => {
                            json!({"error":"Checkout request rejected or unavailable. Check status before retrying."})
                        }
                    }
                }
                Err(_) => json!({"error":"Invalid checkout request"}),
            };
            if let Ok(mut bytes) = serde_json::to_vec(&response) {
                bytes.push(b'\n');
                let _ = writer.write_all(&bytes).await;
            }
        });
    }
}

const BROWSE_ERRORS: &[&str] = &[
    "Invalid browsing URL",
    "Only ordinary HTTP(S) shopping URLs are supported",
    "Only ordinary shopping documents can be observed",
    "Shopping document changed; request a new snapshot",
    "Invalid element reference",
    "Stale element reference; request a new snapshot",
    "Input exceeds limit",
    "Checkout has private control; shopping is paused",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_checkout_keeps_the_person_in_the_bloom_tab() {
        assert_eq!(
            challenge_url(8123, "secret", true),
            "http://localhost:8123/extension"
        );
        assert_eq!(
            challenge_url(8123, "secret", false),
            "http://localhost:8123/private?token=secret"
        );
    }
    #[tokio::test]
    async fn airline_confirmation_becomes_booked_with_its_code() {
        let (url, server) = crate::discovery::tests::fixture(
            "<p data-bloom-total-minor='21730759' data-bloom-currency='ARS'>Total ARS 217307.59</p>
             <input autocomplete='cc-number'><input autocomplete='cc-exp'><input autocomplete='cc-csc'>
             <button>Pagar</button><h1>Tu compra ha sido confirmada</h1><p>Código de reserva: AB12CD</p>".into(),
        )
        .await;
        let root = tempfile::tempdir().unwrap().keep();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.join("profile"),
            &["--no-sandbox".into(), "--ignore-certificate-errors".into()],
        )
        .await
        .unwrap();
        browser
            .browse(crate::browser::BrowseRequest::Open { url })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let tab = browser.handoff().await.unwrap();
        let discovery = Discovery::read(&tab).await.unwrap();
        let service = Arc::new(
            CheckoutService::new(
                browser,
                &root.join("state.db"),
                root.join("unused.sock"),
                unsafe { libc::geteuid() },
                47999,
            )
            .unwrap(),
        );
        let status = Status {
            operation_id: "fixture-booking".into(),
            state: "submitted".into(),
            ceremony_url: None,
            filled_fields: vec!["number".into(), "expiry".into(), "cvc".into()],
            outcome: None,
        };
        service
            .store
            .insert(&status, "card", "Fixture flight")
            .unwrap();
        let token = hex_token(&[23; 32]);
        *service.private.lock().await = Some(PrivateCheckout {
            operation_id: status.operation_id.clone(),
            mode: Mode::Card,
            view_target: tab.target.clone(),
            view_session: tab.session.clone(),
            seen_pages: std::collections::HashSet::from([tab.target.clone()]),
            tab,
            discovery: Some(discovery),
            recipient: None,
            capability: token.clone(),
            claimed: true,
            approved: true,
            manual_submission: false,
        });
        tokio::time::timeout(
            Duration::from_secs(4),
            service.watch_outcome(status.operation_id.clone()),
        )
        .await
        .unwrap();
        let public = service.store.get(&status.operation_id).unwrap();
        assert_eq!(public.state, "booked");
        assert_eq!(public.outcome.unwrap().order_id.as_deref(), Some("AB12CD"));
        let private = service.private_state(&token).await.unwrap();
        assert_eq!(private["state"], "booked");
        assert_eq!(private["outcome"]["order_id"], "AB12CD");
        server.abort();
    }

    #[tokio::test]
    async fn form_error_stays_private_and_manual_pay_is_recorded_before_click() {
        let (url, server) = crate::discovery::tests::fixture(
            "<p data-bloom-total-minor='399' data-bloom-currency='USD'>Total USD 3.99</p>
             <input autocomplete='cc-number'><input autocomplete='cc-exp'><input autocomplete='cc-csc'>
             <p>Debes completar todos los campos</p>
             <button id='pay' onclick=\"setTimeout(()=>document.body.innerHTML='<h1>Tu compra ha sido confirmada</h1><p>Código de reserva: ZX98YU</p>',1200)\">Pagar</button>".into(),
        )
        .await;
        let root = tempfile::tempdir().unwrap().keep();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.join("profile"),
            &["--no-sandbox".into(), "--ignore-certificate-errors".into()],
        )
        .await
        .unwrap();
        browser
            .browse(crate::browser::BrowseRequest::Open { url })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let tab = browser.handoff().await.unwrap();
        let observer = tab.clone();
        let discovery = Discovery::read(&tab).await.unwrap();
        let service = Arc::new(
            CheckoutService::new(
                browser,
                &root.join("state.db"),
                root.join("unused.sock"),
                unsafe { libc::geteuid() },
                47999,
            )
            .unwrap(),
        );
        let status = Status {
            operation_id: "fixture-correction".into(),
            state: "submitted".into(),
            ceremony_url: None,
            filled_fields: vec!["number".into(), "expiry".into(), "cvc".into()],
            outcome: None,
        };
        service
            .store
            .insert(&status, "card", "Fixture correction")
            .unwrap();
        let token = hex_token(&[29; 32]);
        *service.private.lock().await = Some(PrivateCheckout {
            operation_id: status.operation_id.clone(),
            mode: Mode::Card,
            view_target: tab.target.clone(),
            view_session: tab.session.clone(),
            seen_pages: std::collections::HashSet::from([tab.target.clone()]),
            tab,
            discovery: Some(discovery),
            recipient: None,
            capability: token.clone(),
            claimed: true,
            approved: true,
            manual_submission: false,
        });
        let watcher = tokio::spawn({
            let service = service.clone();
            let operation_id = status.operation_id.clone();
            async move { service.watch_outcome(operation_id).await }
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            while service.store.get(&status.operation_id).unwrap().state != "needs_input" {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        assert!(service.private.lock().await.is_some());
        let point = observer
            .cdp
            .evaluate(
                &observer.session,
                "(()=>{const r=document.getElementById('pay').getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};})()".into(),
            )
            .await
            .unwrap();
        service
            .private_action(
                &token,
                ViewAction::Click {
                    x: point["x"].as_f64().unwrap(),
                    y: point["y"].as_f64().unwrap(),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            service.store.get(&status.operation_id).unwrap().state,
            "submitted"
        );
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(
            service.store.get(&status.operation_id).unwrap().state,
            "submitted",
            "stale validation text must not authorize a second payment click"
        );
        assert!(service.private.lock().await.is_some());
        tokio::time::timeout(Duration::from_secs(4), watcher)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            service.store.get(&status.operation_id).unwrap().state,
            "booked"
        );
        server.abort();
    }

    #[tokio::test]
    async fn a_page_that_never_paints_does_not_stall_the_private_view() {
        // A renderer stuck in script cannot answer a screenshot.
        let (url, server) = crate::discovery::tests::fixture(
            "<h1>Bank</h1><script>setTimeout(()=>{for(;;){}},300)</script>".into(),
        )
        .await;
        let root = tempfile::tempdir().unwrap().keep();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.join("profile"),
            &["--no-sandbox".into(), "--ignore-certificate-errors".into()],
        )
        .await
        .unwrap();
        browser.browse(BrowseRequest::Open { url }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(800)).await;
        let tab = browser.handoff().await.unwrap();
        let service = CheckoutService::new(
            browser,
            &root.join("state.db"),
            root.join("unused.sock"),
            unsafe { libc::geteuid() },
            47999,
        )
        .unwrap();
        *service.private.lock().await = Some(PrivateCheckout {
            operation_id: "fixture".into(),
            mode: Mode::TakeOver,
            view_target: tab.target.clone(),
            view_session: tab.session.clone(),
            seen_pages: std::collections::HashSet::from([tab.target.clone()]),
            tab,
            discovery: None,
            recipient: None,
            capability: "fixture".into(),
            claimed: true,
            approved: true,
            manual_submission: false,
        });
        let started = tokio::time::Instant::now();
        let capture = {
            let service = service.clone();
            tokio::spawn(async move { service.private_screenshot("fixture").await })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        // Other private-view requests can take the lock while the capture waits.
        assert!(service.private.try_lock().is_ok());
        let error = capture.await.unwrap().unwrap_err();
        assert_eq!(error.to_string(), "Private page is still loading");
        assert!(started.elapsed() < Duration::from_secs(15));
        server.abort();
    }
    #[tokio::test]
    async fn typed_traveler_values_reach_the_chosen_field_but_not_the_agent() {
        let (url, server) = crate::discovery::tests::fixture(
            "<div><div>Teléfono *</div><input name='n1'></div><div><div>Nacimiento</div><input name='n2'></div>".into(),
        )
        .await;
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
        tokio::time::sleep(Duration::from_millis(200)).await;
        let service = CheckoutService::new(
            browser.clone(),
            &root.join("state.db"),
            root.join("unused.sock"),
            unsafe { libc::geteuid() },
            47999,
        )
        .unwrap();
        let values: BTreeMap<String, zeroize::Zeroizing<String>> =
            [("phone", "+54 9 11 2345-6789"), ("born_on", "1990-05-07")]
                .into_iter()
                .map(|(k, v)| (k.into(), zeroize::Zeroizing::new(v.into())))
                .collect();
        assert_eq!(
            derived_traveler_value(&values, "phone_national")
                .unwrap()
                .as_str(),
            "91123456789"
        );
        browser.redact(["phone_national", "born_on_dmy"].into_iter().map(|f| {
            (
                derived_traveler_value(&values, f).unwrap().to_string(),
                format!("[saved {f}]"),
            )
        }));
        *service.traveler.lock().await = Some(UnlockedTraveler {
            origin: url::Url::parse(&url)
                .unwrap()
                .origin()
                .ascii_serialization(),
            context: browser.shopping_context().await,
            fields: vec![],
            values,
            expires: tokio::time::Instant::now() + Duration::from_secs(60),
        });
        for (index, field) in [(0, "phone_national"), (1, "born_on_dmy")] {
            let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
            let element_ref = snapshot["elements"][index]["ref"]
                .as_str()
                .unwrap()
                .to_owned();
            let typed = service
                .request(Request::Browse {
                    request: BrowseRequest::TypeTraveler {
                        element_ref,
                        field: field.into(),
                    },
                })
                .await
                .unwrap();
            assert!(!typed.to_string().contains("9112345"));
        }
        let snapshot = browser
            .browse(BrowseRequest::Snapshot)
            .await
            .unwrap()
            .to_string();
        assert!(snapshot.contains("[saved phone_national]"), "{snapshot}");
        assert!(snapshot.contains("[saved born_on_dmy]"), "{snapshot}");
        assert!(!snapshot.contains("91123456789") && !snapshot.contains("07/05/1990"));
        // Discarding the booking context (a finished checkout) ends the unlock.
        browser.handoff().await.unwrap();
        browser.return_control().await.unwrap();
        browser.browse(BrowseRequest::Open { url }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let element_ref = snapshot["elements"][0]["ref"].as_str().unwrap().to_owned();
        let error = service
            .request(Request::Browse {
                request: BrowseRequest::TypeTraveler {
                    element_ref,
                    field: "phone".into(),
                },
            })
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "Unlock a saved traveler first");
        assert!(service.traveler.lock().await.is_none());
        server.abort();
    }
    #[tokio::test]
    async fn saved_choices_pick_their_option_in_a_chosen_list() {
        // Shaped like JetSMART's card-holder document type.
        let (url, server) = crate::discovery::tests::fixture(
            "<div>Titular <div><div>Documento</div><input id='doc' readonly></div>
             <div id='list' hidden><div class='opt'>PAS - Pasaporte</div><div class='opt'>DNI - Documento Nacional de Identidad</div></div></div>
             <script>doc.addEventListener('click',()=>list.hidden=false);
             for(const o of document.querySelectorAll('.opt'))o.onclick=()=>{doc.value=o.innerText.split(' ')[0];list.hidden=true;};</script>".into(),
        )
        .await;
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
        tokio::time::sleep(Duration::from_millis(200)).await;
        let service = CheckoutService::new(
            browser.clone(),
            &root.join("state.db"),
            root.join("unused.sock"),
            unsafe { libc::geteuid() },
            47999,
        )
        .unwrap();
        *service.traveler.lock().await = Some(UnlockedTraveler {
            origin: url::Url::parse(&url)
                .unwrap()
                .origin()
                .ascii_serialization(),
            context: browser.shopping_context().await,
            fields: vec![],
            values: [(
                "document_kind".to_owned(),
                zeroize::Zeroizing::new("passport".to_owned()),
            )]
            .into(),
            expires: tokio::time::Instant::now() + Duration::from_secs(60),
        });
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let element_ref = snapshot["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == "Documento")
            .unwrap()["ref"]
            .as_str()
            .unwrap()
            .to_owned();
        service
            .request(Request::Browse {
                request: BrowseRequest::TypeTraveler {
                    element_ref,
                    field: "document_kind".into(),
                },
            })
            .await
            .unwrap();
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let documento = snapshot["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == "Documento")
            .unwrap()
            .clone();
        assert_eq!(documento["value"], "PAS");
        server.abort();
    }
    #[tokio::test]
    async fn a_list_searching_option_starts_is_opened_whole() {
        // JetSMART's card-holder document type: an editable box that only
        // matches the start of "PAS - Pasaporte", and a button opening the list.
        let (url, server) = crate::discovery::tests::fixture(
            "<div><div><div>Documento</div><div><div><input id='doc'></div></div></div><button id='toggle'></button>
             <div id='list'></div></div>
             <script>const all=['PAS - Pasaporte','DNI - Documento Nacional de Identidad'];
             const show=f=>{list.innerHTML='';for(const o of all.filter(f)){const d=document.createElement('div');d.className='option';d.textContent=o;
               d.onclick=()=>{doc.value=o.split(' ')[0];list.innerHTML='';};list.append(d);}};
             doc.addEventListener('input',()=>show(o=>!doc.value||o.toLowerCase().startsWith(doc.value.toLowerCase())));
             toggle.onclick=()=>list.children.length?list.innerHTML='':show(()=>true);
             doc.addEventListener('click',()=>list.children.length?list.innerHTML='':show(()=>true));</script>".into(),
        )
        .await;
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
        tokio::time::sleep(Duration::from_millis(200)).await;
        let service = CheckoutService::new(
            browser.clone(),
            &root.join("state.db"),
            root.join("unused.sock"),
            unsafe { libc::geteuid() },
            47999,
        )
        .unwrap();
        *service.traveler.lock().await = Some(UnlockedTraveler {
            origin: url::Url::parse(&url)
                .unwrap()
                .origin()
                .ascii_serialization(),
            context: browser.shopping_context().await,
            fields: vec![],
            values: [(
                "document_kind".to_owned(),
                zeroize::Zeroizing::new("passport".to_owned()),
            )]
            .into(),
            expires: tokio::time::Instant::now() + Duration::from_secs(60),
        });
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let element_ref = snapshot["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == "Documento")
            .unwrap()["ref"]
            .as_str()
            .unwrap()
            .to_owned();
        service
            .request(Request::Browse {
                request: BrowseRequest::TypeTraveler {
                    element_ref,
                    field: "document_kind".into(),
                },
            })
            .await
            .unwrap();
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let documento = snapshot["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == "Documento")
            .unwrap()
            .clone();
        assert_eq!(documento["value"], "PAS");
        server.abort();
    }
    #[test]
    fn saved_phones_split_by_the_numbering_plan() {
        let values = |phone: &str| -> BTreeMap<String, zeroize::Zeroizing<String>> {
            [(
                "phone".to_owned(),
                zeroize::Zeroizing::new(phone.to_owned()),
            )]
            .into()
        };
        // Argentine mobiles: 11 for Buenos Aires, three and four digit areas elsewhere.
        for (phone, area, local) in [
            ("+5492944123456", "294", "4123456"),
            ("+5491123456789", "11", "23456789"),
            ("+5493514123456", "351", "4123456"),
        ] {
            let values = values(phone);
            assert_eq!(
                derived_traveler_value(&values, "phone_area")
                    .unwrap()
                    .as_str(),
                area,
                "{phone}"
            );
            assert_eq!(
                derived_traveler_value(&values, "phone_local")
                    .unwrap()
                    .as_str(),
                local,
                "{phone}"
            );
        }
        assert!(derived_traveler_value(&values("12345"), "phone_area").is_none());
    }
    #[tokio::test]
    async fn payment_is_not_requested_while_the_page_shows_form_errors() {
        let (url, server) = crate::discovery::tests::fixture(
            "<input aria-label='Nombres *' aria-invalid='true'><div class='field-error'>Este campo es obligatorio</div>
             <p data-bloom-total-minor='399' data-bloom-currency='USD'>Total USD 3.99</p>
             <input autocomplete='cc-number'><input autocomplete='cc-exp'><input autocomplete='cc-csc'><button>Pay</button>".into(),
        )
        .await;
        let root = tempfile::tempdir().unwrap().keep();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.join("profile"),
            &["--no-sandbox".into(), "--ignore-certificate-errors".into()],
        )
        .await
        .unwrap();
        browser.browse(BrowseRequest::Open { url }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let service = CheckoutService::new(
            browser.clone(),
            &root.join("state.db"),
            root.join("unused.sock"),
            unsafe { libc::geteuid() },
            47999,
        )
        .unwrap();
        let error = service
            .request(Request::Checkout {
                operation_id: "c".repeat(64),
                card_id: Some("fixture-card".into()),
                agent_description: "Fixture".into(),
                take_over: false,
            })
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("Este campo es obligatorio"),
            "{error}"
        );
        // Nothing was recorded or handed off: shopping goes on on the same page.
        assert!(service.store.get(&"c".repeat(64)).is_err());
        assert!(browser.browse(BrowseRequest::Snapshot).await.is_ok());
        server.abort();
    }
    #[test]
    fn interrupted_fill_is_not_retried_after_restart() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state.db");
        {
            let store = Store::open(&path).unwrap();
            let status = Status {
                operation_id: "fixture".into(),
                state: "filled".into(),
                ceremony_url: None,
                filled_fields: vec!["given_name".into()],
                outcome: None,
            };
            store
                .insert(&status, "traveler", "Fixture passenger")
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.get("fixture").unwrap().state, "disclosure_unknown");
    }
    #[tokio::test]
    async fn private_view_requires_one_shot_claim_and_handles_bank_popup() {
        use axum::{Router, response::Html, routing::get};
        let fixture = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://127.0.0.1:{}", fixture.local_addr().unwrap().port());
        let fixture_task = tokio::spawn(async move {
            axum::serve(fixture,Router::new()
            .route("/",get(||async {Html("<button onclick=\"window.open('/bank')\">Pay</button>")}))
            .route("/bank",get(||async {Html("<h1>Test bank authentication</h1><input id='otp'><button>Complete</button>")}))).await.unwrap();
        });
        let root = tempfile::tempdir().unwrap().keep();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.join("profile"),
            &["--no-sandbox".into()],
        )
        .await
        .unwrap();
        browser
            .browse(crate::browser::BrowseRequest::Open { url: origin })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let tab = browser.handoff().await.unwrap();
        let view_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = view_listener.local_addr().unwrap().port();
        let service = CheckoutService::new(
            browser.clone(),
            &root.join("state.db"),
            root.join("unused.sock"),
            unsafe { libc::geteuid() },
            port,
        )
        .unwrap();
        let status = Status {
            operation_id: "private-fixture".into(),
            state: "manual_required".into(),
            ceremony_url: None,
            filled_fields: Vec::new(),
            outcome: None,
        };
        service.store.insert(&status, "card", "test").unwrap();
        let token = hex_token(&[42; 32]);
        *service.private.lock().await = Some(PrivateCheckout {
            operation_id: status.operation_id,
            mode: Mode::Card,
            view_target: tab.target.clone(),
            view_session: tab.session.clone(),
            seen_pages: std::collections::HashSet::from([tab.target.clone()]),
            tab,
            discovery: None,
            recipient: None,
            capability: token.clone(),
            claimed: false,
            approved: false,
            manual_submission: false,
        });
        let router = crate::view::router(service.clone());
        let viewer = tokio::spawn(async move {
            axum::serve(view_listener, router).await.unwrap();
        });
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let base = format!("http://localhost:{port}");
        assert!(service.private_claim(&hex_token(&[43; 32])).await.is_err());
        assert!(service.private_state(&token).await.is_err());
        service.private.lock().await.as_mut().unwrap().approved = true;
        let claim = client
            .get(format!("{base}/private?token={token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(claim.status(), reqwest::StatusCode::SEE_OTHER);
        let cookie = claim.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert!(service.private_claim(&token).await.is_err());
        assert_eq!(
            client
                .get(format!("{base}/frame"))
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            client
                .post(format!("{base}/action"))
                .header("cookie", &cookie)
                .header("origin", "https://untrusted.invalid")
                .json(&json!({"action":"finish"}))
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::FORBIDDEN
        );
        assert!(
            browser
                .browse(crate::browser::BrowseRequest::Snapshot)
                .await
                .is_err()
        );
        service
            .private_action(&token, ViewAction::Click { x: 28., y: 20. })
            .await
            .unwrap();
        let root_target = service
            .private
            .lock()
            .await
            .as_ref()
            .unwrap()
            .tab
            .target
            .clone();
        let state = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let state = service.private_state(&token).await.unwrap();
                if state["selected_page"] != root_target {
                    break state;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(state["pages"].as_array().unwrap().len(), 2);
        assert_ne!(state["selected_page"], root_target);
        service
            .private_action(&token, ViewAction::Key { key: "Tab".into() })
            .await
            .unwrap();
        service
            .private_action(
                &token,
                ViewAction::Type {
                    text: "12345".into(),
                },
            )
            .await
            .unwrap();
        {
            let private = service.private.lock().await;
            let checkout = private.as_ref().unwrap();
            assert_eq!(
                checkout
                    .tab
                    .cdp
                    .evaluate(
                        &checkout.view_session,
                        "document.getElementById('otp').value === '12345'".into()
                    )
                    .await
                    .unwrap(),
                json!(true)
            );
        }
        let screenshot = service.private_screenshot(&token).await.unwrap();
        assert_eq!(&screenshot[..8], b"\x89PNG\r\n\x1a\n");
        // A valid PNG header also passes for a completely black frame.
        // Prove that this view captures changes in the selected document.
        {
            let private = service.private.lock().await;
            let checkout = private.as_ref().unwrap();
            checkout
                .tab
                .cdp
                .evaluate(
                    &checkout.view_session,
                    "document.body.style.backgroundColor='rgb(255,0,0)'".into(),
                )
                .await
                .unwrap();
        }
        let painted = service.private_screenshot(&token).await.unwrap();
        assert_ne!(
            screenshot, painted,
            "Private view must render the selected page"
        );
        assert!(
            service
                .private_action(
                    &token,
                    ViewAction::SelectPage {
                        target: "unrelated".into()
                    }
                )
                .await
                .is_err()
        );
        service
            .private_action(
                &token,
                ViewAction::Scroll {
                    x: 200.,
                    y: 200.,
                    delta_y: 450.,
                },
            )
            .await
            .unwrap();
        service
            .private_action(&token, ViewAction::Finish)
            .await
            .unwrap();
        assert_eq!(
            service.private_state(&token).await.unwrap()["state"],
            "uncertain"
        );
        assert_eq!(
            browser
                .browse(crate::browser::BrowseRequest::Snapshot)
                .await
                .unwrap()["url"],
            "about:blank"
        );
        viewer.abort();
        fixture_task.abort();
    }
    #[tokio::test]
    async fn take_over_returns_shopping_on_the_page_the_human_left() {
        use axum::{Router, response::Html, routing::get};
        let fixture = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://127.0.0.1:{}", fixture.local_addr().unwrap().port());
        let fixture_task = tokio::spawn(async move {
            axum::serve(
                fixture,
                Router::new()
                    .route("/", get(|| async { Html("<a href='/account' onclick=\"sessionStorage.booking='fixture-active'\">Log in</a>") }))
                    .route("/account", get(|| async { Html("<h1 id='state'></h1><input id='private-password' type='password' autocomplete='off'><script>document.getElementById('state').textContent=sessionStorage.booking==='fixture-active'?'Signed in; booking kept':'Lost booking';</script>") })),
            )
            .await
            .unwrap();
        });
        let root = tempfile::tempdir().unwrap().keep();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.join("profile"),
            &["--no-sandbox".into()],
        )
        .await
        .unwrap();
        browser
            .browse(crate::browser::BrowseRequest::Open {
                url: origin.clone(),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let tab = browser.handoff().await.unwrap();
        let service = CheckoutService::new(
            browser.clone(),
            &root.join("state.db"),
            root.join("unused.sock"),
            unsafe { libc::geteuid() },
            1,
        )
        .unwrap();
        let status = Status {
            operation_id: "take-over".into(),
            state: "human_control".into(),
            ceremony_url: None,
            filled_fields: Vec::new(),
            outcome: None,
        };
        service.store.insert(&status, "card", "test").unwrap();
        let token = hex_token(&[44; 32]);
        *service.private.lock().await = Some(PrivateCheckout {
            operation_id: status.operation_id,
            mode: Mode::TakeOver,
            view_target: tab.target.clone(),
            view_session: tab.session.clone(),
            seen_pages: std::collections::HashSet::from([tab.target.clone()]),
            tab,
            discovery: None,
            recipient: None,
            capability: token.clone(),
            claimed: true,
            approved: true,
            manual_submission: false,
        });
        service
            .private_action(&token, ViewAction::Click { x: 20., y: 15. })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        {
            let private = service.private.lock().await;
            let checkout = private.as_ref().unwrap();
            checkout.tab.cdp.evaluate(&checkout.view_session,
                "globalThis.privateFixture='do-not-retain';document.getElementById('private-password').focus()".into()).await.unwrap();
        }
        service
            .private_action(
                &token,
                ViewAction::Type {
                    text: "fixture-private-password".into(),
                },
            )
            .await
            .unwrap();
        service
            .private_action(&token, ViewAction::Finish)
            .await
            .unwrap();
        assert_eq!(service.store.get("take-over").unwrap().state, "returned");
        tokio::time::sleep(Duration::from_millis(300)).await;
        let snapshot = browser
            .browse(crate::browser::BrowseRequest::Snapshot)
            .await
            .unwrap();
        assert_eq!(snapshot["url"], format!("{origin}/account"));
        assert!(snapshot["text"].as_str().unwrap().contains("Signed in"));
        assert!(snapshot["text"].as_str().unwrap().contains("booking kept"));
        let tab = browser.handoff().await.unwrap();
        assert_eq!(tab.cdp.evaluate(&tab.session,
            "globalThis.privateFixture===undefined&&document.getElementById('private-password').value===''".into()).await.unwrap(), json!(true));
        let history = tab
            .cdp
            .call(Some(&tab.session), "Page.getNavigationHistory", json!({}))
            .await
            .unwrap();
        assert_eq!(history["entries"].as_array().unwrap().len(), 1);
        fixture_task.abort();
    }

    #[test]
    fn durable_consumption_has_one_winner_and_restart_preserves_uncertainty() {
        let root = tempfile::tempdir().unwrap().keep();
        let path = root.join("operations.sqlite3");
        let store = Arc::new(Store::open(&path).unwrap());
        let status = Status {
            operation_id: "synthetic-operation".into(),
            state: "awaiting_approval".into(),
            ceremony_url: None,
            filled_fields: Vec::new(),
            outcome: None,
        };
        store.insert(&status, "card", "Two socks").unwrap();
        store
            .record_order(
                "synthetic-operation",
                Some("https://shop.example"),
                Some((1250, "EUR")),
            )
            .unwrap();
        let workers = (0..8)
            .map(|_| {
                let store = store.clone();
                std::thread::spawn(move || store.consume("synthetic-operation").is_ok())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            workers
                .into_iter()
                .map(|w| w.join().unwrap())
                .filter(|won| *won)
                .count(),
            1
        );
        drop(store);
        let reopened = Store::open(&path).unwrap();
        assert_eq!(
            reopened.get("synthetic-operation").unwrap().state,
            "disclosure_unknown"
        );
        assert!(reopened.consume("synthetic-operation").is_err());
        assert!(reopened.insert(&status, "card", "again").is_err());
        let history = reopened.history().unwrap();
        assert_eq!(history.len(), 1);
        let entry = &history[0];
        assert_eq!(
            (
                entry.kind.as_str(),
                entry.description.as_str(),
                entry.shop.as_deref()
            ),
            ("card", "Two socks", Some("https://shop.example"))
        );
        assert_eq!(
            (entry.total_minor, entry.currency.as_deref()),
            (Some(1250), Some("EUR"))
        );
        assert_eq!(entry.status.as_ref().unwrap().state, "disclosure_unknown");
        let submitted = Status {
            operation_id: "submitted-operation".into(),
            state: "submitted".into(),
            ceremony_url: None,
            filled_fields: vec!["number".into(), "expiry".into(), "cvc".into()],
            outcome: None,
        };
        reopened.insert(&submitted, "card", "Flight").unwrap();
        let mut needs_input = submitted.clone();
        needs_input.operation_id = "needs-input-operation".into();
        needs_input.state = "needs_input".into();
        reopened
            .insert(&needs_input, "card", "Flight form")
            .unwrap();
        drop(reopened);
        let reopened = Store::open(&path).unwrap();
        assert_eq!(
            reopened.get("submitted-operation").unwrap().state,
            "uncertain"
        );
        assert_eq!(
            reopened.get("needs-input-operation").unwrap().state,
            "not_submitted"
        );
    }
}
