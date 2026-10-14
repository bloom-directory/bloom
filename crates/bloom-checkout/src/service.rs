use crate::{
    browser::{Browser, PrivateTab},
    discovery::Discovery,
    hpke::Recipient,
};
use anyhow::{Context, Result, bail};
use bloom_signer_api::{
    CardOperationState, CardOperationStatus, CustodyOutputHpkeAad, CustodyResult, OperationId,
    Token,
};
use parking_lot::Mutex;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
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
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS private_origins(origin TEXT PRIMARY KEY NOT NULL);",
        )?;
        // A lost recipient cannot be reconstructed. Interrupted disclosure is never retried.
        conn.execute("UPDATE operations SET state='disclosure_unknown',status=json_set(status,'$.state','disclosure_unknown','$.ceremony_url',NULL) WHERE state IN ('release_started','filled','submitted','partially_filled','ready_for_payment')",[])?;
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
    fn private_origins(&self) -> Result<Vec<String>> {
        let db = self.0.lock();
        let mut stmt = db.prepare("SELECT origin FROM private_origins")?;
        Ok(stmt
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }
    fn protect_origin(&self, origin: &str) -> Result<()> {
        self.0.lock().execute(
            "INSERT OR IGNORE INTO private_origins VALUES (?1)",
            [origin],
        )?;
        Ok(())
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
    Traveler,
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
    traveler: Option<crate::travelers::TravelerDiscovery>,
    contains_traveler: bool,
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
    async fn start_traveler(
        self: &Arc<Self>,
        operation_id: String,
        traveler_id: String,
    ) -> Result<Value> {
        OperationId::new(&operation_id).map_err(|_| anyhow::anyhow!("Invalid operation ID"))?;
        Token::new(&traveler_id).map_err(|_| anyhow::anyhow!("Invalid traveler ID"))?;
        let mut private = self.private.lock().await;
        if private.is_some() {
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
            &format!("Autofill {} privately", metadata.label),
        )?;
        let tab = self.browser.handoff().await?;
        let discovery = match crate::travelers::TravelerDiscovery::read(&tab, &metadata.fields)
            .await
        {
            Ok(discovery) => discovery,
            Err(_) => {
                self.set_state(&operation_id, "failed_before_release");
                let resume = tab_url(&tab).await;
                self.browser.return_control_at(&tab.target, resume).await?;
                bail!(
                    "No unambiguous saved traveler fields on this page; continue to passenger entry first"
                );
            }
        };
        self.store
            .record_order(&operation_id, Some(&discovery.scope.origin), None)?;
        let recipient = Recipient::generate();
        use rand::RngCore;
        let mut token = [0; 32];
        rand::thread_rng().fill_bytes(&mut token);
        let capability = hex_token(&token);
        let challenge_url = format!(
            "http://localhost:{}/private?token={}",
            self.view_port, capability
        );
        let response=self.intake(json!({"method":"traveler","operation_id":operation_id,"traveler_id":traveler_id,
            "scope":discovery.scope,"recipient_key":recipient.public,"challenge_url":challenge_url})).await;
        let ceremony_url = match response {
            Ok(IntakeResponse::Prepared { ceremony_url }) => ceremony_url,
            _ => {
                self.set_state(&operation_id, "failed_before_release");
                let resume = tab_url(&tab).await;
                self.browser.return_control_at(&tab.target, resume).await?;
                bail!("Private autofill approval unavailable");
            }
        };
        status.state = "awaiting_approval".into();
        status.ceremony_url = Some(ceremony_url);
        self.store.update(&status)?;
        *private = Some(PrivateCheckout {
            operation_id: operation_id.clone(),
            mode: Mode::Traveler,
            view_target: tab.target.clone(),
            view_session: tab.session.clone(),
            seen_pages: std::collections::HashSet::from([tab.target.clone()]),
            tab,
            discovery: None,
            traveler: Some(discovery),
            contains_traveler: true,
            recipient: Some(recipient),
            capability,
            claimed: false,
            approved: false,
        });
        let service = self.clone();
        tokio::spawn(async move {
            service.finish_approved(operation_id).await;
        });
        Ok(serde_json::to_value(status)?)
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
        for origin in store.private_origins()? {
            browser.protect_origin(origin)?;
        }
        Ok(Arc::new(Self {
            browser,
            store,
            private: AsyncMutex::new(None),
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
            Request::PrivateFacts { operation_id } => {
                let private = self.private.lock().await;
                let checkout = private
                    .as_ref()
                    .filter(|c| {
                        c.operation_id == operation_id && c.mode == Mode::Traveler && c.approved
                    })
                    .context("No approved private traveler booking")?;
                let discovery = Discovery::read(&checkout.tab)
                    .await
                    .context("Supported payment page not ready")?;
                if checkout
                    .traveler
                    .as_ref()
                    .is_none_or(|t| t.scope.origin != discovery.facts.origin)
                {
                    bail!("Booking merchant changed; private review required");
                }
                Ok(serde_json::to_value(discovery.facts)?)
            }
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
                continue_private,
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
                let held = if let Some(previous) = private.as_ref() {
                    if take_over
                        || previous.mode != Mode::Traveler
                        || !previous.approved
                        || continue_private.as_deref() != Some(previous.operation_id.as_str())
                        || self.store.get(&previous.operation_id)?.state != "ready_for_payment"
                    {
                        bail!("A checkout already has private control");
                    }
                    if previous.view_target != previous.tab.target {
                        bail!("Return to the approved booking tab before payment");
                    }
                    Some(previous.tab.clone())
                } else {
                    if continue_private.is_some() {
                        bail!("Private booking is no longer active");
                    }
                    None
                };
                let traveler_origin = private
                    .as_ref()
                    .and_then(|p| p.traveler.as_ref())
                    .map(|t| t.scope.origin.clone());
                if let Some(origin) = &traveler_origin {
                    let current = tab_url(held.as_ref().context("Private booking unavailable")?)
                        .await
                        .and_then(|u| url::Url::parse(&u).ok())
                        .map(|u| u.origin().ascii_serialization());
                    if current.as_ref() != Some(origin) {
                        bail!("Booking merchant changed; private review required");
                    }
                }
                let mut status = Status {
                    operation_id: operation_id.clone(),
                    state: "requested".into(),
                    ceremony_url: None,
                    filled_fields: Vec::new(),
                    outcome: None,
                };
                let kind = match mode {
                    Mode::Card => "card",
                    Mode::Site => "site",
                    Mode::TakeOver => "take_over",
                    Mode::Traveler => "traveler",
                };
                self.store.insert(&status, kind, &agent_description)?;
                let contains_traveler = held.is_some();
                let tab = match held {
                    Some(tab) => tab,
                    None => self.browser.handoff().await?,
                };
                status.state = "preparing".into();
                self.store.update(&status)?;
                let discovery = match mode {
                    Mode::Card => Discovery::read(&tab).await.ok(),
                    Mode::Site => Discovery::read_site(&tab).await.ok(),
                    Mode::TakeOver | Mode::Traveler => None,
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
                let challenge_url = format!(
                    "http://localhost:{}/private?token={}",
                    self.view_port, capability
                );
                let request = match (&discovery, &recipient) {
                    (Some(discovery), Some(recipient)) => {
                        json!({"method":"prepare","operation_id":operation_id,"card_id":card_id,
                        "facts":discovery.facts,"recipient_key":recipient.public,
                        "agent_description":agent_description,"challenge_url":challenge_url,
                        "order_preview":crate::discovery::order_preview(&tab).await})
                    }
                    (Some(discovery), None) => {
                        json!({"method":"site","operation_id":operation_id,
                        "facts":discovery.facts,"agent_description":agent_description,
                        "challenge_url":challenge_url,
                        "order_preview":crate::discovery::order_preview(&tab).await})
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
                            traveler: None,
                            contains_traveler,
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
        let deadline = tokio::time::Instant::now() + Duration::from_secs(125);
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
        if checkout.mode == Mode::Traveler {
            let mut status = self.store.consume(&checkout.operation_id)?;
            let traveler = checkout
                .traveler
                .as_ref()
                .context("Private traveler binding missing")?;
            self.store.protect_origin(&traveler.scope.origin)?;
            self.browser.protect_origin(traveler.scope.origin.clone())?;
            let key = checkout
                .recipient
                .take()
                .context("Traveler recipient already consumed")?;
            let receipt = receipt.context("Traveler release unavailable")?;
            let aad = aad.context("Traveler release binding unavailable")?;
            if receipt.custody_operation_id.as_str() != checkout.operation_id
                || aad.custody_operation_id.as_str() != checkout.operation_id
                || receipt.surface.as_ref() != Some(&aad.surface)
            {
                bail!("Traveler release binding mismatch");
            }
            let plaintext = key.open(
                receipt
                    .encrypted_browser_result
                    .as_ref()
                    .context("Traveler release unavailable")?,
                &aad.canonical_bytes()
                    .map_err(|_| anyhow::anyhow!("Traveler release binding invalid"))?,
            )?;
            let values: std::collections::BTreeMap<String, zeroize::Zeroizing<String>> =
                serde_json::from_slice(&plaintext)
                    .map_err(|_| anyhow::anyhow!("Invalid private traveler release"))?;
            status.filled_fields = traveler.fill(&checkout.tab, &values).await?;
            status.state = "filled".into();
            status.ceremony_url = None;
            self.store.update(&status)?;
            return Ok(());
        }
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
            if discovery.submit(&checkout.tab).await.is_err() {
                status.state = "uncertain".into();
                self.store.update(&status)?;
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
        // Record the submission attempt first; a lost response must not cause a second click.
        status.state = "submitted".into();
        self.store.update(&status)?;
        if discovery.submit(&checkout.tab).await.is_err() {
            status.state = "uncertain".into();
            self.store.update(&status)?;
            return Ok(());
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
    async fn private_pages(checkout: &mut PrivateCheckout) -> Result<Vec<Value>> {
        let targets = checkout
            .tab
            .cdp
            .call(None, "Target.getTargets", json!({}))
            .await?;
        let infos = targets["targetInfos"]
            .as_array()
            .context("Missing private pages")?;
        let mut owned = std::collections::HashSet::from([checkout.tab.target.clone()]);
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
        let mut selected = None;
        for info in infos {
            let Some(id) = info["targetId"].as_str().filter(|id| owned.contains(*id)) else {
                continue;
            };
            let origin = url::Url::parse(info["url"].as_str().unwrap_or(""))
                .ok()
                .map(|u| u.origin().ascii_serialization())
                .unwrap_or_else(|| "Loading".into());
            pages.push(json!({"target":id,"origin":origin}));
            if checkout.seen_pages.insert(id.to_owned()) {
                selected = Some(id.to_owned());
            }
        }
        if !pages.iter().any(|p| p["target"] == checkout.view_target) {
            selected = Some(checkout.tab.target.clone());
        }
        if let Some(target) = selected {
            Self::select_private_page(checkout, target).await?;
        }
        Ok(pages)
    }

    async fn page_url(checkout: &PrivateCheckout) -> Option<String> {
        let target = checkout
            .tab
            .cdp
            .call(
                None,
                "Target.getTargetInfo",
                json!({"targetId":checkout.view_target}),
            )
            .await
            .ok()?;
        target["targetInfo"]["url"].as_str().map(str::to_owned)
    }

    async fn select_private_page(checkout: &mut PrivateCheckout, target: String) -> Result<()> {
        let session = if target == checkout.tab.target {
            checkout.tab.session.clone()
        } else {
            let attachment = checkout
                .tab
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
        checkout
            .tab
            .cdp
            .call(Some(&session), "Page.enable", json!({}))
            .await?;
        checkout
            .tab
            .cdp
            .call(
                Some(&session),
                "Emulation.setDeviceMetricsOverride",
                json!({"width":1280,"height":900,"deviceScaleFactor":1,"mobile":false}),
            )
            .await?;
        checkout
            .tab
            .cdp
            .call(Some(&session), "Page.bringToFront", json!({}))
            .await?;
        checkout.view_target = target;
        checkout.view_session = session;
        Ok(())
    }

    async fn watch_outcome(&self, id: String) {
        let started = tokio::time::Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let mut private = self.private.lock().await;
            let Some(checkout) = private.as_ref().filter(|p| p.operation_id == id) else {
                return;
            };
            // A take-over may include a login with an emailed or texted code.
            let take_over = matches!(checkout.mode, Mode::TakeOver | Mode::Traveler);
            let deadline = started + Duration::from_secs(if take_over { 900 } else { 300 });
            let Ok(mut status) = self.store.get(&id) else {
                return;
            };
            if checkout.mode != Mode::Traveler
                && matches!(
                    status.state.as_str(),
                    "submitted"
                        | "manual_required"
                        | "uncertain"
                        | "partially_filled"
                        | "disclosure_unknown"
                )
            {
                let contexts = checkout
                    .tab
                    .cdp
                    .contexts(&checkout.tab.session, "bloom-outcome")
                    .await
                    .unwrap_or_default();
                for context in contexts {
                    let result=checkout.tab.cdp.call(Some(&context.session),"Runtime.evaluate",json!({"contextId":context.world,"expression":include_str!("outcome.js"),"returnByValue":true})).await;
                    let Ok(result) = result else {
                        continue;
                    };
                    let outcome = result["result"]["value"].clone();
                    if matches!(outcome["state"].as_str(), Some("paid" | "declined")) {
                        status.state = outcome["state"].as_str().unwrap().into();
                        status.outcome = serde_json::from_value(outcome).ok();
                        if checkout.contains_traveler {
                            if let Some(outcome) = &mut status.outcome {
                                outcome.order_id = None;
                                outcome.source = "merchant".into();
                            }
                        }
                        status.ceremony_url = None;
                        if self.store.update(&status).is_ok()
                            && self.browser.return_control().await.is_ok()
                        {
                            self.retain_completed(checkout, status);
                            *private = None;
                        }
                        return;
                    }
                }
            }
            if tokio::time::Instant::now() >= deadline {
                // Only a plain take-over resumes its page; a session that held
                // traveler data is discarded with its browsing context.
                let resume = if checkout.mode == Mode::TakeOver && !checkout.contains_traveler {
                    Self::page_url(checkout).await
                } else {
                    None
                };
                if self
                    .browser
                    .return_control_at(&checkout.view_target, resume)
                    .await
                    .is_ok()
                {
                    self.set_state(&id, if take_over { "returned" } else { "uncertain" });
                    if let Ok(status) = self.store.get(&id) {
                        self.retain_completed(checkout, status);
                    }
                    *private = None;
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

    pub async fn private_state(&self, token: &str) -> Result<Value> {
        let mut private = self.private.lock().await;
        let Some(checkout) = private.as_mut() else {
            let completed = self.completed.lock();
            let completed = completed
                .as_ref()
                .filter(|c| c.claimed && same_token(&c.capability, token))
                .context("Private view rejected")?;
            return Ok(
                json!({"state":completed.status.state,"outcome":completed.status.outcome,"closed":true,"pages":[]}),
            );
        };
        authorize_view(checkout, token)?;
        let pages = Self::private_pages(checkout).await?;
        let status = self.store.get(&checkout.operation_id)?;
        if checkout.contains_traveler {
            // Popups belong to the same private booking even when they have
            // not been selected. Never reopen their saved session to shopping.
            for page in &pages {
                if let Some(origin) = page["origin"].as_str()
                    && let Ok(url) = url::Url::parse(origin)
                    && matches!(url.scheme(), "http" | "https")
                {
                    self.store.protect_origin(origin)?;
                    self.browser.protect_origin(origin.to_owned())?;
                }
            }
            for context in checkout
                .tab
                .cdp
                .contexts(&checkout.view_session, "bloom-private-history")
                .await?
            {
                if let Ok(url) = url::Url::parse(&context.url) {
                    if matches!(url.scheme(), "http" | "https") {
                        let origin = url.origin().ascii_serialization();
                        self.store.protect_origin(&origin)?;
                        self.browser.protect_origin(origin)?;
                    }
                }
            }
        }
        if status.state == "ready_for_payment" {
            return Ok(
                json!({"state":"ready_for_payment","outcome":null,"closed":true,"pages":[]}),
            );
        }
        Ok(
            json!({"state":status.state,"outcome":status.outcome,"pages":pages,"selected_page":checkout.view_target,"closed":false,"traveler":checkout.mode==Mode::Traveler}),
        )
    }

    pub async fn private_screenshot(&self, token: &str) -> Result<Vec<u8>> {
        let private = self.private.lock().await;
        let checkout = private.as_ref().context("No active private checkout")?;
        authorize_view(checkout, token)?;
        // The initial handoff may not have switched pages. Activate the held
        // page before capture so a background headless tab paints as well.
        checkout
            .tab
            .cdp
            .call(Some(&checkout.view_session), "Page.bringToFront", json!({}))
            .await?;
        let result = checkout
            .tab
            .cdp
            .call(
                Some(&checkout.view_session),
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
        let mut private = self.private.lock().await;
        let checkout = private.as_mut().context("No active private checkout")?;
        authorize_view(checkout, token)?;
        match action {
            ViewAction::Click { x, y } => {
                if !x.is_finite()
                    || !y.is_finite()
                    || !(0.0..=1280.0).contains(&x)
                    || !(0.0..=900.0).contains(&y)
                {
                    bail!("Invalid private pointer");
                }
                for kind in ["mousePressed", "mouseReleased"] {
                    checkout
                        .tab
                        .cdp
                        .call(
                            Some(&checkout.view_session),
                            "Input.dispatchMouseEvent",
                            json!({"type":kind,"x":x,"y":y,"button":"left","clickCount":1}),
                        )
                        .await?;
                }
            }
            ViewAction::Type { text } => {
                if text.len() > 4096 {
                    bail!("Private input exceeds limit");
                }
                let text = zeroize::Zeroizing::new(text);
                checkout
                    .tab
                    .cdp
                    .call(
                        Some(&checkout.view_session),
                        "Input.insertText",
                        json!({"text":text.as_str()}),
                    )
                    .await?;
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
                for kind in ["keyDown", "keyUp"] {
                    checkout
                        .tab
                        .cdp
                        .call(
                            Some(&checkout.view_session),
                            "Input.dispatchKeyEvent",
                            json!({"type":kind,"key":key,"code":key,
                                "windowsVirtualKeyCode":key_code,
                                "text":if key == "Enter" && kind == "keyDown" {"\r"} else {""}}),
                        )
                        .await?;
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
                checkout
                    .tab
                    .cdp
                    .call(
                        Some(&checkout.view_session),
                        "Input.dispatchMouseEvent",
                        json!({"type":"mouseWheel","x":x,"y":y,"deltaX":0,"deltaY":delta_y}),
                    )
                    .await?;
            }
            ViewAction::SelectPage { target } => {
                let pages = Self::private_pages(checkout).await?;
                if !pages.iter().any(|p| p["target"] == target) {
                    bail!("Unknown private page");
                }
                Self::select_private_page(checkout, target).await?;
            }
            ViewAction::Finish => {
                if checkout.mode == Mode::Traveler {
                    let discovery = Discovery::read(&checkout.tab)
                        .await
                        .context("Continue to the supported payment page before finishing")?;
                    if checkout.view_target != checkout.tab.target
                        || checkout
                            .traveler
                            .as_ref()
                            .is_none_or(|t| t.scope.origin != discovery.facts.origin)
                    {
                        bail!("Return to the approved booking tab before payment");
                    }
                    self.set_state(&checkout.operation_id, "ready_for_payment");
                    return Ok(());
                } else if checkout.mode == Mode::TakeOver {
                    let resume = Self::page_url(checkout).await;
                    self.browser
                        .return_control_at(&checkout.view_target, resume)
                        .await?;
                    self.set_state(&checkout.operation_id, "returned");
                } else {
                    self.set_state(&checkout.operation_id, "uncertain");
                    self.browser.return_control().await?;
                }
                self.retain_completed(checkout, self.store.get(&checkout.operation_id)?);
                *private = None;
            }
        }
        Ok(())
    }
}

async fn tab_url(tab: &PrivateTab) -> Option<String> {
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
    #[tokio::test]
    async fn ready_private_traveler_exposes_only_financial_facts() {
        let (url, server) = crate::discovery::tests::fixture("<p data-bloom-total-minor='399' data-bloom-currency='USD'>Total USD 3.99</p><input autocomplete='given-name'><input autocomplete='cc-number'><input autocomplete='cc-exp'><input autocomplete='cc-csc'><button>Pay</button>".into()).await;
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
        let traveler = crate::travelers::TravelerDiscovery::read(
            &tab,
            &[bloom_signer_api::TravelerField::GivenName],
        )
        .await
        .unwrap();
        let service = CheckoutService::new(
            browser,
            &root.join("state.db"),
            root.join("unused.sock"),
            unsafe { libc::geteuid() },
            47999,
        )
        .unwrap();
        service
            .store
            .insert(
                &Status {
                    operation_id: "fixture".into(),
                    state: "filled".into(),
                    ceremony_url: None,
                    filled_fields: vec!["given_name".into()],
                    outcome: None,
                },
                "traveler",
                "Fixture",
            )
            .unwrap();
        *service.private.lock().await = Some(PrivateCheckout {
            operation_id: "fixture".into(),
            mode: Mode::Traveler,
            view_target: tab.target.clone(),
            view_session: tab.session.clone(),
            seen_pages: std::collections::HashSet::from([tab.target.clone()]),
            tab,
            discovery: None,
            recipient: None,
            traveler: Some(traveler),
            contains_traveler: true,
            capability: "fixture".into(),
            claimed: true,
            approved: true,
        });
        service
            .private_action("fixture", ViewAction::Finish)
            .await
            .unwrap();
        let facts = service
            .request(Request::PrivateFacts {
                operation_id: "fixture".into(),
            })
            .await
            .unwrap();
        let facts: bloom_checkout_api::PaymentFacts = serde_json::from_value(facts).unwrap();
        assert_eq!(facts.total_minor, 399);
        assert_eq!(facts.currency, "USD");
        server.abort();
    }
    #[test]
    fn private_origin_guard_survives_restart_and_interrupted_fill_is_not_retried() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state.db");
        {
            let store = Store::open(&path).unwrap();
            store.protect_origin("https://booking.example").unwrap();
            store.protect_origin("https://booking.example").unwrap();
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
        assert_eq!(
            store.private_origins().unwrap(),
            ["https://booking.example"]
        );
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
            traveler: None,
            contains_traveler: false,
            view_target: tab.target.clone(),
            view_session: tab.session.clone(),
            seen_pages: std::collections::HashSet::from([tab.target.clone()]),
            tab,
            discovery: None,
            recipient: None,
            capability: token.clone(),
            claimed: false,
            approved: false,
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
        tokio::time::sleep(Duration::from_millis(200)).await;
        let state = service.private_state(&token).await.unwrap();
        assert_eq!(state["pages"].as_array().unwrap().len(), 2);
        let root_target = service
            .private
            .lock()
            .await
            .as_ref()
            .unwrap()
            .tab
            .target
            .clone();
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
            traveler: None,
            contains_traveler: false,
            view_target: tab.target.clone(),
            view_session: tab.session.clone(),
            seen_pages: std::collections::HashSet::from([tab.target.clone()]),
            tab,
            discovery: None,
            recipient: None,
            capability: token.clone(),
            claimed: true,
            approved: true,
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
    }
}
