pub(crate) use crate::travelers::{derived_traveler_value, formatted_phone};
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

/// Approval links last fifteen minutes; allow a short result-delivery grace.
const APPROVAL_RESULT_WAIT: Duration = Duration::from_secs(15 * 60 + 30);

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
        // Form errors can arrive after a pay click. Older versions incorrectly
        // converted them to not_submitted; neither state proves no charge.
        conn.execute("UPDATE operations SET state='uncertain',status=json_set(status,'$.state','uncertain','$.ceremony_url',NULL) WHERE state IN ('submitted','needs_input','not_submitted')",[])?;
        conn.execute("UPDATE operations SET state='disclosure_unknown',status=json_set(status,'$.state','disclosure_unknown','$.ceremony_url',NULL) WHERE state IN ('release_started','filled','partially_filled')",[])?;
        conn.execute("UPDATE operations SET state='failed_before_release',status=json_set(status,'$.state','failed_before_release','$.ceremony_url',NULL) WHERE state IN ('requested','preparing','awaiting_approval','manual_required','human_control')",[])?;
        // The unlocked values lived in memory. After a restart they are gone.
        conn.execute("UPDATE operations SET state='expired',status=json_set(status,'$.state','expired','$.ceremony_url',NULL) WHERE state='unlocked'",[])?;
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
    fn kind(&self, id: &str) -> Result<String> {
        self.0
            .lock()
            .query_row("SELECT kind FROM operations WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .context("Unknown checkout request")
    }
    fn finish_traveler(&self, id: &str, state: &str) -> Result<()> {
        self.0.lock().execute("UPDATE operations SET state=?2,status=json_set(status,'$.state',?2,'$.ceremony_url',NULL) WHERE id=?1 AND kind='traveler' AND state!='cancelled'",params![id,state])?;
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
    fn unresolved(&self, shop: &str) -> Result<Option<String>> {
        let conn = self.0.lock();
        match conn.query_row(
            "SELECT id FROM operations WHERE shop=?1 AND kind IN ('card','site') AND state IN \
             ('submitted','needs_input','uncertain','disclosure_unknown','partially_filled','filled','release_started') \
             LIMIT 1",
            [shop],
            |row| row.get(0),
        ) {
            Ok(id) => Ok(Some(id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
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
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get::<_, String>(6)?,
            ))
        })?;
        rows.map(|row| {
            let (created, kind, description, shop, total_minor, currency, status) = row?;
            Ok(HistoryEntry {
                created,
                kind,
                description,
                shop,
                total_minor,
                currency,
                status: serde_json::from_str(&status)?,
            })
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
    /// Checkout pressed the pay button, or may have. Without this or a manual
    /// submission, no page text can make the checkout paid or booked.
    submitted: bool,
}

struct PendingUnlock {
    operation_id: String,
    traveler_id: String,
    recipient: Recipient,
    origin: String,
    context: String,
    fields: Vec<bloom_signer_api::TravelerField>,
}

struct UnlockedTraveler {
    operation_id: String,
    origin: String,
    /// The unlock ends with the booking's browsing context.
    context: String,
    fields: Vec<bloom_signer_api::TravelerField>,
    values: BTreeMap<String, zeroize::Zeroizing<String>>,
    expires: tokio::time::Instant,
}

/// Drops travelers of another booking or past expiry; returns their unlock IDs.
fn prune_travelers(
    travelers: &mut BTreeMap<String, UnlockedTraveler>,
    context: &str,
    origin: &str,
) -> Vec<String> {
    let now = tokio::time::Instant::now();
    let mut dropped = Vec::new();
    travelers.retain(|_, traveler| {
        let keep =
            traveler.context == context && traveler.origin == origin && now < traveler.expires;
        if !keep {
            dropped.push(traveler.operation_id.clone());
        }
        keep
    });
    dropped
}

fn selected_traveler<'a>(
    travelers: &'a mut BTreeMap<String, UnlockedTraveler>,
    context: &str,
    origin: &str,
    id: Option<&str>,
) -> Result<&'a UnlockedTraveler> {
    prune_travelers(travelers, context, origin);
    if let Some(id) = id {
        return travelers
            .get(id)
            .context("Unlock that saved traveler for this booking first");
    }
    if travelers.len() > 1 {
        bail!("Choose traveler_id explicitly when multiple people are unlocked");
    }
    travelers
        .values()
        .next()
        .context("Unlock a saved traveler first")
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
    travelers: AsyncMutex<BTreeMap<String, UnlockedTraveler>>,
    /// The one `fill_traveler` person for this browsing context.
    journey_filler: AsyncMutex<Option<(String, String)>>,
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
    Error,
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
        let (context, origin) = self.browser.private_shopping_scope().await?;
        self.forget_journey_filler_unless(&context).await;
        {
            let mut travelers = self.travelers.lock().await;
            self.prune(&mut travelers, &context, &origin);
            if travelers.contains_key(&traveler_id) {
                bail!("That traveler is already unlocked; select their traveler_id when filling");
            }
        }
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
            paused: false,
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
            traveler_id,
            recipient,
            origin,
            context,
            fields: metadata.fields,
        });
        let service = self.clone();
        tokio::spawn(async move { service.finish_unlock(operation_id).await });
        Ok(serde_json::to_value(status)?)
    }

    async fn finish_unlock(self: Arc<Self>, operation_id: String) {
        let deadline = tokio::time::Instant::now() + APPROVAL_RESULT_WAIT;
        loop {
            tokio::time::sleep(Duration::from_millis(300)).await;
            if self
                .store
                .get(&operation_id)
                .is_ok_and(|status| status.state == "cancelled")
            {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = self.store.finish_traveler(&operation_id, "expired");
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
                            Err(_)
                                if self
                                    .store
                                    .get(&operation_id)
                                    .is_ok_and(|status| status.state == "cancelled") =>
                            {
                                return;
                            }
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
            let _ = self.store.finish_traveler(&operation_id, state);
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
        // Serialize record installation with cancellation, so a late release
        // cannot resurrect permission after cancel has returned.
        let mut travelers = self.travelers.lock().await;
        let mut status = self.store.consume(&pending.operation_id)?;
        let (context, origin) = self.browser.shopping_scope().await?;
        if context != pending.context || origin != pending.origin {
            bail!("Booking changed during traveler approval; unlock again for this booking");
        }
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
        for field in ["born_on", "document_expiry"] {
            if let Some(value) = values.get(field) {
                Self::remember_sent(&self.browser, field, value);
            }
        }
        status.filled_fields = values.keys().cloned().collect();
        self.forget_journey_filler_unless(&pending.context).await;
        self.prune(&mut travelers, &pending.context, &pending.origin);
        travelers.insert(
            pending.traveler_id,
            UnlockedTraveler {
                operation_id: pending.operation_id,
                origin: pending.origin,
                context: pending.context,
                fields: pending.fields,
                values,
                expires: tokio::time::Instant::now() + Duration::from_secs(1800),
            },
        );
        status.state = "unlocked".into();
        self.store.update(&status)?;
        Ok(())
    }

    async fn cancel_traveler(&self, operation_id: &str) -> Result<Value> {
        let mut unlocking = self.unlocking.lock().await;
        let mut travelers = self.travelers.lock().await;
        let mut status = self.store.get(operation_id)?;
        if !matches!(
            status.state.as_str(),
            "requested" | "awaiting_approval" | "release_started" | "unlocked"
        ) {
            return Ok(serde_json::to_value(status)?);
        }
        let pending = unlocking
            .as_ref()
            .is_some_and(|record| record.operation_id == operation_id);
        if pending {
            unlocking.take();
        } // Drops the only recipient private key.
        travelers.retain(|_, traveler| traveler.operation_id != operation_id);
        status.state = "cancelled".into();
        status.ceremony_url = None;
        self.store.update(&status)?;
        drop(travelers);
        drop(unlocking);
        if pending {
            // Local revocation is already durable. If Broker is unavailable,
            // its old ciphertext is unusable and the ceremony expires normally.
            let _ = self
                .intake(json!({"method":"cancel","operation_id":operation_id}))
                .await;
        }
        Ok(serde_json::to_value(status)?)
    }

    async fn type_traveler(
        &self,
        element_ref: String,
        field: &str,
        traveler_id: Option<&str>,
    ) -> Result<Value> {
        if self.private.lock().await.is_some() {
            bail!("A checkout already has private control");
        }
        let (context, origin) = self.browser.shopping_scope().await?;
        self.forget_journey_filler_unless(&context).await;
        let mut travelers = self.travelers.lock().await;
        self.prune(&mut travelers, &context, &origin);
        let traveler = selected_traveler(&mut travelers, &context, &origin, traveler_id)?;
        let text = derived_traveler_value(&traveler.values, field)
            .context("That saved traveler field is not available")?;
        Self::remember_sent(&self.browser, field, &text);
        if matches!(
            field,
            "gender" | "nationality" | "document_kind" | "document_country"
        ) {
            // A choice goes into a list: pick the option naming the saved value.
            self.browser
                .choose_traveler(
                    &element_ref,
                    field,
                    &text,
                    &traveler.context,
                    &traveler.origin,
                )
                .await?;
        } else {
            self.browser
                .type_traveler(
                    &element_ref,
                    field,
                    &text,
                    &traveler.context,
                    &traveler.origin,
                )
                .await?;
        }
        Ok(json!({"state":"typed","filled_fields":[field]}))
    }

    async fn fill_traveler(&self, traveler_id: Option<&str>) -> Result<Value> {
        if self.private.lock().await.is_some() {
            bail!("A checkout already has private control");
        }
        let (context, origin) = self.browser.shopping_scope().await?;
        self.forget_journey_filler_unless(&context).await;
        let mut travelers = self.travelers.lock().await;
        self.prune(&mut travelers, &context, &origin);
        let traveler = selected_traveler(&mut travelers, &context, &origin, traveler_id)?;
        let mut values = traveler.values.clone();
        let fields = traveler.fields.clone();
        let traveler_origin = traveler.origin.clone();
        let traveler_context = traveler.context.clone();
        let selected_id = match traveler_id {
            Some(id) => id.to_owned(),
            None => travelers
                .keys()
                .next()
                .context("Unlock a saved traveler first")?
                .clone(),
        };
        if let Some((saved_context, saved_id)) = self.journey_filler.lock().await.clone() {
            if saved_context == context && saved_id != selected_id {
                bail!(
                    "fill_traveler already filled {saved_id} on this booking; use type_traveler with the person's id for each field."
                );
            }
        }
        if let Some(phone) = values.get("phone").and_then(|p| formatted_phone(p)) {
            values.insert("phone".into(), zeroize::Zeroizing::new(phone));
        }
        for field in ["phone_national", "phone_area", "phone_local"] {
            if let Some(part) = derived_traveler_value(&values, field) {
                values.insert(field.into(), part);
            }
        }
        Self::remember_fill(&self.browser, &values);
        let filled = self
            .browser
            .fill_traveler(&traveler_origin, &traveler_context, &fields, &values)
            .await
            .inspect_err(|e| eprintln!("traveler fill refused: {e:#}"))?;
        *self.journey_filler.lock().await = Some((context, selected_id));
        Ok(json!({"state":"filled","filled_fields":filled}))
    }

    /// Every string about to be typed, including the formatted phone and the
    /// birth year a date control shows on its own.
    fn remember_fill(browser: &Browser, values: &BTreeMap<String, zeroize::Zeroizing<String>>) {
        for (field, value) in values {
            Self::remember_sent(browser, field, value);
        }
        for field in [
            "born_on_year",
            "born_on_month",
            "born_on_day",
            "born_on_dmy",
        ] {
            if values.contains_key(field) {
                continue;
            }
            if let Some(part) = derived_traveler_value(values, field) {
                Self::remember_sent(browser, field, &part);
            }
        }
    }

    fn remember_sent(browser: &Browser, field: &str, value: &str) {
        if value.is_empty() {
            return;
        }
        let item = (value.to_owned(), format!("[saved {field}]"));
        // Review pages commonly spell the month rather than repeat the ISO
        // value sent to their controls (Jetabroad: "1 Jan 1990").
        if matches!(field, "born_on" | "document_expiry") {
            let parts: Vec<_> = value.split('-').collect();
            if let [year, month, day] = parts.as_slice()
                && let (Ok(month), Ok(day)) = (month.parse::<usize>(), day.parse::<u8>())
                && (1..=12).contains(&month)
                && (1..=31).contains(&day)
            {
                let names = [
                    "January",
                    "February",
                    "March",
                    "April",
                    "May",
                    "June",
                    "July",
                    "August",
                    "September",
                    "October",
                    "November",
                    "December",
                ];
                let mut forms = vec![
                    format!("{day}/{month}/{year}"),
                    format!("{month}/{day}/{year}"),
                    format!("{day:02}/{month:02}/{year}"),
                    format!("{month:02}/{day:02}/{year}"),
                ];
                for name in [names[month - 1], &names[month - 1][..3]] {
                    forms.extend([
                        format!("{day} {name} {year}"),
                        format!("{day:02} {name} {year}"),
                        format!("{day} {name},{year}"),
                        format!("{day:02} {name},{year}"),
                        format!("{name} {day}, {year}"),
                    ]);
                }
                browser.redact(
                    forms
                        .into_iter()
                        .map(|form| (form, format!("[saved {field}]"))),
                );
            }
        }
        if field == "born_on_year" {
            browser.redact_min([item], 1);
        } else {
            browser.redact([item]);
        }
    }

    /// A new browsing context drops the person `fill_traveler` already used.
    async fn forget_journey_filler_unless(&self, context: &str) {
        let mut filler = self.journey_filler.lock().await;
        if filler.as_ref().is_some_and(|(saved, _)| saved != context) {
            *filler = None;
        }
    }

    /// Drop travelers outside this booking or past expiry; their unlocks end.
    fn prune(
        &self,
        travelers: &mut BTreeMap<String, UnlockedTraveler>,
        context: &str,
        origin: &str,
    ) {
        for id in prune_travelers(travelers, context, origin) {
            let _ = self.store.finish_traveler(&id, "expired");
        }
    }

    /// Drop every unlocked traveler's values and end their unlocks.
    async fn forget_travelers(&self) {
        let dropped = std::mem::take(&mut *self.travelers.lock().await);
        for traveler in dropped.into_values() {
            let _ = self
                .store
                .finish_traveler(&traveler.operation_id, "expired");
        }
    }

    async fn return_control(&self) -> Result<()> {
        self.forget_travelers().await;
        self.journey_filler.lock().await.take();
        self.browser.return_control().await
    }

    async fn return_control_at(&self, target: &str, url: Option<String>) -> Result<()> {
        self.forget_travelers().await;
        self.journey_filler.lock().await.take();
        self.browser.return_control_at(target, url).await
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
            travelers: AsyncMutex::new(BTreeMap::new()),
            journey_filler: AsyncMutex::new(None),
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
        if let IntakeResponse::Error = response {
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
                request: BrowseRequest::FillTraveler { traveler_id },
            } => self.fill_traveler(traveler_id.as_deref()).await,
            Request::Browse {
                request:
                    BrowseRequest::TypeTraveler {
                        element_ref,
                        field,
                        traveler_id,
                    },
            } => {
                self.type_traveler(element_ref, &field, traveler_id.as_deref())
                    .await
            }
            Request::Browse { request } => {
                if matches!(request, BrowseRequest::Open { .. }) {
                    self.forget_travelers().await;
                }
                self.browser.browse(request).await
            }
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
                let unlocking = self.unlocking.lock().await;
                let mut private = self.private.lock().await;
                if private.is_some() {
                    bail!("A checkout already has private control");
                }
                if unlocking.is_some() {
                    bail!(
                        "A saved traveler unlock is waiting for approval; finish or cancel it before payment"
                    );
                }
                drop(unlocking);
                let mut status = Status {
                    operation_id: operation_id.clone(),
                    state: "requested".into(),
                    ceremony_url: None,
                    filled_fields: Vec::new(),
                    outcome: None,
                    paused: false,
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
                        eprintln!(
                            "payment refused over form errors: {}",
                            Self::form_error_count(&attention)
                        );
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
                if matches!(mode, Mode::Card | Mode::Site) {
                    if let Ok((_, origin)) = self.browser.shopping_scope().await {
                        if let Some(open) = self.store.unresolved(&origin)? {
                            bail!(
                                "{open}: ask the person to check the merchant or bank, then write resolve"
                            );
                        }
                    }
                }
                if self.store.get(&operation_id).is_ok() {
                    bail!("Operation ID already used");
                }
                let tab = self.browser.handoff().await?;
                if let Err(error) = self.store.insert(&status, kind, &agent_description) {
                    let _ = self.return_control().await;
                    return Err(error);
                }
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
                let challenge_url = challenge_url(self.view_port, &capability);
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
                            submitted: false,
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
                        self.return_control().await?;
                        Ok(serde_json::to_value(status)?)
                    }
                }
            }
            Request::Cancel { operation_id } => {
                if self.store.kind(&operation_id)? == "traveler" {
                    return self.cancel_traveler(&operation_id).await;
                }
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
                self.return_control().await?;
                *private = None;
                Ok(serde_json::to_value(status)?)
            }
            Request::Resolve { operation_id } => {
                OperationId::new(&operation_id)
                    .map_err(|_| anyhow::anyhow!("Invalid operation ID"))?;
                if !matches!(self.store.kind(&operation_id)?.as_str(), "card" | "site") {
                    bail!("That checkout has no unresolved result to check");
                }
                if self
                    .private
                    .lock()
                    .await
                    .as_ref()
                    .is_some_and(|checkout| checkout.operation_id == operation_id)
                {
                    bail!(
                        "That checkout's private view is still open; the payment may still finish there. Resolve after the person closes it."
                    );
                }
                let mut status = self.store.get(&operation_id)?;
                if matches!(status.state.as_str(), "requested" | "awaiting_approval") {
                    bail!(
                        "That checkout is still in progress; resolve is for a result the person must check"
                    );
                }
                if !matches!(
                    status.state.as_str(),
                    "submitted"
                        | "needs_input"
                        | "uncertain"
                        | "disclosure_unknown"
                        | "partially_filled"
                        | "filled"
                        | "release_started"
                ) {
                    bail!("That checkout has no unresolved result to check");
                }
                let mut outcome = status
                    .outcome
                    .take()
                    .unwrap_or(bloom_checkout_api::Outcome {
                        state: "resolved".into(),
                        source: "human".into(),
                        confirmation_reached: false,
                        order_id: None,
                        merchant_reported_total_minor: None,
                        currency: None,
                        resolution: None,
                    });
                outcome.resolution = Some("human_checked".into());
                status.state = "resolved".into();
                status.ceremony_url = None;
                status.outcome = Some(outcome);
                self.store.update(&status)?;
                Ok(serde_json::to_value(status)?)
            }
        }
    }

    async fn finish_approved(self: Arc<Self>, operation_id: String) {
        let deadline = tokio::time::Instant::now() + APPROVAL_RESULT_WAIT;
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
                        if self.return_control().await.is_ok() {
                            *private = None;
                        }
                        return;
                    }
                    _ => {}
                }
            }
            if tokio::time::Instant::now() >= deadline {
                self.set_state(&operation_id, "expired");
                if self.return_control().await.is_ok() {
                    *private = None;
                }
                return;
            }
        }
    }

    /// The number of form-error strings. Their text can repeat what the person typed.
    fn form_error_count(attention: &Value) -> usize {
        attention["errors"]
            .as_array()
            .map(|errors| errors.len())
            .unwrap_or(0)
    }

    fn mark_paused(&self, id: &str) {
        if let Ok(mut status) = self.store.get(id) {
            status.paused = true;
            let _ = self.store.update(&status);
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
                Ok(true) => checkout.submitted = true,
                Ok(false) => {
                    status.state = "needs_input".into();
                    self.store.update(&status)?;
                }
                Err(_) => {
                    checkout.submitted = true;
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
            Ok(true) => checkout.submitted = true,
            Ok(false) => {
                status.state = "needs_input".into();
                self.store.update(&status)?;
            }
            Err(_) => {
                checkout.submitted = true;
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

/// The state a card or site checkout ends in when its private view closes:
/// a recorded result stays; anything else is uncertain until checked.
fn closing_state(current: &str) -> &str {
    match current {
        "paid" | "booked" | "declined" | "resolved" => current,
        _ => "uncertain",
    }
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

fn challenge_url(view_port: u16, capability: &str) -> String {
    format!("http://localhost:{view_port}/private?token={capability}")
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
            let (mode, tab, view_target, submitted) = {
                let private = self.private.lock().await;
                let Some(checkout) = private.as_ref().filter(|p| p.operation_id == id) else {
                    return;
                };
                (
                    checkout.mode,
                    checkout.tab.clone(),
                    checkout.view_target.clone(),
                    checkout.submitted || checkout.manual_submission,
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
                    | "declined"
                    | "manual_required"
                    | "uncertain"
                    | "partially_filled"
                    | "disclosure_unknown"
            ) {
                let mut observed = Vec::new();
                let contexts = tokio::time::timeout(
                    Duration::from_secs(2),
                    tab.cdp.contexts(&tab.session, "bloom-outcome"),
                )
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default();
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
                    let is_top = context.parent_id.is_none();
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
                    observed.push((is_top, outcome));
                }
                let attempt = matches!(status.state.as_str(), "submitted" | "needs_input");
                // Success text counts only from the top document, after checkout
                // or the person pressed pay. "needs_input" alone may mean the
                // pay button was never pressed.
                let completed_allowed =
                    status.state == "submitted" || (status.state == "needs_input" && submitted);
                let outcome = observed
                    .iter()
                    .find_map(|(is_top, outcome)| {
                        let terminal = match outcome["state"].as_str() {
                            Some("booked") if *is_top && completed_allowed => Some("booked"),
                            // Help text can say "payment failed" before anyone pays.
                            Some("declined") if attempt || status.state == "declined" => {
                                Some("declined")
                            }
                            Some("payment_phrase") if *is_top && completed_allowed => Some("paid"),
                            _ => None,
                        }?;
                        Some((terminal, outcome))
                    })
                    .or_else(|| {
                        observed
                            .iter()
                            .find(|(_, outcome)| outcome["state"] == "needs_input")
                            .map(|(_, outcome)| ("needs_input", outcome))
                    });
                if let Some((state, outcome)) = outcome {
                    if state == "needs_input" {
                        // The page needs attention, but may already have sent
                        // payment. Do not infer a bank outcome from form text.
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
                    } else if state == "declined" {
                        // Record the merchant decline and leave the pages up.
                        if status.state != "declined" {
                            status.state = "declined".into();
                            status.outcome = serde_json::from_value((*outcome).clone()).ok();
                            status.ceremony_url = None;
                            let _ = self.store.update(&status);
                        }
                    } else {
                        let mut recorded = (*outcome).clone();
                        if state == "paid" {
                            recorded["state"] = json!("paid");
                        }
                        let close = matches!(status.state.as_str(), "submitted" | "needs_input");
                        status.state = state.into();
                        status.outcome = serde_json::from_value(recorded).ok();
                        status.ceremony_url = None;
                        let stored = self.store.update(&status).is_ok();
                        if close && stored && self.return_control().await.is_ok() {
                            let mut private = self.private.lock().await;
                            if let Some(checkout) =
                                private.as_ref().filter(|p| p.operation_id == id)
                            {
                                self.retain_completed(checkout, status);
                                *private = None;
                            }
                        } else if close && stored {
                            status.paused = true;
                            let _ = self.store.update(&status);
                        } else {
                            let _ = self.store.update(&status);
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
                if self.return_control_at(&view_target, resume).await.is_ok() {
                    let current = self.store.get(&id).map(|s| s.state).unwrap_or_default();
                    let final_state = if mode == Mode::TakeOver {
                        "returned"
                    } else {
                        closing_state(&current)
                    };
                    self.set_state(&id, final_state);
                    if let Ok(status) = self.store.get(&id) {
                        let mut private = self.private.lock().await;
                        if let Some(checkout) = private.as_ref().filter(|p| p.operation_id == id) {
                            self.retain_completed(checkout, status);
                            *private = None;
                        }
                    }
                } else {
                    self.mark_paused(&id);
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
                    self.return_control_at(&view_target, resume).await?;
                    self.set_state(&operation_id, "returned");
                } else {
                    let current = self.store.get(&operation_id)?.state;
                    self.set_state(&operation_id, closing_state(&current));
                    self.return_control().await?;
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
    "payment requires approval",
    "Input exceeds limit",
    "Checkout has private control; shopping is paused",
    "Saved traveler details are unlocked for another booking or website",
    "Choose traveler_id explicitly when multiple people are unlocked",
    "Unlock that saved traveler for this booking first",
    "Unlock a saved traveler first",
    "That saved traveler field is not available",
    "That list did not take the saved value; choose it in the private view",
    "A checkout already has private control",
    "That field is in an embedded frame from another website; type it in the private view",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn multiple_travelers_and_a_different_payer_require_explicit_records_and_targets() {
        let (url, server) = crate::discovery::tests::fixture(
            "<fieldset><legend>Passenger one</legend><input aria-label='Passenger one given name' autocomplete='given-name'></fieldset>
             <fieldset><legend>Passenger two</legend><input aria-label='Passenger two given name' autocomplete='given-name'></fieldset>
             <fieldset><legend>Cardholder</legend><input aria-label='Payer given name' autocomplete='given-name'></fieldset>
             <input type='email' aria-label='Contact email'>".into(),
        ).await;
        let root = tempfile::tempdir().unwrap();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.path().join("profile"),
            &["--no-sandbox".into(), "--ignore-certificate-errors".into()],
        )
        .await
        .unwrap();
        browser
            .browse(BrowseRequest::Open { url: url.clone() })
            .await
            .unwrap();
        let mut ready = false;
        for _ in 0..100 {
            if browser
                .browse(BrowseRequest::Snapshot)
                .await
                .is_ok_and(|s| s["elements"].as_array().is_some_and(|e| e.len() == 4))
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(ready, "fixture did not load");
        let service = CheckoutService::new(
            browser.clone(),
            &root.path().join("state.db"),
            root.path().join("unused.sock"),
            unsafe { libc::geteuid() },
            47999,
        )
        .unwrap();
        let (context, origin) = browser.shopping_scope().await.unwrap();
        // Cancellation remains effective even if Broker is unavailable and a
        // delayed poll/expiry tries to publish an older lifecycle result.
        service
            .store
            .insert(
                &Status {
                    operation_id: "pending-unlock".into(),
                    state: "awaiting_approval".into(),
                    ceremony_url: None,
                    filled_fields: vec![],
                    outcome: None,
                    paused: false,
                },
                "traveler",
                "Synthetic pending unlock",
            )
            .unwrap();
        *service.unlocking.lock().await = Some(PendingUnlock {
            operation_id: "pending-unlock".into(),
            traveler_id: "cancelled-record".into(),
            recipient: Recipient::generate(),
            context: context.clone(),
            origin: origin.clone(),
            fields: vec![],
        });
        assert_eq!(
            service.cancel_traveler("pending-unlock").await.unwrap()["state"],
            "cancelled"
        );
        assert!(service.unlocking.lock().await.is_none());
        service
            .store
            .finish_traveler("pending-unlock", "expired")
            .unwrap();
        assert_eq!(
            service.store.get("pending-unlock").unwrap().state,
            "cancelled"
        );
        assert!(service.store.consume("pending-unlock").is_err());
        // These records stand in for three independently approved releases.
        // There is no Broker fixture here and no claim of ceremony acceptance.
        for (id, name, email) in [
            ("person-one", "FixtureAlice", "alice@example.test"),
            ("person-two", "FixtureBob", "bob@example.test"),
            ("payer", "FixtureCasey", "payer@example.test"),
        ] {
            browser.redact([
                (name.into(), "[saved given_name]".into()),
                (email.into(), "[saved email]".into()),
            ]);
            service.travelers.lock().await.insert(
                id.into(),
                UnlockedTraveler {
                    operation_id: format!("{id}-unlock"),
                    origin: origin.clone(),
                    context: context.clone(),
                    fields: vec![
                        bloom_signer_api::TravelerField::GivenName,
                        bloom_signer_api::TravelerField::Email,
                    ],
                    values: [
                        ("given_name".into(), zeroize::Zeroizing::new(name.into())),
                        ("email".into(), zeroize::Zeroizing::new(email.into())),
                    ]
                    .into(),
                    expires: tokio::time::Instant::now() + Duration::from_secs(60),
                },
            );
        }
        let error = service
            .request(Request::Browse {
                request: BrowseRequest::FillTraveler { traveler_id: None },
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Choose traveler_id"));
        // Even an explicit person must not auto-fill two passenger blocks.
        assert!(
            service
                .request(Request::Browse {
                    request: BrowseRequest::FillTraveler {
                        traveler_id: Some("person-one".into())
                    }
                })
                .await
                .is_err()
        );
        assert!(
            service
                .request(Request::Browse {
                    request: BrowseRequest::FillTraveler {
                        traveler_id: Some("not-approved".into())
                    }
                })
                .await
                .is_err()
        );
        for (id, label, field) in [
            ("person-one", "Passenger one given name", "given_name"),
            ("person-two", "Passenger two given name", "given_name"),
            ("payer", "Payer given name", "given_name"),
            ("payer", "Contact email", "email"),
        ] {
            let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
            let element_ref = snapshot["elements"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["label"] == label)
                .unwrap()["ref"]
                .as_str()
                .unwrap()
                .to_owned();
            let response = service
                .request(Request::Browse {
                    request: BrowseRequest::TypeTraveler {
                        element_ref,
                        field: field.into(),
                        traveler_id: Some(id.into()),
                    },
                })
                .await
                .unwrap();
            assert_eq!(response, json!({"state":"typed","filled_fields":[field]}));
        }
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        for element in snapshot["elements"].as_array().unwrap() {
            assert!(element["value"].as_str().unwrap().starts_with("[saved "));
        }
        let tab = browser.handoff().await.unwrap();
        let actual = tab
            .cdp
            .evaluate(
                &tab.session,
                "Array.from(document.querySelectorAll('input'), e => e.value)".into(),
            )
            .await
            .unwrap();
        assert_eq!(
            actual,
            json!([
                "FixtureAlice",
                "FixtureBob",
                "FixtureCasey",
                "payer@example.test"
            ])
        );
        service
            .store
            .insert(
                &Status {
                    operation_id: "person-two-unlock".into(),
                    state: "unlocked".into(),
                    ceremony_url: None,
                    filled_fields: vec![],
                    outcome: None,
                    paused: false,
                },
                "traveler",
                "Synthetic approved person",
            )
            .unwrap();
        let cancelled = service
            .request(Request::Cancel {
                operation_id: "person-two-unlock".into(),
            })
            .await
            .unwrap();
        assert_eq!(cancelled["state"], "cancelled");
        assert!(!service.travelers.lock().await.contains_key("person-two"));
        service
            .travelers
            .lock()
            .await
            .get_mut("person-one")
            .unwrap()
            .expires = tokio::time::Instant::now();
        assert!(service.fill_traveler(Some("person-one")).await.is_err());
        assert!(!service.travelers.lock().await.contains_key("person-one"));
        assert_eq!(service.travelers.lock().await.len(), 1);
        service.return_control().await.unwrap();
        assert!(service.travelers.lock().await.is_empty());
        service
            .request(Request::Browse {
                request: BrowseRequest::Open { url },
            })
            .await
            .unwrap();
        assert!(service.fill_traveler(Some("person-one")).await.is_err());
        assert!(service.travelers.lock().await.is_empty());
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn one_fill_traveler_person_per_booking() {
        let (url, server) = crate::discovery::tests::fixture(
            "<div><div>Given name</div><input autocomplete='given-name'></div>
             <div><div>Document number</div><input aria-label='Document number'></div>"
                .into(),
        )
        .await;
        let root = tempfile::tempdir().unwrap();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.path().join("profile"),
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
            &root.path().join("state.db"),
            root.path().join("unused.sock"),
            unsafe { libc::geteuid() },
            47999,
        )
        .unwrap();
        let (context, origin) = browser.shopping_scope().await.unwrap();
        for (id, name, document) in [
            ("person-a", "FixtureAlice", None),
            ("person-b", "FixtureBob", Some("BDOC999")),
        ] {
            let mut values =
                BTreeMap::from([("given_name".into(), zeroize::Zeroizing::new(name.into()))]);
            let mut fields = vec![bloom_signer_api::TravelerField::GivenName];
            if let Some(document) = document {
                values.insert(
                    "document_number".into(),
                    zeroize::Zeroizing::new(document.into()),
                );
                fields.push(bloom_signer_api::TravelerField::DocumentNumber);
            }
            service.travelers.lock().await.insert(
                id.into(),
                UnlockedTraveler {
                    operation_id: format!("{id}-unlock"),
                    origin: origin.clone(),
                    context: context.clone(),
                    fields,
                    values,
                    expires: tokio::time::Instant::now() + Duration::from_secs(60),
                },
            );
        }
        let filled = service.fill_traveler(Some("person-a")).await.unwrap();
        assert_eq!(filled["filled_fields"], json!(["given_name"]));
        let error = service
            .fill_traveler(Some("person-b"))
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "fill_traveler already filled person-a on this booking; use type_traveler with the person's id for each field."
        );
        let tab = browser.handoff().await.unwrap();
        let values = tab
            .cdp
            .evaluate(
                &tab.session,
                "Array.from(document.querySelectorAll('input'), e => e.value)".into(),
            )
            .await
            .unwrap();
        assert_eq!(values, json!(["FixtureAlice", ""]));
        server.abort();
    }

    #[tokio::test]
    async fn filled_phone_and_birth_year_appear_only_as_placeholders() {
        let (url, server) = crate::discovery::tests::fixture(
            "<div>Fecha de Nacimiento <select aria-label='Año'><option value=''></option><option value='1990'>1990</option><option value='1991'>1991</option></select></div>
             <input aria-label='Teléfono'>"
                .into(),
        )
        .await;
        let root = tempfile::tempdir().unwrap();
        let browser = Browser::launch(
            &crate::test_chromium(),
            &root.path().join("profile"),
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
            &root.path().join("state.db"),
            root.path().join("unused.sock"),
            unsafe { libc::geteuid() },
            47999,
        )
        .unwrap();
        let (context, origin) = browser.shopping_scope().await.unwrap();
        service.travelers.lock().await.insert(
            "person".into(),
            UnlockedTraveler {
                operation_id: "person-unlock".into(),
                origin,
                context,
                fields: vec![
                    bloom_signer_api::TravelerField::Phone,
                    bloom_signer_api::TravelerField::BornOn,
                ],
                values: [
                    (
                        "phone".into(),
                        zeroize::Zeroizing::new("+5491123456789".into()),
                    ),
                    (
                        "born_on".into(),
                        zeroize::Zeroizing::new("1990-05-07".into()),
                    ),
                ]
                .into(),
                expires: tokio::time::Instant::now() + Duration::from_secs(60),
            },
        );
        let filled = service.fill_traveler(Some("person")).await.unwrap();
        assert!(
            filled["filled_fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field == "phone")
        );
        let formatted = formatted_phone("+5491123456789").expect("saved phone formats");
        let snapshot = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let text = snapshot.to_string();
        assert!(
            !text.contains(&formatted),
            "formatted phone {formatted} leaked: {text}"
        );
        assert!(!text.contains("+5491123456789"), "raw phone leaked: {text}");
        assert!(!text.contains("1990"), "birth year leaked: {text}");
        assert!(text.contains("[saved phone]"), "{text}");
        assert!(text.contains("[saved born_on_year]"), "{text}");
        server.abort();
    }

    #[tokio::test]
    async fn traveler_cache_drops_expired_records_and_rejects_unapproved_ids() {
        let mut records = BTreeMap::new();
        for (id, expired) in [("active", false), ("expired", true)] {
            records.insert(
                id.into(),
                UnlockedTraveler {
                    operation_id: format!("{id}-unlock"),
                    origin: "https://shop.example".into(),
                    context: "booking".into(),
                    fields: vec![],
                    values: BTreeMap::new(),
                    expires: tokio::time::Instant::now()
                        + if expired {
                            Duration::ZERO
                        } else {
                            Duration::from_secs(60)
                        },
                },
            );
        }
        assert!(
            selected_traveler(
                &mut records,
                "booking",
                "https://shop.example",
                Some("expired")
            )
            .is_err()
        );
        assert_eq!(records.len(), 1);
        assert!(selected_traveler(&mut records, "booking", "https://shop.example", None).is_ok());
        assert!(
            selected_traveler(
                &mut records,
                "booking",
                "https://other.example",
                Some("active")
            )
            .is_err()
        );
        assert!(records.is_empty());
    }

    /// A claimed private card checkout on `html` in `state`, ready to watch.
    async fn watched_checkout(
        html: &str,
        state: &str,
        submitted: bool,
        lose_shopping: bool,
    ) -> (
        Arc<CheckoutService>,
        String,
        String,
        tokio::task::JoinHandle<()>,
    ) {
        let (url, server) = crate::discovery::tests::fixture(html.into()).await;
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
        tokio::time::sleep(Duration::from_millis(300)).await;
        let tab = browser.handoff().await.unwrap();
        if lose_shopping {
            browser.lose_shopping_context().await;
        }
        let service = CheckoutService::new(
            browser,
            &root.join("state.db"),
            root.join("unused.sock"),
            unsafe { libc::geteuid() },
            47999,
        )
        .unwrap();
        let status = Status {
            operation_id: "d".repeat(64),
            state: state.into(),
            ceremony_url: None,
            filled_fields: vec!["number".into()],
            outcome: None,
            paused: false,
        };
        service
            .store
            .insert(&status, "card", "Fixture shop")
            .unwrap();
        let token = hex_token(&[31; 32]);
        *service.private.lock().await = Some(PrivateCheckout {
            operation_id: status.operation_id.clone(),
            mode: Mode::Card,
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
            submitted,
        });
        (service, status.operation_id, token, server)
    }

    /// Watch for a few polls; the watcher keeps running until its deadline.
    async fn watch_briefly(service: &Arc<CheckoutService>, id: &str) -> String {
        let _ =
            tokio::time::timeout(Duration::from_secs(3), service.watch_outcome(id.into())).await;
        service.store.get(id).unwrap().state
    }

    #[tokio::test]
    async fn payment_phrase_counts_only_after_a_recorded_submission() {
        let page = "<h1>Thank you for your order</h1>";
        let (service, id, _, server) = watched_checkout(page, "needs_input", false, false).await;
        assert_eq!(watch_briefly(&service, &id).await, "needs_input");
        server.abort();
        let (service, id, _, server) = watched_checkout(page, "needs_input", true, false).await;
        assert_eq!(watch_briefly(&service, &id).await, "paid");
        server.abort();
    }

    #[tokio::test]
    async fn booking_phrase_needs_a_submission_and_the_top_document() {
        let booked = "<h1>Tu compra ha sido confirmada</h1><p>Código de reserva: AB12CD</p>";
        let framed = format!("<p>Checkout</p><iframe srcdoc='{booked}'></iframe>");
        let (service, id, _, server) = watched_checkout(&framed, "submitted", true, false).await;
        assert_eq!(watch_briefly(&service, &id).await, "submitted");
        server.abort();
        let (service, id, _, server) =
            watched_checkout(booked, "manual_required", false, false).await;
        assert_eq!(watch_briefly(&service, &id).await, "manual_required");
        server.abort();
    }

    async fn wait_for_shopping_page(browser: &Browser, url: &str) {
        let origin = url::Url::parse(url).unwrap().origin().ascii_serialization();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if browser
                    .browse(BrowseRequest::Snapshot)
                    .await
                    .is_ok_and(|page| page["url"] == url)
                    && browser
                        .shopping_scope()
                        .await
                        .is_ok_and(|(_, site)| site == origin)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("fixture shopping page did not load");
    }

    /// A service shopping on `html`, with no private checkout.
    async fn shopping_service(
        html: &str,
    ) -> (
        Arc<CheckoutService>,
        Arc<Browser>,
        String,
        tokio::task::JoinHandle<()>,
    ) {
        let (url, server) = crate::discovery::tests::fixture(html.into()).await;
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
        wait_for_shopping_page(&browser, &url).await;
        let service = CheckoutService::new(
            browser.clone(),
            &root.join("state.db"),
            root.join("unused.sock"),
            unsafe { libc::geteuid() },
            47999,
        )
        .unwrap();
        (service, browser, url, server)
    }

    /// An unlocked traveler on the current booking, recorded as `unlocked`.
    async fn unlocked(service: &CheckoutService, id: &str, lifetime: Duration) {
        let (context, origin) = service.browser.shopping_scope().await.unwrap();
        let operation_id = format!("{id}-unlock");
        service
            .store
            .insert(
                &Status {
                    operation_id: operation_id.clone(),
                    state: "unlocked".into(),
                    ceremony_url: None,
                    filled_fields: vec![],
                    outcome: None,
                    paused: false,
                },
                "traveler",
                "Synthetic unlock",
            )
            .unwrap();
        service.travelers.lock().await.insert(
            id.into(),
            UnlockedTraveler {
                operation_id,
                origin,
                context,
                fields: vec![],
                values: BTreeMap::new(),
                expires: tokio::time::Instant::now() + lifetime,
            },
        );
    }

    #[tokio::test]
    async fn dropped_traveler_values_end_their_unlock_as_expired() {
        let (service, _browser, url, server) = shopping_service("<input>").await;
        let state = |id: &str| service.store.get(&format!("{id}-unlock")).unwrap().state;
        unlocked(&service, "opened", Duration::from_secs(60)).await;
        service
            .request(Request::Browse {
                request: BrowseRequest::Open { url: url.clone() },
            })
            .await
            .unwrap();
        assert_eq!(state("opened"), "expired");
        wait_for_shopping_page(&service.browser, &url).await;
        unlocked(&service, "old", Duration::ZERO).await;
        assert!(
            service
                .request(Request::Browse {
                    request: BrowseRequest::TypeTraveler {
                        element_ref: "0:0".into(),
                        field: "given_name".into(),
                        traveler_id: Some("old".into()),
                    },
                })
                .await
                .is_err()
        );
        assert_eq!(state("old"), "expired");
        unlocked(&service, "returned", Duration::from_secs(60)).await;
        service.return_control().await.unwrap();
        assert_eq!(state("returned"), "expired");
        server.abort();
    }

    #[tokio::test]
    async fn traveler_guidance_reaches_the_agent() {
        let mut none = BTreeMap::new();
        let Err(error) = selected_traveler(&mut none, "booking", "https://shop.example", None)
        else {
            panic!("no traveler is unlocked");
        };
        let error = error.to_string();
        assert!(BROWSE_ERRORS.contains(&error.as_str()), "{error}");
        assert!(BROWSE_ERRORS.contains(&"That saved traveler field is not available"));
    }

    #[tokio::test]
    async fn checkout_waits_for_a_pending_traveler_unlock() {
        let (service, _browser, _, server) = shopping_service("<button>Pay</button>").await;
        let (context, origin) = service.browser.shopping_scope().await.unwrap();
        *service.unlocking.lock().await = Some(PendingUnlock {
            operation_id: "pending-unlock".into(),
            traveler_id: "person".into(),
            recipient: Recipient::generate(),
            context,
            origin,
            fields: vec![],
        });
        let error = service
            .request(Request::Checkout {
                operation_id: "e".repeat(64),
                card_id: None,
                agent_description: "Fixture".into(),
                take_over: true,
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("traveler"), "{error}");
        assert!(service.store.get(&"e".repeat(64)).is_err());
        server.abort();
    }

    #[tokio::test]
    async fn a_failed_handoff_leaves_no_requested_checkout() {
        let (service, browser, _, server) = shopping_service("<button>Pay</button>").await;
        let _held = browser.handoff().await.unwrap();
        assert!(
            service
                .request(Request::Checkout {
                    operation_id: "f".repeat(64),
                    card_id: None,
                    agent_description: "Fixture".into(),
                    take_over: true,
                })
                .await
                .is_err()
        );
        assert!(service.store.get(&"f".repeat(64)).is_err());
        server.abort();
    }

    #[tokio::test]
    async fn finish_keeps_a_recorded_outcome() {
        let booked = "<h1>Tu compra ha sido confirmada</h1><p>Código de reserva: AB12CD</p>";
        let (service, id, token, server) = watched_checkout(booked, "submitted", true, true).await;
        assert_eq!(watch_briefly(&service, &id).await, "booked");
        assert!(service.store.get(&id).unwrap().paused);
        let _ = service.private_action(&token, ViewAction::Finish).await;
        assert_eq!(service.store.get(&id).unwrap().state, "booked");
        server.abort();
    }

    #[test]
    fn closing_without_a_result_is_uncertain_but_keeps_recorded_ones() {
        for kept in ["paid", "booked", "declined", "resolved"] {
            assert_eq!(closing_state(kept), kept);
        }
        for open in ["submitted", "needs_input", "manual_required", "filled"] {
            assert_eq!(closing_state(open), "uncertain");
        }
    }

    #[tokio::test]
    async fn resolve_waits_until_the_private_view_closes() {
        let page = "<h1>Bank check</h1>";
        let (service, id, _, server) = watched_checkout(page, "needs_input", true, false).await;
        let error = service
            .request(Request::Resolve {
                operation_id: id.clone(),
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("private view"), "{error}");
        assert_eq!(service.store.get(&id).unwrap().state, "needs_input");
        server.abort();
    }

    #[tokio::test]
    async fn airline_confirmation_becomes_booked_with_its_code() {
        let (service, browser, _, server) = shopping_service(
            "<p data-bloom-total-minor='21730759' data-bloom-currency='ARS'>Total ARS 217307.59</p>
             <h1>Tu compra ha sido confirmada</h1><p>Código de reserva: AB12CD</p>",
        )
        .await;
        let tab = browser.handoff().await.unwrap();
        let status = Status {
            operation_id: "fixture-booking".into(),
            state: "submitted".into(),
            ceremony_url: None,
            filled_fields: vec!["number".into(), "expiry".into(), "cvc".into()],
            outcome: None,
            paused: false,
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
            discovery: None,
            recipient: None,
            capability: token.clone(),
            claimed: true,
            approved: true,
            manual_submission: false,
            submitted: false,
        });
        tokio::time::timeout(
            Duration::from_secs(10),
            service.watch_outcome(status.operation_id.clone()),
        )
        .await
        .unwrap();
        let public = service.store.get(&status.operation_id).unwrap();
        assert_eq!(public.state, "booked");
        assert_eq!(public.outcome.unwrap().order_id.as_deref(), Some("AB12CD"));
        assert!(!public.paused);
        let private = service.private_state(&token).await.unwrap();
        assert_eq!(private["state"], "booked");
        assert_eq!(private["outcome"]["order_id"], "AB12CD");
        server.abort();
    }

    #[tokio::test]
    async fn failed_return_keeps_booked_and_marks_shopping_paused() {
        let (url, server) = crate::discovery::tests::fixture(
            "<h1>Tu compra ha sido confirmada</h1><p>Código de reserva: AB12CD</p>".into(),
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
        browser.lose_shopping_context().await;
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
            operation_id: "fixture-paused".into(),
            state: "submitted".into(),
            ceremony_url: None,
            filled_fields: vec!["number".into()],
            outcome: None,
            paused: false,
        };
        service
            .store
            .insert(&status, "card", "Fixture flight")
            .unwrap();
        *service.private.lock().await = Some(PrivateCheckout {
            operation_id: status.operation_id.clone(),
            mode: Mode::Card,
            view_target: tab.target.clone(),
            view_session: tab.session.clone(),
            seen_pages: std::collections::HashSet::from([tab.target.clone()]),
            tab,
            discovery: None,
            recipient: None,
            capability: hex_token(&[29; 32]),
            claimed: true,
            approved: true,
            manual_submission: false,
            submitted: false,
        });
        tokio::time::timeout(
            Duration::from_secs(4),
            service.watch_outcome(status.operation_id.clone()),
        )
        .await
        .unwrap();
        let public = service.store.get(&status.operation_id).unwrap();
        assert_eq!(public.state, "booked");
        assert!(public.paused, "status.json must say shopping is paused");
        assert!(service.private.lock().await.is_some());
        server.abort();
    }

    #[tokio::test]
    async fn thank_you_with_live_card_fields_stays_manual_required() {
        let (url, server) = crate::discovery::tests::fixture(
            "<h1>Thank you for shopping</h1>
             <input autocomplete='cc-number'><input autocomplete='cc-exp'><input autocomplete='cc-csc'>
             <button>Pay</button>".into(),
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
            operation_id: "fixture-thanks".into(),
            state: "manual_required".into(),
            ceremony_url: None,
            filled_fields: vec![],
            outcome: None,
            paused: false,
        };
        service
            .store
            .insert(&status, "card", "Fixture thanks")
            .unwrap();
        *service.private.lock().await = Some(PrivateCheckout {
            operation_id: status.operation_id.clone(),
            mode: Mode::Card,
            view_target: tab.target.clone(),
            view_session: tab.session.clone(),
            seen_pages: std::collections::HashSet::from([tab.target.clone()]),
            tab,
            discovery: None,
            recipient: None,
            capability: hex_token(&[31; 32]),
            claimed: true,
            approved: true,
            manual_submission: false,
            submitted: false,
        });
        let finished = tokio::time::timeout(
            Duration::from_secs(3),
            service.watch_outcome(status.operation_id.clone()),
        )
        .await;
        assert!(
            finished.is_err(),
            "a thank-you on the card form closed the session"
        );
        assert_eq!(
            service.store.get(&status.operation_id).unwrap().state,
            "manual_required"
        );
        assert!(service.private.lock().await.is_some());
        server.abort();
    }

    #[tokio::test]
    async fn payment_failed_help_text_keeps_manual_required() {
        let (url, server) = crate::discovery::tests::fixture(
            "<h1>Help</h1><p>If your payment failed, check the card and try again.</p>
             <input autocomplete='cc-number'><button>Pay</button>"
                .into(),
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
            operation_id: "fixture-faq".into(),
            state: "manual_required".into(),
            ceremony_url: None,
            filled_fields: vec![],
            outcome: None,
            paused: false,
        };
        service
            .store
            .insert(&status, "card", "Fixture help")
            .unwrap();
        *service.private.lock().await = Some(PrivateCheckout {
            operation_id: status.operation_id.clone(),
            mode: Mode::Card,
            view_target: tab.target.clone(),
            view_session: tab.session.clone(),
            seen_pages: std::collections::HashSet::from([tab.target.clone()]),
            tab,
            discovery: None,
            recipient: None,
            capability: hex_token(&[33; 32]),
            claimed: true,
            approved: true,
            manual_submission: false,
            submitted: false,
        });
        let finished = tokio::time::timeout(
            Duration::from_secs(3),
            service.watch_outcome(status.operation_id.clone()),
        )
        .await;
        assert!(finished.is_err(), "help text must not dispose the session");
        assert_eq!(
            service.store.get(&status.operation_id).unwrap().state,
            "manual_required"
        );
        assert!(service.private.lock().await.is_some());
        server.abort();
    }

    #[tokio::test]
    async fn form_error_stays_private_and_manual_pay_is_recorded_before_click() {
        let (service, browser, _, server) = shopping_service(
            "<p data-bloom-total-minor='399' data-bloom-currency='USD'>Total USD 3.99</p>
             <input autocomplete='cc-number'><input autocomplete='cc-exp'><input autocomplete='cc-csc'>
             <p>Debes completar todos los campos</p>
             <button id='pay' onclick=\"window.fixturePayCount=(window.fixturePayCount||0)+1\">Pagar</button>",
        )
        .await;
        let tab = browser.handoff().await.unwrap();
        let observer = tab.clone();
        let discovery = Discovery::read(&tab).await.unwrap();
        let status = Status {
            operation_id: "fixture-correction".into(),
            state: "submitted".into(),
            ceremony_url: None,
            filled_fields: vec!["number".into(), "expiry".into(), "cvc".into()],
            outcome: None,
            paused: false,
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
            submitted: false,
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
        // The person sees the private view before clicking. Its capture also
        // brings the handed-off tab forward; macOS can throttle native input
        // to a background tab. Exercise that path rather than retrying a click.
        assert!(!service.private_screenshot(&token).await.unwrap().is_empty());
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
        // Confirm only after checking the pending state. A background browser's
        // timer can be throttled on macOS; elapsed wall time is not the outcome.
        let clicks = observer
            .cdp
            .evaluate(&observer.session, "window.fixturePayCount".into())
            .await
            .unwrap();
        assert_eq!(clicks, json!(1));
        observer
            .cdp
            .evaluate(
                &observer.session,
                "document.body.innerHTML='<h1>Tu compra ha sido confirmada</h1><p>Código de reserva: ZX98YU</p>'".into(),
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), watcher)
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
            submitted: false,
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
    async fn split_birth_dates_are_private_without_redacting_prices_or_flight_dates() {
        let (service, browser, _, server) = shopping_service(
            "<p>Total USD 7.05</p><p>Flight 7 May</p><p>Passenger born 7 May 1990</p><p>Jettzy Mr/07 May,1990/US</p><label>Birth day<input autocomplete='bday-day'></label><label>Birth month<select aria-label='Birth month' autocomplete='bday-month'><option value=''></option><option value='5'>May</option><option value='6'>June</option></select></label><label>Birth year<input autocomplete='bday-year'></label><input aria-label='Manual day'>",
        ).await;
        unlocked(&service, "fixture", Duration::from_secs(60)).await;
        {
            let mut travelers = service.travelers.lock().await;
            let traveler = travelers.get_mut("fixture").unwrap();
            traveler.fields = vec![bloom_signer_api::TravelerField::BornOn];
            traveler.values.insert(
                "born_on".into(),
                zeroize::Zeroizing::new("1990-05-07".into()),
            );
        }
        service.fill_traveler(Some("fixture")).await.unwrap();
        let page = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        let manual = page["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["role"] == "input" && e["label"] == "Manual day")
            .unwrap()["ref"]
            .as_str()
            .unwrap()
            .to_owned();
        service
            .type_traveler(manual, "born_on_day", Some("fixture"))
            .await
            .unwrap();
        let page = browser.browse(BrowseRequest::Snapshot).await.unwrap();
        for (label, expected) in [
            ("Birth day", "[saved born_on_day]"),
            ("Birth month", "[saved born_on_month]"),
            ("Birth year", "[saved born_on_year]"),
            ("Manual day", "[saved born_on_day]"),
        ] {
            let control = page["elements"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| {
                    matches!(e["role"].as_str(), Some("input" | "select")) && e["label"] == label
                })
                .unwrap();
            assert_eq!(control["value"], expected, "{label}");
            assert!(
                control["ref"]
                    .as_str()
                    .unwrap()
                    .split_once(':')
                    .unwrap()
                    .0
                    .parse::<u64>()
                    .is_ok()
            );
        }
        let text = page["text"].as_str().unwrap();
        assert!(
            text.contains("Total USD 7.05") && text.contains("Flight 7 May"),
            "{text}"
        );
        assert!(!text.contains("combobox: Birth month"), "{text}");
        assert!(text.contains("Passenger born [saved born_on]"), "{text}");
        assert!(text.contains("Jettzy Mr/[saved born_on]/US"), "{text}");
        let tab = browser.handoff().await.unwrap();
        let actual = tab
            .cdp
            .evaluate(
                &tab.session,
                "[...document.querySelectorAll('input,select')].map(e=>e.value)".into(),
            )
            .await
            .unwrap();
        assert_eq!(actual, json!(["7", "5", "1990", "07"]));
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
        service.travelers.lock().await.insert(
            "fixture".into(),
            UnlockedTraveler {
                operation_id: "fixture-unlock".into(),
                origin: url::Url::parse(&url)
                    .unwrap()
                    .origin()
                    .ascii_serialization(),
                context: browser.shopping_context().await,
                fields: vec![],
                values,
                expires: tokio::time::Instant::now() + Duration::from_secs(60),
            },
        );
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
                        traveler_id: None,
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
                    traveler_id: None,
                },
            })
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "Unlock a saved traveler first");
        assert!(service.travelers.lock().await.is_empty());
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
        service.travelers.lock().await.insert(
            "fixture".into(),
            UnlockedTraveler {
                operation_id: "fixture-unlock".into(),
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
            },
        );
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
                    traveler_id: None,
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
        assert_eq!(documento["value"], "[saved document_kind]");
        let tab = browser.handoff().await.unwrap();
        assert_eq!(
            tab.cdp
                .evaluate(&tab.session, "document.getElementById('doc').value".into())
                .await
                .unwrap(),
            "PAS"
        );
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
        service.travelers.lock().await.insert(
            "fixture".into(),
            UnlockedTraveler {
                operation_id: "fixture-unlock".into(),
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
            },
        );
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
                    traveler_id: None,
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
        assert_eq!(documento["value"], "[saved document_kind]");
        let tab = browser.handoff().await.unwrap();
        assert_eq!(
            tab.cdp
                .evaluate(&tab.session, "document.getElementById('doc').value".into())
                .await
                .unwrap(),
            "PAS"
        );
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
        for (phone, national) in [
            ("+60 12-345 6789", "123456789"),
            ("+65 8123 4567", "81234567"),
            ("+852 5123 4567", "51234567"),
            ("+39 06 6988 0000", "0669880000"),
            ("+1 202 555 0123", "2025550123"),
            ("020 7946 0018", "02079460018"),
        ] {
            assert_eq!(
                derived_traveler_value(&values(phone), "phone_national")
                    .unwrap()
                    .as_str(),
                national,
                "{phone}"
            );
        }
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
    #[tokio::test]
    async fn an_unresolved_shop_blocks_the_next_checkout_until_resolve() {
        let (url, server) = crate::discovery::tests::fixture("<h1>Shop</h1>".into()).await;
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
        let (_, origin) = browser.shopping_scope().await.unwrap();
        let prior = "a".repeat(64);
        service
            .store
            .insert(
                &Status {
                    operation_id: prior.clone(),
                    state: "uncertain".into(),
                    ceremony_url: None,
                    filled_fields: vec![],
                    outcome: None,
                    paused: false,
                },
                "card",
                "Fixture prior",
            )
            .unwrap();
        service
            .store
            .record_order(&prior, Some(&origin), None)
            .unwrap();
        let blocked = service
            .request(Request::Checkout {
                operation_id: "b".repeat(64),
                card_id: None,
                agent_description: "Fixture again".into(),
                take_over: false,
            })
            .await
            .unwrap_err()
            .to_string();
        assert!(
            blocked.contains(&prior) && blocked.contains("write resolve"),
            "{blocked}"
        );
        assert!(service.store.get(&"b".repeat(64)).is_err());
        let resolved = service
            .request(Request::Resolve {
                operation_id: prior.clone(),
            })
            .await
            .unwrap();
        assert_eq!(resolved["state"], "resolved");
        assert_eq!(resolved["outcome"]["resolution"], "human_checked");
        let again = service
            .request(Request::Checkout {
                operation_id: "c".repeat(64),
                card_id: None,
                agent_description: "Fixture after resolve".into(),
                take_over: false,
            })
            .await
            .unwrap();
        assert_ne!(again["state"], "uncertain");
        assert!(service.store.get(&"c".repeat(64)).is_ok());
        let pending = "d".repeat(64);
        service
            .store
            .insert(
                &Status {
                    operation_id: pending.clone(),
                    state: "awaiting_approval".into(),
                    ceremony_url: None,
                    filled_fields: vec![],
                    outcome: None,
                    paused: false,
                },
                "card",
                "Fixture open approval",
            )
            .unwrap();
        let refused = service
            .request(Request::Resolve {
                operation_id: pending.clone(),
            })
            .await
            .unwrap_err()
            .to_string();
        assert!(refused.contains("still in progress"), "{refused}");
        assert_eq!(
            service.store.get(&pending).unwrap().state,
            "awaiting_approval"
        );
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
                paused: false,
            };
            store
                .insert(&status, "traveler", "Fixture passenger")
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.get("fixture").unwrap().state, "disclosure_unknown");
    }

    #[test]
    fn unlocked_traveler_expires_on_restart() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("state.db");
        {
            let store = Store::open(&path).unwrap();
            let status = Status {
                operation_id: "unlocked-traveler".into(),
                state: "unlocked".into(),
                ceremony_url: Some("http://localhost/unlocked".into()),
                filled_fields: vec!["given_name".into()],
                outcome: None,
                paused: false,
            };
            store
                .insert(&status, "traveler", "Fixture passenger")
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        let status = store.get("unlocked-traveler").unwrap();
        assert_eq!(status.state, "expired");
        assert!(status.ceremony_url.is_none());
    }

    #[test]
    fn payment_refusal_log_counts_errors_without_page_text() {
        let attention = json!({
            "errors": ["ada@example.test is invalid", "Name is required"],
            "invalid": 1
        });
        let line = format!(
            "payment refused over form errors: {}",
            CheckoutService::form_error_count(&attention)
        );
        assert_eq!(line, "payment refused over form errors: 2");
        assert!(!line.contains("ada@example.test"), "{line}");
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
            paused: false,
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
            submitted: false,
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
            paused: false,
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
            submitted: false,
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
    fn result_wait_outlives_the_approval_link() {
        assert!(APPROVAL_RESULT_WAIT > Duration::from_secs(15 * 60));
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
            paused: false,
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
        assert_eq!(entry.status.state, "disclosure_unknown");
        let submitted = Status {
            operation_id: "submitted-operation".into(),
            state: "submitted".into(),
            ceremony_url: None,
            filled_fields: vec!["number".into(), "expiry".into(), "cvc".into()],
            outcome: None,
            paused: false,
        };
        reopened.insert(&submitted, "card", "Flight").unwrap();
        let mut needs_input = submitted.clone();
        needs_input.operation_id = "needs-input-operation".into();
        needs_input.state = "needs_input".into();
        reopened
            .insert(&needs_input, "card", "Flight form")
            .unwrap();
        let mut legacy = needs_input.clone();
        legacy.operation_id = "legacy-not-submitted-operation".into();
        legacy.state = "not_submitted".into();
        reopened
            .insert(&legacy, "card", "Legacy ambiguous result")
            .unwrap();
        drop(reopened);
        let reopened = Store::open(&path).unwrap();
        assert_eq!(
            reopened.get("submitted-operation").unwrap().state,
            "uncertain"
        );
        assert_eq!(
            reopened.get("needs-input-operation").unwrap().state,
            "uncertain"
        );
        assert_eq!(
            reopened
                .get("legacy-not-submitted-operation")
                .unwrap()
                .state,
            "uncertain"
        );
        assert!(reopened.consume("legacy-not-submitted-operation").is_err());
    }
}
