use crate::{
    browser::{BrowseRequest, Browser, PrivateTab},
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
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    sync::Mutex as AsyncMutex,
};

#[derive(Deserialize, Serialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Browse {
        request: BrowseRequest,
    },
    Checkout {
        operation_id: String,
        card_id: String,
        agent_description: String,
    },
    Status {
        operation_id: String,
    },
    Cancel {
        operation_id: String,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub operation_id: String,
    pub state: String,
    pub ceremony_url: Option<String>,
    pub filled_fields: Vec<String>,
    pub outcome: Option<Value>,
}

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
        conn.execute_batch("PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,state TEXT NOT NULL,status TEXT NOT NULL);")?;
        // A lost recipient cannot be reconstructed. Interrupted disclosure is never retried.
        conn.execute("UPDATE operations SET state='disclosure_unknown',status=json_set(status,'$.state','disclosure_unknown','$.ceremony_url',NULL) WHERE state IN ('release_started','filled','submitted','partially_filled')",[])?;
        conn.execute("UPDATE operations SET state='failed_before_release',status=json_set(status,'$.state','failed_before_release','$.ceremony_url',NULL) WHERE state IN ('requested','preparing','awaiting_approval','manual_required')",[])?;
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
    fn insert(&self, status: &Status) -> Result<()> {
        self.0
            .lock()
            .execute(
                "INSERT INTO operations VALUES(?1,?2,?3)",
                params![
                    status.operation_id,
                    status.state,
                    serde_json::to_string(status)?
                ],
            )
            .context("Checkout request already exists; use status, never retry automatically")?;
        Ok(())
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

struct PrivateCheckout {
    operation_id: String,
    tab: PrivateTab,
    discovery: Option<Discovery>,
    recipient: Option<Recipient>,
    capability: String,
    claimed: bool,
    approved: bool,
}

pub struct CheckoutService {
    pub browser: Arc<Browser>,
    store: Store,
    private: AsyncMutex<Option<PrivateCheckout>>,
    broker_socket: PathBuf,
    broker_uid: u32,
    pub view_port: u16,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum IntakeResponse {
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
        Ok(Arc::new(Self {
            browser,
            store: Store::open(state)?,
            private: AsyncMutex::new(None),
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
            Request::Browse { request } => self.browser.browse(request).await,
            Request::Status { operation_id } => {
                Ok(serde_json::to_value(self.store.get(&operation_id)?)?)
            }
            Request::Checkout {
                operation_id,
                card_id,
                agent_description,
            } => {
                OperationId::new(&operation_id)
                    .map_err(|_| anyhow::anyhow!("Invalid operation ID"))?;
                Token::new(&card_id).map_err(|_| anyhow::anyhow!("Invalid card ID"))?;
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
                self.store.insert(&status)?;
                let tab = self.browser.handoff().await?;
                status.state = "preparing".into();
                self.store.update(&status)?;
                let discovery = Discovery::read(&tab).await.ok();
                let recipient = discovery.as_ref().map(|_| Recipient::generate());
                use rand::RngCore;
                let mut token = [0; 32];
                rand::thread_rng().fill_bytes(&mut token);
                let capability = hex_token(&token);
                let challenge_url = format!(
                    "http://localhost:{}/private?token={}",
                    self.view_port, capability
                );
                let request = if let Some(discovery) = &discovery {
                    json!({"method":"prepare","operation_id":operation_id,"card_id":card_id,
                        "facts":discovery.facts,"recipient_key":recipient.as_ref().unwrap().public,
                        "agent_description":agent_description,"challenge_url":challenge_url})
                } else {
                    json!({"method":"manual","operation_id":operation_id,"card_id":card_id,
                        "agent_description":agent_description,"challenge_url":challenge_url})
                };
                match self.intake(request).await {
                    Ok(IntakeResponse::Prepared { ceremony_url }) => {
                        status.state = "awaiting_approval".into();
                        status.ceremony_url = Some(ceremony_url);
                        self.store.update(&status)?;
                        *private = Some(PrivateCheckout {
                            operation_id: operation_id.clone(),
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
            match self
                .intake(json!({"method":"result","operation_id":operation_id}))
                .await
            {
                Ok(IntakeResponse::Result {
                    status,
                    receipt,
                    output_aad,
                }) => match status.state {
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
                },
                _ => {}
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
            self.set_state(&checkout.operation_id, "manual_required");
            return Ok(());
        };
        let mut status = self.store.consume(&checkout.operation_id)?; // Durable before plaintext.
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
    async fn watch_outcome(&self, id: String) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let mut private = self.private.lock().await;
            let Some(checkout) = private.as_ref().filter(|p| p.operation_id == id) else {
                return;
            };
            let Ok(mut status) = self.store.get(&id) else {
                return;
            };
            if status.state == "submitted" || status.state == "manual_required" {
                if let Ok(outcome) = checkout
                    .tab
                    .cdp
                    .evaluate(&checkout.tab.session, include_str!("outcome.js").into())
                    .await
                {
                    if matches!(outcome["state"].as_str(), Some("paid" | "declined")) {
                        status.state = outcome["state"].as_str().unwrap().into();
                        status.outcome = Some(outcome);
                        status.ceremony_url = None;
                        if self.store.update(&status).is_ok()
                            && self.browser.return_control().await.is_ok()
                        {
                            *private = None;
                        }
                        return;
                    }
                }
            }
            if tokio::time::Instant::now() >= deadline {
                self.set_state(&id, "uncertain");
                if self.browser.return_control().await.is_ok() {
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
                let checkout = private.as_mut().context("No private checkout")?;
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
        let private = self.private.lock().await;
        let checkout = private.as_ref().context("No active private checkout")?;
        authorize_view(checkout, token)?;
        let status = self.store.get(&checkout.operation_id)?;
        Ok(json!({"state":status.state,"outcome":status.outcome}))
    }

    pub async fn private_screenshot(&self, token: &str) -> Result<Vec<u8>> {
        let private = self.private.lock().await;
        let checkout = private.as_ref().context("No active private checkout")?;
        authorize_view(checkout, token)?;
        let result = checkout
            .tab
            .cdp
            .call(
                Some(&checkout.tab.session),
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
        let checkout = private.as_ref().context("No active private checkout")?;
        authorize_view(checkout, token)?;
        match action {
            ViewAction::Click { x, y } => {
                if !x.is_finite()
                    || !y.is_finite()
                    || !(0.0..=10000.0).contains(&x)
                    || !(0.0..=10000.0).contains(&y)
                {
                    bail!("Invalid private pointer");
                }
                for kind in ["mousePressed", "mouseReleased"] {
                    checkout
                        .tab
                        .cdp
                        .call(
                            Some(&checkout.tab.session),
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
                        Some(&checkout.tab.session),
                        "Input.insertText",
                        json!({"text":text.as_str()}),
                    )
                    .await?;
            }
            ViewAction::Key { key } => {
                if !matches!(
                    key.as_str(),
                    "Tab" | "Enter" | "Backspace" | "Escape" | "ArrowDown" | "ArrowUp"
                ) {
                    bail!("Unsupported private key");
                }
                for kind in ["keyDown", "keyUp"] {
                    checkout
                        .tab
                        .cdp
                        .call(
                            Some(&checkout.tab.session),
                            "Input.dispatchKeyEvent",
                            json!({"type":kind,"key":key}),
                        )
                        .await?;
                }
            }
            ViewAction::Finish => {
                self.set_state(&checkout.operation_id, "uncertain");
                self.browser.return_control().await?;
                *private = None;
            }
        }
        Ok(())
    }
}

fn hex_token(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The login principal has this narrow API, never the private browser channel.
pub async fn serve_api(service: Arc<CheckoutService>, path: &Path, machine_uid: u32) -> Result<()> {
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
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
                Ok(request) => match service.request(request).await {
                    Ok(value) => value,
                    Err(_) => {
                        json!({"error":"Checkout request rejected or unavailable. Check status before retrying."})
                    }
                },
                Err(_) => json!({"error":"Invalid checkout request"}),
            };
            if let Ok(mut bytes) = serde_json::to_vec(&response) {
                bytes.push(b'\n');
                let _ = writer.write_all(&bytes).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        store.insert(&status).unwrap();
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
        assert!(reopened.insert(&status).is_err());
    }
}
