//! Waiting for the owner, for every transport.
//!
//! A confirm refused for owner approval answers at once with the approval
//! link the first time, and a repeat waits for the owner, then sends. This
//! lived in the IPC server, so a mount behaved differently from `bloom vfs`
//! and MCP for the same write. Both now call [`write`].

use std::time::Duration;

use serde_json::Value;

use crate::{Handler, HandlerError, Vfs, VfsPath};

/// Whether the caller gave up (its connection closed, say).
pub type Cancelled<'a> = &'a (dyn Fn() -> bool + Send + Sync);

/// How long a `bloom vfs` or MCP confirm waits for the owner's approval before it returns.
/// It stays under the 60 s request timeout common MCP clients default to.
pub const APPROVAL_WAIT: Duration = Duration::from_secs(50);
pub const APPROVAL_POLL: Duration = Duration::from_millis(500);
pub const BATCH_APPROVAL_POLL: Duration = Duration::from_secs(2);
/// A receipt read waits this many polls (5 s) for the transaction to be mined.
pub const RECEIPT_POLLS: u32 = 10;

pub enum WriteError {
    Handler(HandlerError),
    /// The owner's approval did not arrive; the message says what to do.
    Approval(String),
}

impl From<HandlerError> for WriteError {
    fn from(error: HandlerError) -> Self {
        WriteError::Handler(error)
    }
}

/// The approval challenge beside a pending outbox `confirm` sink.
fn confirm_challenge_path(path: &VfsPath) -> Option<VfsPath> {
    match path.segments() {
        [root, _, _, chains, _, outbox, pending, _, control]
            if root == "wallets"
                && chains == "chains"
                && outbox == "outbox"
                && pending == "pending"
                && matches!(control.as_str(), "confirm" | "confirm.override") =>
        {
            let mut segments = path.segments().to_vec();
            segments.pop();
            VfsPath::parse(&format!("/{}/approval_challenge.json", segments.join("/"))).ok()
        }
        _ => None,
    }
}

/// Write `bytes` to `path`, waiting for the owner where a repeat of the
/// same request is the caller's next step. `wait` bounds that wait.
pub async fn write(
    vfs: &Vfs,
    path: &VfsPath,
    bytes: &[u8],
    wait: Duration,
    cancelled: Cancelled<'_>,
) -> Result<(), WriteError> {
    if matches!(path.segments(), [root, _, _, leaf] if root == "wallets" && leaf == "confirm-batch")
    {
        return write_batch_confirm(vfs, path, bytes, wait, cancelled).await;
    }
    let Some(challenge) = confirm_challenge_path(path) else {
        return match vfs.write(path, bytes).await {
            // `outbox/send.tx` stages and asks the owner in one write:
            // answer as a first confirm does, with the link.
            Err(HandlerError::ApprovalPending(challenge))
                if path.segments().last().is_some_and(|leaf| leaf == "send.tx") =>
            {
                let url = match VfsPath::parse(&format!("/{challenge}")) {
                    Ok(challenge) => vfs.read(&challenge).await.ok(),
                    Err(_) => None,
                }
                .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok());
                // Several bodies were staged: say so, or the caller
                // checks each entry before asking the owner.
                let staged = url
                    .as_ref()
                    .and_then(|doc| doc["entries"].as_array())
                    .filter(|entries| entries.len() > 1)
                    .map(|entries| {
                        format!(" for {} staged transactions, sent in order", entries.len())
                    })
                    .unwrap_or_default();
                let url = url.and_then(|doc| doc["ceremony_url"].as_str().map(str::to_owned));
                Err(match url {
                    Some(url) => WriteError::Approval(format!(
                        "permission denied: owner approval required{staged}: {url} . Write y to latest/confirm: it waits for their approval, then sends."
                    )),
                    None => HandlerError::ApprovalPending(challenge).into(),
                })
            }
            written => Ok(written?),
        };
    };
    // An entry asked for as part of a batch waits as its batch does.
    if let [root, wallet, number, _, chain, _, _, id, _] = path.segments()
        && root == "wallets"
        && bytes.trim_ascii() == b"y"
        && let Ok(batch) = VfsPath::parse(&format!("/wallets/{wallet}/{number}/confirm-batch"))
        && let Ok(raw) = vfs.read(&batch).await
        && let Ok(status) = serde_json::from_slice::<Value>(&raw)
        && status["status"] == "awaiting_ceremony"
        && status["entries"]
            .as_array()
            .is_some_and(|entries| entries.iter().any(|e| *e == format!("{chain}:{id}")))
    {
        return write_batch_confirm(vfs, &batch, b"y", wait, cancelled).await;
    }
    let waiting_for = approval_id(vfs, &challenge).await;
    match vfs.write(path, bytes).await {
        Err(denied @ (HandlerError::PermissionDenied | HandlerError::ApprovalPending(_))) => {
            await_approval(
                vfs,
                path,
                bytes,
                &challenge,
                waiting_for,
                denied,
                wait,
                cancelled,
            )
            .await
        }
        result => Ok(result?),
    }
}

/// The batch a `confirm-batch` file reports as waiting for the owner.
async fn awaited_batch(vfs: &Vfs, path: &VfsPath) -> Option<(String, String)> {
    let status: Value = serde_json::from_slice(&vfs.read(path).await.ok()?).ok()?;
    (status["status"] == "awaiting_ceremony").then(|| {
        (
            status["action_id"].as_str().unwrap_or_default().to_owned(),
            status["ceremony_url"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        )
    })
}

/// `confirm-batch` behaves as a single confirm does: the first write
/// returns the owner's link at once, and a repeat for the same batch
/// waits for their approval, then sends.
async fn write_batch_confirm(
    vfs: &Vfs,
    path: &VfsPath,
    bytes: &[u8],
    wait: Duration,
    cancelled: Cancelled<'_>,
) -> Result<(), WriteError> {
    let waiting_for = awaited_batch(vfs, path).await.map(|(action, _)| action);
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match vfs.write(path, bytes).await {
            Err(HandlerError::ApprovalPending(_)) => {}
            result => return Ok(result?),
        }
        let (action, url) = awaited_batch(vfs, path).await.unwrap_or_default();
        if waiting_for.as_deref() != Some(action.as_str())
            || cancelled()
            || tokio::time::Instant::now() >= deadline
        {
            return Err(WriteError::Approval(format!(
                "permission denied: owner approval required: {url} . Write y to confirm-batch: it waits for their approval, then sends."
            )));
        }
        // Each attempt is an audited request, so poll less often than a
        // single confirm does.
        tokio::time::sleep(BATCH_APPROVAL_POLL).await;
    }
}

async fn approval_id(vfs: &Vfs, challenge_path: &VfsPath) -> Option<String> {
    let raw = vfs.read(challenge_path).await.ok()?;
    let challenge: Value = serde_json::from_slice(&raw).ok()?;
    challenge["approval_id"].as_str().map(str::to_owned)
}

/// A confirm denied for owner approval returns the ceremony link at once
/// when the approval is new to the caller. A confirm made after the
/// caller already saw that approval waits, outside every VFS lock, for
/// Broker to report it active, then repeats the same write. That retry is
/// the ordinary confirm path: it re-verifies the approval with Broker and
/// signs at most once under the entry's dispatch marker. Waiting never
/// starts a ceremony or restages anything.
async fn await_approval(
    vfs: &Vfs,
    path: &VfsPath,
    bytes: &[u8],
    challenge_path: &VfsPath,
    waiting_for: Option<String>,
    denied: HandlerError,
    wait: Duration,
    cancelled: Cancelled<'_>,
) -> Result<(), WriteError> {
    let deadline = tokio::time::Instant::now() + wait;
    let challenge_file = challenge_path.to_string_path();
    let mut retried_active = false;
    let mut first = true;
    loop {
        let Ok(raw) = vfs.read(challenge_path).await else {
            // A denial with no challenge is not an approval wait. A
            // challenge that disappears mid-wait means the entry left
            // `pending/` (sent, cancelled, expired): report where it went.
            if first {
                return Err(denied.into());
            }
            return Ok(vfs.write(path, bytes).await?);
        };
        let challenge: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        let url = challenge["ceremony_url"].as_str().unwrap_or_default();
        let new_approval = challenge["approval_id"].as_str() != waiting_for.as_deref();
        // A Petal rechecks its conditions when it confirms, so its entries
        // are retried through it, never by rewriting this raw confirm.
        if challenge["staged_by"].is_string() {
            let next = challenge["next"].as_str().unwrap_or_default();
            let link = if url.is_empty() {
                String::new()
            } else {
                format!(" Ceremony link: {url}.")
            };
            return Err(WriteError::Approval(format!(
                "permission denied: owner approval required.{link} {next} Details: {challenge_file}"
            )));
        }
        match challenge["state"].as_str().unwrap_or("unknown") {
            "active" if retried_active => return Err(HandlerError::PermissionDenied.into()),
            "active" => {
                retried_active = true;
                match vfs.write(path, bytes).await {
                    Err(HandlerError::PermissionDenied | HandlerError::ApprovalPending(_)) => {
                        continue;
                    }
                    result => return Ok(result?),
                }
            }
            "awaiting_ceremony" | "unknown" => retried_active = false,
            state => {
                let next = challenge["next"].as_str().unwrap_or_default();
                return Err(WriteError::Approval(format!(
                    "permission denied: owner approval {state}. {next} Details: {challenge_file}"
                )));
            }
        }
        if new_approval || cancelled() || tokio::time::Instant::now() >= deadline {
            // Short on purpose: naming the challenge file here sent
            // agents off to read it before retrying.
            let link = if url.is_empty() {
                format!("the link in {challenge_file}")
            } else {
                url.to_owned()
            };
            return Err(WriteError::Approval(format!(
                "permission denied: owner approval required: {link} . Write confirm again: it waits for their approval, then sends."
            )));
        }
        first = false;
        tokio::time::sleep(APPROVAL_POLL).await;
    }
}

/// Whether `path` names the receipt of an outbox entry that was broadcast
/// (it has a `tx_hash`) but has no receipt recorded yet.
pub async fn receipt_is_due(vfs: &Vfs, path: &VfsPath, error: &HandlerError) -> bool {
    let segments = path.segments();
    let [.., outbox, sent, _, leaf] = segments else {
        return false;
    };
    if !matches!(error, HandlerError::NotFound(_))
        || outbox != "outbox"
        || sent != "sent"
        || leaf != "receipt.json"
    {
        return false;
    }
    let sibling = format!("/{}/tx_hash", segments[..segments.len() - 1].join("/"));
    match VfsPath::parse(&sibling) {
        Ok(tx_hash) => vfs.lookup(&tx_hash).await.is_ok(),
        Err(_) => false,
    }
}

/// Look `path` up. A receipt is recorded once the transaction is mined,
/// moments after the confirm that sent it returns, so a receipt that is due
/// is waited for briefly: a caller that confirms and then reads the receipt
/// finds it.
pub async fn lookup(vfs: &Vfs, path: &VfsPath) -> Result<crate::Entry, HandlerError> {
    let absent = match vfs.lookup(path).await {
        Err(error) => error,
        found => return found,
    };
    if !receipt_is_due(vfs, path, &absent).await {
        return Err(absent);
    }
    for _ in 0..RECEIPT_POLLS {
        tokio::time::sleep(APPROVAL_POLL).await;
        match vfs.lookup(path).await {
            Err(HandlerError::NotFound(_)) => continue,
            found => return found,
        }
    }
    Err(absent)
}
