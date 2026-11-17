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

/// A write [`write`] may wait for the owner on.
enum Waiting<'a> {
    /// A wallet's `policy.json`, named by its wallet.
    Policy(&'a str),
    Batch,
    /// A pending entry's confirm, with its approval challenge.
    Confirm(VfsPath),
}

fn waiting(path: &VfsPath) -> Option<Waiting<'_>> {
    match path.segments() {
        [root, wallet, leaf] if root == "wallets" && leaf == "policy.json" => {
            Some(Waiting::Policy(wallet))
        }
        [root, _, _, leaf] if root == "wallets" && leaf == "confirm-batch" => Some(Waiting::Batch),
        _ => confirm_challenge_path(path).map(Waiting::Confirm),
    }
}

/// Whether a write to `path` is one [`write`] may wait for the owner on.
pub fn may_wait(path: &VfsPath) -> bool {
    waiting(path).is_some()
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
    let challenge = match waiting(path) {
        Some(Waiting::Policy(wallet)) => {
            return write_policy(vfs, wallet, path, bytes, wait, cancelled).await;
        }
        Some(Waiting::Batch) => {
            return write_batch_confirm(vfs, path, bytes, wait, cancelled).await;
        }
        Some(Waiting::Confirm(challenge)) => Some(challenge),
        None => None,
    };
    let Some(challenge) = challenge else {
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
                // Name the entry: `latest` is whatever was staged last,
                // which another writer may have changed since.
                let id = url
                    .as_ref()
                    .and_then(|doc| doc["entries"].as_array()?.last()?.as_str())
                    .and_then(|entry| entry.split_once(':'))
                    .map(|(_, id)| id.to_owned())
                    .or_else(|| challenge.rsplit('/').nth(1).map(str::to_owned))
                    .unwrap_or_default();
                let url = url.and_then(|doc| doc["ceremony_url"].as_str().map(str::to_owned));
                Err(match url {
                    Some(url) => WriteError::Approval(format!(
                        "permission denied: owner approval required{staged}: {url} . Write y to pending/{id}/confirm: it waits for their approval, then sends."
                    )),
                    None => HandlerError::ApprovalPending(challenge).into(),
                })
            }
            written => Ok(written?),
        };
    };
    // An entry asked for as part of a batch waits as its batch does.
    // Only `confirm`, as the handler does: `confirm.override` is its own
    // request and is never turned into the batch's plain `y`.
    if let [root, wallet, number, _, chain, _, _, id, control] = path.segments()
        && root == "wallets"
        && control == "confirm"
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
    let mut written = vfs.write(path, bytes).await;
    loop {
        match written {
            Err(HandlerError::ApprovalPending(_)) => {}
            result => return Ok(result?),
        }
        let (action, url) = awaited_batch(vfs, path).await.unwrap_or_default();
        // A batch whose approval was declined or expired is asked for again
        // by the next `y`: say so, or the new link reads as the same request.
        if waiting_for
            .as_deref()
            .is_some_and(|before| before != action && !action.is_empty())
        {
            return Err(WriteError::Approval(format!(
                "permission denied: the owner did not approve the earlier request (declined, expired, or replaced by another batch). A new approval was asked for: {url} . Check with the owner before writing y to confirm-batch again."
            )));
        }
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
        // `y` repeats whichever batch the file reports. If another write
        // replaced this one meanwhile, report that batch instead of confirming it.
        written = match awaited_batch(vfs, path).await {
            Some((action, _)) if waiting_for.as_deref() != Some(action.as_str()) => {
                Err(HandlerError::ApprovalPending(String::new()))
            }
            _ => vfs.write(path, bytes).await,
        };
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
#[allow(clippy::too_many_arguments)] // the write, its challenge and the wait's limits
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

/// A receipt is recorded once the transaction is mined, moments after the
/// confirm that sent it returns. Wait briefly for one that
/// [`receipt_is_due`], so a caller that confirms and then looks the receipt
/// up finds it; `absent` is the answer if it does not arrive.
pub async fn await_receipt(
    vfs: &Vfs,
    path: &VfsPath,
    absent: HandlerError,
) -> Result<crate::Entry, HandlerError> {
    for _ in 0..RECEIPT_POLLS {
        tokio::time::sleep(APPROVAL_POLL).await;
        match vfs.lookup(path).await {
            Err(HandlerError::NotFound(_)) => continue,
            found => return found,
        }
    }
    Err(absent)
}

/// A policy change needs the owner's approval, and the write alone reports
/// that as a bare "permission denied". The first write answers with the
/// ceremony link; a repeat of it waits for the owner, as a repeated confirm
/// does, and installs the policy only if they approved.
async fn write_policy(
    vfs: &Vfs,
    wallet: &str,
    path: &VfsPath,
    bytes: &[u8],
    wait: Duration,
    cancelled: Cancelled<'_>,
) -> Result<(), WriteError> {
    const WAITING: &str = "awaiting_custody";
    let status_file = format!("wallets/{wallet}/policy-updates/latest/status.json");
    let status_path = VfsPath::parse(&format!("/{status_file}"))
        .map_err(|e| HandlerError::invalid(e.to_string()))?;
    let update =
        || async { serde_json::from_slice::<Value>(&vfs.read(&status_path).await.ok()?).ok() };
    let waiting_before = update()
        .await
        .filter(|update| update["status"] == WAITING)
        .map(|update| update["action_id"].clone());
    let denied = match vfs.write(path, bytes).await {
        Err(denied @ (HandlerError::PermissionDenied | HandlerError::ApprovalPending(_))) => denied,
        written => {
            written?;
            // A write that finds the awaited update declined or expired
            // retires it to `failed/` and succeeds without installing it.
            if let Some(action) = waiting_before.as_ref().and_then(Value::as_str)
                && let Ok(failed) = VfsPath::parse(&format!(
                    "/wallets/{wallet}/policy-updates/failed/{action}/status.json"
                ))
                && vfs.read(&failed).await.is_ok()
            {
                return Err(WriteError::Approval(
                    "permission denied: policy not changed: the owner declined or the approval expired. Write the policy again to ask them again.".into(),
                ));
            }
            return Ok(());
        }
    };
    let asked = update().await;
    // The owner approved between the write and this read.
    if asked
        .as_ref()
        .is_some_and(|update| update["status"] == "ready_to_commit")
    {
        return Ok(vfs.write(path, bytes).await?);
    }
    let Some(asked) = asked.filter(|update| update["status"] == WAITING) else {
        return Err(denied.into());
    };
    if waiting_before.as_ref() == Some(&asked["action_id"]) {
        let deadline = tokio::time::Instant::now() + wait;
        while tokio::time::Instant::now() < deadline && !cancelled() {
            tokio::time::sleep(APPROVAL_POLL).await;
            let Some(now) = update().await else {
                continue;
            };
            if now["action_id"] != asked["action_id"] {
                return Err(WriteError::Approval(format!(
                    "permission denied: another policy update replaced this one; read {status_file}"
                )));
            }
            return match now["status"].as_str() {
                // prepare_pending: Broker has not opened the ceremony yet.
                Some(WAITING | "prepare_pending") => continue,
                Some("confirmed") => Ok(()),
                // Approved: the same bytes written again install the policy.
                Some("ready_to_commit") => Ok(vfs.write(path, bytes).await?),
                status => Err(WriteError::Approval(format!(
                    "permission denied: policy not changed: the update is {} (declined, expired, or the policy changed meanwhile); see {status_file}",
                    status.unwrap_or("in an unknown state")
                ))),
            };
        }
    }
    let url = asked["ceremony_url"].as_str().unwrap_or_default();
    Err(WriteError::Approval(format!(
        "permission denied: owner approval required: {url} . Write the same policy again: it waits for their approval, then installs it."
    )))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::Entry;

    /// A wallet whose policy write is refused until the owner approves: the
    /// update's status appears with the first write.
    #[derive(Default)]
    struct PolicyUpdate {
        writes: AtomicUsize,
        approved: std::sync::atomic::AtomicBool,
        declined: std::sync::atomic::AtomicBool,
        installed: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Handler for PolicyUpdate {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            Ok(Entry::file(p.segments().last().unwrap()))
        }
        async fn read(&self, p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            // `latest` still reads as waiting: the decline is only seen by
            // the next write, as when the owner declines just before it.
            let retired = p.to_string_path().contains("/failed/");
            if self.writes.load(Ordering::SeqCst) == 0
                || (retired && !self.declined.load(Ordering::SeqCst))
            {
                return Err(HandlerError::not_found(p.to_string_path()));
            }
            let status = if self.approved.load(Ordering::SeqCst) {
                "ready_to_commit"
            } else {
                "awaiting_custody"
            };
            Ok(format!(
                r#"{{"status":"{status}","action_id":"a1","ceremony_url":"http://localhost/c/policy"}}"#
            )
            .into_bytes())
        }
        async fn write(&self, _p: &VfsPath, _data: &[u8]) -> Result<(), HandlerError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            // A declined update is retired and the write succeeds.
            if self.declined.load(Ordering::SeqCst) {
                return Ok(());
            }
            if !self.approved.load(Ordering::SeqCst) {
                return Err(HandlerError::PermissionDenied);
            }
            self.installed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// The first policy write answers with the link at once; the repeat
    /// waits for the owner and installs the policy. MCP callers get this
    /// too, not only `bloom vfs write`.
    #[tokio::test]
    async fn a_repeated_policy_write_waits_for_the_owner() {
        let wallet = Arc::new(PolicyUpdate::default());
        let vfs = Vfs::builder().mount("wallets", wallet.clone()).build();
        let path = VfsPath::parse("/wallets/alice/policy.json").unwrap();
        let wait = Duration::from_secs(50);

        let started = tokio::time::Instant::now();
        let Err(WriteError::Approval(first)) = write(&vfs, &path, b"{}", wait, &|| false).await
        else {
            panic!("the first write is refused with the link");
        };
        assert!(first.contains("http://localhost/c/policy"), "{first}");
        assert!(started.elapsed() < APPROVAL_POLL);

        let owner = wallet.clone();
        tokio::spawn(async move {
            tokio::time::sleep(APPROVAL_POLL).await;
            owner.approved.store(true, Ordering::SeqCst);
        });
        assert!(write(&vfs, &path, b"{}", wait, &|| false).await.is_ok());
        assert!(started.elapsed() >= APPROVAL_POLL);
        assert_eq!(wallet.installed.load(Ordering::SeqCst), 1);
    }

    /// A repeat that finds the update declined is not reported as installed.
    #[tokio::test]
    async fn a_declined_policy_write_is_not_reported_as_installed() {
        let wallet = Arc::new(PolicyUpdate::default());
        let vfs = Vfs::builder().mount("wallets", wallet.clone()).build();
        let path = VfsPath::parse("/wallets/alice/policy.json").unwrap();
        let wait = Duration::from_secs(50);
        assert!(write(&vfs, &path, b"{}", wait, &|| false).await.is_err());

        wallet.declined.store(true, Ordering::SeqCst);
        let Err(WriteError::Approval(declined)) = write(&vfs, &path, b"{}", wait, &|| false).await
        else {
            panic!("a declined update is refused");
        };
        assert!(declined.contains("policy not changed"), "{declined}");
        assert_eq!(wallet.installed.load(Ordering::SeqCst), 0);
    }
}
