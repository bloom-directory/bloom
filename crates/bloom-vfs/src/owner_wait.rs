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

/// Whether a write to `path` is one [`write`] may wait for the owner on.
pub fn may_wait(path: &VfsPath) -> bool {
    matches!(path.segments(), [root, _, leaf] if root == "wallets" && leaf == "policy.json")
        || matches!(path.segments(), [root, _, _, leaf] if root == "wallets" && leaf == "confirm-batch")
        || confirm_challenge_path(path).is_some()
}

/// Write `bytes` to `path`, waiting for the owner where a repeat of the
/// same request is the caller's next step. `wait` bounds that wait.
///
/// With `report`, a confirm that sends answers with one line per entry it
/// sent, from the receipts, so the caller need not list `sent/` or read them
/// afterwards. A mount cannot return text, so it passes `false`.
pub async fn write(
    vfs: &Vfs,
    path: &VfsPath,
    bytes: &[u8],
    wait: Duration,
    cancelled: Cancelled<'_>,
    report: bool,
) -> Result<Option<String>, WriteError> {
    if let [root, wallet, leaf] = path.segments()
        && root == "wallets"
        && leaf == "policy.json"
    {
        write_policy(vfs, wallet, path, bytes, wait, cancelled).await?;
        return Ok(None);
    }
    if matches!(path.segments(), [root, _, _, leaf] if root == "wallets" && leaf == "confirm-batch")
    {
        write_batch_confirm(vfs, path, bytes, wait, cancelled).await?;
        return Ok(None);
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
            written => Ok(written.map(|()| None)?),
        };
    };
    // The batch the latest `confirm-batch` shows, if this entry is in it:
    // a confirm repeated after its link was returned waits for it.
    let batch_ref = match path.segments() {
        [_, _, _, _, chain, _, _, id, _] => format!("{chain}:{id}"),
        _ => String::new(),
    };
    let seen_batch = match path.segments() {
        [_, wallet, number, ..] => {
            VfsPath::parse(&format!("/wallets/{wallet}/{number}/confirm-batch")).ok()
        }
        _ => None,
    };
    let seen_batch = match &seen_batch {
        Some(batch) => awaited_batch(vfs, batch).await,
        None => None,
    }
    .filter(|(_, _, entries)| entries.contains(&batch_ref));
    // A batch's entries are sent together, so the answer covers them all.
    let sending = match &seen_batch {
        Some((_, _, entries)) => entries.clone(),
        None => vec![batch_ref.clone()],
    };
    let waiting_for = approval_id(vfs, &challenge).await;
    let written: Result<(), WriteError> = match vfs.write(path, bytes).await {
        // An entry asked for as part of a batch waits as its batch does,
        // retrying exactly that batch's entries: a batch another writer
        // starts meanwhile is never sent in its place.
        Err(HandlerError::ApprovalPending(batch)) if batch.ends_with("/confirm-batch") => {
            let pending = || HandlerError::ApprovalPending(batch.clone());
            let batch_path = VfsPath::parse(&format!("/{batch}")).map_err(|_| pending())?;
            match awaited_batch(vfs, &batch_path).await {
                Some((_, _, entries)) if entries.contains(&batch_ref) => {
                    let seen = seen_batch.map(|(action, ..)| action);
                    let named = entries.join(" ");
                    await_batch(vfs, &batch_path, named.as_bytes(), seen, wait, cancelled).await
                }
                _ => Err(pending().into()),
            }
        }
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
    };
    written?;
    if !report || !matches!(bytes.trim_ascii(), b"y" | b"override") {
        return Ok(None);
    }
    Ok(sent_report(vfs, path, &sending).await)
}

/// One line per `chain:id` entry: its receipt, or where it is when it has
/// none. The receipt is shown whole, since its fields differ by chain.
async fn sent_report(vfs: &Vfs, path: &VfsPath, entries: &[String]) -> Option<String> {
    let [root, wallet, number, ..] = path.segments() else {
        return None;
    };
    let mut lines = Vec::new();
    for entry in entries {
        let (chain, id) = entry.split_once(':')?;
        let sent = format!("{root}/{wallet}/{number}/chains/{chain}/outbox/sent/{id}");
        let receipt = VfsPath::parse(&format!("/{sent}/receipt.json")).ok()?;
        let raw = match vfs.read(&receipt).await {
            Err(error) if receipt_is_due(vfs, &receipt, &error).await => {
                match await_receipt(vfs, &receipt, error).await {
                    Ok(_) => vfs.read(&receipt).await.ok(),
                    Err(_) => None,
                }
            }
            read => read.ok(),
        };
        let receipt: Option<Value> = raw.and_then(|raw| serde_json::from_slice(&raw).ok());
        lines.push(match receipt {
            Some(receipt) => format!("{id}: {receipt}"),
            None => {
                let hash = VfsPath::parse(&format!("/{sent}/tx_hash")).ok()?;
                match vfs.read(&hash).await {
                    Ok(hash) => format!(
                        "{id}: broadcast tx {}; receipt not recorded yet: {sent}/receipt.json",
                        String::from_utf8_lossy(&hash).trim()
                    ),
                    Err(_) => format!("{id}: not in sent/; read its entry for the outcome"),
                }
            }
        });
    }
    // What the account holds now on that chain, so the caller need not check
    // a swap's or supply's result with separate balance reads.
    let chain = entries.first().and_then(|entry| entry.split_once(':'))?.0;
    if let Some(balances) = balances(vfs, root, wallet, number, chain).await {
        lines.push(format!("{chain} balances now: {balances}"));
    }
    Some(lines.join("\n"))
}

/// The account's balances on `chain` from its `holdings.json`, as one line.
async fn balances(
    vfs: &Vfs,
    root: &str,
    wallet: &str,
    number: &str,
    chain: &str,
) -> Option<String> {
    let path = VfsPath::parse(&format!("/{root}/{wallet}/{number}/holdings.json")).ok()?;
    let holdings: Value = serde_json::from_slice(&vfs.read(&path).await.ok()?).ok()?;
    let held: Vec<&str> = holdings["holdings"]
        .as_array()?
        .iter()
        .filter(|holding| holding["chain"] == chain)
        .filter_map(|holding| holding["display"].as_str())
        .collect();
    (!held.is_empty()).then(|| held.join(", "))
}

/// The batch a `confirm-batch` file reports as waiting for the owner:
/// its action, link and entries in order.
async fn awaited_batch(vfs: &Vfs, path: &VfsPath) -> Option<(String, String, Vec<String>)> {
    let status: Value = serde_json::from_slice(&vfs.read(path).await.ok()?).ok()?;
    let field = |name: &str| status[name].as_str().unwrap_or_default().to_owned();
    let entries = status["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.as_str().map(str::to_owned))
        .collect();
    (status["status"] == "awaiting_ceremony")
        .then(|| (field("action_id"), field("ceremony_url"), entries))
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
    let awaited = awaited_batch(vfs, path).await;
    // `y` repeats the batch waiting now. Retry it by its entries, so a
    // batch another writer starts meanwhile is never sent in its place.
    let named = match &awaited {
        Some((_, _, entries)) if bytes.trim_ascii() == b"y" && !entries.is_empty() => {
            entries.join(" ").into_bytes()
        }
        _ => bytes.to_vec(),
    };
    match vfs.write(path, &named).await {
        Err(HandlerError::ApprovalPending(_)) => {}
        result => return Ok(result?),
    }
    let waiting_for = awaited.map(|(action, ..)| action);
    await_batch(vfs, path, &named, waiting_for, wait, cancelled).await
}

/// After a batch write was denied for approval: when the caller already
/// saw that approval (`waiting_for`), repeat `bytes` until the owner
/// approves; otherwise return the link.
async fn await_batch(
    vfs: &Vfs,
    path: &VfsPath,
    bytes: &[u8],
    waiting_for: Option<String>,
    wait: Duration,
    cancelled: Cancelled<'_>,
) -> Result<(), WriteError> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let (action, url, _) = awaited_batch(vfs, path).await.unwrap_or_default();
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
        match vfs.write(path, bytes).await {
            Err(HandlerError::ApprovalPending(_)) => {}
            result => return Ok(result?),
        }
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
        written => return Ok(written?),
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
        installed: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Handler for PolicyUpdate {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            Ok(Entry::file(p.segments().last().unwrap()))
        }
        async fn read(&self, p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            if self.writes.load(Ordering::SeqCst) == 0 {
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
            if !self.approved.load(Ordering::SeqCst) {
                return Err(HandlerError::PermissionDenied);
            }
            self.installed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Batch `tx-1, tx-2` awaiting the owner, approved: `tx-1` has its
    /// receipt, `tx-2` was broadcast but is not mined yet.
    struct SentBatch;

    #[async_trait::async_trait]
    impl Handler for SentBatch {
        // `tx_hash` is not looked up, so the answer does not wait 5 s for
        // `tx-2`'s receipt.
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            match p.segments().last().unwrap().as_str() {
                "tx_hash" => Err(HandlerError::not_found(p.to_string_path())),
                leaf => Ok(Entry::file(leaf)),
            }
        }
        async fn read(&self, p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            Ok(match p.to_string_path().as_str() {
                "/w/0/confirm-batch" => {
                    br#"{"status":"awaiting_ceremony","action_id":"b1","entries":["base:tx-1","base:tx-2"]}"#.to_vec()
                }
                "/w/0/chains/base/outbox/sent/tx-1/receipt.json" => {
                    br#"{"outcome":"success","tx_hash":"0xaa","block_number":7,"revert_reason":null}"#.to_vec()
                }
                "/w/0/chains/base/outbox/sent/tx-2/tx_hash" => b"0xbb\n".to_vec(),
                "/w/0/holdings.json" => br#"{"holdings":[{"chain":"base","display":"1.5 ETH"},{"chain":"arc","display":"9 USDC"},{"chain":"base","display":"20 USDC"}]}"#.to_vec(),
                other => return Err(HandlerError::not_found(other)),
            })
        }
        async fn write(&self, _p: &VfsPath, _data: &[u8]) -> Result<(), HandlerError> {
            Ok(())
        }
    }

    /// A confirm that sends answers with every entry of its batch, so the
    /// caller need not list `sent/` or read the receipts; `cancel` does not.
    #[tokio::test]
    async fn a_confirm_answers_with_what_it_sent() {
        let vfs = Vfs::builder().mount("wallets", Arc::new(SentBatch)).build();
        let path = VfsPath::parse("/wallets/w/0/chains/base/outbox/pending/tx-2/confirm").unwrap();
        let wait = Duration::from_secs(50);
        let sent = write(&vfs, &path, b"y\n", wait, &|| false, true).await;
        assert_eq!(
            sent.ok().flatten().as_deref(),
            Some(
                "tx-1: {\"outcome\":\"success\",\"tx_hash\":\"0xaa\",\"block_number\":7,\"revert_reason\":null}\n\
                 tx-2: broadcast tx 0xbb; receipt not recorded yet: wallets/w/0/chains/base/outbox/sent/tx-2/receipt.json\n\
                 base balances now: 1.5 ETH, 20 USDC"
            )
        );
        let cancelled = write(&vfs, &path, b"cancel", wait, &|| false, true).await;
        assert_eq!(cancelled.ok().flatten(), None);
        let mounted = write(&vfs, &path, b"y", wait, &|| false, false).await;
        assert_eq!(mounted.ok().flatten(), None);
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
        let Err(WriteError::Approval(first)) =
            write(&vfs, &path, b"{}", wait, &|| false, true).await
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
        assert!(
            write(&vfs, &path, b"{}", wait, &|| false, true)
                .await
                .is_ok()
        );
        assert!(started.elapsed() >= APPROVAL_POLL);
        assert_eq!(wallet.installed.load(Ordering::SeqCst), 1);
    }
}
