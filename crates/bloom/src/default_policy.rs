//! Default wallet policy: the `bloom init` setup menu and the one policy that
//! allows the Petals it chose.
//!
//! Setup only proposes. The wallet policy still changes through the owner's
//! policy ceremony, and every transaction keeps its own approval. See
//! `docs/architecture/Default Wallet Policy.md`.

use std::io::{BufRead, Write};
use std::ops::ControlFlow;

use anyhow::{Context, Result, anyhow};
use bloom_daemon::Daemon;
use bloom_proto::config::{DEFAULT_POLICY_WALLET, PetalSetupConfig, WalletSetup};
use serde::{Deserialize, Serialize};

use crate::github_source;

/// How often a waiting command asks Machine where the default policy stands.
pub(crate) const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// How long `bloom wallet default-policy` waits out another command that holds
/// the wallet's policy lock before telling the owner to try again.
pub(crate) const POLICY_LOCK_GRACE_MS: u64 = 30_000;

/// How long a waiting command keeps polling a ceremony past its expiry,
/// before Broker reports it retired.
const EXPIRED_CEREMONY_GRACE_MS: u64 = 30_000;

/// The Petals setup offers, and the only ones a setup proposes or waits for.
const SETUP_PETALS: &[&str] = bloom_proto::config::SETUP_PETALS;

/// Name shown in the setup menu and in messages.
pub(crate) fn petal_label(name: &str) -> &str {
    match name {
        "polymarket" => "Polymarket",
        "hyperliquid" => "Hyperliquid",
        "enso" => "Enso",
        "near-intents" => "NEAR Intents",
        "feedback" => "Feedback",
        "safe" => "Safe",
        other => other,
    }
}

fn petal_labels(names: &[String]) -> String {
    names
        .iter()
        .map(|name| petal_label(name))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Petals the setup menu offers: Bloom's catalog Petals, in the order
/// `bloom init` installs them, except those setup leaves to the owner
/// ([`bloom_proto::config::PETALS_NOT_IN_SETUP`]).
pub(crate) fn menu_petals() -> Vec<String> {
    github_source::DEFAULT_PETALS
        .iter()
        .filter(|name| !bloom_proto::config::PETALS_NOT_IN_SETUP.contains(name))
        .map(|name| (*name).to_owned())
        .collect()
}

/// Whether `bloom init` can ask the setup questions.
pub(crate) fn interactive_setup_available() -> bool {
    use std::io::IsTerminal as _;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Ask which Petals `main`'s policy allows. An empty answer, or the end of
/// input, accepts the suggestion: every Petal on a fresh config, or the
/// earlier choice on one setup already ran on.
pub(crate) fn run_setup_menu(
    setup: &mut WalletSetup,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    writeln!(
        output,
        "Choose the Petals your main wallet's policy allows. Each transaction still needs your approval."
    )?;
    let earlier = std::mem::take(&mut setup.petals);
    for name in menu_petals() {
        let suggested = earlier.is_empty() || earlier.contains_key(&name);
        if ask_yes_no(
            input,
            output,
            &format!("Use {}?", petal_label(&name)),
            suggested,
        )? {
            setup.petals.insert(name, PetalSetupConfig::default());
        }
    }
    Ok(())
}

/// The non-interactive form of the setup menu: accept every suggestion. With
/// no earlier choices that records every Petal setup offers; earlier choices
/// are kept as they are, so a declined Petal stays declined.
pub(crate) fn accept_setup_suggestions(setup: &mut WalletSetup) {
    if !setup.petals.is_empty() {
        return;
    }
    for name in menu_petals() {
        setup.petals.insert(name, PetalSetupConfig::default());
    }
}

fn ask_yes_no(
    input: &mut impl BufRead,
    output: &mut impl Write,
    question: &str,
    suggested: bool,
) -> Result<bool> {
    let hint = if suggested { "[Y/n]" } else { "[y/N]" };
    loop {
        write!(output, "{question} {hint} ")?;
        output.flush()?;
        let mut line = String::new();
        if input.read_line(&mut line).context("read setup answer")? == 0 {
            writeln!(output)?;
            return Ok(suggested);
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "" => return Ok(suggested),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => writeln!(output, "Answer y or n.")?,
        }
    }
}

/// The verb, pronoun and phrases for naming `count` Petals that are not
/// installed: ("is", "it", "it is", "it stays") for one.
fn not_installed_words(count: usize) -> (&'static str, &'static str, &'static str, &'static str) {
    if count == 1 {
        ("is", "it", "it is", "it stays")
    } else {
        ("are", "them", "they are", "one stays")
    }
}

fn policy_update_steps(wallet: &str) -> String {
    format!(
        "run `bloom wallet update-policy {wallet} --file <policy.json>`, approve the change at the ceremony_url it prints, then run `bloom wallet commit-policy <operation_id>` with the operation_id it printed"
    )
}

/// Machine before this field existed only reported its own proposal.
pub(crate) fn proposes_chosen_petals_default() -> bool {
    true
}

/// Where a wallet's default policy stands, as reported by Machine. Fields
/// this CLI does not know are ignored, so it still reads a status from a
/// later Machine that reports more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum DefaultPolicyStatus {
    /// No Petal is chosen for the wallet, as on a packaged install, where
    /// `bloom init` cannot run while Machine does.
    NothingChosen,
    /// Chosen Petals are not installed yet, so the default policy was not
    /// proposed: it allows every chosen Petal in one approval, and a policy
    /// without these would need another to add them. The wallet keeps the
    /// policy creation installed, so the whole default policy is proposed once
    /// they are installed.
    PetalsNotInstalled { not_installed: Vec<String> },
    /// The wallet does not exist yet, or Broker could not answer for now
    /// while Machine read the wallet or proposed its policy: it was
    /// unavailable, rate-limited or over quota. `reason` says which.
    WaitingForWallet {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// A policy change for the wallet is waiting for the owner.
    AwaitingOwner {
        operation_id: String,
        ceremony_url: Option<String>,
        ceremony_expires_at_ms: Option<u64>,
        petals: Vec<String>,
        /// Whether this pending change is exactly the default policy. Any
        /// other change, such as an agent's proposal of the default policy
        /// plus a destination of its own, must finish first, and is never
        /// announced as the default policy.
        #[serde(default = "crate::default_policy::proposes_chosen_petals_default")]
        proposes_chosen_petals: bool,
        /// Chosen Petals not installed yet.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        not_installed: Vec<String>,
    },
    /// The ceremony a waiting command announced ended without the owner's
    /// approval, expired or refused, and nothing was proposed in its place.
    ProposalEnded,
    /// The wallet policy allows every chosen, installed Petal.
    Applied {
        petals: Vec<String>,
        /// Chosen Petals not installed, such as one uninstalled since.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        not_installed: Vec<String>,
    },
    /// The wallet's policy has changed since creation, so nothing was
    /// proposed: Bloom never restores what the owner removed.
    ChangedSinceCreation {
        /// Chosen, installed Petals the policy does not allow.
        missing: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        not_installed: Vec<String>,
    },
    /// Another command is changing the wallet's policy right now.
    Busy,
}

/// What a default-policy request does with the wallet's setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DefaultPolicyMode {
    /// Propose it only while the policy is the one wallet creation installed;
    /// afterwards report what the policy lacks.
    Resume,
    /// Propose it whatever the policy's version: the owner has just chosen it.
    OwnerJustChose,
    /// Propose nothing: settle and report, committing a change the owner
    /// approved. A command waiting on a ceremony it has announced asks this,
    /// so once that ceremony ends unapproved it stops rather than handing
    /// the owner a new one.
    Observe,
}

impl DefaultPolicyMode {
    /// The mode a `WalletDefaultPolicy` Machine command asks for.
    pub(crate) fn of_command(owner_just_chose: bool, observe_only: bool) -> Self {
        if observe_only {
            Self::Observe
        } else if owner_just_chose {
            Self::OwnerJustChose
        } else {
            Self::Resume
        }
    }
}

/// What the default policy asks of a wallet's policy: each chosen, installed
/// Petal's package and destinations. All of them are required.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct DefaultPolicyRequest {
    /// Chosen, installed Petals, in step with `packages`.
    pub(crate) petals: Vec<String>,
    pub(crate) packages: Vec<bloom_broker_api::Digest32>,
    pub(crate) destinations: Vec<bloom_broker_api::PolicyDestination>,
    /// Chosen Petals not installed yet, so not proposed: one may still be
    /// installing after Machine started, or have failed to.
    pub(crate) not_installed: Vec<String>,
}

impl DefaultPolicyRequest {
    /// Whether `current` allows every package and destination asked for.
    fn allowed_by(&self, current: &bloom_broker_api::SignedPolicySnapshot) -> Result<bool> {
        let policy = decode_policy(current)?;
        Ok(self
            .packages
            .iter()
            .all(|package| policy.allowed_petal_packages.contains(package))
            && self
                .destinations
                .iter()
                .all(|destination| policy.allowed_destinations.contains(destination)))
    }

    /// The chosen, installed Petals `current` does not allow: its package,
    /// or any of the destinations its transactions need, is missing.
    fn missing(&self, current: &bloom_broker_api::SignedPolicySnapshot) -> Result<Vec<String>> {
        let policy = decode_policy(current)?;
        let mut missing = Vec::new();
        for (name, package) in self.petals.iter().zip(&self.packages) {
            if !policy.allowed_petal_packages.contains(package)
                || policy_destinations(name)?
                    .iter()
                    .any(|destination| !policy.allowed_destinations.contains(destination))
            {
                missing.push(name.clone());
            }
        }
        Ok(missing)
    }
}

/// What a request asks of a wallet's policy, from `setup`: each chosen,
/// installed Petal's package and destinations. A chosen Petal that is not
/// installed is named, not proposed. Only the Petals setup offers count.
fn default_policy_request(daemon: &Daemon, setup: &WalletSetup) -> Result<DefaultPolicyRequest> {
    let mut request = DefaultPolicyRequest::default();
    for name in setup.petals.keys() {
        // Setup never offers these, so a config naming one, as only a hand
        // edit or a Petal since dropped from the catalog can, allows nothing
        // more; no release installs it, so waiting for it would never end.
        if !SETUP_PETALS.contains(&name.as_str()) {
            tracing::warn!(petal = %name, "default_policy.petal_not_in_setup_ignored");
            continue;
        }
        let Some(hash) = daemon
            .petals
            .store()
            .resolve_petal_owner(name)
            .with_context(|| format!("resolve installed Petal {name}"))?
        else {
            request.not_installed.push(name.clone());
            continue;
        };
        request.packages.push(
            bloom_broker_api::Digest32::new(hash)
                .with_context(|| format!("installed Petal {name} has an invalid package hash"))?,
        );
        request.destinations.extend(policy_destinations(name)?);
        request.petals.push(name.clone());
    }
    Ok(request)
}

/// Propose `wallet`'s setup through its existing policy operation, committing
/// a completed ceremony, and report the result. The setup is read from the
/// config on disk, not the copy Machine loaded at startup. `mode` says what
/// to do once the policy has changed since creation.
pub(crate) async fn advance_default_policy(
    daemon: &Daemon,
    wallet: &str,
    mode: DefaultPolicyMode,
) -> Result<DefaultPolicyStatus> {
    let config = bloom_proto::Config::load(&daemon.home.config_path())
        .with_context(|| format!("read {wallet}'s setup"))?;
    let request = default_policy_request(daemon, config.setup.wallet(wallet))?;
    if request.petals.is_empty() && request.not_installed.is_empty() {
        return Ok(DefaultPolicyStatus::NothingChosen);
    }
    let wallet_id = bloom_broker_api::Token::new(wallet.to_owned())?;
    if let ControlFlow::Break(status) =
        wallet_read_step(daemon.wallet_projections.get_wallet(&wallet_id).await)?
    {
        return Ok(status);
    }
    // While a chosen Petal is missing, or once a waiting command has
    // announced its ceremony, nothing is proposed: a change already proposed
    // is settled, so one still waiting is reported with its link and one the
    // owner approved commits.
    if mode == DefaultPolicyMode::Observe || !request.not_installed.is_empty() {
        let reconciled = match policy_step(
            daemon
                .reconciled_wallet_policy(wallet, &request.packages, &request.destinations)
                .await,
        )? {
            ControlFlow::Continue(reconciled) => reconciled,
            ControlFlow::Break(status) => return Ok(status),
        };
        let current = match reconciled {
            bloom_vfs::handlers::ReconciledPolicy::Awaiting { pending, .. } => {
                return Ok(awaiting_owner(&pending, &request));
            }
            bloom_vfs::handlers::ReconciledPolicy::Current(current) => current,
        };
        let creation_policy =
            current.version.get() == bloom_vfs::handlers::wallets::CREATION_POLICY_VERSION;
        return Ok(match mode {
            _ if request.not_installed.is_empty() && request.allowed_by(&current)? => {
                DefaultPolicyStatus::Applied {
                    petals: request.petals,
                    not_installed: Vec::new(),
                }
            }
            // The announced ceremony ended unapproved.
            DefaultPolicyMode::Observe if creation_policy => DefaultPolicyStatus::ProposalEnded,
            // Proposing now would allow only part of the setup, and the first
            // committed change ends setup's proposals: wait for every chosen
            // Petal, so the owner approves the whole setup once.
            DefaultPolicyMode::OwnerJustChose | DefaultPolicyMode::Resume
                if mode == DefaultPolicyMode::OwnerJustChose || creation_policy =>
            {
                DefaultPolicyStatus::PetalsNotInstalled {
                    not_installed: request.not_installed,
                }
            }
            _ => DefaultPolicyStatus::ChangedSinceCreation {
                missing: request.missing(&current)?,
                not_installed: request.not_installed,
            },
        });
    }
    let eligibility = match policy_step(
        daemon
            .ensure_default_policy(
                wallet,
                &request.packages,
                &request.destinations,
                if mode == DefaultPolicyMode::OwnerJustChose {
                    bloom_vfs::handlers::AfterPolicyChange::Propose
                } else {
                    bloom_vfs::handlers::AfterPolicyChange::Report
                },
            )
            .await,
    )? {
        ControlFlow::Continue(eligibility) => eligibility,
        ControlFlow::Break(status) => return Ok(status),
    };
    Ok(match eligibility {
        bloom_machine_client::PetalEligibility::Allowed(_) => DefaultPolicyStatus::Applied {
            petals: request.petals,
            not_installed: Vec::new(),
        },
        bloom_machine_client::PetalEligibility::ChangedSinceCreation(current) => {
            DefaultPolicyStatus::ChangedSinceCreation {
                missing: request.missing(&current)?,
                not_installed: Vec::new(),
            }
        }
        bloom_machine_client::PetalEligibility::AwaitingPolicyApproval(pending) => {
            awaiting_owner(&pending, &request)
        }
    })
}

/// The status of policy change `pending`, waiting for the owner. It is
/// announced as the default policy only when it is exactly that: the current
/// policy with nothing but the request added. Anything else, including a
/// change proposed while a chosen Petal was installed that is missing now,
/// is reported as a change waiting at its link, never as the default policy.
fn awaiting_owner(
    pending: &bloom_machine_client::PendingPolicyUpdate,
    request: &DefaultPolicyRequest,
) -> DefaultPolicyStatus {
    let (ceremony_url, ceremony_expires_at_ms) = pending
        .prepare
        .as_ref()
        .map(|prepare| {
            (
                prepare.ceremony_url.clone(),
                prepare.ceremony_expires_at_ms.get(),
            )
        })
        .unzip();
    DefaultPolicyStatus::AwaitingOwner {
        operation_id: pending.operation_id.as_str().to_owned(),
        ceremony_url,
        ceremony_expires_at_ms,
        petals: request.petals.clone(),
        proposes_chosen_petals: pending.includes_requested && request.not_installed.is_empty(),
        not_installed: request.not_installed.clone(),
    }
}

/// How the wallet read leaves [`advance_default_policy`]: go on to the
/// policy, stop with a status that keeps a waiting command polling, or end
/// it with the error. The projection reader reports a wallet absent from the
/// authoritative list as an invalid request, though other invalid requests
/// look the same, so the message is kept. A Broker failure that may clear
/// up, such as Broker restarting just after the wallet ceremony, is waited
/// out until the caller's deadline instead of ending it.
fn wallet_read_step<T>(
    read: std::result::Result<T, bloom_broker_api::ProtocolError>,
) -> Result<ControlFlow<DefaultPolicyStatus>> {
    let error = match read {
        Ok(_) => return Ok(ControlFlow::Continue(())),
        Err(error) => error,
    };
    let reason = if error.code == bloom_broker_api::ProtocolErrorCode::BackendInvalidRequest {
        error.message
    } else if outage_retry(error.retry).is_some() {
        error.to_string()
    } else {
        return Err(error.into());
    };
    Ok(ControlFlow::Break(DefaultPolicyStatus::WaitingForWallet {
        reason: Some(reason),
    }))
}

/// How the policy step leaves [`advance_default_policy`]: go on with its
/// result, stop with a status that keeps a waiting command polling, or end it
/// with the error. Broker failures that may clear up are waited out until the
/// caller's deadline, by the same rule as the wallet read.
fn policy_step<T>(
    result: std::result::Result<T, bloom_vfs::HandlerError>,
) -> Result<ControlFlow<DefaultPolicyStatus, T>> {
    match result {
        Ok(value) => Ok(ControlFlow::Continue(value)),
        Err(error) if bloom_vfs::handlers::wallets::is_policy_coordination_busy(&error) => {
            Ok(ControlFlow::Break(DefaultPolicyStatus::Busy))
        }
        Err(bloom_vfs::HandlerError::Backend(message)) if reported_outage(&message).is_some() => {
            Ok(ControlFlow::Break(DefaultPolicyStatus::WaitingForWallet {
                reason: Some(message),
            }))
        }
        Err(bloom_vfs::HandlerError::Backend(message)) => Err(anyhow!("{message}")),
        Err(error) => Err(error.into()),
    }
}

/// `retry` when a Broker failure with it may clear up if the same request is
/// made again: an unavailable service (`SameOperation`), or a rate limit or
/// quota (`AfterBackoff`).
fn outage_retry(retry: bloom_broker_api::RetryClass) -> Option<bloom_broker_api::RetryClass> {
    use bloom_broker_api::RetryClass;
    matches!(retry, RetryClass::SameOperation | RetryClass::AfterBackoff).then_some(retry)
}

/// The retry class of a Broker failure that may clear up, read from `message`
/// as the VFS reports a [`bloom_broker_api::ProtocolError`]: its code, `: `,
/// then its message.
fn reported_outage(message: &str) -> Option<bloom_broker_api::RetryClass> {
    message
        .split_once(": ")
        .and_then(|(code, _)| code.parse::<bloom_broker_api::ProtocolErrorCode>().ok())
        .and_then(|code| outage_retry(code.contract().retry))
}

/// What to wait for before running `bloom wallet default-policy` again, after
/// a wait for `wallet` ended on `reason`.
fn wait_hint(wallet: &str, reason: Option<&str>) -> String {
    use bloom_broker_api::RetryClass;
    match reason.and_then(reported_outage) {
        Some(RetryClass::AfterBackoff) => format!(
            "once Broker accepts the request again, for example after another ceremony for {wallet} finishes"
        ),
        Some(_) => "once Bloom can reach Broker again".to_owned(),
        None => "once it exists".to_owned(),
    }
}

fn decode_policy(
    current: &bloom_broker_api::SignedPolicySnapshot,
) -> Result<bloom_broker_api::CanonicalWalletPolicy> {
    serde_json::from_slice(&current.canonical_policy.decode())
        .context("decode the wallet's current policy")
}

/// The destinations a chosen Petal's transactions need, from Bloom's catalog.
/// Only the catalog supplies them, so an edited config cannot add any.
pub(crate) fn policy_destinations(name: &str) -> Result<Vec<bloom_broker_api::PolicyDestination>> {
    bloom_proto::petal_destinations::for_petal(name)
        .iter()
        .map(|destination| {
            Ok(bloom_broker_api::PolicyDestination {
                chain: bloom_broker_api::Token::new(destination.chain.to_owned())?,
                destination: destination.destination.to_owned(),
            })
        })
        .collect()
}

/// Whether a waiting command should poll again.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WaitStep {
    Poll,
    Stop,
}

/// Follows the default policy for one wallet from a waiting command, printing
/// each ceremony once and never announcing a replacement for an expired one.
pub(crate) struct DefaultPolicyWait {
    wallet: String,
    deadline_ms: u64,
    announced: Option<String>,
    announced_other: Option<String>,
    /// Whether a Broker refusal being waited out has been reported.
    announced_wait: bool,
    /// Whether this follows creating the wallet, so a skipped default policy
    /// says how to get it in the same step next time.
    creating_wallet: bool,
}

impl DefaultPolicyWait {
    /// `deadline_ms` bounds the wait before a policy ceremony is announced,
    /// such as the wallet creation ceremony's expiry.
    pub(crate) fn new(wallet: &str, deadline_ms: u64) -> Self {
        Self {
            wallet: wallet.to_owned(),
            deadline_ms,
            announced: None,
            announced_other: None,
            announced_wait: false,
            creating_wallet: false,
        }
    }

    /// Wait for the default policy of a wallet this command just created.
    pub(crate) fn for_new_wallet(mut self) -> Self {
        self.creating_wallet = true;
        self
    }

    fn resume(&self) -> String {
        format!("bloom wallet default-policy {}", self.wallet)
    }

    /// Whether this wait has announced a ceremony, so Machine must propose
    /// nothing more for it ([`DefaultPolicyMode::Observe`]).
    pub(crate) fn announced_ceremony(&self) -> bool {
        self.announced.is_some()
    }

    /// Whether the announced policy ceremony has expired. Checked after a
    /// status read so an idle owner is not handed a replacement ceremony.
    pub(crate) fn ceremony_expired(&self, now_ms: u64) -> bool {
        self.announced.is_some() && now_ms >= self.deadline_ms
    }

    pub(crate) fn report_expired(&self, output: &mut impl Write) -> Result<()> {
        writeln!(
            output,
            "default_policy: the approval for {} ended without your approval, as it expired or was refused, so nothing changed; run `{}` for a new one",
            self.wallet,
            self.resume()
        )?;
        Ok(())
    }

    fn report_not_installed(
        &self,
        output: &mut impl Write,
        not_installed: &[String],
    ) -> Result<()> {
        if not_installed.is_empty() {
            return Ok(());
        }
        let wallet = &self.wallet;
        let (verb, _, _, missing) = not_installed_words(not_installed.len());
        writeln!(
            output,
            "default_policy: {}, chosen for {wallet}, {verb} not installed. Bloom installs its catalog Petals as it starts; if {missing} missing, restart Bloom",
            petal_labels(not_installed)
        )?;
        Ok(())
    }

    /// Report, once, a policy change waiting for the owner that is not
    /// exactly the default policy, without describing it as one: it must
    /// finish before the default policy can be proposed.
    fn observe_other(
        &mut self,
        operation_id: &str,
        ceremony_url: &Option<String>,
        not_installed: &[String],
        now_ms: u64,
        output: &mut impl Write,
    ) -> Result<WaitStep> {
        let wallet = self.wallet.clone();
        if self.announced_other.as_deref() != Some(operation_id) {
            self.announced_other = Some(operation_id.to_owned());
            match ceremony_url {
                Some(url) => writeln!(
                    output,
                    "default_policy: a policy change for {wallet} is waiting for you at {url}; approve or refuse it, and the default policy is checked again once it finishes"
                )?,
                None => writeln!(
                    output,
                    "default_policy: a policy change for {wallet} is in progress; the default policy is checked again once it finishes"
                )?,
            }
            self.report_not_installed(output, not_installed)?;
        }
        if now_ms < self.deadline_ms {
            return Ok(WaitStep::Poll);
        }
        writeln!(
            output,
            "default_policy: run `{}` once that change finishes",
            self.resume()
        )?;
        Ok(WaitStep::Stop)
    }

    pub(crate) fn observe(
        &mut self,
        status: &DefaultPolicyStatus,
        now_ms: u64,
        output: &mut impl Write,
    ) -> Result<WaitStep> {
        let wallet = self.wallet.clone();
        let resume = self.resume();
        match status {
            DefaultPolicyStatus::PetalsNotInstalled { not_installed } => {
                let (verb, them, done, missing) = not_installed_words(not_installed.len());
                writeln!(
                    output,
                    "default_policy: {}, chosen for {wallet}, {verb} not installed yet, so Bloom proposes nothing for {wallet}'s default policy until every chosen Petal is: the default policy allows them all in one approval. Once {done} installed, run `{resume}`. Bloom installs its catalog Petals as it starts; if {missing} missing, restart Bloom, or leave {them} out of `[setup.wallets.{wallet}.petals]` in Bloom's config",
                    petal_labels(not_installed)
                )?;
                if self.creating_wallet {
                    writeln!(
                        output,
                        "default_policy: to approve the default policy as part of creating a wallet, create it once `bloom petals ls` lists the chosen Petals"
                    )?;
                }
                Ok(WaitStep::Stop)
            }
            DefaultPolicyStatus::NothingChosen => {
                writeln!(
                    output,
                    "default_policy: no Petals are chosen for {wallet}, so there is no default policy to approve"
                )?;
                Ok(WaitStep::Stop)
            }
            DefaultPolicyStatus::Applied {
                petals,
                not_installed,
            } => {
                if !petals.is_empty() {
                    writeln!(
                        output,
                        "default_policy: {wallet} allows {}; each transaction still needs your approval",
                        petal_labels(petals)
                    )?;
                }
                self.report_not_installed(output, not_installed)?;
                Ok(WaitStep::Stop)
            }
            DefaultPolicyStatus::ChangedSinceCreation {
                missing,
                not_installed,
            } => {
                if !missing.is_empty() {
                    writeln!(
                        output,
                        "default_policy: {wallet}'s policy has changed since the wallet was created and does not allow {}; Bloom proposes the default policy only for a new wallet, so nothing was proposed. To allow one, {}",
                        petal_labels(missing),
                        policy_update_steps(&wallet)
                    )?;
                }
                self.report_not_installed(output, not_installed)?;
                Ok(WaitStep::Stop)
            }
            DefaultPolicyStatus::WaitingForWallet { reason } => {
                if now_ms < self.deadline_ms {
                    // Say once why a Broker refusal is being waited out, so a
                    // long wait is not silent.
                    if let Some(reason) = reason
                        && !self.announced_wait
                        && reported_outage(reason).is_some()
                    {
                        writeln!(
                            output,
                            "default_policy: waiting for Broker ({reason}); retrying until it answers or this command stops waiting"
                        )?;
                        self.announced_wait = true;
                    }
                    return Ok(WaitStep::Poll);
                }
                let hint = wait_hint(&wallet, reason.as_deref());
                match reason {
                    Some(reason) if reported_outage(reason).is_some() => writeln!(
                        output,
                        "default_policy: stopped waiting for Broker ({reason}); {hint}, run `{resume}`"
                    )?,
                    Some(reason) => writeln!(
                        output,
                        "default_policy: stopped waiting for wallet {wallet} ({reason}); {hint}, run `{resume}`"
                    )?,
                    None => writeln!(
                        output,
                        "default_policy: stopped waiting for wallet {wallet}; {hint}, run `{resume}`"
                    )?,
                }
                Ok(WaitStep::Stop)
            }
            DefaultPolicyStatus::ProposalEnded => {
                self.report_expired(output)?;
                Ok(WaitStep::Stop)
            }
            // Another command holds the policy lock. Keep asking, but never
            // past the deadline: the lock holder may outlive this command.
            DefaultPolicyStatus::Busy => {
                if now_ms < self.deadline_ms {
                    return Ok(WaitStep::Poll);
                }
                writeln!(
                    output,
                    "default_policy: another command is still changing {wallet}'s policy; run `{resume}` once it finishes"
                )?;
                Ok(WaitStep::Stop)
            }
            DefaultPolicyStatus::AwaitingOwner {
                operation_id,
                ceremony_url,
                ceremony_expires_at_ms,
                petals,
                proposes_chosen_petals,
                not_installed,
            } => {
                if !proposes_chosen_petals {
                    return self.observe_other(
                        operation_id,
                        ceremony_url,
                        not_installed,
                        now_ms,
                        output,
                    );
                }
                if self.announced.as_deref() == Some(operation_id.as_str()) {
                    return Ok(WaitStep::Poll);
                }
                // Broker retires a ceremony past its expiry when next asked;
                // never hand out a dead link.
                if let Some(expires_at_ms) = ceremony_expires_at_ms.filter(|at| now_ms >= *at) {
                    if now_ms < expires_at_ms.saturating_add(EXPIRED_CEREMONY_GRACE_MS) {
                        return Ok(WaitStep::Poll);
                    }
                    self.report_expired(output)?;
                    return Ok(WaitStep::Stop);
                }
                if let Some(url) = ceremony_url {
                    writeln!(
                        output,
                        "default_policy: approve the policy for {wallet} to allow {}",
                        petal_labels(petals)
                    )?;
                    writeln!(output, "default_policy_url: {url}")?;
                    self.announced = Some(operation_id.clone());
                    if let Some(expires_at_ms) = ceremony_expires_at_ms {
                        self.deadline_ms = *expires_at_ms;
                    }
                    return Ok(WaitStep::Poll);
                }
                if now_ms < self.deadline_ms {
                    return Ok(WaitStep::Poll);
                }
                writeln!(
                    output,
                    "default_policy: another policy change for {wallet} is in progress; run `{resume}` once it finishes"
                )?;
                Ok(WaitStep::Stop)
            }
        }
    }
}

/// Run a wallet creation or import command. For the default-policy wallet,
/// then wait for the wallet and walk the owner through its default policy.
pub(crate) async fn create_wallet_then_default_policy(
    endpoint: &crate::ResolvedEndpoint,
    name: String,
    kind: bloom_daemon::ipc::MachineCustodyKind,
    local: bool,
) -> Result<()> {
    let output = crate::machine_command(
        endpoint,
        bloom_daemon::ipc::MachineCommand::WalletCustody {
            name: name.clone(),
            kind,
            local,
        },
    )
    .await?;
    crate::print_machine_command_output(&output)?;
    if output.exit_code != 0 || name != DEFAULT_POLICY_WALLET {
        return Ok(());
    }
    // Without a parseable expiry, wait as long as a wallet ceremony can last.
    let deadline_ms = ceremony_expiry_from_output(&output.stdout)
        .unwrap_or_else(|| crate::current_unix_ms().saturating_add(10 * 60 * 1000));
    poll_default_policy(
        endpoint,
        &name,
        DefaultPolicyWait::new(&name, deadline_ms).for_new_wallet(),
    )
    .await
}

/// Poll Machine until the wallet's default policy is applied, the announced
/// ceremony expires, or there is nothing to wait for.
pub(crate) async fn wait_for_default_policy(
    endpoint: &crate::ResolvedEndpoint,
    wallet: &str,
    deadline_ms: u64,
) -> Result<()> {
    poll_default_policy(
        endpoint,
        wallet,
        DefaultPolicyWait::new(wallet, deadline_ms),
    )
    .await
}

async fn poll_default_policy(
    endpoint: &crate::ResolvedEndpoint,
    wallet: &str,
    mut wait: DefaultPolicyWait,
) -> Result<()> {
    loop {
        let output = crate::machine_command(
            endpoint,
            // A waiting command resumes a setup choice; it never re-chooses.
            bloom_daemon::ipc::MachineCommand::WalletDefaultPolicy {
                name: wallet.to_owned(),
                owner_just_chose: false,
                observe_only: wait.announced_ceremony(),
            },
        )
        .await?;
        if output.exit_code != 0 {
            return crate::print_machine_command_output(&output);
        }
        let status: DefaultPolicyStatus = serde_json::from_str(output.stdout.trim())
            .context("decode default policy status from Machine")?;
        if wait.observe(&status, crate::current_unix_ms(), &mut std::io::stdout())?
            == WaitStep::Stop
        {
            return Ok(());
        }
        // Expiry is judged only after a status read, so a ceremony completed in
        // the last poll interval still commits instead of being called expired.
        if wait.ceremony_expired(crate::current_unix_ms()) {
            return wait.report_expired(&mut std::io::stderr());
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Read the wallet ceremony expiry from custody command output.
pub(crate) fn ceremony_expiry_from_output(output: &str) -> Option<u64> {
    output
        .lines()
        .find_map(|line| line.strip_prefix("ceremony_expires_at_ms: "))
        .and_then(|value| value.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chosen_setup(names: &[&str]) -> WalletSetup {
        let mut setup = WalletSetup::default();
        for name in names {
            setup
                .petals
                .insert((*name).to_owned(), PetalSetupConfig::default());
        }
        setup
    }

    fn observe(
        wait: &mut DefaultPolicyWait,
        status: &DefaultPolicyStatus,
        now_ms: u64,
    ) -> (WaitStep, String) {
        let mut output = Vec::new();
        let step = wait.observe(status, now_ms, &mut output).unwrap();
        (step, String::from_utf8(output).unwrap())
    }

    fn awaiting(operation: &str, expires_at_ms: u64, own: bool) -> DefaultPolicyStatus {
        DefaultPolicyStatus::AwaitingOwner {
            operation_id: operation.into(),
            ceremony_url: Some(format!("http://localhost:18734/ceremony/{operation}")),
            ceremony_expires_at_ms: Some(expires_at_ms),
            petals: vec!["polymarket".into(), "near-intents".into()],
            proposes_chosen_petals: own,
            not_installed: Vec::new(),
        }
    }

    fn snapshot(
        policy: &bloom_broker_api::CanonicalWalletPolicy,
        version: u64,
    ) -> bloom_broker_api::SignedPolicySnapshot {
        let bytes = serde_jcs::to_vec(policy).unwrap();
        bloom_broker_api::SignedPolicySnapshot {
            wallet_id: policy.wallet_id.clone(),
            version: bloom_broker_api::DecimalU64::new(version),
            canonical_policy: bloom_broker_api::Base64UrlBytes::from_bytes(&bytes),
            policy_digest: bloom_broker_api::Digest32::from_bytes([9; 32]),
            policy_signing_key_id: bloom_broker_api::Token::new("policy-key").unwrap(),
            policy_verifying_key: bloom_broker_api::Base64UrlBytes::from_bytes(&[2; 32]),
            signer_signature: bloom_broker_api::Base64UrlBytes::from_bytes(&[3; 64]),
        }
    }

    fn menu(answers: &str, setup: &mut WalletSetup) -> String {
        let mut output = Vec::new();
        run_setup_menu(setup, &mut answers.as_bytes(), &mut output).unwrap();
        String::from_utf8(output).unwrap()
    }

    /// The menu offers each Petal setup offers, Safe excepted; an empty
    /// answer or the end of input accepts every one on a fresh config, and an
    /// earlier choice on a config setup already ran on.
    #[test]
    fn the_menu_offers_setup_petals_and_suggests_earlier_choices() {
        assert_eq!(menu_petals(), SETUP_PETALS);
        assert!(github_source::DEFAULT_PETALS.contains(&"safe"));
        let mut setup = WalletSetup::default();
        let output = menu("", &mut setup);
        assert_eq!(setup, chosen_setup(SETUP_PETALS));
        assert!(output.contains("Use NEAR Intents? [Y/n]"), "{output}");
        assert!(!output.contains("Safe"), "{output}");

        let mut setup = WalletSetup::default();
        menu("y\nn\nmaybe\nn\nn\nn\n", &mut setup);
        assert_eq!(setup, chosen_setup(&["polymarket"]));
        let output = menu("", &mut setup);
        assert_eq!(setup, chosen_setup(&["polymarket"]), "earlier choice kept");
        assert!(output.contains("Use Hyperliquid? [y/N]"), "{output}");

        let mut accepted = WalletSetup::default();
        accept_setup_suggestions(&mut accepted);
        assert_eq!(accepted, chosen_setup(SETUP_PETALS));
        let mut declined = chosen_setup(&["enso"]);
        accept_setup_suggestions(&mut declined);
        assert_eq!(declined, chosen_setup(&["enso"]), "earlier declines kept");
    }

    /// Every catalog Petal takes a decision when it is added to the catalog:
    /// setup offers it with its destinations, offers it as needing none, or
    /// leaves it out with the reason.
    #[test]
    fn every_catalog_petal_has_destinations_or_is_known_to_need_none() {
        // Hyperliquid declares no `bloom:tx.outbox` capability: it signs venue
        // payloads and never stages an on-chain transaction.
        // Feedback declares only HTTP/store capabilities and never stages transactions.
        const NO_DESTINATIONS: &[&str] = &["hyperliquid", "feedback"];
        let not_in_setup = bloom_proto::config::PETALS_NOT_IN_SETUP;
        let menu = menu_petals();
        for name in github_source::DEFAULT_PETALS {
            let offered = menu.iter().any(|offered| offered == name);
            assert!(
                offered != not_in_setup.contains(name),
                "{name}: offer it in setup or list it in PETALS_NOT_IN_SETUP, not both"
            );
            if !offered {
                continue;
            }
            let listed = !bloom_proto::petal_destinations::for_petal(name).is_empty();
            let exempt = NO_DESTINATIONS.contains(name);
            assert!(
                listed != exempt,
                "{name}: list its destinations in petal_destinations::for_petal, add it to NO_DESTINATIONS, or leave it out of setup in PETALS_NOT_IN_SETUP, with the reason"
            );
        }
        // Each entry left out is a catalog Petal, so the list cannot go stale.
        for name in not_in_setup {
            assert!(github_source::DEFAULT_PETALS.contains(name), "{name}");
        }
    }

    /// Safe, which setup never offers, and a Petal no release installs are
    /// ignored though a config names them; chosen Petals not installed are
    /// named, not proposed.
    #[test]
    fn a_request_names_missing_petals_and_ignores_others() {
        let home = tempfile::tempdir().unwrap();
        let daemon =
            bloom_daemon::Daemon::from_home(bloom_proto::HomeDir::at(home.path())).unwrap();
        let request = default_policy_request(
            &daemon,
            &chosen_setup(&["hyperliquid", "polymarket", "safe", "tolly"]),
        )
        .unwrap();
        assert_eq!(request.not_installed, ["hyperliquid", "polymarket"]);
        assert!(request.petals.is_empty());
        assert!(request.packages.is_empty());
    }

    /// A chosen Petal counts as allowed only with its package and every
    /// destination its transactions need.
    #[test]
    fn a_petal_is_allowed_only_with_its_destinations() {
        let package = bloom_broker_api::Digest32::from_bytes([2; 32]);
        let destinations = policy_destinations("polymarket").unwrap();
        assert!(!destinations.is_empty());
        let request = DefaultPolicyRequest {
            petals: vec!["polymarket".into()],
            packages: vec![package.clone()],
            destinations: destinations.clone(),
            not_installed: Vec::new(),
        };
        let mut policy = bloom_broker_api::CanonicalWalletPolicy {
            wallet_id: bloom_broker_api::Token::new("main").unwrap(),
            maximum_approval_lifetime_ms: 60_000,
            allowed_petal_packages: vec![package],
            allowed_destinations: Vec::new(),
            required_verifiers: Vec::new(),
            clear_signing: None,
        };
        assert!(!request.allowed_by(&snapshot(&policy, 2)).unwrap());
        assert_eq!(
            request.missing(&snapshot(&policy, 2)).unwrap(),
            ["polymarket"]
        );
        policy.allowed_destinations = destinations;
        assert!(request.allowed_by(&snapshot(&policy, 2)).unwrap());
        assert!(request.missing(&snapshot(&policy, 2)).unwrap().is_empty());
    }

    /// With a chosen Petal not installed, a setup the owner just chose is not
    /// proposed even before Machine asks Broker.
    #[tokio::test]
    async fn the_default_policy_waits_for_every_chosen_petal() {
        let home = tempfile::tempdir().unwrap();
        let daemon =
            bloom_daemon::Daemon::from_home(bloom_proto::HomeDir::at(home.path())).unwrap();
        let mut config = bloom_proto::Config::local_default();
        config.setup.complete = true;
        *config.setup.wallet_mut(DEFAULT_POLICY_WALLET) = chosen_setup(&["hyperliquid"]);
        config.save(&daemon.home.config_path()).unwrap();
        let status = advance_default_policy(
            &daemon,
            DEFAULT_POLICY_WALLET,
            DefaultPolicyMode::OwnerJustChose,
        )
        .await;
        // Without a Broker the wallet read fails before anything is proposed.
        assert!(
            !matches!(status, Ok(DefaultPolicyStatus::AwaitingOwner { .. })),
            "{status:?}"
        );
        config.setup.wallets.clear();
        config.save(&daemon.home.config_path()).unwrap();
        assert_eq!(
            advance_default_policy(&daemon, DEFAULT_POLICY_WALLET, DefaultPolicyMode::Resume)
                .await
                .unwrap(),
            DefaultPolicyStatus::NothingChosen
        );
    }

    /// A waiting change is announced as the default policy only when it is
    /// exactly that; anything else, including Bloom's own proposal while a
    /// chosen Petal is missing, is a change waiting at its link.
    #[test]
    fn only_the_default_policy_itself_is_announced_as_it() {
        let operation_id = "ab".repeat(32);
        let pending = |includes_requested| bloom_machine_client::PendingPolicyUpdate {
            operation_id: bloom_broker_api::OperationId::new(operation_id.clone()).unwrap(),
            ceremony_state: bloom_broker_api::CeremonyState::AwaitingUser,
            prepare: Some(bloom_broker_api::PolicyUpdatePrepareResponse {
                operation_id: bloom_broker_api::OperationId::new(operation_id.clone()).unwrap(),
                ceremony_kind: bloom_broker_api::CeremonyKind::PolicyUpdate,
                ceremony_url: "http://127.0.0.1:1/ceremony".into(),
                ceremony_expires_at_ms: bloom_broker_api::DecimalU64::new(42),
                review_manifest_digest: bloom_broker_api::Digest32::from_bytes([3; 32]),
            }),
            status_path: String::new(),
            challenge_path: String::new(),
            includes_requested,
        };
        let mut request = DefaultPolicyRequest {
            petals: vec!["feedback".into()],
            ..Default::default()
        };
        let own = |status: DefaultPolicyStatus| match status {
            DefaultPolicyStatus::AwaitingOwner {
                proposes_chosen_petals,
                ceremony_url,
                ..
            } => {
                assert!(ceremony_url.is_some());
                proposes_chosen_petals
            }
            other => panic!("{other:?}"),
        };
        assert!(own(awaiting_owner(&pending(true), &request)));
        assert!(!own(awaiting_owner(&pending(false), &request)));
        request.not_installed = vec!["hyperliquid".into()];
        assert!(!own(awaiting_owner(&pending(true), &request)));
    }

    #[test]
    fn the_wait_announces_once_and_stops_when_applied() {
        let mut wait = DefaultPolicyWait::new("main", 1_000);
        let (step, output) = observe(
            &mut wait,
            &DefaultPolicyStatus::WaitingForWallet { reason: None },
            10,
        );
        assert_eq!(step, WaitStep::Poll);
        assert!(output.is_empty());
        let (step, output) = observe(&mut wait, &awaiting("op", 5_000, true), 20);
        assert_eq!(step, WaitStep::Poll);
        assert!(output.contains("approve the policy for main to allow Polymarket, NEAR Intents"));
        assert!(output.contains("default_policy_url: http://localhost:18734/ceremony/op"));
        assert!(wait.announced_ceremony(), "later polls propose nothing");
        let (step, output) = observe(&mut wait, &awaiting("op", 5_000, true), 30);
        assert_eq!(step, WaitStep::Poll);
        assert!(output.is_empty(), "announced once");
        let (step, output) = observe(
            &mut wait,
            &DefaultPolicyStatus::Applied {
                petals: vec!["polymarket".into()],
                not_installed: Vec::new(),
            },
            40,
        );
        assert_eq!(step, WaitStep::Stop);
        assert!(output.contains("main allows Polymarket"), "{output}");
    }

    /// Once announced, a ceremony that ended unapproved ends the wait without
    /// a new link, and an expired one is never announced.
    #[test]
    fn the_wait_never_hands_out_a_dead_or_replacement_link() {
        let mut wait = DefaultPolicyWait::new("main", 1_000);
        observe(&mut wait, &awaiting("op", 5_000, true), 20);
        let (step, output) = observe(&mut wait, &DefaultPolicyStatus::ProposalEnded, 30);
        assert_eq!(step, WaitStep::Stop);
        assert!(output.contains("ended without your approval"), "{output}");
        assert!(
            output.contains("run `bloom wallet default-policy main`"),
            "{output}"
        );
        assert!(!output.contains("default_policy_url"), "{output}");

        let mut wait = DefaultPolicyWait::new("main", 1_000);
        let (step, output) = observe(&mut wait, &awaiting("stale", 5_000, true), 5_000);
        assert_eq!(step, WaitStep::Poll);
        assert!(output.is_empty());
        let (step, output) = observe(
            &mut wait,
            &awaiting("stale", 5_000, true),
            5_000 + EXPIRED_CEREMONY_GRACE_MS,
        );
        assert_eq!(step, WaitStep::Stop);
        assert!(!output.contains("default_policy_url"), "{output}");
    }

    /// Another change waiting is reported once, without calling it the
    /// default policy, with any missing Petal named beside it.
    #[test]
    fn another_change_is_reported_as_waiting_not_as_the_default_policy() {
        let mut wait = DefaultPolicyWait::new("main", 1_000);
        let DefaultPolicyStatus::AwaitingOwner {
            operation_id,
            ceremony_url,
            ceremony_expires_at_ms,
            petals,
            ..
        } = awaiting("other", 5_000, false)
        else {
            unreachable!()
        };
        let status = DefaultPolicyStatus::AwaitingOwner {
            operation_id,
            ceremony_url,
            ceremony_expires_at_ms,
            petals,
            proposes_chosen_petals: false,
            not_installed: vec!["hyperliquid".into()],
        };
        let (step, output) = observe(&mut wait, &status, 10);
        assert_eq!(step, WaitStep::Poll);
        assert!(output.contains("a policy change for main is waiting for you at http://localhost:18734/ceremony/other; approve or refuse it"), "{output}");
        assert!(!output.contains("approve the policy for main"), "{output}");
        assert!(
            output.contains("Hyperliquid, chosen for main, is not installed"),
            "{output}"
        );
        let (_, output) = observe(&mut wait, &status, 20);
        assert!(output.is_empty(), "reported once");
        let (step, output) = observe(&mut wait, &status, 2_000);
        assert_eq!(step, WaitStep::Stop);
        assert!(
            output.contains("run `bloom wallet default-policy main` once that change finishes")
        );
    }

    #[test]
    fn missing_petals_and_a_changed_policy_say_what_to_do() {
        let mut wait = DefaultPolicyWait::new("main", 1_000).for_new_wallet();
        let (step, output) = observe(
            &mut wait,
            &DefaultPolicyStatus::PetalsNotInstalled {
                not_installed: vec!["hyperliquid".into(), "polymarket".into()],
            },
            10,
        );
        assert_eq!(step, WaitStep::Stop);
        assert!(output.contains("Hyperliquid, Polymarket, chosen for main, are not installed yet, so Bloom proposes nothing"), "{output}");
        assert!(
            output.contains("Once they are installed, run `bloom wallet default-policy main`"),
            "{output}"
        );
        assert!(
            output.contains("leave them out of `[setup.wallets.main.petals]`"),
            "{output}"
        );
        assert!(
            output.contains("create it once `bloom petals ls` lists the chosen Petals"),
            "{output}"
        );

        let mut wait = DefaultPolicyWait::new("main", 1_000);
        let (_, output) = observe(
            &mut wait,
            &DefaultPolicyStatus::ChangedSinceCreation {
                missing: vec!["enso".into()],
                not_installed: Vec::new(),
            },
            10,
        );
        assert!(
            output.contains("has changed since the wallet was created and does not allow Enso"),
            "{output}"
        );
        assert!(
            output.contains("bloom wallet update-policy main"),
            "{output}"
        );
    }

    /// A Broker that cannot answer for now, or a policy another command
    /// holds, is waited out; anything else ends the command.
    #[test]
    fn a_policy_read_outage_is_waited_out() {
        use bloom_broker_api::{ProtocolError, ProtocolErrorCode};
        let backend = |code, message| {
            bloom_vfs::HandlerError::backend(ProtocolError::new(code, message).to_string())
        };
        assert_eq!(policy_step(Ok(7)).unwrap(), ControlFlow::Continue(7));
        assert_eq!(
            policy_step::<()>(Err(backend(
                ProtocolErrorCode::ServiceUnavailable,
                "try again"
            )))
            .unwrap(),
            ControlFlow::Break(DefaultPolicyStatus::WaitingForWallet {
                reason: Some("SERVICE_UNAVAILABLE: try again".into())
            })
        );
        assert_eq!(
            policy_step::<()>(Err(bloom_vfs::HandlerError::backend(format!(
                "{}: another command holds it",
                bloom_vfs::handlers::wallets::POLICY_COORDINATION_BUSY
            ))))
            .unwrap(),
            ControlFlow::Break(DefaultPolicyStatus::Busy)
        );
        assert!(
            policy_step::<()>(Err(backend(
                ProtocolErrorCode::PolicyBaselineStale,
                "reread it"
            )))
            .is_err()
        );
        assert!(
            wallet_read_step::<()>(Err(ProtocolError::new(
                ProtocolErrorCode::BackendInvalidRequest,
                "wallet main not found"
            )))
            .unwrap()
            .is_break()
        );
    }

    /// Statuses round-trip between Machine and the CLI, and a status with
    /// fields this CLI does not know still reads.
    #[test]
    fn statuses_round_trip_and_tolerate_unknown_fields() {
        for status in [
            DefaultPolicyStatus::NothingChosen,
            DefaultPolicyStatus::ProposalEnded,
            DefaultPolicyStatus::Busy,
            awaiting("op", 5, true),
            DefaultPolicyStatus::Applied {
                petals: vec!["enso".into()],
                not_installed: vec!["feedback".into()],
            },
        ] {
            let text = serde_json::to_string(&status).unwrap();
            assert_eq!(
                serde_json::from_str::<DefaultPolicyStatus>(&text).unwrap(),
                status
            );
        }
        let later =
            serde_json::json!({"state": "applied", "petals": [], "settings_pending": ["x"]});
        assert!(serde_json::from_value::<DefaultPolicyStatus>(later).is_ok());
    }

    #[test]
    fn the_mode_follows_the_command() {
        assert_eq!(
            DefaultPolicyMode::of_command(false, false),
            DefaultPolicyMode::Resume
        );
        assert_eq!(
            DefaultPolicyMode::of_command(true, false),
            DefaultPolicyMode::OwnerJustChose
        );
        assert_eq!(
            DefaultPolicyMode::of_command(false, true),
            DefaultPolicyMode::Observe
        );
        assert_eq!(
            ceremony_expiry_from_output("ceremony_kind: X\nceremony_expires_at_ms: 42\n"),
            Some(42)
        );
    }
}
