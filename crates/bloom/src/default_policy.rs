//! Default wallet policy: the `bloom init` setup menu, the Petal settings it
//! chooses, and the one policy that allows the chosen Petals.
//!
//! Setup only proposes. The wallet policy still changes through the owner's
//! policy ceremony, and every transaction keeps its own approval. See
//! `docs/architecture/Default Wallet Policy.md`.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use anyhow::{Context, Result, bail};
use bloom_daemon::Daemon;
use bloom_proto::config::{DEFAULT_POLICY_WALLET, PetalSetupConfig, PetalsConfig};
use serde::{Deserialize, Serialize};

use crate::github_source::{self, PetalSetupTemplate};

/// How often a waiting command asks Machine where the default policy stands.
pub(crate) const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// How long `bloom wallet default-policy` waits out another command that holds
/// the wallet's policy lock before telling the owner to try again.
pub(crate) const POLICY_LOCK_GRACE_MS: u64 = 30_000;

/// How long a waiting command keeps polling a ceremony past its expiry while
/// Machine cancels it and proposes a replacement.
const EXPIRED_CEREMONY_GRACE_MS: u64 = 30_000;

/// Name shown in the setup menu and in messages.
pub(crate) fn petal_label(name: &str) -> &str {
    match name {
        "polymarket" => "Polymarket",
        "hyperliquid" => "Hyperliquid",
        "enso" => "Enso",
        "near-intents" => "NEAR Intents",
        "tolly" => "Tolly",
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

/// Petals the setup menu offers: Bloom's canonical Petals, in the order
/// `bloom init` installs them.
pub(crate) fn menu_petals() -> Vec<String> {
    github_source::DEFAULT_PETALS
        .iter()
        .map(|name| (*name).to_owned())
        .collect()
}

/// Runtime values a chosen Petal needs before it can act, recorded in
/// `[petals.runtime.<name>.values]`. Tolly refuses buys, sells, and launches
/// until writes are enabled; each one still waits for the owner's approval.
fn setup_runtime_values(name: &str) -> &'static [(&'static str, &'static str)] {
    match name {
        "tolly" => &[("tolly_writes", "enabled")],
        _ => &[],
    }
}

/// Record a chosen Petal's runtime values, keeping any the owner already set.
fn record_runtime_values(petals: &mut PetalsConfig, name: &str) {
    let values = setup_runtime_values(name);
    if values.is_empty() {
        return;
    }
    let runtime = petals.runtime.entry(name.to_owned()).or_default();
    for (key, value) in values {
        runtime
            .values
            .entry((*key).to_owned())
            .or_insert_with(|| (*value).to_owned());
    }
}

/// Whether `bloom init` can ask the setup questions.
pub(crate) fn interactive_setup_available() -> bool {
    use std::io::IsTerminal as _;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Ask which Petals to use and the values each chosen Petal's settings need.
/// An empty answer, or the end of input, accepts the suggestion.
///
/// Bloom installs every canonical Petal regardless. Each chosen Petal is
/// recorded in `setup`, which the default policy proposes, along with any
/// runtime values it needs to act.
pub(crate) fn run_setup_menu(
    petals: &mut PetalsConfig,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    writeln!(
        output,
        "Choose the Petals your main wallet's policy allows. Each transaction still needs your approval."
    )?;
    let mut chosen = Vec::new();
    for name in menu_petals() {
        if ask_yes_no(input, output, &format!("Use {}?", petal_label(&name)))? {
            chosen.push(name);
        }
    }
    let mut setup = BTreeMap::new();
    for name in &chosen {
        let mut values = BTreeMap::new();
        if let Some(template) = setup_template(name) {
            for value in template.values {
                let answer = ask_amount(input, output, value.prompt, value.default)?;
                values.insert(value.name.to_owned(), answer);
            }
        }
        setup.insert(name.clone(), PetalSetupConfig { values });
    }
    petals.setup = setup;
    for name in &chosen {
        record_runtime_values(petals, name);
    }
    Ok(())
}

/// The non-interactive form of the setup menu: record every canonical Petal
/// as chosen, with the catalog's suggested values. Existing choices are kept.
pub(crate) fn accept_setup_suggestions(petals: &mut PetalsConfig) {
    for name in menu_petals() {
        record_runtime_values(petals, &name);
        let values = setup_template(&name)
            .map(|template| {
                template
                    .values
                    .iter()
                    .map(|value| (value.name.to_owned(), value.default.to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        petals
            .setup
            .entry(name.clone())
            .or_insert(PetalSetupConfig { values });
    }
}

fn ask_yes_no(input: &mut impl BufRead, output: &mut impl Write, question: &str) -> Result<bool> {
    loop {
        write!(output, "{question} [Y/n] ")?;
        output.flush()?;
        let Some(answer) = read_answer(input)? else {
            writeln!(output)?;
            return Ok(true);
        };
        match answer.to_ascii_lowercase().as_str() {
            "" | "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => writeln!(output, "Answer y or n.")?,
        }
    }
}

fn ask_amount(
    input: &mut impl BufRead,
    output: &mut impl Write,
    prompt: &str,
    suggestion: &str,
) -> Result<String> {
    loop {
        write!(output, "{prompt} [{suggestion}]: ")?;
        output.flush()?;
        let Some(answer) = read_answer(input)? else {
            writeln!(output)?;
            return Ok(suggestion.to_owned());
        };
        let answer = if answer.is_empty() {
            suggestion
        } else {
            answer.as_str()
        };
        if is_setup_amount(answer) {
            return Ok(answer.to_owned());
        }
        writeln!(
            output,
            "Enter a positive amount, such as {suggestion} or 12.5."
        )?;
    }
}

fn read_answer(input: &mut impl BufRead) -> Result<Option<String>> {
    let mut line = String::new();
    if input.read_line(&mut line).context("read setup answer")? == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim().to_owned()))
}

/// A positive decimal with at most six fractional digits. It is the only value
/// shape setup writes into a Petal's settings, so a value can never change the
/// settings file's structure.
pub(crate) fn is_setup_amount(value: &str) -> bool {
    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (value, None),
    };
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    digits(whole)
        && whole.len() <= 18
        && fraction.is_none_or(|fraction| digits(fraction) && fraction.len() <= 6)
        && value.bytes().any(|byte| matches!(byte, b'1'..=b'9'))
}

fn setup_template(name: &str) -> Option<&'static PetalSetupTemplate> {
    github_source::preinstalled_petal(name).and_then(|entry| entry.setup)
}

/// A rendered settings file for one Petal.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PetalSettingsWrite {
    /// Absolute VFS path of the Petal's settings route.
    pub path: String,
    pub body: Vec<u8>,
    /// The chosen values, for messages.
    pub summary: String,
}

/// Render a Petal's settings from its catalog template and the saved setup
/// values, falling back to the catalog's suggestions.
pub(crate) fn render_petal_settings(
    petals: &PetalsConfig,
    name: &str,
    wallet: &str,
) -> Result<Option<PetalSettingsWrite>> {
    let Some(template) = setup_template(name) else {
        return Ok(None);
    };
    let saved = petals.setup.get(name);
    let mut body = template.body.to_owned();
    let mut summary = Vec::new();
    for value in template.values {
        let chosen = saved
            .and_then(|setup| setup.values.get(value.name))
            .map(String::as_str)
            .unwrap_or(value.default);
        if !is_setup_amount(chosen) {
            bail!(
                "[petals.setup.{name}.values] {} = {chosen:?} is not a positive amount",
                value.name
            );
        }
        body = body.replace(&format!("{{{}}}", value.name), chosen);
        summary.push(format!("{} = {chosen}", value.name));
    }
    Ok(Some(PetalSettingsWrite {
        path: format!(
            "/petals/{name}/{}",
            template.path.replace("{wallet}", wallet)
        ),
        body: body.into_bytes(),
        // A template without values reports the file it wrote.
        summary: if summary.is_empty() {
            template.path.replace("{wallet}", wallet)
        } else {
            summary.join(", ")
        },
    }))
}

/// Write a Petal's setup settings through its own settings route. Returns the
/// chosen values, or `None` when the Petal has no setup settings.
pub(crate) async fn write_petal_settings(
    vfs: &bloom_vfs::Vfs,
    petals: &PetalsConfig,
    name: &str,
) -> Result<Option<String>> {
    let Some(settings) = render_petal_settings(petals, name, DEFAULT_POLICY_WALLET)? else {
        return Ok(None);
    };
    let path = bloom_vfs::VfsPath::parse(&settings.path)?;
    bloom_vfs::Handler::write(vfs, &path, &settings.body)
        .await
        .with_context(|| format!("write {} settings to {}", petal_label(name), settings.path))?;
    Ok(Some(settings.summary))
}

/// Installed Petal owners by name.
pub(crate) fn petal_owners(daemon: &Daemon) -> Result<BTreeMap<String, String>> {
    Ok(daemon
        .petals
        .store()
        .list_petal_owners()
        .context("list installed Petal owners")?
        .into_iter()
        .collect())
}

/// After `bloom init` provisions Petals, write settings for each chosen Petal
/// that setup just configured, installed, or updated. An update replaces the
/// Petal's stored state, so its saved settings are written again.
///
/// A failed write is reported and the rest continue, as in `bloom serve`. A
/// Petal without its settings fails closed: Polymarket refuses buys and Enso
/// refuses routes until the owner writes them.
pub(crate) async fn apply_setup_settings(
    daemon: &Daemon,
    owners_before: &BTreeMap<String, String>,
    first_setup: bool,
) -> Result<Vec<String>> {
    let owners_after = petal_owners(daemon)?;
    let mut messages = Vec::new();
    for name in daemon.config.petals.setup.keys() {
        let Some(installed) = owners_after.get(name) else {
            continue;
        };
        let previous = owners_before.get(name);
        let updated = previous.is_some_and(|previous| previous != installed);
        if !(first_setup || previous.is_none() || updated) {
            continue;
        }
        match write_petal_settings(&daemon.vfs, &daemon.config.petals, name).await {
            Ok(Some(summary)) => messages.push(settings_message(name, &summary, updated)),
            Ok(None) => {}
            Err(error) => messages.push(format!("petal_settings_failed: {error:#}")),
        }
    }
    Ok(messages)
}

/// After `bloom serve` provisions catalog Petals, write setup settings for each
/// chosen Petal it installed or updated. Runs on a blocking provisioning thread.
pub(crate) fn apply_provisioned_settings(
    daemon: &Daemon,
    results: &[crate::petal_provisioning::ProvisioningResult],
) {
    use crate::petal_provisioning::ProvisioningOutcome;

    let runtime = tokio::runtime::Handle::current();
    for result in results {
        if !daemon.config.petals.setup.contains_key(&result.name) {
            continue;
        }
        let updated = match result.outcome {
            ProvisioningOutcome::Installed => false,
            ProvisioningOutcome::Updated => true,
            ProvisioningOutcome::Current | ProvisioningOutcome::Failed(_) => continue,
        };
        match runtime.block_on(write_petal_settings(
            &daemon.vfs,
            &daemon.config.petals,
            &result.name,
        )) {
            Ok(Some(summary)) => tracing::info!(
                petal = %result.name,
                updated,
                message = %settings_message(&result.name, &summary, updated),
                "petal.setup_settings_written"
            ),
            Ok(None) => {}
            Err(error) => tracing::warn!(
                petal = %result.name,
                error = %format!("{error:#}"),
                "petal.setup_settings_failed"
            ),
        }
    }
}

pub(crate) fn settings_message(name: &str, summary: &str, updated: bool) -> String {
    if updated {
        format!(
            "petal_settings: {} was updated, which reset its settings; re-applied {summary}",
            petal_label(name)
        )
    } else {
        format!("petal_settings: {} set {summary}", petal_label(name))
    }
}

/// Machine before this field existed only reported its own proposal.
pub(crate) fn proposes_chosen_petals_default() -> bool {
    true
}

/// Where a wallet's default policy stands, as reported by Machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DefaultPolicyStatus {
    /// None of the Petals chosen during setup is installed.
    NothingToAllow,
    /// The wallet does not exist yet, or Machine could not read it. `reason`
    /// carries Broker's message when the read failed for another cause.
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
        /// Whether this pending change is the one that allows the chosen
        /// Petals. An unrelated change must finish before ours is proposed, and
        /// must never be announced as if it were ours.
        #[serde(default = "crate::default_policy::proposes_chosen_petals_default")]
        proposes_chosen_petals: bool,
    },
    /// The wallet policy allows every chosen, installed Petal.
    Applied { petals: Vec<String> },
    /// Another command holds the wallet's policy lock; ask again shortly.
    Busy,
}

/// Propose the Petals chosen during setup for `wallet` through its existing
/// policy operation, committing a completed ceremony, and report the result.
pub(crate) async fn advance_default_policy(
    daemon: &Daemon,
    wallet: &str,
) -> Result<DefaultPolicyStatus> {
    let mut petals = Vec::new();
    let mut packages = Vec::new();
    let mut destinations = Vec::new();
    for name in daemon.config.petals.setup.keys() {
        let Some(hash) = daemon
            .petals
            .store()
            .resolve_petal_owner(name)
            .with_context(|| format!("resolve installed Petal {name}"))?
        else {
            continue;
        };
        packages.push(
            bloom_broker_api::Digest32::new(hash)
                .with_context(|| format!("installed Petal {name} has an invalid package hash"))?,
        );
        destinations.extend(policy_destinations(name)?);
        petals.push(name.clone());
    }
    if packages.is_empty() {
        return Ok(DefaultPolicyStatus::NothingToAllow);
    }
    let wallet_id = bloom_broker_api::Token::new(wallet.to_owned())?;
    match daemon.wallet_projections.get_wallet(&wallet_id).await {
        Ok(_) => {}
        // The projection reader reports a well-formed wallet absent from the
        // authoritative list this way.
        Err(error) if error.code == bloom_broker_api::ProtocolErrorCode::BackendInvalidRequest => {
            // The projection reader reports an absent wallet this way, but so
            // does every other invalid-request rejection; keep the message.
            return Ok(DefaultPolicyStatus::WaitingForWallet {
                reason: Some(error.message),
            });
        }
        Err(error) => return Err(error.into()),
    }
    let eligibility = match daemon
        .ensure_default_policy(wallet, &packages, &destinations)
        .await
    {
        Ok(eligibility) => eligibility,
        Err(bloom_vfs::HandlerError::Backend(message))
            if message.starts_with(bloom_vfs::handlers::wallets::POLICY_COORDINATION_BUSY) =>
        {
            return Ok(DefaultPolicyStatus::Busy);
        }
        Err(error) => return Err(error.into()),
    };
    Ok(match eligibility {
        bloom_machine_client::PetalEligibility::Allowed(_) => {
            DefaultPolicyStatus::Applied { petals }
        }
        bloom_machine_client::PetalEligibility::AwaitingPolicyApproval(pending) => {
            DefaultPolicyStatus::AwaitingOwner {
                operation_id: pending.operation_id.as_str().to_owned(),
                ceremony_url: pending
                    .prepare
                    .as_ref()
                    .map(|prepare| prepare.ceremony_url.clone()),
                ceremony_expires_at_ms: pending
                    .prepare
                    .as_ref()
                    .map(|prepare| prepare.ceremony_expires_at_ms.get()),
                petals,
                proposes_chosen_petals: pending.includes_requested,
            }
        }
    })
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
    announced_unrelated: Option<String>,
}

impl DefaultPolicyWait {
    /// `deadline_ms` bounds the wait before a policy ceremony is announced,
    /// such as the wallet creation ceremony's expiry.
    pub(crate) fn new(wallet: &str, deadline_ms: u64) -> Self {
        Self {
            wallet: wallet.to_owned(),
            deadline_ms,
            announced: None,
            announced_unrelated: None,
        }
    }

    /// Whether the announced policy ceremony has expired. Checked after a
    /// status read so an idle owner is not handed a replacement ceremony.
    pub(crate) fn ceremony_expired(&self, now_ms: u64) -> bool {
        self.announced.is_some() && now_ms >= self.deadline_ms
    }

    pub(crate) fn report_expired(&self, output: &mut impl Write) -> Result<()> {
        let wallet = &self.wallet;
        writeln!(
            output,
            "default_policy: the approval for {wallet} expired; run `bloom wallet default-policy {wallet}` for a new one"
        )?;
        Ok(())
    }

    /// Report an unrelated pending policy change once, without describing it
    /// as the default policy. It must finish before ours can be proposed.
    fn observe_unrelated(
        &mut self,
        operation_id: &str,
        ceremony_url: &Option<String>,
        now_ms: u64,
        output: &mut impl Write,
    ) -> Result<WaitStep> {
        let wallet = &self.wallet;
        if self.announced_unrelated.as_deref() != Some(operation_id) {
            self.announced_unrelated = Some(operation_id.to_owned());
            match ceremony_url {
                Some(url) => writeln!(
                    output,
                    "default_policy: another policy change for {wallet} is waiting for you at {url}; the default policy follows once it finishes"
                )?,
                None => writeln!(
                    output,
                    "default_policy: another policy change for {wallet} is in progress; the default policy follows once it finishes"
                )?,
            }
        }
        if now_ms < self.deadline_ms {
            return Ok(WaitStep::Poll);
        }
        writeln!(
            output,
            "default_policy: run `bloom wallet default-policy {wallet}` once that change finishes"
        )?;
        Ok(WaitStep::Stop)
    }

    pub(crate) fn observe(
        &mut self,
        status: &DefaultPolicyStatus,
        now_ms: u64,
        output: &mut impl Write,
    ) -> Result<WaitStep> {
        let wallet = &self.wallet;
        match status {
            DefaultPolicyStatus::NothingToAllow => {
                writeln!(
                    output,
                    "default_policy: none of the Petals chosen during setup is installed; nothing to approve"
                )?;
                Ok(WaitStep::Stop)
            }
            DefaultPolicyStatus::Applied { petals } => {
                writeln!(
                    output,
                    "default_policy: {wallet} allows {}; each transaction still needs your approval",
                    petal_labels(petals)
                )?;
                Ok(WaitStep::Stop)
            }
            DefaultPolicyStatus::WaitingForWallet { reason } => {
                if now_ms < self.deadline_ms {
                    return Ok(WaitStep::Poll);
                }
                match reason {
                    Some(reason) => writeln!(
                        output,
                        "default_policy: stopped waiting for wallet {wallet} ({reason}); once it exists, run `bloom wallet default-policy {wallet}`"
                    )?,
                    None => writeln!(
                        output,
                        "default_policy: stopped waiting for wallet {wallet}; once it exists, run `bloom wallet default-policy {wallet}`"
                    )?,
                }
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
                    "default_policy: another command is still changing {wallet}'s policy; run `bloom wallet default-policy {wallet}` once it finishes"
                )?;
                Ok(WaitStep::Stop)
            }
            DefaultPolicyStatus::AwaitingOwner {
                operation_id,
                ceremony_url,
                ceremony_expires_at_ms,
                petals,
                proposes_chosen_petals,
            } => {
                if !proposes_chosen_petals {
                    return self.observe_unrelated(operation_id, ceremony_url, now_ms, output);
                }
                if self.announced.as_deref() == Some(operation_id.as_str()) {
                    return Ok(WaitStep::Poll);
                }
                // Machine cancels a ceremony past its expiry on the next poll and
                // proposes a replacement; never hand out a dead link.
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
                    "default_policy: another policy change for {wallet} is in progress; run `bloom wallet default-policy {wallet}` once it finishes"
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
) -> Result<()> {
    let output = crate::machine_command(
        endpoint,
        bloom_daemon::ipc::MachineCommand::WalletCustody {
            name: name.clone(),
            kind,
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
    wait_for_default_policy(endpoint, &name, deadline_ms).await
}

/// Poll Machine until the wallet's default policy is applied, the announced
/// ceremony expires, or there is nothing to wait for.
pub(crate) async fn wait_for_default_policy(
    endpoint: &crate::ResolvedEndpoint,
    wallet: &str,
    deadline_ms: u64,
) -> Result<()> {
    let mut wait = DefaultPolicyWait::new(wallet, deadline_ms);
    loop {
        let output = crate::machine_command(
            endpoint,
            bloom_daemon::ipc::MachineCommand::WalletDefaultPolicy {
                name: wallet.to_owned(),
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

    fn menu(answers: &str) -> (PetalsConfig, String) {
        let mut petals = PetalsConfig::default();
        let mut output = Vec::new();
        run_setup_menu(&mut petals, &mut answers.as_bytes(), &mut output).unwrap();
        (petals, String::from_utf8(output).unwrap())
    }

    fn polymarket_limit(petals: &PetalsConfig) -> Option<&str> {
        petals
            .setup
            .get("polymarket")
            .and_then(|setup| setup.values.get("max_daily_usd"))
            .map(String::as_str)
    }

    fn chosen(petals: &PetalsConfig) -> Vec<&str> {
        petals.setup.keys().map(String::as_str).collect()
    }

    fn tolly_writes(petals: &PetalsConfig) -> Option<&str> {
        petals
            .runtime
            .get("tolly")
            .and_then(|runtime| runtime.values.get("tolly_writes"))
            .map(String::as_str)
    }

    #[test]
    fn menu_offers_the_canonical_petals_with_polymarket_limit_suggested() {
        let (petals, output) = menu("\n\n\n\n\n\n");
        assert_eq!(
            menu_petals(),
            ["polymarket", "hyperliquid", "enso", "near-intents", "tolly"]
        );
        assert!(petals.preinstalled.is_empty());
        assert_eq!(
            chosen(&petals),
            ["enso", "hyperliquid", "near-intents", "polymarket", "tolly"]
        );
        assert!(petals.setup["hyperliquid"].values.is_empty());
        assert_eq!(polymarket_limit(&petals), Some("100"));
        assert_eq!(tolly_writes(&petals), Some("enabled"));
        for label in ["Polymarket", "Hyperliquid", "Enso", "NEAR Intents", "Tolly"] {
            assert!(output.contains(&format!("Use {label}? [Y/n] ")), "{output}");
        }
        assert!(output.contains("Polymarket daily buy limit in pUSD [100]: "));
    }

    #[test]
    fn menu_records_declines_and_rejects_invalid_limits() {
        let (petals, output) = menu("y\nmaybe\nno\nno\nY\nn\nabc\n25.5\n");
        assert_eq!(chosen(&petals), ["near-intents", "polymarket"]);
        assert_eq!(polymarket_limit(&petals), Some("25.5"));
        assert_eq!(tolly_writes(&petals), None);
        assert!(output.contains("Answer y or n."));
        assert!(output.contains("Enter a positive amount"));
    }

    #[test]
    fn menu_accepts_remaining_suggestions_at_end_of_input() {
        let (petals, _) = menu("n\n");
        assert_eq!(
            chosen(&petals),
            ["enso", "hyperliquid", "near-intents", "tolly"]
        );
        assert_eq!(polymarket_limit(&petals), None);
        assert_eq!(tolly_writes(&petals), Some("enabled"));
    }

    #[test]
    fn scripted_setup_chooses_every_canonical_petal_and_keeps_existing_values() {
        let mut petals = PetalsConfig::default();
        accept_setup_suggestions(&mut petals);
        assert_eq!(
            chosen(&petals),
            ["enso", "hyperliquid", "near-intents", "polymarket", "tolly"]
        );
        assert_eq!(polymarket_limit(&petals), Some("100"));
        assert_eq!(tolly_writes(&petals), Some("enabled"));

        let mut edited = PetalsConfig::default();
        edited.setup.insert(
            "polymarket".into(),
            PetalSetupConfig {
                values: BTreeMap::from([("max_daily_usd".into(), "5".into())]),
            },
        );
        accept_setup_suggestions(&mut edited);
        assert_eq!(polymarket_limit(&edited), Some("5"));

        let mut disabled = PetalsConfig::default();
        disabled
            .runtime
            .entry("tolly".into())
            .or_default()
            .values
            .insert("tolly_writes".into(), "disabled".into());
        accept_setup_suggestions(&mut disabled);
        assert_eq!(tolly_writes(&disabled), Some("disabled"));
    }

    #[test]
    fn chosen_petals_round_trip_as_config_tables() {
        let mut config = bloom_proto::Config::local_default();
        accept_setup_suggestions(&mut config.petals);
        let encoded = toml::to_string(&config).unwrap();
        assert!(encoded.contains("[petals.setup.hyperliquid]"), "{encoded}");
        assert!(
            encoded.contains("[petals.setup.polymarket.values]\nmax_daily_usd = \"100\""),
            "{encoded}"
        );
        assert!(encoded.contains("tolly_writes = \"enabled\""), "{encoded}");
        let decoded: bloom_proto::Config = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.petals.setup, config.petals.setup);
        assert_eq!(tolly_writes(&decoded.petals), Some("enabled"));
    }

    #[test]
    fn setup_amounts_are_positive_bounded_decimals() {
        for valid in ["100", "0.5", "1.123456", "007"] {
            assert!(is_setup_amount(valid), "{valid}");
        }
        for invalid in [
            "",
            "0",
            "0.000",
            "1.",
            ".5",
            "-1",
            "1e3",
            "1.1234567",
            "1_000",
            " 1",
            "1\"\nenabled = false",
        ] {
            assert!(!is_setup_amount(invalid), "{invalid:?}");
        }
    }

    #[test]
    fn polymarket_settings_render_saved_or_suggested_limits() {
        let mut petals = PetalsConfig::default();
        let suggested = render_petal_settings(&petals, "polymarket", "main")
            .unwrap()
            .unwrap();
        assert_eq!(
            suggested.path,
            "/petals/polymarket/settings/main/venue.toml"
        );
        assert_eq!(
            suggested.body,
            b"enabled = true\nmax_daily_usd = \"100\"\n".to_vec()
        );
        assert_eq!(suggested.summary, "max_daily_usd = 100");

        petals.setup.insert(
            "polymarket".into(),
            PetalSetupConfig {
                values: BTreeMap::from([("max_daily_usd".into(), "42.5".into())]),
            },
        );
        let saved = render_petal_settings(&petals, "polymarket", "main")
            .unwrap()
            .unwrap();
        assert_eq!(
            saved.body,
            b"enabled = true\nmax_daily_usd = \"42.5\"\n".to_vec()
        );
        assert!(
            render_petal_settings(&petals, "hyperliquid", "main")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn enso_has_no_settings_template_and_covers_its_own_chains() {
        // Enso v0.1.5 ships its own per-wallet route rules at
        // settings/wallets/<wallet>/venue.toml; Bloom writes none.
        assert!(
            render_petal_settings(&PetalsConfig::default(), "enso", "main")
                .unwrap()
                .is_none()
        );

        const ROUTER: &str = "0xf75584ef6673ad213a685a1b58cc0330b8ea22cf";
        const LINEA: &str = "0xa146d46823f3f594b785200102be5385cafce9b5";
        const ARC_FAMILY: &str = "0xcfbaa9cfce952ca4f4069874ff1df8c05e37a3c7";
        let destinations: Vec<(String, String)> = policy_destinations("enso")
            .unwrap()
            .into_iter()
            .map(|destination| {
                (
                    destination.chain.as_str().to_owned(),
                    destination.destination,
                )
            })
            .collect();
        let expected: Vec<(String, String)> = [
            ("arbitrum", ROUTER),
            ("avalanche", ROUTER),
            ("base", ROUTER),
            ("bsc", ROUTER),
            ("ethereum", ROUTER),
            ("gnosis", ROUTER),
            ("hyperliquid", ROUTER),
            ("optimism", ROUTER),
            ("polygon", ROUTER),
            ("linea", LINEA),
            ("arc", ARC_FAMILY),
            ("robinhood", ARC_FAMILY),
            ("tempo", ARC_FAMILY),
        ]
        .map(|(chain, router)| (chain.to_owned(), router.to_owned()))
        .to_vec();
        assert_eq!(destinations, expected);

        // Every chain Enso's shipped rules allow is covered, by Bloom's name
        // for it, so Machine never refuses a route Enso planned.
        let covered: std::collections::BTreeSet<&str> = destinations
            .iter()
            .map(|(chain, _)| chain.as_str())
            .collect();
        let configured = bloom_proto::Config::local_default();
        for chain in covered {
            assert!(configured.chains.contains_key(chain), "{chain}");
        }
    }

    #[test]
    fn polymarket_destinations_come_from_the_catalog() {
        let destinations: Vec<(String, String)> = policy_destinations("polymarket")
            .unwrap()
            .into_iter()
            .map(|destination| {
                (
                    destination.chain.as_str().to_owned(),
                    destination.destination,
                )
            })
            .collect();
        assert_eq!(
            destinations,
            [
                // pUSD, native USDC, USDC.e, and the Enso router.
                "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb",
                "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
                "0x2791bca1f2de4661ed88a30c99a7a9449aa84174",
                "0xf75584ef6673ad213a685a1b58cc0330b8ea22cf",
            ]
            .map(|address| ("polygon".to_owned(), address.to_owned()))
        );
        for name in ["hyperliquid", "tolly", "not-in-catalog"] {
            assert!(policy_destinations(name).unwrap().is_empty(), "{name}");
        }
    }

    #[test]
    fn near_intents_is_trusted_with_its_own_per_quote_destinations() {
        // Its deposit address changes per quote, so the entry names the Petal
        // instead of an address. Machine matches it against the `petal_id` it
        // records on the outbox entry.
        let destinations: Vec<(String, String)> = policy_destinations("near-intents")
            .unwrap()
            .into_iter()
            .map(|destination| {
                (
                    destination.chain.as_str().to_owned(),
                    destination.destination,
                )
            })
            .collect();
        assert_eq!(
            destinations,
            [
                "arbitrum",
                "avalanche",
                "base",
                "bsc",
                "ethereum",
                "gnosis",
                "optimism",
                "polygon",
            ]
            .map(|chain| (chain.to_owned(), "petal:near-intents".to_owned()))
        );
        let configured = bloom_proto::Config::local_default();
        for (chain, _) in &destinations {
            assert!(configured.chains.contains_key(chain.as_str()), "{chain}");
        }
    }

    #[test]
    fn edited_config_cannot_inject_settings() {
        let mut petals = PetalsConfig::default();
        petals.setup.insert(
            "polymarket".into(),
            PetalSetupConfig {
                values: BTreeMap::from([(
                    "max_daily_usd".into(),
                    "1\"\nenabled = false\n#".into(),
                )]),
            },
        );
        let error = render_petal_settings(&petals, "polymarket", "main").unwrap_err();
        assert!(error.to_string().contains("is not a positive amount"));
    }

    #[test]
    fn status_uses_a_tagged_json_shape() {
        let status = DefaultPolicyStatus::AwaitingOwner {
            operation_id: "ab".repeat(32),
            ceremony_url: Some("http://localhost:18734/ceremony/token".into()),
            ceremony_expires_at_ms: Some(10),
            petals: vec!["polymarket".into()],
            proposes_chosen_petals: true,
        };
        let encoded = serde_json::to_value(&status).unwrap();
        assert_eq!(encoded["state"], "awaiting_owner");
        assert_eq!(
            serde_json::from_value::<DefaultPolicyStatus>(encoded).unwrap(),
            status
        );
        assert_eq!(
            serde_json::to_value(DefaultPolicyStatus::WaitingForWallet { reason: None }).unwrap(),
            serde_json::json!({"state": "waiting_for_wallet"})
        );
    }

    fn awaiting(operation: &str, expires_at_ms: u64) -> DefaultPolicyStatus {
        DefaultPolicyStatus::AwaitingOwner {
            operation_id: operation.into(),
            ceremony_url: Some(format!("http://localhost:18734/ceremony/{operation}")),
            ceremony_expires_at_ms: Some(expires_at_ms),
            petals: vec!["polymarket".into(), "near-intents".into()],
            proposes_chosen_petals: true,
        }
    }

    #[test]
    fn wait_announces_each_ceremony_once_and_stops_when_applied() {
        let mut wait = DefaultPolicyWait::new("main", 1_000);
        let mut output = Vec::new();
        assert_eq!(
            wait.observe(
                &DefaultPolicyStatus::WaitingForWallet { reason: None },
                10,
                &mut output
            )
            .unwrap(),
            WaitStep::Poll
        );
        for _ in 0..2 {
            assert_eq!(
                wait.observe(&awaiting("one", 5_000), 20, &mut output)
                    .unwrap(),
                WaitStep::Poll
            );
        }
        assert!(!wait.ceremony_expired(4_999));
        let applied = DefaultPolicyStatus::Applied {
            petals: vec!["polymarket".into(), "near-intents".into()],
        };
        assert_eq!(
            wait.observe(&applied, 30, &mut output).unwrap(),
            WaitStep::Stop
        );
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.matches("default_policy_url: ").count(), 1);
        assert!(output.contains("approve the policy for main to allow Polymarket, NEAR Intents"));
        assert!(output.contains("main allows Polymarket, NEAR Intents"));
    }

    #[test]
    fn wait_never_announces_an_unrelated_change_as_the_default_policy() {
        let mut wait = DefaultPolicyWait::new("main", 1_000);
        let mut output = Vec::new();
        let unrelated = DefaultPolicyStatus::AwaitingOwner {
            operation_id: "other".into(),
            ceremony_url: Some("http://localhost:18734/ceremony/other".into()),
            ceremony_expires_at_ms: Some(5_000),
            petals: vec!["polymarket".into(), "near-intents".into()],
            proposes_chosen_petals: false,
        };
        for _ in 0..2 {
            assert_eq!(
                wait.observe(&unrelated, 20, &mut output).unwrap(),
                WaitStep::Poll
            );
        }
        // An unrelated change never becomes the announced default policy, so
        // its expiry never ends this wait.
        assert!(!wait.ceremony_expired(6_000));
        assert_eq!(
            wait.observe(&unrelated, 1_000, &mut output).unwrap(),
            WaitStep::Stop
        );
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.matches("another policy change for main").count(), 1);
        assert!(output.contains("http://localhost:18734/ceremony/other"));
        assert!(!output.contains("approve the policy for main to allow"));
        assert!(!output.contains("default_policy_url: "));
    }

    #[test]
    fn wait_stops_when_the_policy_lock_is_held_past_the_deadline() {
        let mut wait = DefaultPolicyWait::new("main", 1_000);
        let mut output = Vec::new();
        assert_eq!(
            wait.observe(&DefaultPolicyStatus::Busy, 999, &mut output)
                .unwrap(),
            WaitStep::Poll
        );
        assert!(output.is_empty());
        assert_eq!(
            wait.observe(&DefaultPolicyStatus::Busy, 1_000, &mut output)
                .unwrap(),
            WaitStep::Stop
        );
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("another command is still changing main's policy")
        );
    }

    #[test]
    fn wait_reports_why_a_wallet_read_failed() {
        let mut wait = DefaultPolicyWait::new("main", 0);
        let mut output = Vec::new();
        let status = DefaultPolicyStatus::WaitingForWallet {
            reason: Some("wallet projection is not trusted".into()),
        };
        assert_eq!(
            wait.observe(&status, 10, &mut output).unwrap(),
            WaitStep::Stop
        );
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("wallet projection is not trusted")
        );
    }

    #[test]
    fn wait_stops_at_expiry_without_announcing_a_replacement() {
        let mut wait = DefaultPolicyWait::new("main", 1_000);
        let mut output = Vec::new();
        wait.observe(&awaiting("one", 5_000), 20, &mut output)
            .unwrap();
        assert!(wait.ceremony_expired(5_000));
        wait.report_expired(&mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("run `bloom wallet default-policy main` for a new one"));
        assert_eq!(output.matches("default_policy_url: ").count(), 1);
    }

    #[test]
    fn wait_polls_quietly_while_another_command_holds_the_policy_lock() {
        let mut wait = DefaultPolicyWait::new("main", 1_000);
        let mut output = Vec::new();
        assert_eq!(
            wait.observe(&DefaultPolicyStatus::Busy, 10, &mut output)
                .unwrap(),
            WaitStep::Poll
        );
        assert!(output.is_empty());
        assert_eq!(
            serde_json::to_value(DefaultPolicyStatus::Busy).unwrap(),
            serde_json::json!({"state": "busy"})
        );
    }

    #[test]
    fn wait_never_announces_an_expired_ceremony_and_announces_its_replacement() {
        let mut wait = DefaultPolicyWait::new("main", 1_000);
        let mut output = Vec::new();
        assert_eq!(
            wait.observe(&awaiting("stale", 5_000), 5_000, &mut output)
                .unwrap(),
            WaitStep::Poll
        );
        assert!(output.is_empty());
        assert_eq!(
            wait.observe(&awaiting("fresh", 9_000), 6_000, &mut output)
                .unwrap(),
            WaitStep::Poll
        );
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.matches("default_policy_url: ").count(), 1);
        assert!(output.contains("ceremony/fresh"));
    }

    #[test]
    fn wait_reports_expiry_when_a_stale_ceremony_is_never_replaced() {
        let mut wait = DefaultPolicyWait::new("main", 1_000);
        let mut output = Vec::new();
        assert_eq!(
            wait.observe(
                &awaiting("stale", 5_000),
                5_000 + EXPIRED_CEREMONY_GRACE_MS,
                &mut output
            )
            .unwrap(),
            WaitStep::Stop
        );
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("run `bloom wallet default-policy main` for a new one"));
        assert!(!output.contains("default_policy_url: "));
    }

    #[test]
    fn wait_gives_up_on_a_wallet_that_never_appears() {
        let mut wait = DefaultPolicyWait::new("main", 1_000);
        let mut output = Vec::new();
        assert_eq!(
            wait.observe(
                &DefaultPolicyStatus::WaitingForWallet { reason: None },
                1_000,
                &mut output
            )
            .unwrap(),
            WaitStep::Stop
        );
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("once it exists, run `bloom wallet default-policy main`")
        );
    }

    #[test]
    fn custody_output_expiry_is_parsed() {
        let output = "operation_id: ab\nceremony_url: http://x\nceremony_expires_at_ms: 1234\n";
        assert_eq!(ceremony_expiry_from_output(output), Some(1234));
        assert_eq!(ceremony_expiry_from_output("operation_id: ab\n"), None);
    }

    #[test]
    fn updated_petal_messages_say_settings_were_reapplied() {
        assert_eq!(
            settings_message("polymarket", "max_daily_usd = 100", true),
            "petal_settings: Polymarket was updated, which reset its settings; re-applied max_daily_usd = 100"
        );
        assert_eq!(
            settings_message("polymarket", "max_daily_usd = 100", false),
            "petal_settings: Polymarket set max_daily_usd = 100"
        );
    }
}
