//! Default wallet policy: the `bloom init` setup menu, the Petal settings it
//! chooses, and the one policy that allows the chosen Petals.
//!
//! Setup only proposes. The wallet policy still changes through the owner's
//! policy ceremony, and every transaction keeps its own approval. See
//! `docs/architecture/Default Wallet Policy.md`.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::ops::ControlFlow;

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
        "feedback" => "Feedback",
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

/// Whether `bloom init` can ask the setup questions.
pub(crate) fn interactive_setup_available() -> bool {
    use std::io::IsTerminal as _;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Ask which Petals to use and the values each chosen Petal's settings need.
/// An empty answer, or the end of input, accepts the suggestion.
///
/// When the config already records choices (an earlier run of this setup),
/// they are the suggestions: a Petal is suggested only if it was chosen, and
/// a value suggests what was saved. Otherwise every Petal is suggested with
/// the catalog's values.
///
/// Bloom installs every canonical Petal regardless. Each chosen Petal is
/// recorded in `setup`, which the default policy proposes.
pub(crate) fn run_setup_menu(
    petals: &mut PetalsConfig,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    writeln!(
        output,
        "Choose the Petals your main wallet's policy allows. Each transaction still needs your approval."
    )?;
    let earlier = std::mem::take(&mut petals.setup);
    let mut chosen = Vec::new();
    for name in menu_petals() {
        let suggested = earlier.is_empty() || earlier.contains_key(&name);
        if ask_yes_no(
            input,
            output,
            &format!("Use {}?", petal_label(&name)),
            suggested,
        )? {
            chosen.push(name);
        }
    }
    let mut setup = BTreeMap::new();
    for name in &chosen {
        let mut values = BTreeMap::new();
        if let Some(template) = setup_template(name) {
            for value in template.values {
                let suggestion = earlier
                    .get(name)
                    .and_then(|setup| setup.values.get(value.name))
                    .map(String::as_str)
                    .filter(|saved| is_setup_amount(saved))
                    .unwrap_or(value.default);
                let answer = ask_amount(input, output, value.prompt, suggestion)?;
                values.insert(value.name.to_owned(), answer);
            }
        }
        setup.insert(name.clone(), PetalSetupConfig { values });
    }
    petals.setup = setup;
    Ok(())
}

/// The non-interactive form of the setup menu: accept every suggestion. With
/// no earlier choices that records every canonical Petal with the catalog's
/// values; earlier choices are kept as they are, so a declined Petal stays
/// declined and a saved value stays saved.
pub(crate) fn accept_setup_suggestions(petals: &mut PetalsConfig) {
    if !petals.setup.is_empty() {
        return;
    }
    for name in menu_petals() {
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
        let Some(answer) = read_answer(input)? else {
            writeln!(output)?;
            return Ok(suggested);
        };
        match answer.to_ascii_lowercase().as_str() {
            "" => return Ok(suggested),
            "y" | "yes" => return Ok(true),
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

/// Setup settings that could not be written yet, one marker file per Petal.
/// The settings route needs the wallet's account to exist, which on a first
/// run is created after `bloom init`. A marker survives restarts so the write
/// is retried once the account is there, without re-applying settings the
/// owner has since edited.
fn pending_settings_dir(home: &std::path::Path) -> std::path::PathBuf {
    home.join("pending-petal-settings")
}

fn mark_settings_pending(home: &std::path::Path, name: &str) {
    if setup_template(name).is_none() {
        return;
    }
    let dir = pending_settings_dir(home);
    let result = std::fs::create_dir_all(&dir).and_then(|()| std::fs::write(dir.join(name), b""));
    if let Err(error) = result {
        tracing::warn!(petal = %name, %error, "petal.setup_settings_pending_not_recorded");
    }
}

/// Queue the setup settings this `bloom init` is about to write when the
/// choices are saved, before anything is installed. A run that stops after
/// installing a Petal but before writing its settings then still writes them
/// once `main`'s account exists, where otherwise the next run would find setup
/// done and the Petal unchanged, and write nothing. Only what an uninterrupted
/// run would write is queued: a Petal that is already installed while `main`'s
/// account exists, or may exist, keeps whatever settings it has, so its
/// marker is cleared instead. A failure here is returned so setup is not
/// marked done with nothing queued.
pub(crate) async fn record_pending_setup_settings(
    daemon: &Daemon,
    owners_before: &BTreeMap<String, String>,
) -> Result<()> {
    let petals = &daemon.config.petals;
    let account = if petals
        .setup
        .keys()
        .any(|name| setup_template(name).is_some() && owners_before.contains_key(name))
    {
        Some(default_account_presence(&daemon.vfs).await)
    } else {
        None
    };
    let dir = pending_settings_dir(daemon.home.root());
    for (name, queue) in setup_settings_to_queue(petals, owners_before, account.as_ref()) {
        if !queue {
            clear_settings_pending(daemon.home.root(), &name);
            continue;
        }
        std::fs::create_dir_all(&dir)
            .and_then(|()| std::fs::write(dir.join(&name), b""))
            .with_context(|| format!("queue {} setup settings", petal_label(&name)))?;
    }
    Ok(())
}

/// For each chosen Petal with setup settings, whether first setup would write
/// them, by the rule [`apply_setup_settings`] applies after provisioning. A
/// Petal that is not installed yet is installed and written. `account` is
/// read only when some such Petal is already installed; without it nothing
/// installed is queued.
fn setup_settings_to_queue(
    petals: &PetalsConfig,
    owners_before: &BTreeMap<String, String>,
    account: Option<&AccountPresence>,
) -> Vec<(String, bool)> {
    petals
        .setup
        .keys()
        .filter(|name| setup_template(name).is_some())
        .map(|name| {
            let was_installed = owners_before.contains_key(name);
            let queue = match account {
                Some(account) => {
                    setup_settings_step(true, was_installed, false, account)
                        == SetupSettingsStep::Write
                }
                None => !was_installed,
            };
            (name.clone(), queue)
        })
        .collect()
}

fn clear_settings_pending(home: &std::path::Path, name: &str) {
    if let Err(error) = std::fs::remove_file(pending_settings_dir(home).join(name))
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(petal = %name, %error, "petal.setup_settings_pending_not_cleared");
    }
}

/// Chosen Petals whose setup settings are still waiting to be written. Only
/// catalog Petals with a settings template are honoured, so an edited marker
/// directory cannot name anything else.
fn pending_settings(home: &std::path::Path, petals: &PetalsConfig) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(pending_settings_dir(home)) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| setup_template(name).is_some() && petals.setup.contains_key(name))
        .collect();
    names.sort();
    names
}

/// Write the settings that an earlier attempt could not, now that the default
/// wallet exists. The write goes ahead only while the Petal's settings route
/// still reads its unset contents, and that check and the write are one step
/// no other write through Machine can land between. Anything else there may be
/// the owner's, so it stays and the marker is cleared. A write that cannot be
/// made yet, as before the account exists, keeps its marker for next time.
pub(crate) async fn apply_pending_settings(daemon: &Daemon) -> Vec<String> {
    let owners = petal_owners(daemon).unwrap_or_default();
    let mut messages = Vec::new();
    for name in pending_settings(daemon.home.root(), &daemon.config.petals) {
        if !owners.contains_key(&name) {
            continue;
        }
        messages.extend(
            apply_queued_settings(
                &daemon.vfs,
                daemon.home.root(),
                &daemon.config.petals,
                &name,
            )
            .await,
        );
    }
    messages
}

/// Make `name`'s queued setup write through `vfs`, and return its message if
/// it wrote. The marker under `home` is cleared once the route has been
/// checked, whether or not setup's settings went in, and kept when the check
/// or the write failed.
async fn apply_queued_settings(
    vfs: &bloom_vfs::Vfs,
    home: &std::path::Path,
    petals: &PetalsConfig,
    name: &str,
) -> Option<String> {
    let template = setup_template(name)?;
    let attempt = async {
        let settings = render_petal_settings(petals, name, DEFAULT_POLICY_WALLET)?
            .context("Petal has no setup settings")?;
        let path = bloom_vfs::VfsPath::parse(&settings.path)?;
        let written = vfs
            .write_if_reads(&path, template.unset_body.as_bytes(), &settings.body)
            .await
            .with_context(|| {
                format!("write {} settings to {}", petal_label(name), settings.path)
            })?;
        anyhow::Ok((settings, written))
    }
    .await;
    match attempt {
        Ok((settings, true)) => {
            clear_settings_pending(home, name);
            Some(settings_message(name, &settings.summary, false))
        }
        Ok((settings, false)) => {
            clear_settings_pending(home, name);
            tracing::info!(
                petal = %name,
                message = %settings_not_written(
                    name,
                    &settings,
                    "settings were written there after setup, so they stay as they are"
                ),
                "petal.setup_settings_preserved"
            );
            None
        }
        Err(error) => {
            tracing::warn!(
                petal = %name,
                error = %format!("{error:#}"),
                "petal.setup_settings_retry_failed"
            );
            None
        }
    }
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
/// that setup just configured or installed. Signed package lineage carries
/// private settings through updates, so an update must preserve settings the
/// owner may already have written.
///
/// A failed write is reported and the rest continue, as in `bloom serve`. A
/// Petal without its settings fails closed: Polymarket refuses buys and Enso
/// refuses routes until the owner writes them.
///
/// Setup can run on a home that already has a wallet, such as one upgraded
/// from before this setup existed. There an already installed Petal may hold
/// settings the owner wrote through its own route, even after an update,
/// so they are left as they are and the setup choice is reported instead.
pub(crate) async fn apply_setup_settings(
    daemon: &Daemon,
    owners_before: &BTreeMap<String, String>,
    first_setup: bool,
) -> Result<Vec<String>> {
    let owners_after = petal_owners(daemon)?;
    let account = default_account_presence(&daemon.vfs).await;
    let mut messages = Vec::new();
    for name in daemon.config.petals.setup.keys() {
        let Some(installed) = owners_after.get(name) else {
            continue;
        };
        let previous = owners_before.get(name);
        let updated = previous.is_some_and(|previous| previous != installed);
        let step = setup_settings_step(first_setup, previous.is_some(), updated, &account);
        messages.extend(
            settle_setup_settings(
                &daemon.vfs,
                daemon.home.root(),
                &daemon.config.petals,
                name,
                step,
                updated,
                &account,
            )
            .await,
        );
    }
    Ok(messages)
}

/// Carry out `step` for one installed, chosen Petal after `bloom init`
/// provisioned it, and return what to tell the owner. `updated` says
/// provisioning replaced an older release.
async fn settle_setup_settings(
    vfs: &bloom_vfs::Vfs,
    home: &std::path::Path,
    petals: &PetalsConfig,
    name: &str,
    step: SetupSettingsStep,
    updated: bool,
    account: &AccountPresence,
) -> Option<String> {
    let reason = match step {
        SetupSettingsStep::Leave => {
            return finish_interrupted_setup(vfs, home, petals, name, account).await;
        }
        SetupSettingsStep::Write => None,
        SetupSettingsStep::KeepOwners => Some(format!(
            "wallet {DEFAULT_POLICY_WALLET} already exists, so any settings the owner wrote stay as they are"
        )),
        SetupSettingsStep::Unverified => Some(format!(
            "Bloom could not check whether wallet {DEFAULT_POLICY_WALLET} exists ({}), so it did not risk replacing settings the owner wrote",
            match account {
                AccountPresence::Unknown(error) => error.as_str(),
                _ => "unknown",
            }
        )),
    };
    if let Some(reason) = reason {
        // Nothing deferred may later write what setup just declined to.
        clear_settings_pending(home, name);
        return match render_petal_settings(petals, name, DEFAULT_POLICY_WALLET) {
            Ok(Some(settings)) => Some(settings_not_written(name, &settings, &reason)),
            Ok(None) => None,
            Err(error) => Some(format!("petal_settings_failed: {error:#}")),
        };
    }
    match write_petal_settings(vfs, petals, name).await {
        Ok(Some(summary)) => {
            clear_settings_pending(home, name);
            Some(settings_message(name, &summary, updated))
        }
        Ok(None) => None,
        Err(error) => {
            mark_settings_pending(home, name);
            Some(format!(
                "petal_settings_failed: {error:#} (will retry once wallet {DEFAULT_POLICY_WALLET} exists)"
            ))
        }
    }
}

/// Make the write an earlier `bloom init` queued for a Petal this run leaves
/// alone, once `main`'s account exists. That run stopped after installing
/// the Petal and before writing its settings, so the Petal now looks
/// unchanged and nothing else would write them on a home whose `main`
/// already exists: wallet creation, which otherwise applies queued writes,
/// has already happened. As there, the write goes in only over the route's
/// unset contents. Before `main` exists the marker stays for wallet creation.
async fn finish_interrupted_setup(
    vfs: &bloom_vfs::Vfs,
    home: &std::path::Path,
    petals: &PetalsConfig,
    name: &str,
    account: &AccountPresence,
) -> Option<String> {
    if *account != AccountPresence::Exists
        || !pending_settings(home, petals)
            .iter()
            .any(|pending| pending == name)
    {
        return None;
    }
    apply_queued_settings(vfs, home, petals, name).await
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SetupSettingsStep {
    /// Not a setup or install event for this Petal.
    Leave,
    /// The owner may already hold settings for this Petal; do not replace them.
    KeepOwners,
    /// Whether the owner may hold settings could not be established; do not
    /// replace them.
    Unverified,
    Write,
}

/// Whether the default wallet's account 0 exists.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AccountPresence {
    Exists,
    /// Machine's projection says the wallet or account does not exist.
    Absent,
    /// The projection could not be read, for example because Broker is down.
    Unknown(String),
}

impl AccountPresence {
    /// Only a definite "not found" means absent: an unreachable Broker or a
    /// stale projection says nothing about whether the wallet exists.
    pub(crate) fn from_read<T>(read: &Result<T, bloom_vfs::HandlerError>) -> Self {
        match read {
            Ok(_) => Self::Exists,
            Err(bloom_vfs::HandlerError::NotFound(_)) => Self::Absent,
            Err(error) => Self::Unknown(error.to_string()),
        }
    }
}

/// Whether `bloom init` writes a chosen Petal's setup settings. A Petal that
/// was just installed gets them. An already installed Petal gets them on
/// first setup or update only when the default wallet's account is known not
/// to exist. Otherwise its carried settings may belong to the owner and are
/// preserved, including when account presence cannot be checked.
pub(crate) fn setup_settings_step(
    first_setup: bool,
    was_installed: bool,
    updated: bool,
    account: &AccountPresence,
) -> SetupSettingsStep {
    if !was_installed {
        SetupSettingsStep::Write
    } else if !first_setup && !updated {
        SetupSettingsStep::Leave
    } else {
        match account {
            AccountPresence::Absent => SetupSettingsStep::Write,
            AccountPresence::Exists => SetupSettingsStep::KeepOwners,
            AccountPresence::Unknown(_) => SetupSettingsStep::Unverified,
        }
    }
}

async fn default_account_presence(vfs: &bloom_vfs::Vfs) -> AccountPresence {
    let path = format!("/wallets/{DEFAULT_POLICY_WALLET}/0/account.json");
    match bloom_vfs::VfsPath::parse(&path) {
        Ok(path) => AccountPresence::from_read(&bloom_vfs::Handler::read(vfs, &path).await),
        Err(error) => AccountPresence::Unknown(format!("{error:#}")),
    }
}

/// After `bloom serve` provisions catalog Petals, write setup settings for each
/// chosen Petal it installed. Updates preserve carried owner settings.
/// Runs on a blocking provisioning thread.
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
        if updated {
            let account = runtime.block_on(default_account_presence(&daemon.vfs));
            if setup_settings_step(false, true, true, &account) != SetupSettingsStep::Write {
                clear_settings_pending(daemon.home.root(), &result.name);
                tracing::info!(
                    petal = %result.name,
                    "petal.setup_settings_preserved"
                );
                continue;
            }
        }
        match runtime.block_on(write_petal_settings(
            &daemon.vfs,
            &daemon.config.petals,
            &result.name,
        )) {
            Ok(Some(summary)) => {
                clear_settings_pending(daemon.home.root(), &result.name);
                tracing::info!(
                    petal = %result.name,
                    updated,
                    message = %settings_message(&result.name, &summary, updated),
                    "petal.setup_settings_written"
                );
            }
            Ok(None) => {}
            Err(error) => {
                mark_settings_pending(daemon.home.root(), &result.name);
                tracing::warn!(
                    petal = %result.name,
                    error = %format!("{error:#}"),
                    "petal.setup_settings_failed"
                );
            }
        }
    }
}

/// A setup choice Bloom did not write, with the command that applies it.
fn settings_not_written(name: &str, settings: &PetalSettingsWrite, reason: &str) -> String {
    format!(
        "petal_settings_not_written: {} settings were not written: {reason}. To apply setup's choice, run: printf '{}' | bloom vfs write {}",
        petal_label(name),
        String::from_utf8_lossy(&settings.body).replace('\n', "\\n"),
        settings.path
    )
}

pub(crate) fn settings_message(name: &str, summary: &str, updated: bool) -> String {
    if updated {
        format!(
            "petal_settings: {} was updated; set {summary}",
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
        /// Whether this pending change is the one that allows the chosen
        /// Petals. An unrelated change must finish before ours is proposed, and
        /// must never be announced as if it were ours.
        #[serde(default = "crate::default_policy::proposes_chosen_petals_default")]
        proposes_chosen_petals: bool,
    },
    /// The wallet policy allows every chosen, installed Petal.
    Applied { petals: Vec<String> },
    /// The policy has changed since the wallet was created and does not allow
    /// `missing`. Only a new wallet's policy is proposed, so nothing is.
    ChangedSinceCreation { missing: Vec<String> },
    /// Another command holds the wallet's policy lock; ask again shortly.
    Busy,
}

/// Propose the Petals chosen during setup for `wallet` through its existing
/// policy operation, committing a completed ceremony, and report the result.
/// After the policy has changed since creation they are proposed only when
/// `owner_just_chose` says the owner has just recorded this choice.
pub(crate) async fn advance_default_policy(
    daemon: &Daemon,
    wallet: &str,
    owner_just_chose: bool,
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
    if let ControlFlow::Break(status) =
        wallet_read_step(daemon.wallet_projections.get_wallet(&wallet_id).await)?
    {
        return Ok(status);
    }
    if wallet == DEFAULT_POLICY_WALLET {
        for message in apply_pending_settings(daemon).await {
            tracing::info!(%message, "petal.setup_settings_written");
        }
    }
    let eligibility = match policy_step(
        daemon
            .ensure_default_policy(wallet, &packages, &destinations, owner_just_chose)
            .await,
    )? {
        ControlFlow::Continue(eligibility) => eligibility,
        ControlFlow::Break(status) => return Ok(status),
    };
    Ok(match eligibility {
        bloom_machine_client::PetalEligibility::Allowed(_) => {
            DefaultPolicyStatus::Applied { petals }
        }
        bloom_machine_client::PetalEligibility::ChangedSinceCreation(current) => {
            DefaultPolicyStatus::ChangedSinceCreation {
                missing: petals_not_allowed(&current, &petals, &packages)?,
            }
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
        Err(bloom_vfs::HandlerError::Backend(message))
            if message.starts_with(bloom_vfs::handlers::wallets::POLICY_COORDINATION_BUSY) =>
        {
            Ok(ControlFlow::Break(DefaultPolicyStatus::Busy))
        }
        Err(bloom_vfs::HandlerError::Backend(message)) if reported_outage(&message).is_some() => {
            Ok(ControlFlow::Break(DefaultPolicyStatus::WaitingForWallet {
                reason: Some(message),
            }))
        }
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

/// The chosen Petals `current` does not allow: its package, or any of the
/// destinations its transactions need, is missing. `packages` pairs with
/// `petals` by position.
fn petals_not_allowed(
    current: &bloom_broker_api::SignedPolicySnapshot,
    petals: &[String],
    packages: &[bloom_broker_api::Digest32],
) -> Result<Vec<String>> {
    let policy: bloom_broker_api::CanonicalWalletPolicy =
        serde_json::from_slice(&current.canonical_policy.decode())
            .context("decode the wallet's current policy")?;
    let mut missing = Vec::new();
    for (name, package) in petals.iter().zip(packages) {
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
    /// Whether a Broker refusal being waited out has been reported.
    announced_wait: bool,
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
            announced_wait: false,
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
                    "default_policy: another policy change for {wallet} is waiting for you at {url}; the default policy is checked again once it finishes"
                )?,
                None => writeln!(
                    output,
                    "default_policy: another policy change for {wallet} is in progress; the default policy is checked again once it finishes"
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
            DefaultPolicyStatus::ChangedSinceCreation { missing } => {
                writeln!(
                    output,
                    "default_policy: {wallet}'s policy has changed since the wallet was created and does not allow {}; Bloom proposes the default policy only for a new wallet, so nothing was proposed. To allow one again, propose it with `bloom wallet update-policy {wallet} --file <policy.json>`",
                    petal_labels(missing)
                )?;
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
                let hint = wait_hint(wallet, reason.as_deref());
                match reason {
                    Some(reason) if reported_outage(reason).is_some() => writeln!(
                        output,
                        "default_policy: stopped waiting for Broker ({reason}); {hint}, run `bloom wallet default-policy {wallet}`"
                    )?,
                    Some(reason) => writeln!(
                        output,
                        "default_policy: stopped waiting for wallet {wallet} ({reason}); {hint}, run `bloom wallet default-policy {wallet}`"
                    )?,
                    None => writeln!(
                        output,
                        "default_policy: stopped waiting for wallet {wallet}; {hint}, run `bloom wallet default-policy {wallet}`"
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
            // A waiting command resumes a setup choice; it never re-chooses.
            bloom_daemon::ipc::MachineCommand::WalletDefaultPolicy {
                name: wallet.to_owned(),
                owner_just_chose: false,
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

    fn chosen_setup(names: &[&str]) -> PetalsConfig {
        let mut petals = PetalsConfig::default();
        for name in names {
            petals
                .setup
                .insert((*name).to_owned(), PetalSetupConfig::default());
        }
        petals
    }

    #[test]
    fn failed_settings_stay_pending_until_written() {
        let home = tempfile::tempdir().unwrap();
        let petals = chosen_setup(&["polymarket"]);
        assert!(pending_settings(home.path(), &petals).is_empty());

        mark_settings_pending(home.path(), "polymarket");
        assert_eq!(pending_settings(home.path(), &petals), ["polymarket"]);
        // A second failed attempt leaves one marker, not two.
        mark_settings_pending(home.path(), "polymarket");
        assert_eq!(pending_settings(home.path(), &petals), ["polymarket"]);

        clear_settings_pending(home.path(), "polymarket");
        assert!(pending_settings(home.path(), &petals).is_empty());
        // Clearing an absent marker is not an error.
        clear_settings_pending(home.path(), "polymarket");
    }

    /// `unset_body` is what the pinned Polymarket release's settings route
    /// reads before anything is written there. A deferred setup write goes
    /// ahead only over exactly those bytes, so a catalog bump must re-check
    /// them against the new release's `read_venue_config`, or every deferred
    /// write would be kept as if the owner had written it.
    #[test]
    fn the_unset_polymarket_settings_are_pinned_with_their_release() {
        let entry = github_source::preinstalled_petal("polymarket").unwrap();
        assert_eq!(
            entry.expected_hash,
            Some("0f365cd7f613129f73ce66fb07256c8a42c4e70abbb77721804dbd6df85b96b5"),
            "re-check unset_body against the new release, then update both"
        );
        let template = setup_template("polymarket").unwrap();
        assert_eq!(
            template.unset_body,
            "enabled = false\nallow_neg_risk = true\n"
        );
        // Setup's own settings never read as unset, so a written choice is
        // never mistaken for an empty route.
        let written = render_petal_settings(&chosen_setup(&["polymarket"]), "polymarket", "main")
            .unwrap()
            .unwrap();
        assert_ne!(written.body, template.unset_body.as_bytes());
    }

    /// Choosing Petals queues each one's settings before anything is
    /// installed, so a `bloom init` that stops part-way still writes them once
    /// `main`'s account exists. Only Petals with setup settings are queued.
    #[test]
    fn choosing_petals_queues_only_the_settings_setup_would_write() {
        let petals = chosen_setup(&["polymarket", "hyperliquid", "enso"]);
        let none = BTreeMap::new();
        let installed = BTreeMap::from([("polymarket".to_owned(), "a".repeat(64))]);
        // Only Polymarket has setup settings. Not installed yet, it is
        // installed and written whatever the account.
        assert_eq!(
            setup_settings_to_queue(&petals, &none, None),
            [("polymarket".to_owned(), true)]
        );
        assert_eq!(
            setup_settings_to_queue(&petals, &none, Some(&AccountPresence::Exists)),
            [("polymarket".to_owned(), true)]
        );
        // Already installed, it is written only while `main` is known not to
        // exist; otherwise its marker is cleared, as an uninterrupted run
        // leaves the owner's settings.
        assert_eq!(
            setup_settings_to_queue(&petals, &installed, Some(&AccountPresence::Absent)),
            [("polymarket".to_owned(), true)]
        );
        for account in [
            AccountPresence::Exists,
            AccountPresence::Unknown("Broker is down".into()),
        ] {
            assert_eq!(
                setup_settings_to_queue(&petals, &installed, Some(&account)),
                [("polymarket".to_owned(), false)],
                "{account:?}"
            );
        }
        assert_eq!(
            setup_settings_to_queue(&petals, &installed, None),
            [("polymarket".to_owned(), false)]
        );
        assert!(setup_settings_to_queue(&chosen_setup(&["hyperliquid"]), &none, None).is_empty());
    }

    /// A Petal settings route for [`apply_queued_settings`]. A paused read
    /// returns what it saw before the pause.
    struct SettingsRoute {
        value: tokio::sync::Mutex<Option<Vec<u8>>>,
        pause_reads: std::sync::atomic::AtomicBool,
        read_started: tokio::sync::Notify,
        release_read: tokio::sync::Notify,
    }

    impl SettingsRoute {
        /// `None` fails every read, as before `main`'s account exists.
        fn holding(value: Option<&[u8]>) -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                value: tokio::sync::Mutex::new(value.map(<[u8]>::to_vec)),
                pause_reads: std::sync::atomic::AtomicBool::new(false),
                read_started: tokio::sync::Notify::new(),
                release_read: tokio::sync::Notify::new(),
            })
        }

        async fn value(&self) -> Option<Vec<u8>> {
            self.value.lock().await.clone()
        }
    }

    #[async_trait::async_trait]
    impl bloom_vfs::Handler for SettingsRoute {
        async fn lookup(
            &self,
            _path: &bloom_vfs::VfsPath,
        ) -> std::result::Result<bloom_vfs::Entry, bloom_vfs::HandlerError> {
            Ok(bloom_vfs::Entry::file("venue.toml"))
        }

        async fn read(
            &self,
            _path: &bloom_vfs::VfsPath,
        ) -> std::result::Result<Vec<u8>, bloom_vfs::HandlerError> {
            let value = self.value.lock().await.clone();
            if self.pause_reads.load(std::sync::atomic::Ordering::SeqCst) {
                self.read_started.notify_one();
                self.release_read.notified().await;
            }
            value.ok_or_else(|| bloom_vfs::HandlerError::not_found("wallet main"))
        }

        async fn write(
            &self,
            _path: &bloom_vfs::VfsPath,
            data: &[u8],
        ) -> std::result::Result<(), bloom_vfs::HandlerError> {
            *self.value.lock().await = Some(data.to_vec());
            Ok(())
        }
    }

    fn queued_polymarket(
        route: &std::sync::Arc<SettingsRoute>,
    ) -> (tempfile::TempDir, bloom_vfs::Vfs) {
        let home = tempfile::tempdir().unwrap();
        mark_settings_pending(home.path(), "polymarket");
        let vfs = bloom_vfs::Vfs::builder()
            .mount("petals", route.clone())
            .build();
        (home, vfs)
    }

    fn polymarket_setup_body() -> Vec<u8> {
        render_petal_settings(&chosen_setup(&["polymarket"]), "polymarket", "main")
            .unwrap()
            .unwrap()
            .body
    }

    #[tokio::test]
    async fn a_queued_write_goes_in_only_over_unset_settings() {
        let petals = chosen_setup(&["polymarket"]);
        let unset = setup_template("polymarket").unwrap().unset_body.as_bytes();

        let route = SettingsRoute::holding(Some(unset));
        let (home, vfs) = queued_polymarket(&route);
        let message = apply_queued_settings(&vfs, home.path(), &petals, "polymarket").await;
        assert!(message.unwrap().starts_with("petal_settings: "));
        assert_eq!(route.value().await.unwrap(), polymarket_setup_body());
        assert!(pending_settings(home.path(), &petals).is_empty());

        // The owner's settings stay, and nothing is queued any longer.
        let route = SettingsRoute::holding(Some(b"enabled = false\n"));
        let (home, vfs) = queued_polymarket(&route);
        assert_eq!(
            apply_queued_settings(&vfs, home.path(), &petals, "polymarket").await,
            None
        );
        assert_eq!(route.value().await.unwrap(), b"enabled = false\n");
        assert!(pending_settings(home.path(), &petals).is_empty());

        // A route that cannot be read yet keeps the marker for next time.
        let route = SettingsRoute::holding(None);
        let (home, vfs) = queued_polymarket(&route);
        assert_eq!(
            apply_queued_settings(&vfs, home.path(), &petals, "polymarket").await,
            None
        );
        assert_eq!(route.value().await, None);
        assert_eq!(pending_settings(home.path(), &petals), ["polymarket"]);
    }

    /// A rerun of `bloom init` makes the write an interrupted run queued, but
    /// only once `main` exists and only for a Petal with a marker.
    #[tokio::test]
    async fn a_rerun_of_setup_finishes_an_interrupted_settings_write() {
        let petals = chosen_setup(&["polymarket"]);
        let unset = setup_template("polymarket").unwrap().unset_body.as_bytes();
        for account in [
            AccountPresence::Absent,
            AccountPresence::Unknown("Broker is down".into()),
        ] {
            let route = SettingsRoute::holding(Some(unset));
            let (home, vfs) = queued_polymarket(&route);
            let finished = settle_setup_settings(
                &vfs,
                home.path(),
                &petals,
                "polymarket",
                SetupSettingsStep::Leave,
                false,
                &account,
            )
            .await;
            assert_eq!(finished, None, "{account:?}");
            assert_eq!(route.value().await.unwrap(), unset, "{account:?}");
            assert_eq!(pending_settings(home.path(), &petals), ["polymarket"]);
        }

        let route = SettingsRoute::holding(Some(unset));
        let (home, vfs) = queued_polymarket(&route);
        let exists = AccountPresence::Exists;
        let finished = settle_setup_settings(
            &vfs,
            home.path(),
            &petals,
            "polymarket",
            SetupSettingsStep::Leave,
            false,
            &exists,
        )
        .await;
        assert!(finished.unwrap().starts_with("petal_settings: "));
        assert_eq!(route.value().await.unwrap(), polymarket_setup_body());
        assert!(pending_settings(home.path(), &petals).is_empty());

        // Nothing queued: nothing written, even over unset settings.
        let route = SettingsRoute::holding(Some(unset));
        let vfs = bloom_vfs::Vfs::builder()
            .mount("petals", route.clone())
            .build();
        let home = tempfile::tempdir().unwrap();
        let finished = settle_setup_settings(
            &vfs,
            home.path(),
            &petals,
            "polymarket",
            SetupSettingsStep::Leave,
            false,
            &exists,
        )
        .await;
        assert_eq!(finished, None);
        assert_eq!(route.value().await.unwrap(), unset);
    }

    /// An owner's write that arrives while the queued write is checking the
    /// route lands after it, so setup's settings never replace it.
    #[tokio::test]
    async fn a_queued_write_never_replaces_an_owner_write_made_during_its_check() {
        let petals = chosen_setup(&["polymarket"]);
        let unset = setup_template("polymarket").unwrap().unset_body.as_bytes();
        let route = SettingsRoute::holding(Some(unset));
        route
            .pause_reads
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let (home, vfs) = queued_polymarket(&route);
        let settings_path = render_petal_settings(&petals, "polymarket", "main")
            .unwrap()
            .unwrap()
            .path;

        let queued = {
            let (vfs, home, petals) = (vfs.clone(), home.path().to_owned(), petals.clone());
            tokio::spawn(
                async move { apply_queued_settings(&vfs, &home, &petals, "polymarket").await },
            )
        };
        route.read_started.notified().await;
        let owner = {
            let vfs = vfs.clone();
            tokio::spawn(async move {
                bloom_vfs::Handler::write(
                    &vfs,
                    &bloom_vfs::VfsPath::parse(&settings_path).unwrap(),
                    b"enabled = false\n",
                )
                .await
                .unwrap();
            })
        };
        tokio::task::yield_now().await;
        route.release_read.notify_one();

        assert!(
            queued.await.unwrap().is_some(),
            "the check saw unset settings"
        );
        owner.await.unwrap();
        assert_eq!(route.value().await.unwrap(), b"enabled = false\n");
    }

    fn waiting(reason: &str) -> ControlFlow<DefaultPolicyStatus> {
        ControlFlow::Break(DefaultPolicyStatus::WaitingForWallet {
            reason: Some(reason.to_owned()),
        })
    }

    /// A brief outage keeps a waiting command polling until its deadline; a
    /// final failure still ends it.
    #[test]
    fn a_wallet_read_outage_is_waited_out() {
        use bloom_broker_api::{ProtocolError, ProtocolErrorCode};
        let read = |code, message| wallet_read_step::<()>(Err(ProtocolError::new(code, message)));
        assert_eq!(wallet_read_step(Ok(())).unwrap(), ControlFlow::Continue(()));
        assert_eq!(
            read(
                ProtocolErrorCode::BackendInvalidRequest,
                "wallet main not found"
            )
            .unwrap(),
            waiting("wallet main not found")
        );
        assert_eq!(
            read(ProtocolErrorCode::ServiceUnavailable, "Broker restarting").unwrap(),
            waiting("SERVICE_UNAVAILABLE: Broker restarting")
        );
        assert_eq!(
            read(ProtocolErrorCode::QuotaExceeded, "slow down").unwrap(),
            waiting("QUOTA_EXCEEDED: slow down")
        );
        assert!(read(ProtocolErrorCode::UnauthenticatedPeer, "who are you").is_err());
    }

    /// The policy step waits out the same Broker failures as the wallet read,
    /// as the VFS reports them.
    #[test]
    fn a_policy_read_outage_is_waited_out() {
        use bloom_broker_api::{ProtocolError, ProtocolErrorCode};
        let backend = |code, message| {
            bloom_vfs::HandlerError::backend(ProtocolError::new(code, message).to_string())
        };
        assert_eq!(policy_step(Ok(7)).unwrap(), ControlFlow::Continue(7));
        for code in [
            ProtocolErrorCode::ServiceUnavailable,
            ProtocolErrorCode::QuotaExceeded,
            ProtocolErrorCode::CeremonyRateLimited,
        ] {
            assert_eq!(
                policy_step::<()>(Err(backend(code, "try again"))).unwrap(),
                waiting(&format!("{}: try again", code.as_str()))
            );
        }
        assert_eq!(
            policy_step::<()>(Err(bloom_vfs::HandlerError::backend(format!(
                "{}: another command holds it",
                bloom_vfs::handlers::wallets::POLICY_COORDINATION_BUSY
            ))))
            .unwrap(),
            ControlFlow::Break(DefaultPolicyStatus::Busy)
        );
        for error in [
            backend(ProtocolErrorCode::PolicyBaselineStale, "reread it"),
            backend(
                ProtocolErrorCode::BackendInvalidRequest,
                "wallet main not found",
            ),
            bloom_vfs::HandlerError::backend("SERVICE_UNAVAILABLE"),
            bloom_vfs::HandlerError::backend("the policy service: is down"),
            bloom_vfs::HandlerError::invalid("SERVICE_UNAVAILABLE: not a Broker error"),
        ] {
            assert!(policy_step::<()>(Err(error)).is_err());
        }
    }

    #[test]
    fn pending_markers_cannot_name_anything_but_chosen_catalog_petals() {
        let home = tempfile::tempdir().unwrap();
        let dir = pending_settings_dir(home.path());
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["polymarket", "../escape", "not-a-petal", "enso"] {
            let _ = std::fs::write(dir.join(name), b"");
        }
        // Not chosen in setup: ignored. No settings template (enso): ignored.
        assert!(pending_settings(home.path(), &chosen_setup(&["enso"])).is_empty());
        assert_eq!(
            pending_settings(
                home.path(),
                &chosen_setup(&["polymarket", "enso", "not-a-petal"])
            ),
            ["polymarket"]
        );
        let fresh = tempfile::tempdir().unwrap();
        mark_settings_pending(fresh.path(), "not-a-petal");
        assert!(!pending_settings_dir(fresh.path()).exists());
    }
    use super::*;

    /// Machine refuses an outbox transaction whose destination the wallet
    /// policy does not list, so a canonical Petal missing from `for_petal`
    /// would install and then have every transaction denied. Adding a Petal
    /// to the catalog must be a decision made here, one way or the other.
    #[test]
    fn every_canonical_petal_has_destinations_or_is_known_to_need_none() {
        // Hyperliquid declares no `bloom:tx.outbox` capability: it signs venue
        // payloads and never stages an on-chain transaction.
        // Feedback declares only HTTP/store capabilities and never stages transactions.
        const NO_DESTINATIONS: &[&str] = &["hyperliquid", "feedback"];
        for name in menu_petals() {
            let listed = !bloom_proto::petal_destinations::for_petal(&name).is_empty();
            let exempt = NO_DESTINATIONS.contains(&name.as_str());
            assert!(
                listed != exempt,
                "{name}: list its destinations in petal_destinations::for_petal, or add it to NO_DESTINATIONS with the reason"
            );
        }
    }

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
            [
                "polymarket",
                "hyperliquid",
                "enso",
                "near-intents",
                "feedback"
            ]
        );
        assert!(petals.preinstalled.is_empty());
        assert_eq!(
            chosen(&petals),
            [
                "enso",
                "feedback",
                "hyperliquid",
                "near-intents",
                "polymarket"
            ]
        );
        assert!(petals.setup["hyperliquid"].values.is_empty());
        assert_eq!(polymarket_limit(&petals), Some("100"));
        assert_eq!(tolly_writes(&petals), None);
        for label in [
            "Polymarket",
            "Hyperliquid",
            "Enso",
            "NEAR Intents",
            "Feedback",
        ] {
            assert!(output.contains(&format!("Use {label}? [Y/n] ")), "{output}");
        }
        assert!(output.contains("Polymarket daily buy limit in pUSD [100]: "));
    }

    #[test]
    fn menu_suggests_earlier_choices_on_an_existing_config() {
        // An earlier run chose Hyperliquid and Polymarket with a custom cap and
        // declined the rest. Enter at every prompt keeps exactly that.
        let mut petals = PetalsConfig::default();
        petals
            .setup
            .insert("hyperliquid".into(), PetalSetupConfig::default());
        petals.setup.insert(
            "polymarket".into(),
            PetalSetupConfig {
                values: BTreeMap::from([("max_daily_usd".into(), "42.5".into())]),
            },
        );
        let mut output = Vec::new();
        run_setup_menu(&mut petals, &mut "\n\n\n\n\n\n".as_bytes(), &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert_eq!(chosen(&petals), ["hyperliquid", "polymarket"]);
        assert_eq!(polymarket_limit(&petals), Some("42.5"));
        assert!(output.contains("Use Polymarket? [Y/n] "), "{output}");
        assert!(output.contains("Use Enso? [y/N] "), "{output}");
        assert!(
            output.contains("Polymarket daily buy limit in pUSD [42.5]: "),
            "{output}"
        );

        // The same at the end of input, and an explicit answer still wins.
        let mut eof = petals.clone();
        run_setup_menu(&mut eof, &mut "".as_bytes(), &mut Vec::new()).unwrap();
        assert_eq!(chosen(&eof), ["hyperliquid", "polymarket"]);
        assert_eq!(polymarket_limit(&eof), Some("42.5"));
        let mut changed = petals.clone();
        run_setup_menu(
            &mut changed,
            &mut "\n\ny\n\n\n60\n".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(chosen(&changed), ["enso", "hyperliquid", "polymarket"]);
        assert_eq!(polymarket_limit(&changed), Some("60"));
    }

    #[test]
    fn scripted_setup_keeps_earlier_declines() {
        let mut petals = PetalsConfig::default();
        petals.setup.insert(
            "polymarket".into(),
            PetalSetupConfig {
                values: BTreeMap::from([("max_daily_usd".into(), "42.5".into())]),
            },
        );
        accept_setup_suggestions(&mut petals);
        assert_eq!(chosen(&petals), ["polymarket"]);
        assert_eq!(polymarket_limit(&petals), Some("42.5"));
    }

    #[test]
    fn setup_never_replaces_settings_the_owner_may_hold() {
        use AccountPresence::*;
        use SetupSettingsStep::*;
        let down = Unknown("backend: SERVICE_UNAVAILABLE".into());
        // (first_setup, was_installed, updated, account)
        // A fresh install gets setup settings. Updates keep carried owner settings.
        assert_eq!(setup_settings_step(true, false, false, &Exists), Write);
        assert_eq!(setup_settings_step(true, false, false, &down), Write);
        assert_eq!(setup_settings_step(false, true, true, &Exists), KeepOwners);
        assert_eq!(setup_settings_step(false, true, true, &down), Unverified);
        assert_eq!(setup_settings_step(false, true, true, &Absent), Write);
        // First setup on a home known to have no wallet: nothing to overwrite.
        assert_eq!(setup_settings_step(true, true, false, &Absent), Write);
        // First setup on a home whose wallet exists (an upgraded home): the
        // owner may have written settings through the Petal; keep them.
        assert_eq!(setup_settings_step(true, true, false, &Exists), KeepOwners);
        // If that cannot be checked (Broker down), do not risk it either.
        assert_eq!(setup_settings_step(true, true, false, &down), Unverified);
        // A later init with nothing installed or updated leaves them alone.
        assert_eq!(setup_settings_step(false, true, false, &Exists), Leave);
        assert_eq!(setup_settings_step(false, true, false, &Absent), Leave);
    }

    #[test]
    fn only_a_definite_not_found_counts_as_no_account() {
        let found: Result<Vec<u8>, bloom_vfs::HandlerError> = Ok(Vec::new());
        assert_eq!(AccountPresence::from_read(&found), AccountPresence::Exists);
        let absent: Result<Vec<u8>, _> = Err(bloom_vfs::HandlerError::not_found("main"));
        assert_eq!(AccountPresence::from_read(&absent), AccountPresence::Absent);
        for error in [
            bloom_vfs::HandlerError::backend("SERVICE_UNAVAILABLE: Broker is unreachable"),
            bloom_vfs::HandlerError::PermissionDenied,
            bloom_vfs::HandlerError::invalid("stale projection"),
        ] {
            let read: Result<Vec<u8>, _> = Err(error);
            assert!(
                matches!(
                    AccountPresence::from_read(&read),
                    AccountPresence::Unknown(_)
                ),
                "{read:?}"
            );
        }
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
            ["enso", "feedback", "hyperliquid", "near-intents"]
        );
        assert_eq!(polymarket_limit(&petals), None);
        assert_eq!(tolly_writes(&petals), None);
    }

    #[test]
    fn scripted_setup_chooses_every_canonical_petal_and_keeps_existing_values() {
        let mut petals = PetalsConfig::default();
        accept_setup_suggestions(&mut petals);
        assert_eq!(
            chosen(&petals),
            [
                "enso",
                "feedback",
                "hyperliquid",
                "near-intents",
                "polymarket"
            ]
        );
        assert_eq!(polymarket_limit(&petals), Some("100"));
        assert_eq!(tolly_writes(&petals), None);

        let mut edited = PetalsConfig::default();
        edited.setup.insert(
            "polymarket".into(),
            PetalSetupConfig {
                values: BTreeMap::from([("max_daily_usd".into(), "5".into())]),
            },
        );
        accept_setup_suggestions(&mut edited);
        assert_eq!(polymarket_limit(&edited), Some("5"));
        assert_eq!(chosen(&edited), ["polymarket"]);

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
        assert!(!encoded.contains("tolly_writes"), "{encoded}");
        let decoded: bloom_proto::Config = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.petals.setup, config.petals.setup);
        assert_eq!(tolly_writes(&decoded.petals), None);
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
            "/petals/polymarket/settings/main/0/venue.toml"
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
        assert_eq!(
            serde_json::to_value(DefaultPolicyStatus::ChangedSinceCreation {
                missing: vec!["hyperliquid".into()]
            })
            .unwrap(),
            serde_json::json!({"state": "changed_since_creation", "missing": ["hyperliquid"]})
        );
    }

    #[test]
    fn the_owner_choice_flag_is_sent_only_when_set() {
        use bloom_daemon::ipc::MachineCommand;
        // Omitted when false, so a waiting command's request is unchanged and
        // an older Machine, which rejects unknown fields, still accepts it.
        let resume = MachineCommand::WalletDefaultPolicy {
            name: "main".into(),
            owner_just_chose: false,
        };
        assert_eq!(
            serde_json::to_value(&resume).unwrap(),
            serde_json::json!({"command": "wallet_default_policy", "name": "main"})
        );
        assert_eq!(
            serde_json::from_value::<MachineCommand>(
                serde_json::json!({"command": "wallet_default_policy", "name": "main"})
            )
            .unwrap(),
            resume
        );
        assert_eq!(
            serde_json::to_value(MachineCommand::WalletDefaultPolicy {
                name: "main".into(),
                owner_just_chose: true,
            })
            .unwrap(),
            serde_json::json!({
                "command": "wallet_default_policy",
                "name": "main",
                "owner_just_chose": true
            })
        );
    }

    #[test]
    fn a_changed_policy_reports_each_chosen_petal_it_does_not_fully_allow() {
        let package = |byte| bloom_broker_api::Digest32::from_bytes([byte; 32]);
        let petals = ["hyperliquid".to_owned(), "polymarket".to_owned()];
        let packages = [package(1), package(2)];
        let snapshot = |policy: &bloom_broker_api::CanonicalWalletPolicy| {
            let bytes = serde_jcs::to_vec(policy).unwrap();
            bloom_broker_api::SignedPolicySnapshot {
                wallet_id: bloom_broker_api::Token::new("main").unwrap(),
                version: bloom_broker_api::DecimalU64::new(3),
                canonical_policy: bloom_broker_api::Base64UrlBytes::from_bytes(&bytes),
                policy_digest: package(9),
                policy_signing_key_id: bloom_broker_api::Token::new("policy-key").unwrap(),
                policy_verifying_key: bloom_broker_api::Base64UrlBytes::from_bytes(&[2; 32]),
                signer_signature: bloom_broker_api::Base64UrlBytes::from_bytes(&[3; 64]),
            }
        };
        let mut policy = bloom_broker_api::CanonicalWalletPolicy {
            wallet_id: bloom_broker_api::Token::new("main").unwrap(),
            allowed_petal_packages: packages.to_vec(),
            allowed_destinations: policy_destinations("polymarket").unwrap(),
            maximum_approval_lifetime_ms: 60_000,
            required_verifiers: Vec::new(),
            clear_signing: None,
        };
        assert!(
            petals_not_allowed(&snapshot(&policy), &petals, &packages)
                .unwrap()
                .is_empty()
        );
        // The owner removed Hyperliquid, and one of Polymarket's destinations.
        policy.allowed_petal_packages.remove(0);
        policy.allowed_destinations.pop();
        assert_eq!(
            petals_not_allowed(&snapshot(&policy), &petals, &packages).unwrap(),
            petals
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
    fn wait_reports_a_policy_changed_since_creation_and_proposes_nothing() {
        let mut wait = DefaultPolicyWait::new("main", 1_000);
        let mut output = Vec::new();
        let changed = DefaultPolicyStatus::ChangedSinceCreation {
            missing: vec!["near-intents".into()],
        };
        assert_eq!(
            wait.observe(&changed, 10, &mut output).unwrap(),
            WaitStep::Stop
        );
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(
            "main's policy has changed since the wallet was created and does not allow NEAR Intents"
        ));
        assert!(output.contains("nothing was proposed"));
        assert!(output.contains("bloom wallet update-policy main --file"));
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
            reason: Some("SERVICE_UNAVAILABLE: Broker restarting".into()),
        };
        assert_eq!(
            wait.observe(&status, 10, &mut output).unwrap(),
            WaitStep::Stop
        );
        let output = String::from_utf8(output).unwrap();
        assert!(
            output.contains("stopped waiting for Broker (SERVICE_UNAVAILABLE: Broker restarting)"),
            "{output}"
        );
        assert!(
            output.contains("once Bloom can reach Broker again"),
            "{output}"
        );

        // A rate limit, such as another live ceremony, is not a read failure.
        let mut wait = DefaultPolicyWait::new("main", 0);
        let mut output = Vec::new();
        let status = DefaultPolicyStatus::WaitingForWallet {
            reason: Some("CEREMONY_RATE_LIMITED: wallet already has a live ceremony".into()),
        };
        wait.observe(&status, 10, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(
            output.contains("once Broker accepts the request again, for example after another ceremony for main finishes"),
            "{output}"
        );

        // A wallet that never appeared is not an outage.
        let mut wait = DefaultPolicyWait::new("main", 0);
        let mut output = Vec::new();
        let status = DefaultPolicyStatus::WaitingForWallet {
            reason: Some("wallet main not found".into()),
        };
        wait.observe(&status, 10, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(
            output.contains("(wallet main not found); once it exists"),
            "{output}"
        );
    }

    #[test]
    fn wait_says_once_why_it_keeps_polling_through_a_broker_refusal() {
        let mut wait = DefaultPolicyWait::new("main", 1_000);
        let mut output = Vec::new();
        let refused = |message: &str| DefaultPolicyStatus::WaitingForWallet {
            reason: Some(message.into()),
        };
        for (status, now) in [
            (refused("wallet main not found"), 10),
            (refused("CEREMONY_RATE_LIMITED: retry after 900 ms"), 20),
            (refused("CEREMONY_RATE_LIMITED: retry after 400 ms"), 30),
            (refused("SERVICE_UNAVAILABLE: Broker restarting"), 40),
        ] {
            assert_eq!(
                wait.observe(&status, now, &mut output).unwrap(),
                WaitStep::Poll
            );
        }
        let output = String::from_utf8(output).unwrap();
        assert_eq!(
            output.matches("default_policy: waiting for Broker").count(),
            1,
            "{output}"
        );
        assert!(
            output.contains("(CEREMONY_RATE_LIMITED: retry after 900 ms)"),
            "{output}"
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
    fn updated_petal_messages_describe_only_the_settings_written() {
        assert_eq!(
            settings_message("polymarket", "max_daily_usd = 100", true),
            "petal_settings: Polymarket was updated; set max_daily_usd = 100"
        );
        assert_eq!(
            settings_message("polymarket", "max_daily_usd = 100", false),
            "petal_settings: Polymarket set max_daily_usd = 100"
        );
    }
}
