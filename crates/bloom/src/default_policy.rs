//! Default wallet policy: the `bloom init` setup menu, the Petal settings it
//! chooses, and the one policy that allows the chosen Petals.
//!
//! Setup only proposes. The wallet policy still changes through the owner's
//! policy ceremony, and every transaction keeps its own approval. See
//! `docs/architecture/Default Wallet Policy.md`.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::ops::ControlFlow;

use anyhow::{Context, Result, anyhow, bail};
use bloom_daemon::Daemon;
use bloom_proto::config::{DEFAULT_POLICY_WALLET, PetalSetupConfig, WalletSetup};
use bloom_proto::persona::{PersonaConfig, PersonaPreset};
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

/// Save a proposal only. Existing homes keep their choice unless an explicit
/// selection is supplied, independently of the Petal setup-complete marker.
pub(crate) fn select_persona(
    saved: &mut Option<PersonaConfig>,
    preset: Option<PersonaPreset>,
) -> Result<()> {
    let Some(preset) = preset else {
        return Ok(());
    };
    let proposal = PersonaConfig::suggested(preset);
    proposal.validate().map_err(anyhow::Error::msg)?;
    *saved = Some(proposal);
    Ok(())
}

/// Ask which persona `main` uses. An empty answer, or the end of input,
/// keeps Institutional. `any_recipient_chains` names the configured chains
/// Degen would open to any recipient ([`any_recipient_chain_names`]).
pub(crate) fn run_persona_menu(
    saved: &mut Option<PersonaConfig>,
    any_recipient_chains: &[String],
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    writeln!(
        output,
        "Persona for main. Every transaction still needs your approval."
    )?;
    writeln!(
        output,
        "  institutional: {}",
        persona_behaviour(PersonaPreset::Custodian, any_recipient_chains)
    )?;
    writeln!(
        output,
        "  trader: {}",
        persona_behaviour(PersonaPreset::Trader, any_recipient_chains)
    )?;
    writeln!(
        output,
        "  degen: {}",
        persona_behaviour(PersonaPreset::Degen, any_recipient_chains)
    )?;
    loop {
        write!(
            output,
            "Choose institutional, trader or degen [institutional]: "
        )?;
        output.flush()?;
        let answer = read_answer(input)?.unwrap_or_default();
        let answer = if answer.is_empty() {
            "custodian"
        } else {
            &answer
        };
        match answer.parse::<PersonaPreset>() {
            Ok(preset) => {
                select_persona(saved, Some(preset))?;
                writeln!(
                    output,
                    "{}",
                    persona_message(saved.as_ref(), any_recipient_chains)
                )?;
                return Ok(());
            }
            Err(error) => writeln!(output, "{error}")?,
        }
    }
}

/// What a persona does: what setup suggests, and what it asks the wallet's
/// policy to allow. It describes the persona, not the wallet's current policy.
fn persona_behaviour(preset: PersonaPreset, any_recipient_chains: &[String]) -> String {
    match preset {
        PersonaPreset::Custodian => "suggests each Petal's usual limits".to_owned(),
        PersonaPreset::Trader => {
            format!("suggests larger Petal limits and lets {PERSONA_STANDING}")
        }
        PersonaPreset::Degen if any_recipient_chains.is_empty() => format!(
            "suggests the largest Petal limits and lets {PERSONA_STANDING}; it would allow curated ERC-20 transfers to any recipient on Ethereum or Polygon, but neither is configured"
        ),
        PersonaPreset::Degen => format!(
            "suggests the largest Petal limits, lets {PERSONA_STANDING}, and asks the wallet's policy to allow curated ERC-20 transfers to any recipient on {}",
            any_recipient_chains.join(" and ")
        ),
    }
}

/// The name an owner chooses a persona by.
fn persona_name(preset: PersonaPreset) -> &'static str {
    match preset {
        PersonaPreset::Custodian => "institutional",
        other => other.as_str(),
    }
}

/// What a wallet's persona means, shown after it is chosen and by
/// `bloom init`. A wallet without one behaves as Institutional.
pub(crate) fn persona_message(
    persona: Option<&PersonaConfig>,
    any_recipient_chains: &[String],
) -> String {
    let preset = persona.map_or(PersonaPreset::Custodian, |persona| persona.preset);
    format!(
        "persona: {}; {}; each transaction still needs your approval",
        persona_name(preset),
        persona_behaviour(preset, any_recipient_chains)
    )
}

/// What `bloom init --persona` says on a home whose setup already ran. A
/// switch is a fresh start for the wallet, which Machine makes while it runs
/// (decision 18), so `bloom init` changes nothing and names the command.
pub(crate) fn persona_switch_note(wallet: &str, requested: PersonaPreset) -> String {
    let name = persona_name(requested);
    format!(
        "persona_note: setup already ran, so nothing changed; to switch {wallet} to {name}, which starts {wallet}'s setup again, resets its Petal limits and replaces its policy in one ceremony, run `bloom wallet persona {wallet} {name}` while Bloom is running"
    )
}

/// Display names of the configured chains Degen would open to any recipient.
pub(crate) fn any_recipient_chain_names(
    chains: &BTreeMap<String, bloom_proto::ChainSpec>,
) -> Vec<String> {
    bloom_daemon::any_recipient_chains(chains)
        .into_iter()
        .map(|chain| {
            chain
                .display_name
                .clone()
                .unwrap_or_else(|| chain.name.clone())
        })
        .collect()
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
/// recorded in `setup`, which the default policy proposes. A value with no
/// saved answer is suggested from `persona` where it has one.
pub(crate) fn run_setup_menu(
    setup: &mut WalletSetup,
    persona: Option<&PersonaConfig>,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    run_wallet_setup_menu(DEFAULT_POLICY_WALLET, setup, persona, input, output)
}

/// [`run_setup_menu`] for `wallet`'s setup.
pub(crate) fn run_wallet_setup_menu(
    wallet: &str,
    setup: &mut WalletSetup,
    persona: Option<&PersonaConfig>,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    if wallet == DEFAULT_POLICY_WALLET {
        writeln!(
            output,
            "Choose the Petals your main wallet's policy allows. Each transaction still needs your approval."
        )?;
    } else {
        writeln!(
            output,
            "Choose the Petals wallet {wallet}'s policy allows. Each transaction still needs your approval."
        )?;
    }
    let earlier = std::mem::take(&mut setup.petals);
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
    let mut choices = BTreeMap::new();
    for name in &chosen {
        let mut values = BTreeMap::new();
        if let Some(template) = setup_template(name) {
            for value in template.values {
                let persona_suggestion = suggested_venue_limit(persona, name, value.name);
                let suggestion = earlier
                    .get(name)
                    .and_then(|choice| choice.values.get(value.name))
                    .map(String::as_str)
                    .filter(|saved| is_setup_amount(saved))
                    .unwrap_or(persona_suggestion.as_deref().unwrap_or(value.default));
                let answer = ask_amount(input, output, value.prompt, suggestion)?;
                values.insert(value.name.to_owned(), answer);
            }
        }
        choices.insert(name.clone(), PetalSetupConfig { values });
    }
    setup.petals = choices;
    Ok(())
}

/// The non-interactive form of the setup menu: accept every suggestion. With
/// no earlier choices that records every canonical Petal with the catalog's
/// values; earlier choices are kept as they are, so a declined Petal stays
/// declined and a saved value stays saved.
pub(crate) fn accept_setup_suggestions(setup: &mut WalletSetup, persona: Option<&PersonaConfig>) {
    if !setup.petals.is_empty() {
        return;
    }
    for name in menu_petals() {
        let values = setup_template(&name)
            .map(|template| {
                template
                    .values
                    .iter()
                    .map(|value| {
                        (
                            value.name.to_owned(),
                            suggested_venue_limit(persona, &name, value.name)
                                .unwrap_or_else(|| value.default.to_owned()),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        setup
            .petals
            .entry(name.clone())
            .or_insert(PetalSetupConfig { values });
    }
}

/// The persona's suggestion for a Petal setting, where it has one. Only
/// Polymarket's daily buy limit is suggested: Trader's and Degen's pUSD
/// token quantities, never a price.
fn suggested_venue_limit(
    persona: Option<&PersonaConfig>,
    petal: &str,
    value: &str,
) -> Option<String> {
    if petal != "polymarket" || value != "max_daily_usd" {
        return None;
    }
    // This existing venue setting is a pUSD order-cost ceiling despite its
    // historic name. Seed fresh settings from the token quantity, never a
    // price. Saved owner settings are still preserved by the setup merge.
    let profile = persona?;
    profile
        .token_amounts("pUSD")
        .map(|(_, total)| total.to_owned())
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
    setup: &WalletSetup,
    name: &str,
    wallet: &str,
) -> Result<Option<PetalSettingsWrite>> {
    let Some(template) = setup_template(name) else {
        return Ok(None);
    };
    let saved = setup.petals.get(name);
    let mut body = template.body.to_owned();
    let mut summary = Vec::new();
    for value in template.values {
        let chosen = saved
            .and_then(|setup| setup.values.get(value.name))
            .map(String::as_str)
            .unwrap_or(value.default);
        if !is_setup_amount(chosen) {
            bail!(
                "[setup.wallets.{wallet}.petals.{name}.values] {} = {chosen:?} is not a positive amount",
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

/// What a setup settings write did.
#[derive(Debug)]
pub(crate) enum SetupWrite {
    /// The Petal has no setup settings.
    NoTemplate,
    /// Setup's values went in; carries the chosen values, for messages.
    Written(String),
    /// Setup left the route as it is, for the reason given.
    Kept(PetalSettingsWrite, String),
    /// The installed release is an earlier one the catalog release updates
    /// from, which keeps these settings elsewhere: the write waits for that
    /// update rather than being dropped. Carries why, for messages.
    Waiting(PetalSettingsWrite, String),
    /// Setup's values went in, but the Petal stored nothing under the key
    /// setup checks, so that check protects nothing; carries the key.
    Unprotected(PetalSettingsWrite, String),
}

/// Write a Petal's setup settings through its own settings route, but only
/// while the Petal stores nothing for them. Settings can be there before
/// setup writes, even for a Petal that was just installed: an uninstall
/// keeps a Petal's private data, so reinstalling the same release finds the
/// owner's settings again. Whether anything is stored decides, not what the
/// route reads, since the route reads the same default when nothing is
/// stored as when the owner saved exactly that. The check and the write are
/// one step ([`bloom_vfs::Vfs::write_if_absent`]), so an owner's edit made
/// meanwhile is never replaced either.
///
/// The key is the one the template's releases store these settings under, so
/// setup writes only to one of them (`installed` is the Petal's package
/// hash): another release under the same name may store them elsewhere, where
/// the check could not see them. An earlier release on the list is written to
/// as well, so a home still updating to the catalog release keeps setup's
/// choice; the signed package lineage carries it forward. An older release the
/// catalog release updates from, but whose settings live elsewhere, gets
/// nothing yet: the write waits until Bloom installs the update. After a
/// write, the key must be stored; if it is not, the pinned key is wrong and
/// setup says so, since it protects nothing.
pub(crate) async fn write_petal_settings(
    vfs: &bloom_vfs::Vfs,
    setup: &WalletSetup,
    name: &str,
    installed: &str,
) -> Result<SetupWrite> {
    let Some(template) = setup_template(name) else {
        return Ok(SetupWrite::NoTemplate);
    };
    let Some(settings) = render_petal_settings(setup, name, DEFAULT_POLICY_WALLET)? else {
        return Ok(SetupWrite::NoTemplate);
    };
    if !template.releases.contains(&installed) {
        if let Some(entry) = crate::github_source::preinstalled_petal(name)
            && entry.predecessor_package_hashes.contains(&installed)
        {
            let reason = format!(
                "the installed {} is an earlier release that keeps these settings elsewhere, so setup writes them once Bloom updates it to {}",
                petal_label(name),
                entry.release_tag
            );
            return Ok(SetupWrite::Waiting(settings, reason));
        }
        let reason = format!(
            "the installed {} is not the release setup knows, so it did not risk replacing settings stored where it cannot check",
            petal_label(name)
        );
        return Ok(SetupWrite::Kept(settings, reason));
    }
    let path = bloom_vfs::VfsPath::parse(&settings.path)?;
    let key = template
        .store_key
        .replace("{wallet}", DEFAULT_POLICY_WALLET);
    let write = || async {
        vfs.write_if_absent(&path, &key, &settings.body)
            .await
            .with_context(|| format!("write {} settings to {}", petal_label(name), settings.path))
    };
    if !write().await? {
        return Ok(SetupWrite::Kept(
            settings,
            SETTINGS_ALREADY_THERE.to_owned(),
        ));
    }
    // Setup's settings are stored under `key` now, so asking again must
    // decline. Writing again, with the same settings, means `key` is not
    // where this release stores them. The settings went in either way, so a
    // check that cannot run is only logged.
    Ok(match write().await {
        Ok(true) => SetupWrite::Unprotected(settings, key),
        Ok(false) => SetupWrite::Written(settings.summary),
        Err(error) => {
            tracing::warn!(
                petal = %name,
                error = %format!("{error:#}"),
                "petal.setup_settings_key_unchecked"
            );
            SetupWrite::Written(settings.summary)
        }
    })
}

/// Setup wrote a Petal's settings, but the key it checks before writing is
/// not where the Petal stored them.
fn settings_unprotected(name: &str, settings: &PetalSettingsWrite, key: &str) -> String {
    format!(
        "petal_settings_unprotected: {} set {}, but stored nothing under {key}, the key Bloom checks before setup writes, so later setup writes could replace settings saved since. Report this as a Bloom bug.",
        petal_label(name),
        settings.summary
    )
}

/// Why setup left settings it found in place.
const SETTINGS_ALREADY_THERE: &str = "settings were already there, so they stay as they are";

/// Setup settings that could not be written yet, one marker file per Petal.
/// The settings route needs the wallet's account to exist, which on a first
/// run is created after `bloom init`. A marker survives restarts so the write
/// is retried once the account is there, without re-applying settings the
/// owner has since edited.
fn pending_settings_dir(home: &std::path::Path) -> std::path::PathBuf {
    home.join("pending-petal-settings")
}

/// Queue a retry of `name`'s setup write. A failure is returned, so no caller
/// promises a retry that was never recorded.
fn mark_settings_pending(home: &std::path::Path, name: &str) -> std::io::Result<()> {
    if setup_template(name).is_none() {
        return Ok(());
    }
    let dir = pending_settings_dir(home);
    std::fs::create_dir_all(&dir).and_then(|()| std::fs::write(dir.join(name), b""))
}

/// What to tell the owner when a setup write failed and its retry could not
/// be queued either: the command that applies setup's choice by hand.
fn retry_not_recorded(
    setup: &WalletSetup,
    name: &str,
    error: &anyhow::Error,
    marker_error: &std::io::Error,
) -> String {
    let reason = format!(
        "writing them failed ({error:#}) and the automatic retry could not be recorded ({marker_error})"
    );
    match render_petal_settings(setup, name, DEFAULT_POLICY_WALLET) {
        Ok(Some(settings)) => settings_not_written(name, &settings, &reason),
        _ => format!(
            "petal_settings_failed: {} settings were not written: {reason}",
            petal_label(name)
        ),
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
    let setup = daemon.config.setup.main();
    let account = if setup
        .petals
        .keys()
        .any(|name| setup_template(name).is_some() && owners_before.contains_key(name))
    {
        Some(default_account_presence(&daemon.vfs).await)
    } else {
        None
    };
    let dir = pending_settings_dir(daemon.home.root());
    for (name, queue) in setup_settings_to_queue(setup, owners_before, account.as_ref()) {
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
    setup: &WalletSetup,
    owners_before: &BTreeMap<String, String>,
    account: Option<&AccountPresence>,
) -> Vec<(String, bool)> {
    setup
        .petals
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
fn pending_settings(home: &std::path::Path, setup: &WalletSetup) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(pending_settings_dir(home)) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| setup_template(name).is_some() && setup.petals.contains_key(name))
        .collect();
    names.sort();
    names
}

/// Write the settings that an earlier attempt could not, now that the default
/// wallet exists. The write goes ahead only while the Petal stores nothing
/// for its settings, and that check and the write are one step no other write
/// through Machine can land between. Anything stored may be the owner's, even
/// if it reads like the default, so it stays and the marker is cleared. A
/// write that cannot be made yet, as before the account exists, keeps its
/// marker for next time.
pub(crate) async fn apply_pending_settings(
    daemon: &Daemon,
    setup: &WalletSetup,
) -> PendingSettings {
    let owners = petal_owners(daemon).unwrap_or_default();
    apply_queued_writes(&daemon.vfs, daemon.home.root(), setup, &owners).await
}

/// What retrying the queued setup writes did.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PendingSettings {
    /// A message for each write that went in.
    pub(crate) written: Vec<String>,
    /// Each write that failed and stays queued: the Petal and why.
    pub(crate) still_queued: Vec<String>,
    /// Each write that waits for its Petal's update: the Petal and why.
    pub(crate) waiting: Vec<String>,
}

/// Retry every queued setup write for an installed Petal.
async fn apply_queued_writes(
    vfs: &bloom_vfs::Vfs,
    home: &std::path::Path,
    setup: &WalletSetup,
    owners: &BTreeMap<String, String>,
) -> PendingSettings {
    let mut outcome = PendingSettings::default();
    for name in pending_settings(home, setup) {
        let Some(installed) = owners.get(&name) else {
            continue;
        };
        match apply_queued_settings(vfs, home, setup, &name, installed).await {
            QueuedWrite::Written(message) => outcome.written.push(message),
            QueuedWrite::Settled => {}
            QueuedWrite::Failed(error) => outcome
                .still_queued
                .push(format!("{} ({error})", petal_label(&name))),
            QueuedWrite::Waiting(reason) => outcome
                .waiting
                .push(format!("{} ({reason})", petal_label(&name))),
        }
    }
    outcome
}

/// How often `bloom serve` checks for queued setup writes it can make, and
/// the longest it waits between checks while a write keeps failing.
const QUEUED_SETTINGS_RETRY: std::time::Duration = std::time::Duration::from_secs(30);
const QUEUED_SETTINGS_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(600);

/// Make queued setup writes while `bloom serve` runs, so a `main` created any
/// way, including by an agent writing `wallets/new`, gets setup's settings
/// without `bloom wallet default-policy`. With nothing queued a check is one
/// directory read. Broker is asked about `main` only while a write is queued,
/// and checks slow down while a write keeps failing.
pub(crate) async fn retry_queued_settings(daemon: Daemon) {
    let mut wait = QUEUED_SETTINGS_RETRY;
    loop {
        tokio::time::sleep(wait).await;
        let queued = std::fs::read_dir(pending_settings_dir(daemon.home.root()))
            .is_ok_and(|mut entries| entries.next().is_some());
        if !queued {
            wait = QUEUED_SETTINGS_RETRY;
            continue;
        }
        // Read `main`'s setup now, not the copy Machine loaded at startup: a
        // persona switch may have saved it since.
        let setup = match bloom_proto::Config::load(&daemon.home.config_path()) {
            Ok(config) => config.setup.main().clone(),
            Err(error) => {
                tracing::warn!(error = %error, "petal.setup_settings_config_unreadable");
                wait = (wait * 2).min(QUEUED_SETTINGS_RETRY_MAX);
                continue;
            }
        };
        if pending_settings(daemon.home.root(), &setup).is_empty() {
            wait = QUEUED_SETTINGS_RETRY;
            continue;
        }
        let owners = petal_owners(&daemon).unwrap_or_default();
        let outcome =
            retry_queued_settings_once(&daemon.vfs, daemon.home.root(), &setup, &owners).await;
        wait = match &outcome {
            Some(outcome) if !outcome.still_queued.is_empty() || !outcome.waiting.is_empty() => {
                (wait * 2).min(QUEUED_SETTINGS_RETRY_MAX)
            }
            _ => QUEUED_SETTINGS_RETRY,
        };
        for message in outcome.into_iter().flat_map(|outcome| outcome.written) {
            tracing::info!(%message, "petal.setup_settings_written");
        }
    }
}

/// One check: once `main`'s account exists, make the queued writes for
/// installed Petals. `None` when nothing was tried.
async fn retry_queued_settings_once(
    vfs: &bloom_vfs::Vfs,
    home: &std::path::Path,
    setup: &WalletSetup,
    owners: &BTreeMap<String, String>,
) -> Option<PendingSettings> {
    if !pending_settings(home, setup)
        .iter()
        .any(|name| owners.contains_key(name))
        || default_account_presence(vfs).await != AccountPresence::Exists
    {
        return None;
    }
    Some(apply_queued_writes(vfs, home, setup, owners).await)
}

/// What one queued setup write did.
#[derive(Debug, PartialEq, Eq)]
enum QueuedWrite {
    /// Setup's settings went in; the message for the owner.
    Written(String),
    /// Nothing is left to do: the route already held other settings, which
    /// stay, or the Petal has no setup settings.
    Settled,
    /// The check or the write failed, so the write stays queued; why.
    Failed(String),
    /// The installed release cannot take the write yet, so it stays queued
    /// for the update; why.
    Waiting(String),
}

/// Make `name`'s queued setup write through `vfs`. The marker under `home` is
/// cleared once the route has been checked, whether or not setup's settings
/// went in, and kept when the check or the write failed or the installed
/// release must be updated first.
async fn apply_queued_settings(
    vfs: &bloom_vfs::Vfs,
    home: &std::path::Path,
    setup: &WalletSetup,
    name: &str,
    installed: &str,
) -> QueuedWrite {
    match write_petal_settings(vfs, setup, name, installed).await {
        Ok(SetupWrite::NoTemplate) => QueuedWrite::Settled,
        Ok(SetupWrite::Written(summary)) => {
            clear_settings_pending(home, name);
            QueuedWrite::Written(settings_message(name, &summary, false))
        }
        Ok(SetupWrite::Kept(settings, reason)) => {
            clear_settings_pending(home, name);
            tracing::info!(
                petal = %name,
                message = %settings_not_written(name, &settings, &reason),
                "petal.setup_settings_preserved"
            );
            QueuedWrite::Settled
        }
        Ok(SetupWrite::Unprotected(settings, key)) => {
            clear_settings_pending(home, name);
            let message = settings_unprotected(name, &settings, &key);
            tracing::error!(petal = %name, %message, "petal.setup_settings_key_not_stored");
            QueuedWrite::Written(message)
        }
        Ok(SetupWrite::Waiting(_, reason)) => {
            tracing::info!(petal = %name, %reason, "petal.setup_settings_waiting");
            QueuedWrite::Waiting(reason)
        }
        Err(error) => {
            let error = format!("{error:#}");
            tracing::warn!(petal = %name, %error, "petal.setup_settings_retry_failed");
            QueuedWrite::Failed(error)
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
/// Petal without its settings fails closed: Polymarket refuses buys until the
/// owner writes them.
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
    for name in daemon.config.setup.main().petals.keys() {
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
                daemon.config.setup.main(),
                name,
                installed,
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
#[allow(clippy::too_many_arguments)]
async fn settle_setup_settings(
    vfs: &bloom_vfs::Vfs,
    home: &std::path::Path,
    setup: &WalletSetup,
    name: &str,
    installed: &str,
    step: SetupSettingsStep,
    updated: bool,
    account: &AccountPresence,
) -> Option<String> {
    let reason = match step {
        SetupSettingsStep::Leave => {
            return finish_interrupted_setup(vfs, home, setup, name, installed, account).await;
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
        // A write an earlier setup queued is setup's own choice, and it goes
        // in only while nothing is stored, so it is made or kept as on
        // `bloom serve`'s update. Only a write this run would add is declined.
        if pending_settings(home, setup)
            .iter()
            .any(|pending| pending == name)
        {
            return finish_interrupted_setup(vfs, home, setup, name, installed, account).await;
        }
        return match render_petal_settings(setup, name, DEFAULT_POLICY_WALLET) {
            Ok(Some(settings)) => Some(settings_not_written(name, &settings, &reason)),
            Ok(None) => None,
            Err(error) => Some(format!("petal_settings_failed: {error:#}")),
        };
    }
    match write_petal_settings(vfs, setup, name, installed).await {
        Ok(SetupWrite::Written(summary)) => {
            clear_settings_pending(home, name);
            Some(settings_message(name, &summary, updated))
        }
        Ok(SetupWrite::Kept(settings, reason)) => {
            clear_settings_pending(home, name);
            Some(settings_not_written(name, &settings, &reason))
        }
        Ok(SetupWrite::Unprotected(settings, key)) => {
            clear_settings_pending(home, name);
            Some(settings_unprotected(name, &settings, &key))
        }
        Ok(SetupWrite::Waiting(settings, reason)) => {
            Some(match mark_settings_pending(home, name) {
                Ok(()) => settings_waiting(name, &reason),
                Err(marker_error) => settings_not_written(
                    name,
                    &settings,
                    &format!("{reason}, and the write could not be queued ({marker_error})"),
                ),
            })
        }
        Ok(SetupWrite::NoTemplate) => None,
        Err(error) => Some(match mark_settings_pending(home, name) {
            // Wallet creation makes the queued write once `main` exists.
            Ok(()) if *account == AccountPresence::Absent => format!(
                "petal_settings_failed: {error:#} (will retry once wallet {DEFAULT_POLICY_WALLET} exists)"
            ),
            // `main` exists, or may: no wallet creation follows to make it.
            Ok(()) => format!(
                "petal_settings_failed: {error:#}. The write is queued. To write them, run: bloom wallet default-policy {DEFAULT_POLICY_WALLET}"
            ),
            Err(marker_error) => retry_not_recorded(setup, name, &error, &marker_error),
        }),
    }
}

/// A setup write that waits for its Petal's update, and what makes it.
fn settings_waiting(name: &str, reason: &str) -> String {
    format!(
        "petal_settings_waiting: {} settings chosen during setup are queued: {reason}. {UPDATE_RETRIED}",
        petal_label(name)
    )
}

/// What updates a catalog Petal, and with it makes a write that waits for it.
const UPDATE_RETRIED: &str =
    "Bloom tries the update each time `bloom serve` starts or `bloom init` runs";

/// Make the write an earlier `bloom init` queued for a Petal this run leaves
/// alone, once `main`'s account exists. That run stopped after installing
/// the Petal and before writing its settings, so the Petal now looks
/// unchanged and nothing else would write them on a home whose `main`
/// already exists: wallet creation, which otherwise applies queued writes,
/// has already happened. As there, the write goes in only while nothing is
/// stored. Before `main` exists the marker stays for wallet creation.
/// A write still queued after this run, because Broker could not say
/// whether `main` exists or the write failed, is reported with the command
/// that makes it, since nothing on such a home would make it on its own.
async fn finish_interrupted_setup(
    vfs: &bloom_vfs::Vfs,
    home: &std::path::Path,
    setup: &WalletSetup,
    name: &str,
    installed: &str,
    account: &AccountPresence,
) -> Option<String> {
    let queued = |home| {
        pending_settings(home, setup)
            .iter()
            .any(|pending| pending == name)
    };
    if !queued(home) {
        return None;
    }
    let why = match account {
        AccountPresence::Absent => return None,
        AccountPresence::Exists => {
            match apply_queued_settings(vfs, home, setup, name, installed).await {
                QueuedWrite::Written(message) => return Some(message),
                QueuedWrite::Settled => return None,
                QueuedWrite::Failed(error) => format!("writing them did not complete ({error})"),
                QueuedWrite::Waiting(reason) => {
                    return queued(home).then(|| settings_waiting(name, &reason));
                }
            }
        }
        AccountPresence::Unknown(error) => {
            format!("Bloom could not check whether wallet {DEFAULT_POLICY_WALLET} exists ({error})")
        }
    };
    queued(home).then(|| {
        format!(
            "petal_settings_pending: {} settings chosen during setup are still queued: {why}. To write them, run: bloom wallet default-policy {DEFAULT_POLICY_WALLET}",
            petal_label(name)
        )
    })
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
    account_presence(vfs, DEFAULT_POLICY_WALLET).await
}

/// Whether `wallet`'s account 0 exists.
async fn account_presence(vfs: &bloom_vfs::Vfs, wallet: &str) -> AccountPresence {
    let path = format!("/wallets/{wallet}/0/account.json");
    match bloom_vfs::VfsPath::parse(&path) {
        Ok(path) => AccountPresence::from_read(&bloom_vfs::Handler::read(vfs, &path).await),
        Err(error) => AccountPresence::Unknown(format!("{error:#}")),
    }
}

/// After `bloom serve` provisions catalog Petals, write setup settings for each
/// chosen Petal it installed. Updates preserve carried owner settings, and
/// make a write setup queued earlier, which goes in only while nothing is
/// stored. Runs on a blocking provisioning thread.
pub(crate) fn apply_provisioned_settings(
    daemon: &Daemon,
    results: &[crate::petal_provisioning::ProvisioningResult],
) {
    use crate::petal_provisioning::ProvisioningOutcome;

    let runtime = tokio::runtime::Handle::current();
    // Read `main`'s setup now, not the copy Machine loaded at startup: an
    // approved persona switch may have saved it since.
    let config = bloom_proto::Config::load(&daemon.home.config_path()).unwrap_or_else(|error| {
        tracing::warn!(error = %error, "petal.setup_settings_config_unreadable");
        daemon.config.clone()
    });
    let setup = config.setup.main();
    for result in results {
        if !setup.petals.contains_key(&result.name) {
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
                let installed = petal_owners(daemon)
                    .ok()
                    .and_then(|owners| owners.get(&result.name).cloned());
                match runtime.block_on(queued_write_after_update(
                    &daemon.vfs,
                    daemon.home.root(),
                    setup,
                    &result.name,
                    installed.as_deref(),
                    &account,
                )) {
                    None => tracing::info!(
                        petal = %result.name,
                        "petal.setup_settings_preserved"
                    ),
                    Some(QueuedWrite::Written(message)) => tracing::info!(
                        petal = %result.name,
                        %message,
                        "petal.setup_settings_written"
                    ),
                    Some(QueuedWrite::Settled) => {}
                    Some(QueuedWrite::Failed(error) | QueuedWrite::Waiting(error)) => {
                        tracing::warn!(petal = %result.name, %error, "petal.setup_settings_still_queued")
                    }
                }
                continue;
            }
        }
        let installed = petal_owners(daemon).and_then(|owners| {
            owners
                .get(&result.name)
                .cloned()
                .with_context(|| format!("{} has no install record", petal_label(&result.name)))
        });
        let write = match installed {
            Ok(installed) => runtime.block_on(write_petal_settings(
                &daemon.vfs,
                setup,
                &result.name,
                &installed,
            )),
            Err(error) => Err(error),
        };
        match write {
            Ok(SetupWrite::Written(summary)) => {
                clear_settings_pending(daemon.home.root(), &result.name);
                tracing::info!(
                    petal = %result.name,
                    updated,
                    message = %settings_message(&result.name, &summary, updated),
                    "petal.setup_settings_written"
                );
            }
            Ok(SetupWrite::Kept(settings, reason)) => {
                clear_settings_pending(daemon.home.root(), &result.name);
                tracing::info!(
                    petal = %result.name,
                    message = %settings_not_written(&result.name, &settings, &reason),
                    "petal.setup_settings_preserved"
                );
            }
            Ok(SetupWrite::Unprotected(settings, key)) => {
                clear_settings_pending(daemon.home.root(), &result.name);
                tracing::error!(
                    petal = %result.name,
                    message = %settings_unprotected(&result.name, &settings, &key),
                    "petal.setup_settings_key_not_stored"
                );
            }
            Ok(SetupWrite::Waiting(settings, reason)) => {
                match mark_settings_pending(daemon.home.root(), &result.name) {
                    Ok(()) => {
                        tracing::info!(petal = %result.name, %reason, "petal.setup_settings_waiting")
                    }
                    Err(marker_error) => tracing::warn!(
                        petal = %result.name,
                        message = %settings_not_written(
                            &result.name,
                            &settings,
                            &format!("{reason}, and the write could not be queued ({marker_error})")
                        ),
                        "petal.setup_settings_failed_unqueued"
                    ),
                }
            }
            Ok(SetupWrite::NoTemplate) => {}
            Err(error) => match mark_settings_pending(daemon.home.root(), &result.name) {
                Ok(()) => tracing::warn!(
                    petal = %result.name,
                    error = %format!("{error:#}"),
                    "petal.setup_settings_failed"
                ),
                Err(marker_error) => tracing::warn!(
                    petal = %result.name,
                    message = %retry_not_recorded(
                        setup,
                        &result.name,
                        &error,
                        &marker_error
                    ),
                    "petal.setup_settings_failed_unqueued"
                ),
            },
        }
    }
}

/// After `bloom serve` updated a chosen Petal on a home where setup leaves
/// carried settings alone, make the write an earlier setup queued for it. That
/// write goes in only while nothing is stored, so the owner's settings are
/// safe from it; dropping it instead would lose setup's choice, as when it
/// waited for this very update. It stays queued while `main` cannot be
/// checked. `None` when nothing is queued.
async fn queued_write_after_update(
    vfs: &bloom_vfs::Vfs,
    home: &std::path::Path,
    setup: &WalletSetup,
    name: &str,
    installed: Option<&str>,
    account: &AccountPresence,
) -> Option<QueuedWrite> {
    if !pending_settings(home, setup)
        .iter()
        .any(|pending| pending == name)
    {
        return None;
    }
    Some(match (account, installed) {
        (AccountPresence::Exists, Some(installed)) => {
            apply_queued_settings(vfs, home, setup, name, installed).await
        }
        (AccountPresence::Exists, None) => {
            QueuedWrite::Failed(format!("{} has no install record", petal_label(name)))
        }
        (AccountPresence::Unknown(error), _) => QueuedWrite::Failed(format!(
            "Bloom could not check whether wallet {DEFAULT_POLICY_WALLET} exists ({error})"
        )),
        (AccountPresence::Absent, _) => {
            QueuedWrite::Failed(format!("wallet {DEFAULT_POLICY_WALLET} does not exist yet"))
        }
    })
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

/// How the owner changes a wallet's policy by hand. `update-policy` only
/// prepares the change and prints its ceremony; nothing changes until the
/// owner approves it there and commits it.
fn policy_update_steps(wallet: &str, file: &str) -> String {
    format!(
        "run `bloom wallet update-policy {wallet} --file {file}`, approve the change at the ceremony_url it prints, then run `bloom wallet commit-policy <operation_id>` with the operation_id it printed"
    )
}

/// Say what the policy still allows beyond the saved persona, and how to
/// remove it. Bloom never removes an entry itself.
fn report_beyond_persona(
    output: &mut dyn Write,
    wallet: &str,
    beyond_persona: &[String],
) -> Result<()> {
    if !beyond_persona.is_empty() {
        writeln!(
            output,
            "default_policy: {wallet}'s policy still allows {}, which the saved persona does not propose; Bloom never removes an entry. To remove it, save `bloom vfs cat /wallets/{wallet}/policy.json` to a file, delete its \"{}\" entries from allowed_destinations, and {}",
            beyond_persona.join(", "),
            bloom_proto::policy::ERC20_ANY_RECIPIENT,
            policy_update_steps(wallet, "<that file>")
        )?;
    }
    Ok(())
}

/// Say which setup writes are still queued and how to retry them, since the
/// command stops once the policy is settled.
fn report_settings_pending(
    output: &mut dyn Write,
    wallet: &str,
    settings_pending: &[String],
) -> Result<()> {
    if !settings_pending.is_empty() {
        writeln!(
            output,
            "petal_settings_pending: settings chosen during setup are still queued for {}. To write them, run: bloom wallet default-policy {wallet}",
            settings_pending.join("; ")
        )?;
    }
    Ok(())
}

/// Say which setup writes wait for their Petal's update, and what makes it.
/// Rerunning this command cannot: it does not update Petals.
fn report_settings_waiting(output: &mut dyn Write, settings_waiting: &[String]) -> Result<()> {
    if !settings_waiting.is_empty() {
        writeln!(
            output,
            "petal_settings_waiting: settings chosen during setup are queued for {}. {UPDATE_RETRIED}",
            settings_waiting.join("; ")
        )?;
    }
    Ok(())
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
    Applied {
        petals: Vec<String>,
        /// Setup writes that failed this time and stay queued.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        settings_pending: Vec<String>,
        /// Setup writes that wait for their Petal's update.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        settings_waiting: Vec<String>,
        /// The limits an approved persona switch reset, one message each.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        settings_reset: Vec<String>,
        /// What the policy still allows that the saved persona does not
        /// propose, such as Degen's transfers after the owner chose another
        /// persona. Bloom never removes it; the owner can.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        beyond_persona: Vec<String>,
    },
    /// The policy has changed since the wallet was created and does not allow
    /// `missing`. Only a new wallet's policy is proposed, so nothing is.
    ChangedSinceCreation {
        missing: Vec<String>,
        /// Setup writes that failed this time and stay queued.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        settings_pending: Vec<String>,
        /// As for `Applied`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        settings_waiting: Vec<String>,
        /// As for `Applied`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        beyond_persona: Vec<String>,
    },
    /// Another command holds the wallet's policy lock; ask again shortly.
    Busy,
    /// A persona switch to `persona` ended without the owner's approval: its
    /// ceremony was refused, expired, or replaced by a later switch. Nothing
    /// of it was applied.
    SwitchEnded { persona: String },
}

/// What a default-policy request does with the wallet's setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DefaultPolicyMode {
    /// Propose it only while the policy is the one wallet creation installed;
    /// afterwards report what the policy lacks.
    Resume,
    /// Propose it whatever the policy's version: the owner has just chosen it.
    OwnerJustChose,
}

impl DefaultPolicyMode {
    /// The mode a `WalletDefaultPolicy` Machine command asks for.
    pub(crate) fn of_command(owner_just_chose: bool) -> Self {
        if owner_just_chose {
            Self::OwnerJustChose
        } else {
            Self::Resume
        }
    }
}

/// A persona switch waiting for the owner to approve its policy
/// (decision 18): the wallet's new setup, and the policy operation that
/// proposes it once Machine has proposed it. None of it applies until that
/// policy commits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingSwitch {
    setup: WalletSetup,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation_id: Option<String>,
}

fn pending_switch_path(home: &std::path::Path, wallet: &str) -> std::path::PathBuf {
    home.join("pending-persona").join(format!("{wallet}.toml"))
}

fn read_pending_switch(home: &std::path::Path, wallet: &str) -> Result<Option<PendingSwitch>> {
    let path = pending_switch_path(home, wallet);
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(Some(toml::from_str(&text).with_context(|| {
            format!(
                "read {wallet}'s waiting persona switch at {}",
                path.display()
            )
        })?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "read {wallet}'s waiting persona switch at {}",
                path.display()
            )
        }),
    }
}

/// Save `switch` whole: a sibling file renamed over the old one.
fn write_pending_switch(
    home: &std::path::Path,
    wallet: &str,
    switch: &PendingSwitch,
) -> Result<()> {
    let path = pending_switch_path(home, wallet);
    let dir = path.parent().context("pending persona directory")?;
    std::fs::create_dir_all(dir).context("create the pending persona directory")?;
    let temporary = dir.join(format!(".{wallet}.{}.tmp", std::process::id()));
    std::fs::write(&temporary, toml::to_string(switch)?)
        .and_then(|()| std::fs::rename(&temporary, &path))
        .with_context(|| format!("save {wallet}'s waiting persona switch"))
}

fn remove_pending_switch(home: &std::path::Path, wallet: &str) -> Result<()> {
    match std::fs::remove_file(pending_switch_path(home, wallet)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(error).with_context(|| format!("clear {wallet}'s persona switch"))
        }
        _ => Ok(()),
    }
}

/// Serialises Machine's own config writes, each a load, change and save.
static CONFIG_WRITE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Save `setup` as `wallet`'s in the config at `path`, leaving the rest of
/// the file as it is.
fn save_wallet_setup(path: &std::path::Path, wallet: &str, setup: &WalletSetup) -> Result<()> {
    let _held = CONFIG_WRITE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut config = bloom_proto::Config::load(path).context("read Bloom's config")?;
    *config.setup.wallet_mut(wallet) = setup.clone();
    config.validate().map_err(anyhow::Error::msg)?;
    config
        .save(path)
        .with_context(|| format!("save {wallet}'s new setup"))
}

/// What a request asks of `wallet`'s policy, from `setup`: each chosen,
/// installed Petal's package and destinations, and the persona's entries and
/// lifetime.
fn default_policy_request(
    daemon: &Daemon,
    chains: &BTreeMap<String, bloom_proto::ChainSpec>,
    setup: &WalletSetup,
) -> Result<DefaultPolicyRequest> {
    let mut request = DefaultPolicyRequest {
        persona_applies: *setup != WalletSetup::default(),
        persona_destinations: bloom_daemon::setup_policy_destinations(chains, setup),
        lifetime: bloom_daemon::persona_policy_lifetime(setup),
        ..DefaultPolicyRequest::default()
    };
    for name in setup.petals.keys() {
        let Some(hash) = daemon
            .petals
            .store()
            .resolve_petal_owner(name)
            .with_context(|| format!("resolve installed Petal {name}"))?
        else {
            continue;
        };
        request.packages.push(
            bloom_broker_api::Digest32::new(hash)
                .with_context(|| format!("installed Petal {name} has an invalid package hash"))?,
        );
        request
            .petal_destinations
            .extend(policy_destinations(name)?);
        request.petals.push(name.clone());
    }
    Ok(request)
}

/// Propose `wallet`'s setup through its existing policy operation, committing
/// a completed ceremony, and report the result. The setup is read from the
/// config on disk, not the copy Machine loaded at startup. A persona switch
/// waiting for the owner takes precedence (decision 18): its replacement is
/// resumed, applied once its policy commits, and reported as ended if the
/// owner refused it or it expired. `mode` says what to do once the policy has
/// changed since creation.
pub(crate) async fn advance_default_policy(
    daemon: &Daemon,
    wallet: &str,
    mode: DefaultPolicyMode,
) -> Result<DefaultPolicyStatus> {
    let config = bloom_proto::Config::load(&daemon.home.config_path())
        .with_context(|| format!("read {wallet}'s setup"))?;
    let switch = read_pending_switch(daemon.home.root(), wallet)?;
    let setup = switch
        .as_ref()
        .map_or_else(|| config.setup.wallet(wallet), |switch| &switch.setup);
    let request = default_policy_request(daemon, &config.chains, setup)?;
    // A switch to a setup that allows nothing still replaces what the policy
    // allowed before.
    if request.is_empty() && switch.is_none() {
        return Ok(DefaultPolicyStatus::NothingToAllow);
    }
    let destinations = request.destinations();
    let wallet_id = bloom_broker_api::Token::new(wallet.to_owned())?;
    if let ControlFlow::Break(status) =
        wallet_read_step(daemon.wallet_projections.get_wallet(&wallet_id).await)?
    {
        return Ok(status);
    }
    let mut settings_pending = Vec::new();
    let mut settings_waiting = Vec::new();
    if wallet == DEFAULT_POLICY_WALLET && switch.is_none() {
        let pending = apply_pending_settings(daemon, config.setup.main()).await;
        for message in pending.written {
            tracing::info!(%message, "petal.setup_settings_written");
        }
        settings_pending = pending.still_queued;
        settings_waiting = pending.waiting;
    }
    let proposal = match &switch {
        // Proposed once; a refused or expired proposal is not proposed again.
        Some(switch) => {
            daemon
                .ensure_policy_replaced(
                    wallet,
                    &request.replacement(),
                    switch.operation_id.is_none(),
                )
                .await
        }
        None => {
            daemon
                .ensure_default_policy(
                    wallet,
                    &request.packages,
                    &destinations,
                    request.lifetime,
                    if mode == DefaultPolicyMode::OwnerJustChose {
                        bloom_vfs::handlers::AfterPolicyChange::Propose
                    } else {
                        bloom_vfs::handlers::AfterPolicyChange::Report
                    },
                )
                .await
        }
    };
    let eligibility = match policy_step(proposal)? {
        ControlFlow::Continue(eligibility) => eligibility,
        ControlFlow::Break(status) => return Ok(status),
    };
    Ok(match eligibility {
        bloom_machine_client::PetalEligibility::Allowed(current) => {
            let settings_reset = match &switch {
                Some(switch) => promote_switch(daemon, wallet, switch).await?,
                None => Vec::new(),
            };
            DefaultPolicyStatus::Applied {
                petals: request.allowed(),
                settings_pending,
                settings_waiting,
                settings_reset,
                beyond_persona: request.beyond_persona(&current)?,
            }
        }
        bloom_machine_client::PetalEligibility::ChangedSinceCreation(current) => match &switch {
            // The switch's own proposal no longer waits and never committed.
            Some(switch) => {
                remove_pending_switch(daemon.home.root(), wallet)?;
                DefaultPolicyStatus::SwitchEnded {
                    persona: persona_name(
                        switch
                            .setup
                            .persona
                            .as_ref()
                            .map_or(PersonaPreset::Custodian, |persona| persona.preset),
                    )
                    .to_owned(),
                }
            }
            None => DefaultPolicyStatus::ChangedSinceCreation {
                missing: request.missing(&current)?,
                settings_pending,
                settings_waiting,
                beyond_persona: request.beyond_persona(&current)?,
            },
        },
        bloom_machine_client::PetalEligibility::AwaitingPolicyApproval(pending) => {
            if let Some(switch) = &switch
                && pending.includes_requested
                && switch.operation_id.as_deref() != Some(pending.operation_id.as_str())
            {
                write_pending_switch(
                    daemon.home.root(),
                    wallet,
                    &PendingSwitch {
                        setup: switch.setup.clone(),
                        operation_id: Some(pending.operation_id.as_str().to_owned()),
                    },
                )?;
            }
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
                petals: request.allowed(),
                proposes_chosen_petals: pending.includes_requested,
            }
        }
    })
}

/// Apply an approved persona switch: save the wallet's new setup, reset its
/// Petals' limits, and clear the switch. Each step can run again, so a
/// switch interrupted part-way is finished by the next check.
async fn promote_switch(
    daemon: &Daemon,
    wallet: &str,
    switch: &PendingSwitch,
) -> Result<Vec<String>> {
    save_wallet_setup(&daemon.home.config_path(), wallet, &switch.setup)?;
    let messages =
        reset_persona_settings(&daemon.vfs, daemon.home.root(), wallet, &switch.setup).await;
    remove_pending_switch(daemon.home.root(), wallet)?;
    Ok(messages)
}

/// Switch `wallet` to `preset` with the Petals the owner chose for it: a
/// fresh start for that wallet (decision 18). Machine holds the new setup as
/// a waiting switch and proposes it as a replacement for the wallet's policy;
/// nothing else changes until the owner approves that policy, which saves the
/// setup and resets its Petals' limits. A switch the owner has not approved
/// is cancelled, so it can never commit behind this one. Nothing is changed
/// for a wallet that does not exist, or whose existence Broker cannot
/// confirm, or for a choice that is not valid.
pub(crate) async fn switch_persona(
    daemon: &Daemon,
    wallet: &str,
    preset: PersonaPreset,
    petals: BTreeMap<String, PetalSetupConfig>,
) -> Result<DefaultPolicyStatus> {
    let setup = WalletSetup {
        persona: Some(PersonaConfig::suggested(preset)),
        petals,
    };
    validate_persona_choice(&setup, wallet)?;
    match account_presence(&daemon.vfs, wallet).await {
        AccountPresence::Exists => {}
        AccountPresence::Absent => {
            bail!("wallet {wallet} does not exist; create it first, then choose its persona")
        }
        AccountPresence::Unknown(error) => bail!(
            "Bloom could not check whether wallet {wallet} exists ({error}), so nothing was changed"
        ),
    }
    let home = daemon.home.root();
    if let Some(earlier) = read_pending_switch(home, wallet)? {
        if let Some(operation_id) = &earlier.operation_id {
            daemon
                .cancel_policy_proposal(wallet, operation_id)
                .await
                .map_err(|error| anyhow!("{error}"))?;
        }
        remove_pending_switch(home, wallet)?;
    }
    write_pending_switch(
        home,
        wallet,
        &PendingSwitch {
            setup,
            operation_id: None,
        },
    )?;
    advance_default_policy(daemon, wallet, DefaultPolicyMode::Resume).await
}

/// A persona switch chooses only Bloom's canonical Petals, with values each
/// one's settings accept.
fn validate_persona_choice(setup: &WalletSetup, wallet: &str) -> Result<()> {
    let canonical = menu_petals();
    for name in setup.petals.keys() {
        anyhow::ensure!(
            canonical.contains(name),
            "{name} is not one of Bloom's canonical Petals ({})",
            canonical.join(", ")
        );
        let known: Vec<&str> = setup_template(name)
            .map(|template| template.values.iter().map(|value| value.name).collect())
            .unwrap_or_default();
        if let Some(unknown) = setup.petals[name]
            .values
            .keys()
            .find(|value| !known.contains(&value.as_str()))
        {
            bail!("{} has no setup value {unknown}", petal_label(name));
        }
        render_petal_settings(setup, name, wallet)?;
    }
    Ok(())
}

/// Write each chosen Petal's settings for `wallet` over whatever the Petal
/// stores: an approved persona switch resets its limits, since the owner
/// asked to start over. For `main`, a setup write still queued is dropped
/// once its Petal's reset went in, and dropped for a Petal the new setup does
/// not choose. A failed write is reported with the command that applies it,
/// and the rest continue.
async fn reset_persona_settings(
    vfs: &bloom_vfs::Vfs,
    home: &std::path::Path,
    wallet: &str,
    setup: &WalletSetup,
) -> Vec<String> {
    let main = wallet == DEFAULT_POLICY_WALLET;
    if main {
        for name in menu_petals() {
            if !setup.petals.contains_key(&name) {
                clear_settings_pending(home, &name);
            }
        }
    }
    let mut messages = Vec::new();
    for name in setup.petals.keys() {
        let settings = match render_petal_settings(setup, name, wallet) {
            Ok(Some(settings)) => settings,
            Ok(None) => {
                if main {
                    clear_settings_pending(home, name);
                }
                continue;
            }
            Err(error) => {
                messages.push(format!("petal_settings_failed: {error:#}"));
                continue;
            }
        };
        let written = match bloom_vfs::VfsPath::parse(&settings.path) {
            Ok(path) => bloom_vfs::Handler::write(vfs, &path, &settings.body)
                .await
                .map_err(|error| anyhow!("{error}")),
            Err(error) => Err(anyhow!("{error}")),
        };
        messages.push(match written {
            Ok(()) => {
                if main {
                    clear_settings_pending(home, name);
                }
                format!(
                    "petal_settings: {} reset to {}",
                    petal_label(name),
                    settings.summary
                )
            }
            Err(error) => {
                settings_not_written(name, &settings, &format!("writing them failed ({error:#})"))
            }
        });
    }
    messages
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

/// How the default policy names the persona's entries to the owner, beside
/// the chosen Petals.
pub(crate) const PERSONA_TRANSFERS: &str = "ERC-20 transfers to any recipient";

/// How the default policy names Trader's and Degen's approval lifetime.
pub(crate) const PERSONA_STANDING: &str = "approvals last until revoked";

/// What the default policy asks of a wallet's policy: each chosen, installed
/// Petal's package and destinations, and the saved persona's entries. All of
/// them are required.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct DefaultPolicyRequest {
    /// Chosen, installed Petals, in step with `packages`.
    pub(crate) petals: Vec<String>,
    pub(crate) packages: Vec<bloom_broker_api::Digest32>,
    /// What the chosen Petals' transactions need.
    pub(crate) petal_destinations: Vec<bloom_broker_api::PolicyDestination>,
    /// Whether the wallet has a setup, so its persona's entries are what
    /// it should allow.
    pub(crate) persona_applies: bool,
    /// The saved persona's entries
    /// ([`bloom_daemon::persona_policy_destinations`]).
    pub(crate) persona_destinations: Vec<bloom_broker_api::PolicyDestination>,
    /// The persona's approval lifetime, when it asks for one
    /// ([`bloom_daemon::persona_policy_lifetime`]).
    pub(crate) lifetime: Option<u64>,
}

impl DefaultPolicyRequest {
    /// Every destination the request needs: the Petals', then the persona's.
    pub(crate) fn destinations(&self) -> Vec<bloom_broker_api::PolicyDestination> {
        let mut destinations = self.petal_destinations.clone();
        destinations.extend(self.persona_destinations.iter().cloned());
        destinations
    }

    /// Nothing to propose: no chosen Petal is installed, and the persona adds
    /// nothing.
    pub(crate) fn is_empty(&self) -> bool {
        self.packages.is_empty() && self.destinations().is_empty() && self.lifetime.is_none()
    }

    /// What the owner is told the policy allows: the Petals, and the
    /// persona's entries and lifetime by name.
    pub(crate) fn allowed(&self) -> Vec<String> {
        let mut allowed = self.petals.clone();
        if !self.persona_destinations.is_empty() {
            allowed.push(PERSONA_TRANSFERS.to_owned());
        }
        if self.lifetime.is_some() {
            allowed.push(PERSONA_STANDING.to_owned());
        }
        allowed
    }

    /// What a persona switch replaces the wallet's policy with: exactly the
    /// request, with the persona's lifetime or, without one, the lifetime
    /// wallet creation installs.
    pub(crate) fn replacement(&self) -> bloom_vfs::handlers::PolicyReplacement {
        bloom_vfs::handlers::PolicyReplacement {
            packages: self.packages.clone(),
            destinations: self.destinations(),
            maximum_approval_lifetime_ms: self
                .lifetime
                .unwrap_or(bloom_proto::policy::CREATION_APPROVAL_LIFETIME_MS),
        }
    }

    /// What `current` lacks: each Petal it does not allow, and the persona's
    /// entries when any is missing.
    pub(crate) fn missing(
        &self,
        current: &bloom_broker_api::SignedPolicySnapshot,
    ) -> Result<Vec<String>> {
        let mut missing = petals_not_allowed(current, &self.petals, &self.packages)?;
        let policy = decode_policy(current)?;
        if self
            .persona_destinations
            .iter()
            .any(|destination| !policy.allowed_destinations.contains(destination))
        {
            missing.push(PERSONA_TRANSFERS.to_owned());
        }
        if self
            .lifetime
            .is_some_and(|lifetime| policy.maximum_approval_lifetime_ms != lifetime)
        {
            missing.push(PERSONA_STANDING.to_owned());
        }
        Ok(missing)
    }

    /// What `current` allows that the saved persona does not propose: an
    /// `erc20:any-recipient` entry keyed `evm-<chain id>` on any chain the
    /// persona does not ask for, as after switching away from Degen. Empty for
    /// a wallet the persona does not apply to.
    pub(crate) fn beyond_persona(
        &self,
        current: &bloom_broker_api::SignedPolicySnapshot,
    ) -> Result<Vec<String>> {
        if !self.persona_applies {
            return Ok(Vec::new());
        }
        let policy = decode_policy(current)?;
        let leftover = policy.allowed_destinations.iter().any(|destination| {
            is_any_recipient_opt_in(destination) && !self.persona_destinations.contains(destination)
        });
        Ok(if leftover {
            vec![PERSONA_TRANSFERS.to_owned()]
        } else {
            Vec::new()
        })
    }
}

/// Whether `destination` is an `erc20:any-recipient` entry Machine honours:
/// keyed `evm-<chain id>`, as `bloom_vfs::advisory_exact_evm_policy` reads it.
/// The same string under a Bloom chain name, such as `ethereum`, allows
/// nothing.
fn is_any_recipient_opt_in(destination: &bloom_broker_api::PolicyDestination) -> bool {
    destination.destination == bloom_proto::policy::ERC20_ANY_RECIPIENT
        && destination
            .chain
            .as_str()
            .strip_prefix("evm-")
            .and_then(|id| id.parse::<u64>().ok().filter(|n| n.to_string() == id))
            .is_some()
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
    /// The command that picks the wait up again.
    resume: String,
    deadline_ms: u64,
    announced: Option<String>,
    announced_unrelated: Option<String>,
    /// Whether a Broker refusal being waited out has been reported.
    announced_wait: bool,
    /// Whether this waits for one persona switch, which is proposed once: a
    /// different ceremony means a later switch replaced it.
    one_switch: bool,
}

impl DefaultPolicyWait {
    /// `deadline_ms` bounds the wait before a policy ceremony is announced,
    /// such as the wallet creation ceremony's expiry.
    pub(crate) fn new(wallet: &str, deadline_ms: u64) -> Self {
        Self {
            wallet: wallet.to_owned(),
            resume: format!("bloom wallet default-policy {wallet}"),
            deadline_ms,
            announced: None,
            announced_unrelated: None,
            announced_wait: false,
            one_switch: false,
        }
    }

    /// Wait for one persona switch, which Machine proposes once.
    pub(crate) fn for_switch(mut self) -> Self {
        self.one_switch = true;
        self
    }

    /// Whether the announced policy ceremony has expired. Checked after a
    /// status read so an idle owner is not handed a replacement ceremony.
    pub(crate) fn ceremony_expired(&self, now_ms: u64) -> bool {
        self.announced.is_some() && now_ms >= self.deadline_ms
    }

    pub(crate) fn report_expired(&self, output: &mut impl Write) -> Result<()> {
        let (wallet, resume) = (&self.wallet, &self.resume);
        writeln!(
            output,
            "default_policy: the approval for {wallet} expired; run `{resume}` for a new one"
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
        let resume = &self.resume;
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
            "default_policy: run `{resume}` once that change finishes"
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
        let resume = &self.resume;
        match status {
            DefaultPolicyStatus::NothingToAllow => {
                writeln!(
                    output,
                    "default_policy: none of the Petals chosen during setup is installed; nothing to approve"
                )?;
                Ok(WaitStep::Stop)
            }
            DefaultPolicyStatus::Applied {
                petals,
                settings_pending,
                settings_waiting,
                settings_reset,
                beyond_persona,
            } => {
                for message in settings_reset {
                    writeln!(output, "{message}")?;
                }
                writeln!(
                    output,
                    "default_policy: {wallet} allows {}; each transaction still needs your approval",
                    petal_labels(petals)
                )?;
                report_beyond_persona(output, wallet, beyond_persona)?;
                report_settings_pending(output, wallet, settings_pending)?;
                report_settings_waiting(output, settings_waiting)?;
                Ok(WaitStep::Stop)
            }
            DefaultPolicyStatus::ChangedSinceCreation {
                missing,
                settings_pending,
                settings_waiting,
                beyond_persona,
            } => {
                writeln!(
                    output,
                    "default_policy: {wallet}'s policy has changed since the wallet was created and does not allow {}; Bloom proposes the default policy only for a new wallet, so nothing was proposed. To allow one, {}",
                    petal_labels(missing),
                    policy_update_steps(wallet, "<policy.json>")
                )?;
                if missing.iter().any(|label| label == PERSONA_TRANSFERS) {
                    writeln!(
                        output,
                        "default_policy: to allow {PERSONA_TRANSFERS}, add {{\"chain\": \"evm-1\", \"destination\": \"{marker}\"}} for Ethereum and {{\"chain\": \"evm-137\", \"destination\": \"{marker}\"}} for Polygon to allowed_destinations in a copy of `bloom vfs cat /wallets/{wallet}/policy.json`, then {steps}",
                        marker = bloom_proto::policy::ERC20_ANY_RECIPIENT,
                        steps = policy_update_steps(wallet, "<that file>")
                    )?;
                }
                report_beyond_persona(output, wallet, beyond_persona)?;
                report_settings_pending(output, wallet, settings_pending)?;
                report_settings_waiting(output, settings_waiting)?;
                Ok(WaitStep::Stop)
            }
            DefaultPolicyStatus::SwitchEnded { persona } => {
                writeln!(
                    output,
                    "default_policy: switching {wallet} to {persona} ended without your approval, so nothing changed; to try again, run `bloom wallet persona {wallet} {persona}`"
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
            } => {
                if !proposes_chosen_petals {
                    return self.observe_unrelated(operation_id, ceremony_url, now_ms, output);
                }
                if self.announced.as_deref() == Some(operation_id.as_str()) {
                    return Ok(WaitStep::Poll);
                }
                if self.one_switch && self.announced.is_some() {
                    writeln!(
                        output,
                        "default_policy: a later persona switch for {wallet} replaced this one, so nothing of it applies; approve that switch where it was started"
                    )?;
                    return Ok(WaitStep::Stop);
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
    wait_for_default_policy(endpoint, &name, deadline_ms).await
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

/// Poll Machine with `wait` until it stops. A persona switch waiting for its
/// ceremony is resumed the same way.
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

/// `bloom wallet persona`: switch `wallet` to `preset`, a fresh start for
/// that wallet (decision 18). The owner chooses its Petals again, starting
/// from the persona's suggestions; Machine saves the choice, resets the
/// Petals' limits and proposes it as the wallet's policy, and this command
/// waits for that ceremony.
pub(crate) async fn run_persona_switch(
    endpoint: &crate::ResolvedEndpoint,
    chains: &BTreeMap<String, bloom_proto::ChainSpec>,
    wallet: &str,
    preset: PersonaPreset,
) -> Result<()> {
    let persona = PersonaConfig::suggested(preset);
    let name = persona_name(preset);
    println!(
        "{}",
        persona_message(Some(&persona), &any_recipient_chain_names(chains))
    );
    println!(
        "persona_note: switching {wallet} to {name} starts its setup again: once you approve the one ceremony that replaces its policy with what you choose now, its Petal limits reset to the persona's; until then nothing changes"
    );
    let mut setup = WalletSetup::default();
    if !crate::structured_service_output() && interactive_setup_available() {
        run_wallet_setup_menu(
            wallet,
            &mut setup,
            Some(&persona),
            &mut std::io::stdin().lock(),
            &mut std::io::stdout(),
        )?;
    } else {
        accept_setup_suggestions(&mut setup, Some(&persona));
    }
    let output = crate::machine_command(
        endpoint,
        bloom_daemon::ipc::MachineCommand::WalletPersona {
            name: wallet.to_owned(),
            persona: preset,
            petals: setup.petals,
        },
    )
    .await?;
    if output.exit_code != 0 {
        return crate::print_machine_command_output(&output);
    }
    let status: DefaultPolicyStatus = serde_json::from_str(output.stdout.trim())
        .context("decode the persona switch from Machine")?;
    // `bloom wallet default-policy` resumes a switch waiting for its ceremony.
    let mut wait = DefaultPolicyWait::new(
        wallet,
        crate::current_unix_ms().saturating_add(POLICY_LOCK_GRACE_MS),
    )
    .for_switch();
    if wait.observe(&status, crate::current_unix_ms(), &mut std::io::stdout())? == WaitStep::Stop {
        return Ok(());
    }
    tokio::time::sleep(POLL_INTERVAL).await;
    poll_default_policy(endpoint, wallet, wait).await
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

    fn chosen_setup(names: &[&str]) -> WalletSetup {
        let mut setup = WalletSetup::default();
        for name in names {
            setup
                .petals
                .insert((*name).to_owned(), PetalSetupConfig::default());
        }
        setup
    }

    #[test]
    fn failed_settings_stay_pending_until_written() {
        let home = tempfile::tempdir().unwrap();
        let petals = chosen_setup(&["polymarket"]);
        assert!(pending_settings(home.path(), &petals).is_empty());

        mark_settings_pending(home.path(), "polymarket").unwrap();
        assert_eq!(pending_settings(home.path(), &petals), ["polymarket"]);
        // A second failed attempt leaves one marker, not two.
        mark_settings_pending(home.path(), "polymarket").unwrap();
        assert_eq!(pending_settings(home.path(), &petals), ["polymarket"]);

        clear_settings_pending(home.path(), "polymarket");
        assert!(pending_settings(home.path(), &petals).is_empty());
        // Clearing an absent marker is not an error.
        clear_settings_pending(home.path(), "polymarket");
    }

    /// `store_key` is where the listed Polymarket releases store a wallet's
    /// venue settings, as the host stores them: the Petal SDK's `state`
    /// namespace (petal 2beed2ff, `STATE_NS`), then `venue_config_key`. A
    /// setup write goes ahead only while nothing is stored there, so a catalog
    /// bump must re-check the key against the new release and list it, or
    /// setup would write over settings it cannot see.
    #[test]
    fn the_polymarket_settings_key_is_pinned_with_its_release() {
        let entry = github_source::preinstalled_petal("polymarket").unwrap();
        assert_eq!(
            entry.expected_hash,
            // v0.1.8: same petal 2beed2ff and `venue_config_key` as v0.1.6.
            Some("6eb2065e8558f3761399fcb0516731a600fdb0b49974c8ed0808abd38fde7db4"),
            "re-check store_key against the new release, then update both"
        );
        let template = setup_template("polymarket").unwrap();
        assert_eq!(
            template.releases,
            [
                // v0.1.6, pinned by Bloom v0.4.0, which a home may still run
                // while it updates.
                "0f365cd7f613129f73ce66fb07256c8a42c4e70abbb77721804dbd6df85b96b5",
                "6eb2065e8558f3761399fcb0516731a600fdb0b49974c8ed0808abd38fde7db4",
            ],
            "list a release only once its key is checked"
        );
        assert!(template.releases.contains(&entry.expected_hash.unwrap()));
        // An earlier release is one the catalog release updates from, so the
        // signed lineage carries a write into it forward.
        for release in template.releases {
            assert!(
                entry.expected_hash == Some(*release)
                    || entry.predecessor_package_hashes.contains(release),
                "{release} is neither the catalog release nor one it updates from"
            );
        }
        assert_eq!(
            setup_template("polymarket").unwrap().store_key,
            "state/settings/{wallet}/venue.toml"
        );
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

    /// What the pinned Polymarket settings route reads while nothing is stored.
    const UNSET: &[u8] = b"enabled = false\nallow_neg_risk = true\n";

    /// A Polymarket settings route: it reads [`UNSET`] while nothing is stored,
    /// and its conditional write checks whether anything is stored, as the
    /// Petal router does, keeping the check and the write together.
    struct SettingsRoute {
        /// Whether `main`'s account exists; the route fails without it.
        account: bool,
        /// Whether the Petal stores its settings under the key setup checks.
        under_key: bool,
        stored: tokio::sync::Mutex<Option<Vec<u8>>>,
        locks: bloom_vfs::WriteLocks,
        pause_reads: std::sync::atomic::AtomicBool,
        read_started: tokio::sync::Notify,
        release_read: tokio::sync::Notify,
    }

    impl SettingsRoute {
        /// `None` fails every read and write, as before `main`'s account
        /// exists. [`UNSET`] means nothing is stored yet; anything else is
        /// stored.
        fn holding(value: Option<&[u8]>) -> std::sync::Arc<Self> {
            Self::with(
                value.is_some(),
                value.filter(|value| *value != UNSET).map(<[u8]>::to_vec),
            )
        }

        /// `value` is stored, even if it reads exactly like [`UNSET`].
        fn storing(value: &[u8]) -> std::sync::Arc<Self> {
            Self::with(true, Some(value.to_vec()))
        }

        /// Nothing is stored, and what gets written is stored under a key
        /// other than the one setup checks, as a stale pinned key would be.
        fn misplacing() -> std::sync::Arc<Self> {
            let mut route = Self::with(true, None);
            std::sync::Arc::get_mut(&mut route).unwrap().under_key = false;
            route
        }

        fn with(account: bool, stored: Option<Vec<u8>>) -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                account,
                under_key: true,
                stored: tokio::sync::Mutex::new(stored),
                locks: bloom_vfs::WriteLocks::default(),
                pause_reads: std::sync::atomic::AtomicBool::new(false),
                read_started: tokio::sync::Notify::new(),
                release_read: tokio::sync::Notify::new(),
            })
        }

        /// What the route reads, or `None` without the account.
        async fn value(&self) -> Option<Vec<u8>> {
            self.account.then_some(())?;
            Some(
                self.stored
                    .lock()
                    .await
                    .clone()
                    .unwrap_or_else(|| UNSET.to_vec()),
            )
        }

        fn no_account() -> bloom_vfs::HandlerError {
            bloom_vfs::HandlerError::not_found("wallet main")
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
            self.value().await.ok_or_else(Self::no_account)
        }

        async fn write(
            &self,
            path: &bloom_vfs::VfsPath,
            data: &[u8],
        ) -> std::result::Result<(), bloom_vfs::HandlerError> {
            let _held = self.locks.shared(&path.to_string_path()).await;
            if !self.account {
                return Err(Self::no_account());
            }
            *self.stored.lock().await = Some(data.to_vec());
            Ok(())
        }

        /// A paused check returns what it saw before the pause, so a write
        /// landing during the pause makes it stale. Only the first check
        /// pauses.
        async fn write_if_absent(
            &self,
            path: &bloom_vfs::VfsPath,
            _key: &str,
            data: &[u8],
        ) -> std::result::Result<bool, bloom_vfs::HandlerError> {
            let _held = self.locks.exclusive(&path.to_string_path()).await?;
            if !self.account {
                return Err(Self::no_account());
            }
            let stored = self.under_key && self.stored.lock().await.is_some();
            if self
                .pause_reads
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                self.read_started.notify_one();
                self.release_read.notified().await;
            }
            if stored {
                return Ok(false);
            }
            *self.stored.lock().await = Some(data.to_vec());
            Ok(true)
        }
    }

    fn queued_polymarket(
        route: &std::sync::Arc<SettingsRoute>,
    ) -> (tempfile::TempDir, bloom_vfs::Vfs) {
        let home = tempfile::tempdir().unwrap();
        mark_settings_pending(home.path(), "polymarket").unwrap();
        let vfs = bloom_vfs::Vfs::builder()
            .mount("petals", route.clone())
            .build();
        (home, vfs)
    }

    /// The Polymarket release setup's settings key is pinned for.
    fn release() -> &'static str {
        github_source::preinstalled_petal("polymarket")
            .and_then(|entry| entry.expected_hash)
            .unwrap()
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
        let unset = UNSET;

        let route = SettingsRoute::holding(Some(unset));
        let (home, vfs) = queued_polymarket(&route);
        let outcome =
            apply_queued_settings(&vfs, home.path(), &petals, "polymarket", release()).await;
        assert!(
            matches!(&outcome, QueuedWrite::Written(message) if message.starts_with("petal_settings: ")),
            "{outcome:?}"
        );
        assert_eq!(route.value().await.unwrap(), polymarket_setup_body());
        assert!(pending_settings(home.path(), &petals).is_empty());

        // The owner's settings stay, and nothing is queued any longer.
        let route = SettingsRoute::holding(Some(b"enabled = false\n"));
        let (home, vfs) = queued_polymarket(&route);
        assert_eq!(
            apply_queued_settings(&vfs, home.path(), &petals, "polymarket", release()).await,
            QueuedWrite::Settled
        );
        assert_eq!(route.value().await.unwrap(), b"enabled = false\n");
        assert!(pending_settings(home.path(), &petals).is_empty());

        // A route that cannot be read yet keeps the marker for next time.
        let route = SettingsRoute::holding(None);
        let (home, vfs) = queued_polymarket(&route);
        assert!(matches!(
            apply_queued_settings(&vfs, home.path(), &petals, "polymarket", release()).await,
            QueuedWrite::Failed(_)
        ));
        assert_eq!(route.value().await, None);
        assert_eq!(pending_settings(home.path(), &petals), ["polymarket"]);
    }

    /// Settings the owner saved are kept even when they read exactly like the
    /// route's default: what is stored decides, not what the route reads.
    /// This covers a reinstall of the same release, which finds the owner's
    /// saved settings again.
    #[tokio::test]
    async fn an_explicitly_saved_default_is_never_replaced() {
        let petals = chosen_setup(&["polymarket"]);

        let route = SettingsRoute::storing(UNSET);
        let (home, vfs) = queued_polymarket(&route);
        assert_eq!(route.value().await.unwrap(), UNSET);
        assert_eq!(
            apply_queued_settings(&vfs, home.path(), &petals, "polymarket", release()).await,
            QueuedWrite::Settled
        );
        assert_eq!(*route.stored.lock().await, Some(UNSET.to_vec()));
        assert!(pending_settings(home.path(), &petals).is_empty());

        let route = SettingsRoute::storing(UNSET);
        let (home, vfs) = queued_polymarket(&route);
        let message = settle_setup_settings(
            &vfs,
            home.path(),
            &petals,
            "polymarket",
            release(),
            SetupSettingsStep::Write,
            false,
            &AccountPresence::Exists,
        )
        .await
        .unwrap();
        assert!(
            message.starts_with("petal_settings_not_written: "),
            "{message}"
        );
        assert_eq!(*route.stored.lock().await, Some(UNSET.to_vec()));
    }

    /// A queued write that fails stays queued, and the command that stops once
    /// the policy is settled says so and names the command that retries it.
    #[tokio::test]
    async fn a_failed_retry_is_reported_with_the_command_that_retries_it() {
        let petals = chosen_setup(&["polymarket"]);
        let route = SettingsRoute::holding(None);
        let (home, vfs) = queued_polymarket(&route);
        let owners = BTreeMap::from([("polymarket".to_owned(), release().to_owned())]);
        let outcome = apply_queued_writes(&vfs, home.path(), &petals, &owners).await;
        assert!(outcome.written.is_empty());
        assert_eq!(outcome.still_queued.len(), 1, "{outcome:?}");
        assert!(outcome.still_queued[0].starts_with("Polymarket ("));
        assert_eq!(pending_settings(home.path(), &petals), ["polymarket"]);

        for status in [
            DefaultPolicyStatus::Applied {
                petals: vec!["polymarket".into()],
                settings_pending: outcome.still_queued.clone(),
                settings_waiting: outcome.waiting.clone(),
                settings_reset: Vec::new(),
                beyond_persona: Vec::new(),
            },
            DefaultPolicyStatus::ChangedSinceCreation {
                missing: vec!["polymarket".into()],
                settings_pending: outcome.still_queued.clone(),
                settings_waiting: outcome.waiting.clone(),
                beyond_persona: Vec::new(),
            },
        ] {
            let mut wait = DefaultPolicyWait::new("main", 30_000);
            let mut output = Vec::new();
            assert_eq!(
                wait.observe(&status, 0, &mut output).unwrap(),
                WaitStep::Stop
            );
            let output = String::from_utf8(output).unwrap();
            assert!(
                output.contains("petal_settings_pending: settings chosen during setup are still queued for Polymarket ("),
                "{output}"
            );
            assert!(
                output.contains("run: bloom wallet default-policy main"),
                "{output}"
            );
        }
    }

    /// A failed setup write promises a retry only once the retry is queued.
    /// Otherwise it says the retry was not recorded and gives the command
    /// that applies setup's choice by hand.
    #[tokio::test]
    async fn a_retry_is_promised_only_once_it_is_queued() {
        let petals = chosen_setup(&["polymarket"]);
        let write = |home: std::path::PathBuf, account: AccountPresence| {
            let petals = petals.clone();
            async move {
                let vfs = bloom_vfs::Vfs::builder()
                    .mount("petals", SettingsRoute::holding(None))
                    .build();
                settle_setup_settings(
                    &vfs,
                    &home,
                    &petals,
                    "polymarket",
                    release(),
                    SetupSettingsStep::Write,
                    false,
                    &account,
                )
                .await
                .unwrap()
            }
        };

        let home = tempfile::tempdir().unwrap();
        let message = write(home.path().to_owned(), AccountPresence::Absent).await;
        assert!(
            message.contains("will retry once wallet main exists"),
            "{message}"
        );
        assert_eq!(pending_settings(home.path(), &petals), ["polymarket"]);

        // Where `main` exists, or may, no wallet creation follows to retry
        // it, so the message names the command that does.
        for account in [
            AccountPresence::Exists,
            AccountPresence::Unknown("Broker is down".into()),
        ] {
            let home = tempfile::tempdir().unwrap();
            let message = write(home.path().to_owned(), account).await;
            assert!(
                message.ends_with(
                    "The write is queued. To write them, run: bloom wallet default-policy main"
                ),
                "{message}"
            );
            assert!(!message.contains("will retry"), "{message}");
            assert_eq!(pending_settings(home.path(), &petals), ["polymarket"]);
        }

        let home = tempfile::tempdir().unwrap();
        std::fs::write(pending_settings_dir(home.path()), b"not a directory").unwrap();
        let message = write(home.path().to_owned(), AccountPresence::Absent).await;
        assert!(
            message.starts_with("petal_settings_not_written: "),
            "{message}"
        );
        assert!(
            message.contains("the automatic retry could not be recorded"),
            "{message}"
        );
        assert!(
            message.contains("| bloom vfs write /petals/polymarket/"),
            "{message}"
        );
        assert!(!message.contains("will retry"), "{message}");
    }

    /// `main`'s account as the wallet tree reports it.
    struct AccountFile {
        exists: bool,
    }

    #[async_trait::async_trait]
    impl bloom_vfs::Handler for AccountFile {
        async fn lookup(
            &self,
            path: &bloom_vfs::VfsPath,
        ) -> std::result::Result<bloom_vfs::Entry, bloom_vfs::HandlerError> {
            Err(bloom_vfs::HandlerError::not_found(path.to_string_path()))
        }

        async fn read(
            &self,
            path: &bloom_vfs::VfsPath,
        ) -> std::result::Result<Vec<u8>, bloom_vfs::HandlerError> {
            if self.exists {
                Ok(b"{}".to_vec())
            } else {
                Err(bloom_vfs::HandlerError::not_found(path.to_string_path()))
            }
        }
    }

    /// `bloom serve` makes a queued write once `main` exists, however it was
    /// created, and leaves it queued until then.
    #[tokio::test]
    async fn serve_makes_a_queued_write_once_main_exists() {
        let petals = chosen_setup(&["polymarket"]);
        let unset = UNSET;
        let installed = BTreeMap::from([("polymarket".to_owned(), release().to_owned())]);
        let check = |exists: bool, owners: BTreeMap<String, String>| {
            let petals = petals.clone();
            async move {
                let route = SettingsRoute::holding(Some(unset));
                let home = tempfile::tempdir().unwrap();
                mark_settings_pending(home.path(), "polymarket").unwrap();
                let vfs = bloom_vfs::Vfs::builder()
                    .mount("petals", route.clone())
                    .mount("wallets", std::sync::Arc::new(AccountFile { exists }))
                    .build();
                let outcome = retry_queued_settings_once(&vfs, home.path(), &petals, &owners).await;
                let queued = pending_settings(home.path(), &petals);
                (outcome, route.value().await.unwrap(), queued)
            }
        };

        // Before `main` exists, and for a Petal not installed, nothing is tried.
        for (exists, owners) in [(false, installed.clone()), (true, BTreeMap::new())] {
            let (outcome, value, queued) = check(exists, owners).await;
            assert_eq!(outcome, None);
            assert_eq!(value, unset);
            assert_eq!(queued, ["polymarket"]);
        }

        let (outcome, value, queued) = check(true, installed).await;
        let outcome = outcome.unwrap();
        assert_eq!(outcome.written.len(), 1, "{outcome:?}");
        assert!(outcome.still_queued.is_empty());
        assert_eq!(value, polymarket_setup_body());
        assert!(queued.is_empty());
    }

    /// A rerun of `bloom init` makes the write an interrupted run queued, but
    /// only once `main` exists and only for a Petal with a marker.
    #[tokio::test]
    async fn a_rerun_of_setup_finishes_an_interrupted_settings_write() {
        let petals = chosen_setup(&["polymarket"]);
        let unset = UNSET;
        // Before `main` exists, wallet creation writes it, so nothing is said.
        // When Broker cannot say, the write stays queued and the owner is told
        // how to make it.
        for (account, says) in [
            (AccountPresence::Absent, None),
            (
                AccountPresence::Unknown("Broker is down".into()),
                Some("could not check whether wallet main exists (Broker is down)"),
            ),
        ] {
            let route = SettingsRoute::holding(Some(unset));
            let (home, vfs) = queued_polymarket(&route);
            let finished = settle_setup_settings(
                &vfs,
                home.path(),
                &petals,
                "polymarket",
                release(),
                SetupSettingsStep::Leave,
                false,
                &account,
            )
            .await;
            match says {
                None => assert_eq!(finished, None, "{account:?}"),
                Some(why) => {
                    let message = finished.unwrap();
                    assert!(message.starts_with("petal_settings_pending: "), "{message}");
                    assert!(message.contains(why), "{message}");
                    assert!(
                        message.ends_with("run: bloom wallet default-policy main"),
                        "{message}"
                    );
                }
            }
            assert_eq!(route.value().await.unwrap(), unset, "{account:?}");
            assert_eq!(pending_settings(home.path(), &petals), ["polymarket"]);
        }

        // A write that fails while `main` exists stays queued, and says so.
        let route = SettingsRoute::holding(None);
        let (home, vfs) = queued_polymarket(&route);
        let finished = settle_setup_settings(
            &vfs,
            home.path(),
            &petals,
            "polymarket",
            release(),
            SetupSettingsStep::Leave,
            false,
            &AccountPresence::Exists,
        )
        .await
        .unwrap();
        assert!(
            finished.contains("writing them did not complete"),
            "{finished}"
        );
        assert_eq!(pending_settings(home.path(), &petals), ["polymarket"]);

        let route = SettingsRoute::holding(Some(unset));
        let (home, vfs) = queued_polymarket(&route);
        let exists = AccountPresence::Exists;
        let finished = settle_setup_settings(
            &vfs,
            home.path(),
            &petals,
            "polymarket",
            release(),
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
            release(),
            SetupSettingsStep::Leave,
            false,
            &exists,
        )
        .await;
        assert_eq!(finished, None);
        assert_eq!(route.value().await.unwrap(), unset);
    }

    /// A pinned key the release does not store its settings under protects
    /// nothing, so setup says so once, loudly, and stops retrying.
    #[tokio::test]
    async fn a_pinned_key_the_release_does_not_store_under_is_reported() {
        let petals = chosen_setup(&["polymarket"]);

        let route = SettingsRoute::misplacing();
        let (home, vfs) = queued_polymarket(&route);
        let outcome =
            apply_queued_settings(&vfs, home.path(), &petals, "polymarket", release()).await;
        assert!(
            matches!(&outcome, QueuedWrite::Written(message)
                if message.starts_with("petal_settings_unprotected: ")
                    && message.contains("state/settings/main/venue.toml")),
            "{outcome:?}"
        );
        assert!(pending_settings(home.path(), &petals).is_empty());

        let route = SettingsRoute::misplacing();
        let (home, vfs) = queued_polymarket(&route);
        let message = settle_setup_settings(
            &vfs,
            home.path(),
            &petals,
            "polymarket",
            release(),
            SetupSettingsStep::Write,
            false,
            &AccountPresence::Exists,
        )
        .await
        .unwrap();
        assert!(
            message.starts_with("petal_settings_unprotected: "),
            "{message}"
        );
        assert!(pending_settings(home.path(), &petals).is_empty());
    }

    /// Another release under the Petal's name may store its settings away
    /// from the pinned key, where setup could not see them, so setup leaves
    /// that release alone and gives the command instead.
    #[tokio::test]
    async fn setup_writes_only_to_the_release_its_key_is_pinned_for() {
        let petals = chosen_setup(&["polymarket"]);
        let other = "f".repeat(64);

        let route = SettingsRoute::holding(Some(UNSET));
        let (home, vfs) = queued_polymarket(&route);
        assert_eq!(
            apply_queued_settings(&vfs, home.path(), &petals, "polymarket", &other).await,
            QueuedWrite::Settled
        );
        assert_eq!(*route.stored.lock().await, None);
        assert!(pending_settings(home.path(), &petals).is_empty());

        let route = SettingsRoute::holding(Some(UNSET));
        let (home, vfs) = queued_polymarket(&route);
        let message = settle_setup_settings(
            &vfs,
            home.path(),
            &petals,
            "polymarket",
            &other,
            SetupSettingsStep::Write,
            false,
            &AccountPresence::Exists,
        )
        .await
        .unwrap();
        assert!(
            message.starts_with("petal_settings_not_written: "),
            "{message}"
        );
        assert!(
            message.contains("is not the release setup knows"),
            "{message}"
        );
        assert!(message.contains("| bloom vfs write "), "{message}");
        assert_eq!(*route.stored.lock().await, None);
        assert!(pending_settings(home.path(), &petals).is_empty());
    }

    /// A home that still runs the release Bloom v0.4.0 installed, because its
    /// update to the catalog release has not landed, keeps setup's choice: the
    /// queued write goes into that release, whose key is the same, and the
    /// signed lineage carries it forward.
    #[tokio::test]
    async fn a_queued_write_goes_into_the_earlier_release_that_shares_the_key() {
        let petals = chosen_setup(&["polymarket"]);
        let earlier = "0f365cd7f613129f73ce66fb07256c8a42c4e70abbb77721804dbd6df85b96b5";
        assert_ne!(earlier, release());

        let route = SettingsRoute::holding(Some(UNSET));
        let (home, vfs) = queued_polymarket(&route);
        let outcome =
            apply_queued_settings(&vfs, home.path(), &petals, "polymarket", earlier).await;
        assert!(
            matches!(&outcome, QueuedWrite::Written(message) if message.starts_with("petal_settings: ")),
            "{outcome:?}"
        );
        assert_eq!(route.value().await.unwrap(), polymarket_setup_body());
        assert!(pending_settings(home.path(), &petals).is_empty());
    }

    /// A home still on an older release the catalog release updates from, one
    /// that keeps these settings elsewhere (v0.1.5's route has no account
    /// index), keeps setup's write queued for the update: it is neither
    /// dropped nor written where the update would not look.
    #[tokio::test]
    async fn a_queued_write_waits_for_an_older_release_to_update() {
        let petals = chosen_setup(&["polymarket"]);
        let older = "5df5a1377dc4d70c71e47ffe6827e691e1f5868543b752dc8d19a500284e5fa6";
        assert!(
            github_source::preinstalled_petal("polymarket")
                .unwrap()
                .predecessor_package_hashes
                .contains(&older)
        );

        let route = SettingsRoute::holding(Some(UNSET));
        let (home, vfs) = queued_polymarket(&route);
        let outcome = apply_queued_settings(&vfs, home.path(), &petals, "polymarket", older).await;
        assert!(
            matches!(&outcome, QueuedWrite::Waiting(reason) if reason.contains("once Bloom updates it to v0.1.8")),
            "{outcome:?}"
        );
        assert_eq!(*route.stored.lock().await, None);
        assert_eq!(pending_settings(home.path(), &petals), ["polymarket"]);

        // `bloom wallet default-policy` reports it as waiting, and why, apart
        // from writes that failed: rerunning that command cannot make it.
        let owners = BTreeMap::from([("polymarket".to_owned(), older.to_owned())]);
        let pending = apply_queued_writes(&vfs, home.path(), &petals, &owners).await;
        assert!(pending.written.is_empty());
        assert!(pending.still_queued.is_empty(), "{pending:?}");
        assert!(
            pending.waiting[0]
                .starts_with("Polymarket (the installed Polymarket is an earlier release"),
            "{pending:?}"
        );

        // So does a `bloom init` that could not update it.
        let message = settle_setup_settings(
            &vfs,
            home.path(),
            &petals,
            "polymarket",
            older,
            SetupSettingsStep::Write,
            false,
            &AccountPresence::Exists,
        )
        .await
        .unwrap();
        assert!(
            message.starts_with(
                "petal_settings_waiting: Polymarket settings chosen during setup are queued: "
            ),
            "{message}"
        );
        assert!(message.ends_with(UPDATE_RETRIED), "{message}");
        assert!(!message.contains("default-policy"), "{message}");
        assert_eq!(*route.stored.lock().await, None);
        assert_eq!(pending_settings(home.path(), &petals), ["polymarket"]);
    }

    /// A `bloom init` rerun that updates a chosen Petal on a home whose
    /// `main` exists makes a write setup queued earlier, as `bloom serve`'s
    /// update does, rather than dropping it; while Broker cannot say whether
    /// `main` exists the write stays queued.
    #[tokio::test]
    async fn a_rerun_that_updates_the_petal_makes_the_write_setup_queued() {
        let petals = chosen_setup(&["polymarket"]);
        let rerun = |vfs, home, step, account| async move {
            settle_setup_settings(
                vfs,
                home,
                &chosen_setup(&["polymarket"]),
                "polymarket",
                release(),
                step,
                true,
                account,
            )
            .await
        };

        let route = SettingsRoute::holding(Some(UNSET));
        let (home, vfs) = queued_polymarket(&route);
        let message = rerun(
            &vfs,
            home.path(),
            SetupSettingsStep::KeepOwners,
            &AccountPresence::Exists,
        )
        .await
        .unwrap();
        assert!(message.starts_with("petal_settings: "), "{message}");
        assert_eq!(route.value().await.unwrap(), polymarket_setup_body());
        assert!(pending_settings(home.path(), &petals).is_empty());

        let route = SettingsRoute::holding(Some(UNSET));
        let (home, vfs) = queued_polymarket(&route);
        let unknown = AccountPresence::Unknown("Broker is down".into());
        let message = rerun(&vfs, home.path(), SetupSettingsStep::Unverified, &unknown)
            .await
            .unwrap();
        assert!(
            message.starts_with("petal_settings_pending: ") && message.contains("Broker is down"),
            "{message}"
        );
        assert_eq!(*route.stored.lock().await, None);
        assert_eq!(pending_settings(home.path(), &petals), ["polymarket"]);

        // With nothing queued, the rerun still leaves the owner's settings.
        let route = SettingsRoute::holding(Some(UNSET));
        let vfs = bloom_vfs::Vfs::builder()
            .mount("petals", route.clone())
            .build();
        let home = tempfile::tempdir().unwrap();
        let message = rerun(
            &vfs,
            home.path(),
            SetupSettingsStep::KeepOwners,
            &AccountPresence::Exists,
        )
        .await
        .unwrap();
        assert!(
            message.starts_with("petal_settings_not_written: "),
            "{message}"
        );
        assert_eq!(*route.stored.lock().await, None);
    }

    /// When `bloom serve` updates a chosen Petal on a home whose `main`
    /// exists, setup leaves carried settings alone, but a write setup queued
    /// earlier still goes in while nothing is stored. Without an answer about
    /// `main` it stays queued, and with nothing queued nothing is written.
    #[tokio::test]
    async fn an_update_makes_the_write_setup_queued() {
        let petals = chosen_setup(&["polymarket"]);
        let update = |vfs, home, account| async move {
            queued_write_after_update(
                vfs,
                home,
                &chosen_setup(&["polymarket"]),
                "polymarket",
                Some(release()),
                account,
            )
            .await
        };

        let route = SettingsRoute::holding(Some(UNSET));
        let (home, vfs) = queued_polymarket(&route);
        assert!(matches!(
            update(&vfs, home.path(), &AccountPresence::Exists).await,
            Some(QueuedWrite::Written(_))
        ));
        assert_eq!(route.value().await.unwrap(), polymarket_setup_body());
        assert!(pending_settings(home.path(), &petals).is_empty());
        // Nothing queued any more: the update leaves the route alone.
        assert_eq!(
            update(&vfs, home.path(), &AccountPresence::Exists).await,
            None
        );

        // The owner's carried settings stay, and the marker is cleared.
        let route = SettingsRoute::holding(Some(b"enabled = false\n"));
        let (home, vfs) = queued_polymarket(&route);
        assert_eq!(
            update(&vfs, home.path(), &AccountPresence::Exists).await,
            Some(QueuedWrite::Settled)
        );
        assert_eq!(route.value().await.unwrap(), b"enabled = false\n");
        assert!(pending_settings(home.path(), &petals).is_empty());

        let route = SettingsRoute::holding(Some(UNSET));
        let (home, vfs) = queued_polymarket(&route);
        let unknown = AccountPresence::Unknown("Broker is down".into());
        assert!(matches!(
            update(&vfs, home.path(), &unknown).await,
            Some(QueuedWrite::Failed(error)) if error.contains("Broker is down")
        ));
        assert_eq!(*route.stored.lock().await, None);
        assert_eq!(pending_settings(home.path(), &petals), ["polymarket"]);
    }

    /// Setup writes a just-installed Petal's settings only over unset ones:
    /// reinstalling a release after an uninstall finds the owner's settings,
    /// which the uninstall kept, and leaves them.
    #[tokio::test]
    async fn setup_never_replaces_settings_a_reinstalled_petal_still_holds() {
        let petals = chosen_setup(&["polymarket"]);
        let unset = UNSET;
        let install = |vfs, home| async move {
            settle_setup_settings(
                vfs,
                home,
                &chosen_setup(&["polymarket"]),
                "polymarket",
                release(),
                SetupSettingsStep::Write,
                false,
                &AccountPresence::Exists,
            )
            .await
            .unwrap()
        };

        let route = SettingsRoute::holding(Some(b"enabled = false\n"));
        let (home, vfs) = queued_polymarket(&route);
        let message = install(&vfs, home.path()).await;
        assert!(
            message.starts_with("petal_settings_not_written: "),
            "{message}"
        );
        assert!(message.contains("already there"), "{message}");
        assert_eq!(route.value().await.unwrap(), b"enabled = false\n");
        assert!(pending_settings(home.path(), &petals).is_empty());

        let route = SettingsRoute::holding(Some(unset));
        let (home, vfs) = queued_polymarket(&route);
        assert!(
            install(&vfs, home.path())
                .await
                .starts_with("petal_settings: ")
        );
        assert_eq!(route.value().await.unwrap(), polymarket_setup_body());
        assert!(pending_settings(home.path(), &petals).is_empty());

        // Before the account exists the route cannot be read: queued for later.
        let route = SettingsRoute::holding(None);
        let vfs = bloom_vfs::Vfs::builder()
            .mount("petals", route.clone())
            .build();
        let home = tempfile::tempdir().unwrap();
        assert!(
            install(&vfs, home.path())
                .await
                .starts_with("petal_settings_failed: ")
        );
        assert_eq!(pending_settings(home.path(), &petals), ["polymarket"]);
    }

    /// An owner's write that arrives while the queued write is checking the
    /// route lands after it, so setup's settings never replace it.
    #[tokio::test]
    async fn a_queued_write_never_replaces_an_owner_write_made_during_its_check() {
        let petals = chosen_setup(&["polymarket"]);
        let unset = UNSET;
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
            tokio::spawn(async move {
                apply_queued_settings(&vfs, &home, &petals, "polymarket", release()).await
            })
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
            matches!(queued.await.unwrap(), QueuedWrite::Written(_)),
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
        mark_settings_pending(fresh.path(), "not-a-petal").unwrap();
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

    #[test]
    fn persona_selection_preserves_unspecified_choices_and_uses_token_windows() {
        let mut saved = None;
        select_persona(&mut saved, None).unwrap();
        assert_eq!(saved, None);
        select_persona(&mut saved, Some(PersonaPreset::Trader)).unwrap();
        let choice = saved.clone();
        select_persona(&mut saved, None).unwrap();
        assert_eq!(saved, choice);
        assert_eq!(saved.as_ref().unwrap().window_secs, 86400);
        select_persona(&mut saved, Some(PersonaPreset::Degen)).unwrap();
        assert_eq!(saved.unwrap().window_secs, 604800);
    }

    #[test]
    fn persona_token_limits_do_not_rewrite_venue_settings_or_saved_owner_choice() {
        let trader = PersonaConfig::suggested(PersonaPreset::Trader);
        let mut fresh = WalletSetup::default();
        accept_setup_suggestions(&mut fresh, Some(&trader));
        assert_eq!(polymarket_limit(&fresh), Some("1000"));
        fresh
            .petals
            .get_mut("polymarket")
            .unwrap()
            .values
            .insert("max_daily_usd".into(), "42.5".into());
        let mut output = Vec::new();
        run_setup_menu(&mut fresh, Some(&trader), &mut "".as_bytes(), &mut output).unwrap();
        assert_eq!(polymarket_limit(&fresh), Some("42.5"));
        assert!(String::from_utf8(output).unwrap().contains("[42.5]"));
    }

    /// Institutional keeps the catalog's suggestion; Degen suggests its pUSD
    /// quantity.
    #[test]
    fn each_persona_suggests_its_own_polymarket_limit() {
        let mut none = WalletSetup::default();
        accept_setup_suggestions(&mut none, None);
        let mut institutional = WalletSetup::default();
        let custodian = PersonaConfig::suggested(PersonaPreset::Custodian);
        accept_setup_suggestions(&mut institutional, Some(&custodian));
        assert_eq!(polymarket_limit(&institutional), polymarket_limit(&none));
        let mut degen = WalletSetup::default();
        let profile = PersonaConfig::suggested(PersonaPreset::Degen);
        accept_setup_suggestions(&mut degen, Some(&profile));
        assert_eq!(polymarket_limit(&degen), Some("10000"));
    }

    /// An empty answer, or the end of input, keeps Institutional; an
    /// unknown answer is asked again.
    #[test]
    fn the_persona_menu_defaults_to_institutional() {
        let chains = any_recipient_chain_names(&bloom_proto::Config::local_default().chains);
        assert_eq!(chains, ["Ethereum Mainnet", "Polygon PoS"]);
        let ask = |answers: &str| {
            let mut saved = None;
            let mut output = Vec::new();
            run_persona_menu(&mut saved, &chains, &mut answers.as_bytes(), &mut output).unwrap();
            (saved.unwrap().preset, String::from_utf8(output).unwrap())
        };
        assert_eq!(ask("").0, PersonaPreset::Custodian);
        assert_eq!(ask("\n").0, PersonaPreset::Custodian);
        let (preset, output) = ask("degen\n");
        assert_eq!(preset, PersonaPreset::Degen);
        assert!(output.contains("persona: degen;"), "{output}");
        assert!(
            output.contains("any recipient on Ethereum Mainnet and Polygon PoS"),
            "{output}"
        );
        let (preset, output) = ask("yolo\ntrader\n");
        assert_eq!(preset, PersonaPreset::Trader);
        assert!(output.contains("persona must be"), "{output}");
        assert!(persona_message(None, &chains).starts_with("persona: institutional;"));
        // Without either network, Degen says so rather than naming them.
        let degen = PersonaConfig::suggested(PersonaPreset::Degen);
        let message = persona_message(Some(&degen), &[]);
        assert!(message.contains("neither is configured"), "{message}");
    }

    /// `bloom init --persona` on a home whose setup already ran changes
    /// nothing: a switch is a fresh start, which `bloom wallet persona` makes.
    #[test]
    fn a_later_persona_choice_names_the_fresh_start() {
        let note = persona_switch_note("main", PersonaPreset::Custodian);
        assert!(
            note.starts_with("persona_note: setup already ran, so nothing changed;"),
            "{note}"
        );
        assert!(
            note.contains("run `bloom wallet persona main institutional` while Bloom is running"),
            "{note}"
        );
        assert!(
            note.contains("resets its Petal limits and replaces its policy"),
            "{note}"
        );
    }

    /// A persona switch replaces the wallet's policy with exactly its
    /// request: the persona's lifetime, or without one the 30 days wallet
    /// creation installs, so leaving Trader or Degen gives up their standing
    /// approvals too.
    #[test]
    fn a_switch_replaces_the_policy_with_exactly_the_request() {
        let package = bloom_broker_api::Digest32::from_bytes([1; 32]);
        let degen = DefaultPolicyRequest {
            petals: vec!["polymarket".into()],
            packages: vec![package.clone()],
            petal_destinations: policy_destinations("polymarket").unwrap(),
            persona_applies: true,
            persona_destinations: vec![any_recipient("evm-1")],
            lifetime: Some(bloom_proto::policy::STANDING_APPROVAL_POLICY_LIFETIME_MS),
        };
        let replacement = degen.replacement();
        assert_eq!(replacement.packages, [package]);
        assert_eq!(replacement.destinations, degen.destinations());
        assert_eq!(
            replacement.maximum_approval_lifetime_ms,
            bloom_proto::policy::STANDING_APPROVAL_POLICY_LIFETIME_MS
        );
        assert_eq!(
            degen.allowed(),
            ["polymarket", PERSONA_TRANSFERS, PERSONA_STANDING]
        );

        let institutional = DefaultPolicyRequest {
            persona_applies: true,
            ..DefaultPolicyRequest::default()
        };
        assert!(institutional.is_empty());
        let replacement = institutional.replacement();
        assert!(replacement.packages.is_empty() && replacement.destinations.is_empty());
        assert_eq!(
            replacement.maximum_approval_lifetime_ms,
            bloom_proto::policy::CREATION_APPROVAL_LIFETIME_MS
        );
    }

    /// The persona's lifetime is required like its entries: a policy without
    /// it reports it missing.
    #[test]
    fn a_missing_lifetime_is_reported() {
        let request = DefaultPolicyRequest {
            persona_applies: true,
            lifetime: Some(bloom_proto::policy::STANDING_APPROVAL_POLICY_LIFETIME_MS),
            ..DefaultPolicyRequest::default()
        };
        assert!(!request.is_empty());
        let mut policy = bloom_broker_api::CanonicalWalletPolicy {
            wallet_id: bloom_broker_api::Token::new("main").unwrap(),
            allowed_petal_packages: Vec::new(),
            allowed_destinations: Vec::new(),
            maximum_approval_lifetime_ms: bloom_proto::policy::CREATION_APPROVAL_LIFETIME_MS,
            required_verifiers: Vec::new(),
            clear_signing: None,
        };
        assert_eq!(
            request.missing(&snapshot_of(&policy)).unwrap(),
            [PERSONA_STANDING]
        );
        policy.maximum_approval_lifetime_ms =
            bloom_proto::policy::STANDING_APPROVAL_POLICY_LIFETIME_MS;
        assert!(request.missing(&snapshot_of(&policy)).unwrap().is_empty());
    }

    /// A waiting switch is kept whole in its own file, apart from the config,
    /// until its policy commits or it ends.
    #[test]
    fn a_waiting_switch_is_kept_apart_until_it_ends() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(read_pending_switch(home.path(), "trading").unwrap(), None);
        let mut switch = PendingSwitch {
            setup: chosen_setup(&["polymarket"]),
            operation_id: None,
        };
        switch.setup.persona = Some(PersonaConfig::suggested(PersonaPreset::Degen));
        write_pending_switch(home.path(), "trading", &switch).unwrap();
        assert_eq!(
            read_pending_switch(home.path(), "trading").unwrap(),
            Some(switch.clone())
        );
        switch.operation_id = Some("ab".repeat(32));
        write_pending_switch(home.path(), "trading", &switch).unwrap();
        assert_eq!(
            read_pending_switch(home.path(), "trading").unwrap(),
            Some(switch)
        );
        assert_eq!(read_pending_switch(home.path(), "main").unwrap(), None);
        remove_pending_switch(home.path(), "trading").unwrap();
        remove_pending_switch(home.path(), "trading").unwrap();
        assert_eq!(read_pending_switch(home.path(), "trading").unwrap(), None);
        let names: Vec<_> = std::fs::read_dir(home.path().join("pending-persona"))
            .unwrap()
            .collect();
        assert!(names.is_empty(), "no temporary file is left");
        std::fs::write(pending_switch_path(home.path(), "trading"), "not toml").unwrap();
        assert!(read_pending_switch(home.path(), "trading").is_err());
    }

    /// Machine's config writes for different wallets never lose each other's
    /// setup, and leave the rest of the config as it was.
    #[test]
    fn concurrent_setup_saves_keep_every_wallet() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("config.toml");
        let mut config = bloom_proto::Config::local_default();
        config.setup.complete = true;
        config.save(&path).unwrap();
        let wallets: Vec<String> = (0..8).map(|n| format!("wallet{n}")).collect();
        std::thread::scope(|scope| {
            for wallet in &wallets {
                let path = &path;
                scope.spawn(move || {
                    for _ in 0..5 {
                        save_wallet_setup(path, wallet, &chosen_setup(&["polymarket"])).unwrap();
                    }
                });
            }
        });
        let saved = bloom_proto::Config::load(&path).unwrap();
        assert!(saved.setup.complete);
        for wallet in &wallets {
            assert_eq!(
                saved.setup.wallet(wallet),
                &chosen_setup(&["polymarket"]),
                "{wallet}"
            );
        }
    }

    /// The wait reports what an approved switch reset, and a switch that
    /// ended without approval as nothing changed.
    #[test]
    fn the_wait_reports_a_switch_applied_or_ended() {
        let observe = |status: DefaultPolicyStatus| {
            let mut wait = DefaultPolicyWait::new("trading", 30_000);
            let mut output = Vec::new();
            assert_eq!(
                wait.observe(&status, 10, &mut output).unwrap(),
                WaitStep::Stop
            );
            String::from_utf8(output).unwrap()
        };
        let output = observe(DefaultPolicyStatus::Applied {
            petals: vec!["polymarket".into()],
            settings_pending: Vec::new(),
            settings_waiting: Vec::new(),
            settings_reset: vec!["petal_settings: Polymarket reset to max_daily_usd = 1000".into()],
            beyond_persona: Vec::new(),
        });
        assert!(
            output.starts_with("petal_settings: Polymarket reset to max_daily_usd = 1000\n"),
            "{output}"
        );
        assert!(
            output.contains("default_policy: trading allows Polymarket"),
            "{output}"
        );
        // A switch's wait stops when a later switch's ceremony replaces it.
        let pending = |operation_id: &str| DefaultPolicyStatus::AwaitingOwner {
            operation_id: operation_id.into(),
            ceremony_url: Some(format!("https://example.test/{operation_id}")),
            ceremony_expires_at_ms: Some(u64::MAX),
            petals: vec!["polymarket".into()],
            proposes_chosen_petals: true,
        };
        let mut wait = DefaultPolicyWait::new("trading", 30_000).for_switch();
        let mut output = Vec::new();
        assert_eq!(
            wait.observe(&pending("first"), 10, &mut output).unwrap(),
            WaitStep::Poll
        );
        assert_eq!(
            wait.observe(&pending("second"), 20, &mut output).unwrap(),
            WaitStep::Stop
        );
        let output = String::from_utf8(output).unwrap();
        assert!(
            output.contains("a later persona switch for trading replaced this one"),
            "{output}"
        );
        assert_eq!(
            output.matches("default_policy_url: ").count(),
            1,
            "{output}"
        );
        let output = observe(DefaultPolicyStatus::SwitchEnded {
            persona: "trader".into(),
        });
        assert!(
            output.contains(
                "switching trading to trader ended without your approval, so nothing changed"
            ) && output.contains("run `bloom wallet persona trading trader`"),
            "{output}"
        );
        assert_eq!(
            serde_json::to_value(DefaultPolicyStatus::SwitchEnded {
                persona: "trader".into()
            })
            .unwrap(),
            serde_json::json!({"state": "switch_ended", "persona": "trader"})
        );
    }

    /// An approved persona switch resets each chosen Petal's limits over what the
    /// owner stored, since the owner asked to start over, and drops `main`'s
    /// queued setup writes. A failed write is reported with the command that
    /// applies it.
    #[tokio::test]
    async fn a_persona_switch_resets_limits_over_stored_settings() {
        let route = SettingsRoute::holding(Some(b"enabled = false\n"));
        let (home, vfs) = queued_polymarket(&route);
        let mut setup = chosen_setup(&["polymarket", "hyperliquid"]);
        setup
            .petals
            .get_mut("polymarket")
            .unwrap()
            .values
            .insert("max_daily_usd".into(), "1000".into());
        let messages = reset_persona_settings(&vfs, home.path(), "main", &setup).await;
        assert_eq!(
            messages,
            ["petal_settings: Polymarket reset to max_daily_usd = 1000"]
        );
        assert_eq!(
            route.value().await.unwrap(),
            b"enabled = true\nmax_daily_usd = \"1000\"\n"
        );
        assert!(pending_settings(home.path(), &setup).is_empty());

        // On main a failed reset keeps the queued write.
        let route = SettingsRoute::holding(None);
        let vfs = bloom_vfs::Vfs::builder()
            .mount("petals", route.clone())
            .build();
        mark_settings_pending(home.path(), "polymarket").unwrap();
        reset_persona_settings(&vfs, home.path(), "main", &setup).await;
        assert_eq!(pending_settings(home.path(), &setup), ["polymarket"]);
        let messages = reset_persona_settings(&vfs, home.path(), "trading", &setup).await;
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert!(
            messages[0].starts_with("petal_settings_not_written: Polymarket settings were not written: writing them failed"),
            "{messages:?}"
        );
        assert!(
            messages[0]
                .contains("| bloom vfs write /petals/polymarket/settings/trading/0/venue.toml"),
            "{messages:?}"
        );
    }

    /// A switch takes only Bloom's canonical Petals, with values their
    /// settings accept and no setting a Petal does not have, so a client
    /// cannot store anything else.
    #[test]
    fn a_persona_switch_takes_only_canonical_petals_with_valid_values() {
        let choose = |petals: &[(&str, &str)]| {
            let mut setup = WalletSetup::default();
            for (name, limit) in petals {
                let values = if limit.is_empty() {
                    BTreeMap::new()
                } else {
                    BTreeMap::from([("max_daily_usd".to_owned(), (*limit).to_owned())])
                };
                setup
                    .petals
                    .insert((*name).to_owned(), PetalSetupConfig { values });
            }
            validate_persona_choice(&setup, "trading")
        };
        choose(&[("polymarket", "1000"), ("hyperliquid", ""), ("enso", "")]).unwrap();
        choose(&[]).unwrap();
        let error = choose(&[("tolly", "")]).unwrap_err().to_string();
        assert!(
            error.contains("not one of Bloom's canonical Petals"),
            "{error}"
        );
        let error = choose(&[("polymarket", "-5")]).unwrap_err().to_string();
        assert!(
            error.contains("[setup.wallets.trading.petals.polymarket.values]"),
            "{error}"
        );
        let mut extra = WalletSetup::default();
        extra.petals.insert(
            "hyperliquid".into(),
            PetalSetupConfig {
                values: BTreeMap::from([("tolly_writes".to_owned(), "enabled".to_owned())]),
            },
        );
        let error = validate_persona_choice(&extra, "trading")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("Hyperliquid has no setup value tolly_writes"),
            "{error}"
        );
    }

    fn snapshot_of(
        policy: &bloom_broker_api::CanonicalWalletPolicy,
    ) -> bloom_broker_api::SignedPolicySnapshot {
        let bytes = serde_jcs::to_vec(policy).unwrap();
        bloom_broker_api::SignedPolicySnapshot {
            wallet_id: policy.wallet_id.clone(),
            version: bloom_broker_api::DecimalU64::new(3),
            canonical_policy: bloom_broker_api::Base64UrlBytes::from_bytes(&bytes),
            policy_digest: bloom_broker_api::Digest32::from_bytes([9; 32]),
            policy_signing_key_id: bloom_broker_api::Token::new("policy-key").unwrap(),
            policy_verifying_key: bloom_broker_api::Base64UrlBytes::from_bytes(&[2; 32]),
            signer_signature: bloom_broker_api::Base64UrlBytes::from_bytes(&[3; 64]),
        }
    }

    fn any_recipient(chain: &str) -> bloom_broker_api::PolicyDestination {
        bloom_broker_api::PolicyDestination {
            chain: bloom_broker_api::Token::new(chain).unwrap(),
            destination: bloom_proto::policy::ERC20_ANY_RECIPIENT.into(),
        }
    }

    /// What the default policy asks for, names and finds missing, with and
    /// without a persona entry and with and without Petals.
    #[test]
    fn the_default_policy_request_counts_the_persona_entries() {
        let package = bloom_broker_api::Digest32::from_bytes([1; 32]);
        let degen = vec![any_recipient("evm-1"), any_recipient("evm-137")];
        let none = DefaultPolicyRequest::default();
        assert!(none.is_empty());
        let degen_only = DefaultPolicyRequest {
            persona_applies: true,
            persona_destinations: degen.clone(),
            ..DefaultPolicyRequest::default()
        };
        assert!(
            !degen_only.is_empty(),
            "a Degen wallet with no Petals has its entry proposed"
        );
        assert_eq!(degen_only.allowed(), [PERSONA_TRANSFERS]);
        assert_eq!(degen_only.destinations(), degen);
        let with_petal = DefaultPolicyRequest {
            petals: vec!["polymarket".into()],
            packages: vec![package.clone()],
            petal_destinations: policy_destinations("polymarket").unwrap(),
            ..degen_only.clone()
        };
        assert_eq!(with_petal.allowed(), ["polymarket", PERSONA_TRANSFERS]);
        assert_eq!(with_petal.destinations().len(), 1 + degen.len());

        let mut policy = bloom_broker_api::CanonicalWalletPolicy {
            wallet_id: bloom_broker_api::Token::new("main").unwrap(),
            allowed_petal_packages: vec![package],
            allowed_destinations: policy_destinations("polymarket").unwrap(),
            maximum_approval_lifetime_ms: 60_000,
            required_verifiers: Vec::new(),
            clear_signing: None,
        };
        assert_eq!(
            with_petal.missing(&snapshot_of(&policy)).unwrap(),
            [PERSONA_TRANSFERS]
        );
        policy.allowed_destinations.extend(degen.iter().cloned());
        assert!(
            with_petal
                .missing(&snapshot_of(&policy))
                .unwrap()
                .is_empty()
        );
        assert!(
            with_petal
                .beyond_persona(&snapshot_of(&policy))
                .unwrap()
                .is_empty()
        );
    }

    /// After leaving Degen, the entry the policy still holds is reported for
    /// the default wallet only; Bloom does not remove it.
    #[test]
    fn an_entry_the_saved_persona_does_not_propose_is_reported() {
        let mut policy = bloom_broker_api::CanonicalWalletPolicy {
            wallet_id: bloom_broker_api::Token::new("main").unwrap(),
            allowed_petal_packages: Vec::new(),
            allowed_destinations: vec![any_recipient("evm-1"), any_recipient("evm-137")],
            maximum_approval_lifetime_ms: 60_000,
            required_verifiers: Vec::new(),
            clear_signing: None,
        };
        let institutional = DefaultPolicyRequest {
            persona_applies: true,
            ..DefaultPolicyRequest::default()
        };
        assert_eq!(
            institutional.beyond_persona(&snapshot_of(&policy)).unwrap(),
            [PERSONA_TRANSFERS]
        );
        // The same string under a Bloom chain name, or a non-canonical id,
        // allows nothing (the planner reads only `evm-<chain id>`), so it is
        // not reported.
        for chain in ["ethereum", "evm-01", "evm-"] {
            policy.allowed_destinations = vec![any_recipient(chain)];
            assert!(
                institutional
                    .beyond_persona(&snapshot_of(&policy))
                    .unwrap()
                    .is_empty(),
                "{chain}"
            );
        }
        policy.allowed_destinations = vec![any_recipient("evm-8453")];
        assert_eq!(
            institutional.beyond_persona(&snapshot_of(&policy)).unwrap(),
            [PERSONA_TRANSFERS]
        );
        // Degen still proposing it on that chain is not a leftover, but one
        // on a chain Degen no longer covers is.
        let degen_on_ethereum = DefaultPolicyRequest {
            persona_applies: true,
            persona_destinations: vec![any_recipient("evm-1")],
            ..DefaultPolicyRequest::default()
        };
        policy.allowed_destinations = vec![any_recipient("evm-1")];
        assert!(
            degen_on_ethereum
                .beyond_persona(&snapshot_of(&policy))
                .unwrap()
                .is_empty()
        );
        policy.allowed_destinations.push(any_recipient("evm-137"));
        assert_eq!(
            degen_on_ethereum
                .beyond_persona(&snapshot_of(&policy))
                .unwrap(),
            [PERSONA_TRANSFERS]
        );
        // Another wallet has no persona to compare with.
        assert!(
            DefaultPolicyRequest::default()
                .beyond_persona(&snapshot_of(&policy))
                .unwrap()
                .is_empty()
        );
    }

    /// The owner is told about a leftover entry with how to remove it, and
    /// about a missing persona entry with exactly what to add.
    #[test]
    fn persona_entries_are_explained_when_present_or_missing() {
        let observe = |status: DefaultPolicyStatus| {
            let mut wait = DefaultPolicyWait::new("main", 30_000);
            let mut output = Vec::new();
            assert_eq!(
                wait.observe(&status, 0, &mut output).unwrap(),
                WaitStep::Stop
            );
            String::from_utf8(output).unwrap()
        };
        let output = observe(DefaultPolicyStatus::Applied {
            petals: vec!["polymarket".into()],
            settings_pending: Vec::new(),
            settings_waiting: Vec::new(),
            settings_reset: Vec::new(),
            beyond_persona: vec![PERSONA_TRANSFERS.into()],
        });
        assert!(output.contains("main allows Polymarket"), "{output}");
        assert!(
            output.contains(&format!(
                "still allows {PERSONA_TRANSFERS}, which the saved persona does not propose"
            )),
            "{output}"
        );
        assert!(
            output.contains("bloom vfs cat /wallets/main/policy.json"),
            "{output}"
        );
        assert!(
            output.contains("bloom wallet update-policy main"),
            "{output}"
        );
        // Preparing changes nothing until the owner approves and commits.
        assert!(
            output.contains("then run `bloom wallet commit-policy <operation_id>`"),
            "{output}"
        );

        let output = observe(DefaultPolicyStatus::ChangedSinceCreation {
            missing: vec![PERSONA_TRANSFERS.into()],
            settings_pending: Vec::new(),
            settings_waiting: Vec::new(),
            beyond_persona: Vec::new(),
        });
        assert!(
            output.contains("To allow one, run `bloom wallet update-policy main --file"),
            "{output}"
        );
        assert!(
            output.contains(r#"{"chain": "evm-1", "destination": "erc20:any-recipient"}"#),
            "{output}"
        );
        assert_eq!(
            output
                .matches("bloom wallet commit-policy <operation_id>")
                .count(),
            2,
            "{output}"
        );
        assert!(!output.contains("still allows"), "{output}");

        // The new field is left out of the JSON when empty, as before.
        assert_eq!(
            serde_json::to_value(DefaultPolicyStatus::Applied {
                petals: Vec::new(),
                settings_pending: Vec::new(),
                settings_waiting: Vec::new(),
                settings_reset: Vec::new(),
                beyond_persona: Vec::new(),
            })
            .unwrap(),
            serde_json::json!({"state": "applied", "petals": []})
        );
    }

    fn menu(answers: &str) -> (WalletSetup, String) {
        let mut petals = WalletSetup::default();
        let mut output = Vec::new();
        run_setup_menu(&mut petals, None, &mut answers.as_bytes(), &mut output).unwrap();
        (petals, String::from_utf8(output).unwrap())
    }

    fn polymarket_limit(setup: &WalletSetup) -> Option<&str> {
        setup
            .petals
            .get("polymarket")
            .and_then(|choice| choice.values.get("max_daily_usd"))
            .map(String::as_str)
    }

    fn chosen(setup: &WalletSetup) -> Vec<&str> {
        setup.petals.keys().map(String::as_str).collect()
    }

    #[test]
    fn menu_offers_the_canonical_petals_with_polymarket_limit_suggested() {
        let (setup, output) = menu("\n\n\n\n\n\n");
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
        assert_eq!(
            chosen(&setup),
            [
                "enso",
                "feedback",
                "hyperliquid",
                "near-intents",
                "polymarket"
            ]
        );
        assert!(setup.petals["hyperliquid"].values.is_empty());
        assert_eq!(polymarket_limit(&setup), Some("100"));
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
        let mut setup = WalletSetup::default();
        setup
            .petals
            .insert("hyperliquid".into(), PetalSetupConfig::default());
        setup.petals.insert(
            "polymarket".into(),
            PetalSetupConfig {
                values: BTreeMap::from([("max_daily_usd".into(), "42.5".into())]),
            },
        );
        let mut output = Vec::new();
        run_setup_menu(
            &mut setup,
            None,
            &mut "\n\n\n\n\n\n".as_bytes(),
            &mut output,
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert_eq!(chosen(&setup), ["hyperliquid", "polymarket"]);
        assert_eq!(polymarket_limit(&setup), Some("42.5"));
        assert!(output.contains("Use Polymarket? [Y/n] "), "{output}");
        assert!(output.contains("Use Enso? [y/N] "), "{output}");
        assert!(
            output.contains("Polymarket daily buy limit in pUSD [42.5]: "),
            "{output}"
        );

        // The same at the end of input, and an explicit answer still wins.
        let mut eof = setup.clone();
        run_setup_menu(&mut eof, None, &mut "".as_bytes(), &mut Vec::new()).unwrap();
        assert_eq!(chosen(&eof), ["hyperliquid", "polymarket"]);
        assert_eq!(polymarket_limit(&eof), Some("42.5"));
        let mut changed = setup.clone();
        run_setup_menu(
            &mut changed,
            None,
            &mut "\n\ny\n\n\n60\n".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(chosen(&changed), ["enso", "hyperliquid", "polymarket"]);
        assert_eq!(polymarket_limit(&changed), Some("60"));
    }

    #[test]
    fn scripted_setup_keeps_earlier_declines() {
        let mut setup = WalletSetup::default();
        setup.petals.insert(
            "polymarket".into(),
            PetalSetupConfig {
                values: BTreeMap::from([("max_daily_usd".into(), "42.5".into())]),
            },
        );
        accept_setup_suggestions(&mut setup, None);
        assert_eq!(chosen(&setup), ["polymarket"]);
        assert_eq!(polymarket_limit(&setup), Some("42.5"));
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
    }

    #[test]
    fn scripted_setup_chooses_every_canonical_petal_and_keeps_existing_values() {
        let mut petals = WalletSetup::default();
        accept_setup_suggestions(&mut petals, None);
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

        let mut edited = WalletSetup::default();
        edited.petals.insert(
            "polymarket".into(),
            PetalSetupConfig {
                values: BTreeMap::from([("max_daily_usd".into(), "5".into())]),
            },
        );
        accept_setup_suggestions(&mut edited, None);
        assert_eq!(polymarket_limit(&edited), Some("5"));
        assert_eq!(chosen(&edited), ["polymarket"]);
    }

    #[test]
    fn chosen_petals_round_trip_as_config_tables() {
        let mut config = bloom_proto::Config::local_default();
        accept_setup_suggestions(config.setup.main_mut(), None);
        let encoded = toml::to_string(&config).unwrap();
        let document: toml::Value = toml::from_str(&encoded).unwrap();
        let petals = &document["setup"]["wallets"]["main"]["petals"];
        assert!(petals.get("hyperliquid").is_some(), "{encoded}");
        assert_eq!(
            petals["polymarket"]["values"]["max_daily_usd"].as_str(),
            Some("100"),
            "{encoded}"
        );
        assert!(!encoded.contains("tolly_writes"), "{encoded}");
        let decoded: bloom_proto::Config = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.setup.main().petals, config.setup.main().petals);
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
        let mut setup = WalletSetup::default();
        let suggested = render_petal_settings(&setup, "polymarket", "main")
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

        setup.petals.insert(
            "polymarket".into(),
            PetalSetupConfig {
                values: BTreeMap::from([("max_daily_usd".into(), "42.5".into())]),
            },
        );
        let saved = render_petal_settings(&setup, "polymarket", "main")
            .unwrap()
            .unwrap();
        assert_eq!(
            saved.body,
            b"enabled = true\nmax_daily_usd = \"42.5\"\n".to_vec()
        );
        assert!(
            render_petal_settings(&setup, "hyperliquid", "main")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn enso_has_no_settings_template_and_covers_its_own_chains() {
        // Enso v0.1.5 ships its own per-wallet route rules at
        // settings/wallets/<wallet>/venue.toml; Bloom writes none.
        assert!(
            render_petal_settings(&WalletSetup::default(), "enso", "main")
                .unwrap()
                .is_none()
        );

        const ROUTER: &str = "0xf75584ef6673ad213a685a1b58cc0330b8ea22cf";
        const LINEA: &str = "0xa146d46823f3f594b785200102be5385cafce9b5";
        const ROBINHOOD_TEMPO: &str = "0xcfbaa9cfce952ca4f4069874ff1df8c05e37a3c7";
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
            ("robinhood", ROBINHOOD_TEMPO),
            ("tempo", ROBINHOOD_TEMPO),
        ]
        .map(|(chain, router)| (chain.to_owned(), router.to_owned()))
        .to_vec();
        assert_eq!(destinations, expected);

        // These are the 12 chains pinned Enso v0.1.7's shipped rules allow,
        // by Bloom's name for each, so Machine never refuses a route Enso
        // planned and allows no router Enso never routes through.
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
        // The Petal, not the token contracts it calls: listing those would
        // let anything staged on the wallet transfer them to anyone.
        assert_eq!(
            destinations,
            [("polygon".to_owned(), "petal:polymarket".to_owned())]
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
        let mut setup = WalletSetup::default();
        setup.petals.insert(
            "polymarket".into(),
            PetalSetupConfig {
                values: BTreeMap::from([(
                    "max_daily_usd".into(),
                    "1\"\nenabled = false\n#".into(),
                )]),
            },
        );
        let error = render_petal_settings(&setup, "polymarket", "main").unwrap_err();
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
                missing: vec!["hyperliquid".into()],
                settings_pending: Vec::new(),
                settings_waiting: Vec::new(),
                beyond_persona: Vec::new(),
            })
            .unwrap(),
            serde_json::json!({"state": "changed_since_creation", "missing": ["hyperliquid"]})
        );
        // A still-queued or waiting write is carried to the CLI; none is left
        // out.
        let applied = DefaultPolicyStatus::Applied {
            petals: vec!["polymarket".into()],
            settings_pending: vec!["Polymarket (busy)".into()],
            settings_waiting: vec!["Polymarket (older release)".into()],
            settings_reset: Vec::new(),
            beyond_persona: Vec::new(),
        };
        let value = serde_json::to_value(&applied).unwrap();
        assert_eq!(
            value["settings_pending"],
            serde_json::json!(["Polymarket (busy)"])
        );
        assert_eq!(
            value["settings_waiting"],
            serde_json::json!(["Polymarket (older release)"])
        );
        assert_eq!(
            serde_json::from_value::<DefaultPolicyStatus>(value).unwrap(),
            applied
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
        assert_eq!(
            DefaultPolicyMode::of_command(false),
            DefaultPolicyMode::Resume
        );
        assert_eq!(
            DefaultPolicyMode::of_command(true),
            DefaultPolicyMode::OwnerJustChose
        );
        // The switch itself names the persona, and the Petals only when any
        // are chosen.
        assert_eq!(
            serde_json::to_value(MachineCommand::WalletPersona {
                name: "trading".into(),
                persona: PersonaPreset::Trader,
                petals: BTreeMap::new(),
            })
            .unwrap(),
            serde_json::json!({
                "command": "wallet_persona",
                "name": "trading",
                "persona": "trader"
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
            settings_pending: Vec::new(),
            settings_waiting: Vec::new(),
            settings_reset: Vec::new(),
            beyond_persona: Vec::new(),
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
            settings_pending: Vec::new(),
            settings_waiting: Vec::new(),
            beyond_persona: Vec::new(),
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
        assert!(output.contains("bloom wallet commit-policy <operation_id>"));
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
