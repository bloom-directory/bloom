//! One best-effort pass per daemon start, then retries of installs refused
//! because other Petal code was running. Installation is not signing
//! authorization.
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use bloom_daemon::{Daemon, ipc::IpcOperationContext};

use crate::github_source::{self, PreinstalledPetal, PreinstalledState, PreparedReleasePetal};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProvisioningResult {
    pub name: String,
    pub outcome: ProvisioningOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProvisioningOutcome {
    Current,
    Installed,
    /// Replaced an older release. Signed package lineage carries the old
    /// release's settings forward; an update outside that lineage starts empty.
    Updated,
    /// Refused because other Petal code was running when this one would have
    /// activated; [`retry_busy`] tries it again.
    Busy(String),
    Failed(String),
}

/// The first wait before a busy install is tried again. It doubles up to
/// [`BUSY_RETRY_MAX`], then stays there while Machine runs.
const BUSY_RETRY_FIRST: Duration = Duration::from_secs(1);
const BUSY_RETRY_MAX: Duration = Duration::from_secs(60);
/// How long a retried install, downloaded and staged, waits for a moment with
/// no Petal code running before it activates. An agent's calls leave gaps
/// between them; activating in one is what lets the install in.
const IDLE_WAIT: Duration = Duration::from_secs(30);

pub(crate) fn provision(daemon: &Daemon, context: &IpcOperationContext) -> Vec<ProvisioningResult> {
    provision_with(
        daemon,
        context,
        github_source::DEFAULT_PETALS,
        |name| github_source::preinstalled_petal(name).copied(),
        github_source::prepare_prebuilt_release_petal,
    )
}

pub(crate) fn provision_with(
    daemon: &Daemon,
    context: &IpcOperationContext,
    names: &[&str],
    resolve: impl Fn(&str) -> Option<PreinstalledPetal>,
    acquire: impl Fn(&Daemon, &PreinstalledPetal, &IpcOperationContext) -> Result<PreparedReleasePetal>,
) -> Vec<ProvisioningResult> {
    let mut results = Vec::new();
    for &name in names {
        let attempt = || -> Result<ProvisioningOutcome> {
            if context.is_cancelled() {
                bail!("default provisioning cancelled");
            }
            let entry =
                resolve(name).ok_or_else(|| anyhow!("unknown pre-installed Petal {name:?}"))?;
            if !entry.default_eligible {
                bail!(
                    "pre-installed Petal {} is not eligible for triad activation: pinned ABI {} is not the triad payload-signing ABI",
                    entry.name,
                    entry.petal_abi
                );
            }
            let expected_owner = daemon.petals.store().resolve_petal_owner(name)?;
            if let Some(hash) = &expected_owner {
                let meta = daemon.petals.store().load_meta(hash)?;
                if github_source::classify_existing_preinstalled(&entry, &meta)?
                    == PreinstalledState::Current
                {
                    return Ok(ProvisioningOutcome::Current);
                }
            }
            let prepared = acquire(daemon, &entry, context)
                .with_context(|| format!("download default {name}"))?;
            let updated = expected_owner.is_some();
            prepared.commit(daemon, context, Some(expected_owner))?;
            Ok(if updated {
                ProvisioningOutcome::Updated
            } else {
                ProvisioningOutcome::Installed
            })
        };
        let outcome = match attempt() {
            Ok(outcome) => outcome,
            Err(error) if is_busy(&error) => ProvisioningOutcome::Busy(format!("{error:#}")),
            // Machine is stopping; its next start installs it.
            Err(error) if context.is_cancelled() => {
                ProvisioningOutcome::Failed(format!("{error:#}"))
            }
            // Machine installs the catalog when it starts. `bloom init` and
            // a repository install are no help on a running home: the first
            // cannot open it, and the second builds a different package
            // from the one the catalog pins.
            Err(error) => {
                ProvisioningOutcome::Failed(format!("{error:#}; restart Bloom to try again"))
            }
        };
        match &outcome {
            ProvisioningOutcome::Busy(error) => {
                tracing::info!(petal = %name, %error, "petal.provisioning_busy");
            }
            ProvisioningOutcome::Failed(error) if context.is_cancelled() => {
                tracing::info!(petal = %name, %error, "petal.provisioning_cancelled");
            }
            ProvisioningOutcome::Failed(error) => {
                tracing::warn!(petal = %name, %error, "petal.provisioning_failed");
            }
            _ => tracing::info!(petal = %name, ?outcome, "petal.provisioning_finished"),
        }
        results.push(ProvisioningResult {
            name: name.to_owned(),
            outcome,
        });
    }
    results
}

/// Whether `error` is a package change refused because Petal code was
/// running, which succeeds once the store is idle.
fn is_busy(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<bloom_petals::PetalError>(),
            Some(bloom_petals::PetalError::Busy)
        )
    })
}

fn busy_names(results: &[ProvisioningResult]) -> Vec<String> {
    results
        .iter()
        .filter(|result| matches!(result.outcome, ProvisioningOutcome::Busy(_)))
        .map(|result| result.name.clone())
        .collect()
}

/// Try again each catalog Petal in `first` whose install was refused because
/// other Petal code was running, such as setup writing Polymarket's settings
/// right after `bloom wallet new`, until it installs, fails for another
/// reason, or Machine stops. Each retry downloads and stages the package,
/// then activates in the first moment no Petal code runs
/// ([`IpcOperationContext::waiting_for_idle_activation`]), so an agent
/// calling Petals back to back cannot starve it. `on_retried` receives each
/// round's results, so setup's settings are written once a chosen Petal
/// installs.
pub(crate) fn retry_busy(
    daemon: &Daemon,
    context: &IpcOperationContext,
    first: &[ProvisioningResult],
    on_retried: impl FnMut(&[ProvisioningResult]),
) {
    let waiting = context.waiting_for_idle_activation(IDLE_WAIT);
    retry_busy_with(
        first,
        |names| {
            provision_with(
                daemon,
                &waiting,
                names,
                |name| github_source::preinstalled_petal(name).copied(),
                github_source::prepare_prebuilt_release_petal,
            )
        },
        |wait| wait_unless_cancelled(context, wait),
        on_retried,
    );
}

/// [`retry_busy`] with its rounds and waits supplied. `wait` returns false
/// once Machine is stopping.
fn retry_busy_with(
    first: &[ProvisioningResult],
    mut round: impl FnMut(&[&str]) -> Vec<ProvisioningResult>,
    mut wait: impl FnMut(Duration) -> bool,
    mut on_retried: impl FnMut(&[ProvisioningResult]),
) {
    let mut busy = busy_names(first);
    let mut delay = BUSY_RETRY_FIRST;
    while !busy.is_empty() {
        if !wait(delay) {
            return;
        }
        delay = (delay * 2).min(BUSY_RETRY_MAX);
        let names: Vec<&str> = busy.iter().map(String::as_str).collect();
        let results = round(&names);
        on_retried(&results);
        busy = busy_names(&results);
    }
}

/// Wait for `total` in short steps; false once `context` is cancelled, so
/// shutdown never waits on a retry.
fn wait_unless_cancelled(context: &IpcOperationContext, total: Duration) -> bool {
    let deadline = Instant::now() + total;
    loop {
        if context.is_cancelled() {
            return false;
        }
        let now = Instant::now();
        if now >= deadline {
            return true;
        }
        std::thread::sleep((deadline - now).min(Duration::from_millis(200)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    fn result(name: &str, outcome: ProvisioningOutcome) -> ProvisioningResult {
        ProvisioningResult {
            name: name.to_owned(),
            outcome,
        }
    }

    fn busy() -> ProvisioningOutcome {
        ProvisioningOutcome::Busy(bloom_petals::PetalError::Busy.to_string())
    }

    /// The store's busy refusal is recognised under the install's context,
    /// and nothing else is.
    #[test]
    fn a_busy_refusal_is_recognised_through_its_context() {
        let refused = anyhow::Error::new(bloom_petals::PetalError::Busy)
            .context("install pre-built Petal package");
        assert!(is_busy(&refused));
        assert!(!is_busy(
            &anyhow::Error::new(bloom_petals::PetalError::vm("Petal install cancelled"))
                .context("install pre-built Petal package")
        ));
        assert!(!is_busy(&anyhow!("offline")));
    }

    /// Only the busy install is tried again, with a doubling wait, until it
    /// goes in; each round's results are passed on.
    #[test]
    fn a_busy_install_is_tried_again_until_it_goes_in() {
        let first = [
            result("polymarket", ProvisioningOutcome::Installed),
            result("enso", busy()),
            result("feedback", ProvisioningOutcome::Failed("offline".into())),
        ];
        let rounds = RefCell::new(Vec::new());
        let waits = RefCell::new(Vec::new());
        let reported = RefCell::new(Vec::new());
        retry_busy_with(
            &first,
            |names| {
                rounds.borrow_mut().push(names.join(","));
                let outcome = if rounds.borrow().len() < 3 {
                    busy()
                } else {
                    ProvisioningOutcome::Installed
                };
                names
                    .iter()
                    .map(|name| result(name, outcome.clone()))
                    .collect()
            },
            |wait| {
                waits.borrow_mut().push(wait.as_secs());
                true
            },
            |results| {
                reported.borrow_mut().extend(
                    results
                        .iter()
                        .map(|result| format!("{}={:?}", result.name, result.outcome)),
                );
            },
        );
        assert_eq!(*rounds.borrow(), ["enso", "enso", "enso"]);
        assert_eq!(*waits.borrow(), [1, 2, 4]);
        assert_eq!(reported.borrow().last().unwrap(), "enso=Installed");
    }

    /// A Petal that stays busy is tried each round, the wait growing to its
    /// cap; stopping Machine ends the retries, and nothing busy means no wait.
    #[test]
    fn retries_back_off_to_a_cap_and_stop_with_machine() {
        let rounds = Cell::new(0);
        let waits = RefCell::new(Vec::new());
        retry_busy_with(
            &[result("enso", busy())],
            |names| {
                rounds.set(rounds.get() + 1);
                names.iter().map(|name| result(name, busy())).collect()
            },
            |wait| {
                waits.borrow_mut().push(wait.as_secs());
                waits.borrow().len() < 9
            },
            |_| {},
        );
        assert_eq!(*waits.borrow(), [1, 2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(rounds.get(), 8, "every round but the stopped one tries");

        let waited = Cell::new(false);
        retry_busy_with(
            &[result("enso", ProvisioningOutcome::Installed)],
            |_| unreachable!(),
            |_| {
                waited.set(true);
                true
            },
            |_| {},
        );
        assert!(!waited.get());
    }

    /// An install stopped because Machine is stopping says so and gives no
    /// restart advice; nothing more is downloaded.
    #[test]
    fn a_cancelled_install_gives_no_restart_advice() {
        let home = tempfile::tempdir().unwrap();
        let daemon = Daemon::from_home(bloom_proto::HomeDir::at(home.path())).unwrap();
        let context = IpcOperationContext::detached();
        context.cancel();
        let results = provision_with(
            &daemon,
            &context,
            &["enso"],
            |name| github_source::preinstalled_petal(name).copied(),
            |_, _, _| unreachable!("nothing is downloaded once Machine is stopping"),
        );
        assert!(
            matches!(&results[0].outcome,
                ProvisioningOutcome::Failed(message) if message == "default provisioning cancelled"),
            "{results:?}"
        );
    }

    #[test]
    fn canonical_defaults_ignore_legacy_config_and_failures_are_per_entry() {
        let home = tempfile::tempdir().unwrap();
        let mut daemon = Daemon::from_home(bloom_proto::HomeDir::at(home.path())).unwrap();
        let context = IpcOperationContext::detached();
        for legacy in [vec![], vec!["unknown".into()], vec!["enso".into()]] {
            daemon.config.petals.preinstalled = legacy;
            let acquired = std::cell::RefCell::new(Vec::new());
            let results = provision_with(
                &daemon,
                &context,
                github_source::DEFAULT_PETALS,
                |name| github_source::preinstalled_petal(name).copied(),
                |_, entry, _| {
                    acquired.borrow_mut().push(entry.name);
                    bail!("offline fixture")
                },
            );
            assert_eq!(
                *acquired.borrow(),
                [
                    "polymarket",
                    "hyperliquid",
                    "enso",
                    "near-intents",
                    "feedback"
                ]
            );
            assert_eq!(results.len(), 5);
            assert!(results.iter().all(|result| matches!(&result.outcome,
                ProvisioningOutcome::Failed(message) if message.contains("download default")
                    && message.ends_with("restart Bloom to try again"))));
        }
    }
}
