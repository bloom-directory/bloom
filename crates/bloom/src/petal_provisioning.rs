//! One best-effort pass per daemon start, then retries of installs refused
//! because other Petal code was running or whose download failed.
//! Installation is not signing authorization.
use std::collections::HashMap;
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
    /// activated; [`retry_pending`] tries it again while Machine runs.
    Busy(String),
    /// A release file could not be downloaded; [`retry_pending`] tries it
    /// again up to [`DOWNLOAD_RETRIES`] times. A failed check of what was
    /// downloaded is [`Self::Failed`].
    DownloadFailed(String),
    Failed(String),
}

/// The first wait before an install is tried again. It doubles up to
/// [`RETRY_MAX`], then stays there while Machine runs.
const RETRY_FIRST: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(60);
/// How many times a failed download is tried again, about a minute in all,
/// before Bloom says to restart it.
const DOWNLOAD_RETRIES: usize = 6;
/// How long a retried install, downloaded and staged, queues for its turn to
/// activate: running Petal calls finish, and calls starting meanwhile wait
/// behind it, so no Petal call waits longer than this for an install.
/// Calls that outlast it leave the install busy until the next retry.
const QUEUE_WAIT: Duration = Duration::from_secs(3);

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
            Err(error)
                if error
                    .downcast_ref::<github_source::DownloadFailed>()
                    .is_some() =>
            {
                ProvisioningOutcome::DownloadFailed(format!("{error:#}"))
            }
            Err(error) => ProvisioningOutcome::Failed(with_restart_advice(&format!("{error:#}"))),
        };
        match &outcome {
            ProvisioningOutcome::Busy(error) => {
                tracing::info!(petal = %name, %error, "petal.provisioning_busy");
            }
            ProvisioningOutcome::DownloadFailed(error) => {
                tracing::info!(petal = %name, %error, "petal.provisioning_download_failed");
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

/// Machine installs the catalog when it starts. `bloom init` and a repository
/// install are no help on a running home: the first cannot open it, and the
/// second builds a different package from the one the catalog pins.
fn with_restart_advice(error: &str) -> String {
    format!("{}; restart Bloom to try again", error.trim_end())
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

/// Try again each catalog Petal in `first` whose install was refused because
/// other Petal code was running, such as setup writing Polymarket's settings
/// right after `bloom wallet new`, until it installs, fails for another
/// reason, or Machine stops. A Petal whose download failed is tried again
/// [`DOWNLOAD_RETRIES`] times. A retry queues briefly for its turn to
/// activate ([`IpcOperationContext::waiting_to_activate`], up to
/// [`QUEUE_WAIT`]): running Petal calls finish, and calls starting meanwhile
/// wait behind it, so agents calling Petals back to back cannot starve it,
/// while no call waits on it for long. `on_retried` receives each round's
/// results, so setup's settings are written once a chosen Petal installs.
pub(crate) fn retry_pending(
    daemon: &Daemon,
    context: &IpcOperationContext,
    first: &[ProvisioningResult],
    on_retried: impl FnMut(&[ProvisioningResult]),
) {
    let waiting = context.waiting_to_activate(QUEUE_WAIT);
    retry_pending_with(
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

/// [`retry_pending`] with its rounds and waits supplied. `wait` returns false
/// once Machine is stopping.
fn retry_pending_with(
    first: &[ProvisioningResult],
    mut round: impl FnMut(&[&str]) -> Vec<ProvisioningResult>,
    mut wait: impl FnMut(Duration) -> bool,
    mut on_retried: impl FnMut(&[ProvisioningResult]),
) {
    let mut downloads = HashMap::<String, usize>::new();
    let mut pending = pending_names(first, &mut downloads);
    let mut delay = RETRY_FIRST;
    while !pending.is_empty() {
        if !wait(delay) {
            return;
        }
        delay = (delay * 2).min(RETRY_MAX);
        let names: Vec<&str> = pending.iter().map(String::as_str).collect();
        let results = round(&names);
        on_retried(&results);
        pending = pending_names(&results, &mut downloads);
    }
}

/// The Petals in `results` to try again: every busy one, and each whose
/// download failed until it has been retried [`DOWNLOAD_RETRIES`] times.
/// `downloads` counts the failed downloads so far.
fn pending_names(
    results: &[ProvisioningResult],
    downloads: &mut HashMap<String, usize>,
) -> Vec<String> {
    let mut pending = Vec::new();
    for result in results {
        match &result.outcome {
            ProvisioningOutcome::Busy(_) => pending.push(result.name.clone()),
            ProvisioningOutcome::DownloadFailed(error) => {
                let failures = downloads.entry(result.name.clone()).or_default();
                *failures += 1;
                if *failures <= DOWNLOAD_RETRIES {
                    pending.push(result.name.clone());
                } else {
                    let error = with_restart_advice(error);
                    tracing::warn!(petal = %result.name, %error, "petal.provisioning_failed");
                }
            }
            _ => {}
        }
    }
    pending
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
        retry_pending_with(
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
        retry_pending_with(
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
        retry_pending_with(
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

    /// A failed download is tried again a bounded number of times, alongside
    /// a busy Petal that keeps being retried; a download that then works
    /// installs.
    #[test]
    fn a_failed_download_is_tried_again_a_few_times() {
        let failed =
            || ProvisioningOutcome::DownloadFailed("download default enso: offline".into());
        let rounds = RefCell::new(Vec::new());
        retry_pending_with(
            &[result("enso", failed()), result("polymarket", busy())],
            |names| {
                rounds.borrow_mut().push(names.join(","));
                names
                    .iter()
                    .map(|&name| result(name, if name == "enso" { failed() } else { busy() }))
                    .collect()
            },
            |_| rounds.borrow().len() < DOWNLOAD_RETRIES + 2,
            |_| {},
        );
        let rounds = rounds.into_inner();
        assert_eq!(rounds.len(), DOWNLOAD_RETRIES + 2);
        assert!(
            rounds[..DOWNLOAD_RETRIES]
                .iter()
                .all(|round| round == "enso,polymarket")
        );
        assert!(
            rounds[DOWNLOAD_RETRIES..]
                .iter()
                .all(|round| round == "polymarket")
        );

        let tried = Cell::new(0);
        let installed = RefCell::new(Vec::new());
        retry_pending_with(
            &[result("enso", failed())],
            |names| {
                tried.set(tried.get() + 1);
                let outcome = if tried.get() < 2 {
                    failed()
                } else {
                    ProvisioningOutcome::Installed
                };
                names
                    .iter()
                    .map(|name| result(name, outcome.clone()))
                    .collect()
            },
            |_| true,
            |results| {
                installed
                    .borrow_mut()
                    .extend(results.iter().map(|r| r.outcome.clone()))
            },
        );
        assert_eq!(tried.get(), 2);
        assert_eq!(
            installed.borrow().last(),
            Some(&ProvisioningOutcome::Installed)
        );
    }

    /// A failed download is marked for retry under the attempt's context,
    /// with no restart advice yet; a failed check of what was downloaded,
    /// which another attempt cannot change, fails at once with it.
    #[test]
    fn only_a_failed_download_is_reported_for_retry() {
        let home = tempfile::tempdir().unwrap();
        let daemon = Daemon::from_home(bloom_proto::HomeDir::at(home.path())).unwrap();
        let attempt = |error: fn() -> anyhow::Error| {
            provision_with(
                &daemon,
                &IpcOperationContext::detached(),
                &["enso"],
                |name| github_source::preinstalled_petal(name).copied(),
                |_, _, _| Err(error()),
            )
            .remove(0)
            .outcome
        };
        assert_eq!(
            attempt(|| anyhow!("curl failed: offline")
                .context(github_source::DownloadFailed::of("https://example.test/enso.tar.gz"))),
            ProvisioningOutcome::DownloadFailed(
                "download default enso: download https://example.test/enso.tar.gz: curl failed: offline"
                    .into()
            )
        );
        assert_eq!(
            attempt(|| anyhow!("checksum mismatch\n")),
            ProvisioningOutcome::Failed(
                "download default enso: checksum mismatch; restart Bloom to try again".into()
            )
        );
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
