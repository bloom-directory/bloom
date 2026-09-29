//! One best-effort pass per daemon start. Installation is not signing authorization.
use anyhow::{Context, Result, anyhow, bail};
use bloom_daemon::{Daemon, ipc::IpcOperationContext};

use crate::github_source::{self, PreinstalledPetal, PreinstalledState, PreparedReleasePetal};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProvisioningResult {
    pub name: String,
    pub outcome: ProvisioningOutcome,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProvisioningOutcome {
    Current,
    Installed,
    Failed(String),
}

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
            let prepared = acquire(daemon, &entry, context).with_context(|| {
                format!("acquire default {name}; retry with `bloom init` or `bloom petals install`")
            })?;
            prepared.commit(daemon, context, Some(expected_owner))?;
            Ok(ProvisioningOutcome::Installed)
        };
        let outcome = match attempt() {
            Ok(outcome) => outcome,
            Err(error) => ProvisioningOutcome::Failed(format!("{error:#}")),
        };
        match &outcome {
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

#[cfg(test)]
mod tests {
    use super::*;

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
                    "tolly",
                    "feedback"
                ]
            );
            assert_eq!(results.len(), 6);
            assert!(results.iter().all(|result| matches!(&result.outcome,
                ProvisioningOutcome::Failed(message) if message.contains("acquire default"))));
        }
    }
}
