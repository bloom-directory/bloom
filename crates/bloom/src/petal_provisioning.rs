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
        |name| github_source::preinstalled_petal(name).copied(),
        github_source::prepare_prebuilt_release_petal,
    )
}

pub(crate) fn provision_with(
    daemon: &Daemon,
    context: &IpcOperationContext,
    resolve: impl Fn(&str) -> Option<PreinstalledPetal>,
    acquire: impl Fn(&Daemon, &PreinstalledPetal, &IpcOperationContext) -> Result<PreparedReleasePetal>,
) -> Vec<ProvisioningResult> {
    let mut results = Vec::new();
    for name in &daemon.config.petals.preinstalled {
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
            name: name.clone(),
            outcome,
        });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_defaults_are_network_free_and_failures_are_per_entry() {
        let home = tempfile::tempdir().unwrap();
        let mut daemon = Daemon::from_home(bloom_proto::HomeDir::at(home.path())).unwrap();
        daemon.config.petals.preinstalled.clear();
        let context = IpcOperationContext::detached();
        assert!(
            provision_with(
                &daemon,
                &context,
                |_| panic!("empty defaults"),
                |_, _, _| panic!("no acquisition")
            )
            .is_empty()
        );
        daemon.config.petals.preinstalled = vec!["unknown".into(), "enso".into()];
        for _ in 0..2 {
            let results = provision(&daemon, &context);
            assert_eq!(results.len(), 2);
            assert!(
                matches!(&results[0].outcome, ProvisioningOutcome::Failed(message) if message.contains("unknown"))
            );
            assert!(
                matches!(&results[1].outcome, ProvisioningOutcome::Failed(message) if message.contains("not eligible"))
            );
        }
    }
}
