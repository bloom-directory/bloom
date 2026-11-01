# Distributing the Bloom skill

`skills/bloom/` is the canonical package for the website and marketplaces.
The entrypoint connects an existing Bloom session or routes new installations to
`references/install.md`. The reviewed installer lives in `scripts/setup.sh`.
Operating procedures belong in the installed VFS, not in marketplace copies.

Installing the skill does not install Bloom or create a wallet. Check both
existing-session use and new-install guidance when changing it. Keep setup's
signature checks and platform-specific privileged handoff intact.

## Website

The private `bloom-directory/website` repository consumes this public package at
an exact commit. Advance its skill revision after the Bloom PR lands, using the
landed commit rather than the PR head. Its build publishes `SKILL.md`, the install
reference, and setup script; `/setup.sh` remains the existing installation URL.
Do not edit generated website copies.

## skills.sh

The public repository is sufficient; no marketplace login or separate repository
is needed. Check discovery before sharing the command:

```sh
npx skills add bloom-directory/bloom --skill bloom --list
npx skills add bloom-directory/bloom --skill bloom
```

The directory lists skills through installation telemetry; listing and ranking
are not an endorsement. See <https://skills.sh/docs/faq>.

Hermes users can also install the package directly:

```sh
hermes skills install bloom-directory/bloom/skills/bloom
```

## ClawHub

Publish this same folder, not the website output or the repository root. A human
signs in to ClawHub with the GitHub identity that should own the listing:

```sh
npx clawhub login
npx clawhub whoami
npx clawhub skill publish ./skills/bloom --slug bloom --name "Bloom Wallet" --version 0.5.0 --changelog "Connect to Bloom and follow its filesystem guidance" --dry-run
```

After the Bloom PR lands, check the account and slug ownership, review the dry
run, and repeat the publish command without `--dry-run`. If the slug is owned
by someone else, resolve ownership or choose an agreed alternative; do not
publish under a misleading identity. Check the resulting listing's scan state
and installation before announcing it.

Keep credentials out of the repository. Do not create a publishing workflow or
store an API token until recurring releases justify automation. See
<https://docs.openclaw.ai/clawhub/quickstart> for the current authentication and
publishing flow.
