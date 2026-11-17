# Distributing the Bloom skill

`skills/bloom/` is the canonical package for the website and marketplaces. It
contains only `SKILL.md`, which connects an existing Bloom session and links
the install guide for new installations. The guide, `install/install.md`, and
its reviewed `install/setup.sh` live outside the package and are served by the
website. Operating procedures belong in the installed VFS, not in marketplace
copies.

Keep privileged commands out of `skills/bloom/`. Marketplaces scan every file
in the package (ClawHub runs SkillSpector and ClawScan; skills.sh shows Gen,
Socket, and Snyk audits), and the root installer's `sudo`/`pkexec` commands
there made ClawHub rate v0.5.0 suspicious. Check each listing's scan result
after publishing.

Installing the skill does not install Bloom or create a wallet. Check both
existing-session use and new-install guidance when changing them. The
[skill evals](../evals/skills/README.md) grade new-install responses; CI runs
their deterministic `check`, and model runs are manual. Keep setup's
signature checks and platform-specific privileged handoff intact.

## Website

The private `bloom-directory/website` repository consumes these files at an
exact commit. Advance its revision after the Bloom PR lands, using the landed
commit rather than the PR head. Its build publishes `SKILL.md`, and serves
`install/install.md` and `install/setup.sh` at the paths the skill and guide
link: `/references/install.md` and `/scripts/setup.sh` (`/setup.sh` remains a
copy for existing links). Do not edit generated website copies.

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

## Claude Code

`skills/bloom/` is also a Claude Code plugin: `.claude-plugin/plugin.json`
makes the folder a plugin whose root `SKILL.md` loads as the `bloom:bloom`
skill, and its `README.md` is the directory listing. The repository's
`.claude-plugin/marketplace.json` lists it, so users can install it before the
directory lists it:

```sh
/plugin install bloom --marketplace bloom-directory/bloom
```

Check both after changing the folder:

```sh
claude plugin validate ./skills/bloom
claude plugin validate .
```

Anthropic's plugin directory follows the default branch from the developer
portal (<https://claude.ai/directory/manage>, plugin path `skills/bloom`). A
merged change that passes its scan is published; a held or failed version
keeps the previous one live. The Propose Release workflow sets the plugin's
`version` with the skill's.

## ClawHub

Publish this folder from the release tag, without `.claude-plugin/`: ClawHub
refuses a folder with a plugin manifest as a skill. A human signs in to ClawHub
with the GitHub identity that should own the listing:

```sh
npx clawhub login
npx clawhub whoami
stage="$(mktemp -d)"
git archive vX.Y.Z skills/bloom ':(exclude)skills/bloom/.claude-plugin' | tar -x -C "$stage"
npx clawhub skill publish "$stage/skills/bloom" --slug bloom --name "Bloom" --owner bloom-directory --version X.Y.Z --changelog "Bloom vX.Y.Z" --dry-run
```

The listing is <https://clawhub.ai/bloom-directory/skills/bloom>, owned by the
`@bloom-directory` publisher. Slugs are per owner, and another publisher also
has a `bloom` skill, so users install ours with
`clawhub install @bloom-directory/bloom`.

Publish from the release tag, with the release version (the skill's
`metadata.version`). ClawHub never reuses a version number, even a withdrawn
one; republish a corrected skill for the same release as `X.Y.Z+N`, then move
`latest` with `npx clawhub skill tag @bloom-directory/bloom X.Y.Z+N`. Review
the dry run, repeat the publish command without `--dry-run`, and check the
stored scans before announcing it. Name the owner in every command; a bare
`bloom` is ambiguous:

```sh
npx clawhub scan download @bloom-directory/bloom --version X.Y.Z -o scan.zip
```

Keep credentials out of the repository. Do not create a publishing workflow or
store an API token until recurring releases justify automation. See
<https://docs.openclaw.ai/clawhub/quickstart> for the current authentication and
publishing flow.

## Releases

The skill's `metadata.version` is the Bloom release version; the Propose
Release workflow bumps it with `Cargo.toml`. After tagging `vX.Y.Z`:

1. Publish to ClawHub from the tag, as above.
2. Repin the website to the tag's commit.
3. Test the upgrade in a clean `HOME` that has the previous release's skill
   installed: `npx skills update -g -y` and `npx clawhub update @bloom-directory/bloom` must
   leave `metadata.version: X.Y.Z` in the installed `SKILL.md`, and the
   Connect command must still work against an upgraded Bloom. v0.4.2 is the
   first skill release, so it gets a fresh-install check instead; upgrade
   tests start at v0.5.0.
