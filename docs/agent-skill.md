# Distributing the Bloom skill

`skills/bloom/` is the canonical package for the website and marketplaces.
The entrypoint connects an existing Bloom session or routes new installations to
`references/install.md`. The reviewed installer lives in `scripts/setup.sh`.
Operating procedures belong in the installed VFS, not in marketplace copies.

Installing the skill does not install Bloom or create a wallet. Check both
existing-session use and new-install guidance when changing it. The
[skill evals](../evals/skills/README.md) grade new-install responses; CI runs
their deterministic `check`, and model runs are manual. Keep setup's
signature checks and platform-specific privileged handoff intact.

## Website

The private `bloom-directory/website` repository consumes this public package at
an exact commit. Advance its skill revision after the Bloom PR lands, using the
landed commit rather than the PR head. Its build publishes `SKILL.md`, the install
reference, and `scripts/setup.sh`, which the skill fetches; `/setup.sh` remains a
copy for existing links.
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

## Claude, Codex, and Gemini

The repository root is also a plugin for each agent, so all three ship the
same `skills/bloom/` folder. Each manifest's `version` is the release version.

- **Claude Code:** `.claude-plugin/plugin.json` and `marketplace.json`. Users run
  `/plugin install bloom --marketplace bloom-directory/bloom`. Check with
  `claude plugin validate --strict .`. Anthropic's directory listing is
  submitted from <https://claude.ai/directory/manage> (paid plan) and reviewed
  there; see <https://code.claude.com/docs/en/plugins/publish.md>.
- **Codex:** `.codex-plugin/plugin.json`. OpenAI's directory takes a ZIP, not a
  repository URL, uploaded at <https://platform.openai.com/plugins> by a
  verified organization. Build it from the tag:

  ```sh
  git archive --format=zip -o bloom-codex-vX.Y.Z.zip vX.Y.Z \
    .codex-plugin skills/bloom docs/assets/bloom-icon.svg
  ```

  See <https://developers.openai.com/plugins/deploy/submission>.
- **Gemini CLI:** `gemini-extension.json`. The gallery at
  <https://geminicli.com/extensions> crawls tagged public repositories with the
  `gemini-cli-extension` topic daily. Users run
  `gemini extensions install https://github.com/bloom-directory/bloom`.

## ClawHub

Not published. The `bloom` slug belongs to an unrelated skill, and publishing
requires a GitHub sign-in. Revisit only if users ask for it.

## Releases

The skill's `metadata.version` is the Bloom release version; the Propose
Release workflow bumps it, and the three plugin manifests, with `Cargo.toml`. After tagging `vX.Y.Z`:

1. Repin the website to the tag's commit.
2. Upload the Codex ZIP from the tag and submit the Claude directory update,
   as above. Gemini picks up the tag on its own.
3. Test the upgrade in a clean `HOME` that has the previous release's skill
   installed: `npx skills update -g -y` must
   leave `metadata.version: "X.Y.Z"` in the installed `SKILL.md`, and the
   Connect command must still work against an upgraded Bloom. v0.4.2 is the
   first skill release, so it gets a fresh-install check instead; upgrade
   tests start at v0.5.0.
