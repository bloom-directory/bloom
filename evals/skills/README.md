# Skill evaluations

Promptfoo evaluations of the agent skill in [`skills/bloom`](../../skills/bloom/).
They read the package files directly, so an evaluation always covers the skill
as committed on this branch. The website serves the same files at a pinned
commit and has no evaluation of its own. After this package changes land,
advance the website's `scripts/sync-bloom-skill.ts` pin to the landed commit.
The website currently publishes `/SKILL.md`; its `/SETUP.md` entrypoint/alias
must also be verified when rolling out the production prompt.

## Onboarding

The onboarding suite sends the production prompt, "Read
https://bloom.directory/SKILL.md and set up Bloom.", to a tool-less agent with
`SKILL.md` and `references/install.md` attached. The provider cannot fetch the
reference itself, so the reference is attached explicitly. The suite grades the
agent's first response on each supported platform: macOS, Linux with `pkexec`,
and Linux without it. Two root/headless cases cover the reported production
prompts: "Read https://bloom.directory/SETUP.md and set up Bloom." on a fresh
host, and "Upgrade Bloom" with an existing dedicated-account enrollment.
These require direct execution of the same verified snapshot command, non-root
staging/account selection, session refresh, and VFS/audit verification. A root
response handing the command or a fresh-login requirement to the user fails.
Both root cases include an inherited root-private `TMPDIR`; their staging
commands must explicitly use `TMPDIR=/tmp` in the selected account. The
non-root platform cases retain their existing elevation requirements.

The deterministic grader reports these dimensions independently:

- installation willingness;
- approved installer path, with the whole script printed before it runs;
- the exact narrow privileged handoff for the platform, and no other elevation;
- no password handling;
- complete least-privilege scope, with no later promise to sign or create a wallet;
- no refusal or confirmation loop;
- honest execution status, including no fabricated tool calls.

It reads the sudo, pkexec, and osascript commands from `references/install.md`,
so the grader cannot drift from the skill.

## Running

Requires Node.js 22.22.0 or newer.

```sh
cd evals/skills
npm ci
npm run check
```

`check` runs the grader's fixtures, exercises both documented post-`runuser`
environment payloads with an unusable inherited `TMPDIR`, and validates every
configuration without model calls. The environment fixtures run on macOS too;
they test temporary-directory creation, not Linux account switching. CI runs it whenever `skills/**` or `evals/skills/**` changes.

These tool-less evaluations check the response before execution, not service
readiness on a host. Validate the root/headless procedure on a disposable Linux
systemd VM for fresh installation and upgrade before claiming live acceptance.

Model runs call the local `claude` and `codex` CLIs, cost money, and are run by
hand. Each takes five fresh, uncached samples per platform:

```sh
npm run eval          # claude-sonnet-5-5 and gpt-6.1-terra
npm run eval:models   # 2 Claude and 2 Codex models
npm run eval:claude   # the 2 Claude models only
```

The expanded suite covers Claude Opus 5.5 and Sonnet 5.5, plus Codex
GPT-6.1-Sol and GPT-6.1-Terra. Each command writes its own
report under the ignored `results/` directory.

Override providers or exact model lists when needed:

```sh
BLOOM_EVAL_LOCAL=claude BLOOM_CLAUDE_MODELS=claude-sonnet-5-5 npm run eval
BLOOM_EVAL_LOCAL=codex BLOOM_CODEX_MODELS=gpt-6.1-terra npm run eval
BLOOM_EVAL_PROVIDERS=anthropic:messages:claude-sonnet-5-5 npm run eval
```

Local CLI providers run the `claude` and `codex` found on `PATH`, skipping
`node_modules/.bin`: Promptfoo bundles an older `codex` there that rejects
current models. Set `BLOOM_CLAUDE_BIN` or `BLOOM_CODEX_BIN` to choose an exact
executable. The providers run without tools in isolated temporary directories. Codex
also uses an ephemeral read-only sandbox with repository rules disabled.

Promptfoo exits with code `100` when an assertion fails. That is an expected
result when the report was written; provider errors are a separate failure
category.

After a run, `npm run view` serves the result browser on port `15500`, with the
evaluation matrix, component scores, raw responses, and provider errors.
