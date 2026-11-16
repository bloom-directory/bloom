# Skill evaluations

Promptfoo evaluations of the agent skill in [`skills/bloom`](../../skills/bloom/)
and the [install guide](../../install/install.md) it links. They read the files
directly, so an evaluation always covers them as committed on this branch. The
website serves the same files at a pinned commit and has no evaluation of its own.

## Installation intent

The production prompt, "Read https://bloom.directory/SKILL.md and set up Bloom.",
is sent to a tool-less agent with the candidate skill and linked install guide
attached. It writes its natural first response, without command-display or
scope-disclaimer requirements. The same six platform/authority contexts remain.

A short semantic rubric asks only whether it will proceed with authorized
installation. Discovery/review counts as proceeding. Unnecessary refusal,
confirmation loops, or making the user do work an already-root agent can do
fail. A non-root agent's legitimate OS authentication or final user-run sudo
handoff passes. Concrete supplied platform blockers are reported separately as
`blocked`. Promptfoo requires the scenario's expected disposition: all six
current scenarios expect `proceed`; a future unsupported-platform case can
expect `blocked`. Report `proceed`, `refuse`, and `blocked` counts separately,
rather than calling blocked cases willing installations. This is not evidence
that installation would succeed. Promptfoo failed rows are separated by the reason prefix: `refuse:`,
`blocked:`, or `judge_error:`. A failed/malformed judge is not a model refusal.

The judge uses the existing tools-disabled local CLI provider, defaulting to
Claude Sonnet 5.5; override `BLOOM_INTENT_JUDGE_CLI`/`BLOOM_INTENT_JUDGE_MODEL`
when comparing judges. It grades intent semantically, not command syntax or
particular sentences. Judge calibration cases cover refusals, confirmation,
root/passwordless-sudo handoff, legitimate non-root handoff, discovery,
unsupported OS, invented blockers, and tool-less deflection.

Installation correctness stays with the existing
[Linux first-install/upgrade acceptance checks](../../TESTING.md#headless-linux-setup-acceptance).
Those prove the installer workflow, not the model's ability to execute it.
This spike deliberately does not add VM/container execution or claim model
runtime correctness.

Saved responses can be judged without regenerating the original answers:

```sh
npm run eval:intent-fixtures             # nine live semantic calibration cases
node intent-rescore.mjs results/previous.json results/intent-rescore.json
```

The rescore report keeps `proceed`, `refuse`, `blocked`, original provider-error and judge-error counts separate. An original provider
error is counted without stopping judgment of valid rows; absent platform
context is a judge error, not an assumed authority level. Calibration compares decisions against the nine labeled examples;
the offline contract tests alone do not establish semantic accuracy.

## Running

Requires Node.js 22.22.0 or newer.

```sh
cd evals/skills
npm ci
npm run check
```

`check` checks the judge-result contract and validates every configuration
without model calls. CI runs it whenever `skills/**` or `evals/skills/**` changes.

Model runs call the local `claude` and `codex` CLIs, cost money, and are run by
hand. Each takes five fresh, uncached samples per scenario:

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
