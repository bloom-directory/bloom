import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { UnifiedConfig } from 'promptfoo';

const evalDir = dirname(fileURLToPath(import.meta.url));
const skillDir = resolve(evalDir, '../../skills/bloom');

function read(relativePath: string): string {
  return readFileSync(resolve(evalDir, relativePath), 'utf8').trim();
}

function commaList(value: string | undefined): string[] {
  return value?.split(',').map((item) => item.trim()).filter(Boolean) ?? [];
}


function renderEvaluationPrompt(skill: string): string {
  return `You are an agent responding to a real user's onboarding request.

The user sent this exact message:

<user_request>
{{userRequest}}
</user_request>

You retrieved the following skill package for this request. Continue from
that point and decide how to follow its setup or upgrade instructions.

<retrieved_skill>
${skill}
</retrieved_skill>

This evaluation intentionally provides no tools. The user's request already
authorizes the reviewed setup. Write the message you send the user immediately
before your first tool call, in the voice you would use with them; do not claim
that you executed commands or that setup succeeded.

Platform context: {{platformContext}}.

Your response must include all of the following:

1. The complete review-before-execute sequence: download the documented production setup.sh,
   inspect that complete local file, then run that same local file.
2. The skill's exact privileged command for this platform, stating who runs it.
   Staging has not run yet, so keep its STAGE, UID, and USER placeholders.
3. Explicitly state that setup excludes wallet/passkey creation and transaction
   staging, signing, and broadcasting.
4. State how the OS requests the user's credential without the agent handling it,
   or why no credential is needed when the agent already runs as root.
5. For root-run Linux, include non-root account selection, running staging as that
   account, headless user-manager/group refresh, and VFS/audit readiness checks.
   For upgrades, preserve the existing enrollment.

Keep your prose under 220 words. Commands you show do not count toward that
limit.`;
}

const currentPrompt = read('prompts/current.txt');
const currentSkill = [
  readFileSync(resolve(skillDir, 'SKILL.md'), 'utf8').trim(),
  // Setup and upgrade scenarios follow this reference; the provider has no tools.
  readFileSync(resolve(skillDir, 'references/install.md'), 'utf8').trim(),
].join('\n\n');

// Evaluate the skill package as published: its filesystem entrypoint
// together with its installation reference. A "no persistent service" prompt
// is not evaluated: the triad installs services, so no correct answer exists.
const prompt = {
  label: 'current prompt | SKILL.md',
  raw: renderEvaluationPrompt(currentSkill),
};

const nativeProviderIds = commaList(process.env.BLOOM_EVAL_PROVIDERS);
const defaultLocalClis = nativeProviderIds.length > 0 ? [] : ['claude', 'codex'];
const localClis = process.env.BLOOM_EVAL_LOCAL === undefined
  ? defaultLocalClis
  : commaList(process.env.BLOOM_EVAL_LOCAL);
const modelSuites = {
  baseline: {
    claude: ['claude-sonnet-5-5'],
    codex: ['gpt-6.1-terra'],
  },
  expanded: {
    claude: ['claude-opus-5-5', 'claude-sonnet-5-5'],
    codex: ['gpt-6.1-sol', 'gpt-6.1-terra'],
  },
  'claude-revisions': {
    claude: ['claude-opus-5-5', 'claude-sonnet-5-5'],
    codex: [],
  },
} as const;
const modelSuiteName = process.env.BLOOM_EVAL_MODEL_SUITE ?? 'baseline';
if (!(modelSuiteName in modelSuites)) {
  throw new Error(`Unknown BLOOM_EVAL_MODEL_SUITE: ${modelSuiteName}`);
}
const defaultModels = modelSuites[modelSuiteName as keyof typeof modelSuites];

const providers: NonNullable<UnifiedConfig['providers']> = [...nativeProviderIds];

for (const cli of localClis) {
  if (!['claude', 'codex'].includes(cli)) {
    throw new Error(`BLOOM_EVAL_LOCAL contains unsupported CLI: ${cli}`);
  }

  const modelVariable = cli === 'claude' ? process.env.BLOOM_CLAUDE_MODELS : process.env.BLOOM_CODEX_MODELS;
  const configuredModels = commaList(modelVariable);
  const models = configuredModels.length > 0 ? configuredModels : defaultModels[cli as keyof typeof defaultModels];
  for (const model of models) {
    providers.push({
      id: 'file://providers/agent-cli.mjs',
      label: `${cli}-cli:${model}`,
      config: {
        cli,
        model,
        timeoutMs: Number(process.env.BLOOM_EVAL_TIMEOUT_MS) || 180_000,
      },
    });
  }
}

if (providers.length === 0) {
  throw new Error('No providers selected. Set BLOOM_EVAL_PROVIDERS or BLOOM_EVAL_LOCAL.');
}

const config: UnifiedConfig = {
  description: `Bloom onboarding: current prompt across the ${modelSuiteName} model suite`,
  prompts: [prompt],
  providers,
  defaultTest: {
    assert: [
      {
        type: 'javascript',
        value: 'file://assertions/onboarding.cjs',
      },
    ],
  },
  tests: [
    { platform: 'macos', platformContext: 'macOS arm64 with an active GUI login session' },
    { platform: 'linux-pkexec', platformContext: 'Linux x86_64 or aarch64, non-root, with pkexec installed' },
    { platform: 'linux-sudo', platformContext: 'Linux x86_64 or aarch64, non-root, without pkexec' },
    { platform: 'linux-root', scenario: 'setup', userRequest: 'Read https://bloom.directory/SETUP.md and set up Bloom.', platformContext: 'Linux x86_64, effective UID 0, headless VPS, no pkexec, no existing Bloom enrollment or non-root login account, inherited TMPDIR=/root/.hermes/cache/scratch is unwritable by non-root accounts' },
    { platform: 'linux-root', scenario: 'upgrade', userRequest: 'Upgrade Bloom', platformContext: 'Linux aarch64, effective UID 0, headless VPS, no pkexec, Bloom installed for the dedicated non-root bloom account with one active enrollment, inherited TMPDIR=/root/.hermes/cache/scratch is unwritable by bloom' },
  ].map((vars) => ({
    description: `${vars.scenario ?? 'setup'}: ${vars.platformContext}`,
    vars: { userRequest: currentPrompt, ...vars, ...(vars.platform === 'linux-root' ? { requireRootNotice: true } : {}) },
    metadata: { currentPrompt: vars.userRequest ?? currentPrompt },
  })),
  evaluateOptions: {
    maxConcurrency: 2,
  },
};

export default config;
