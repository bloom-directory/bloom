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

This evaluation provides no tools. Continue as you would for this user.
Write the message immediately before your first tool call.
Do not claim commands have run or setup has succeeded.

Platform context: {{platformContext}}.`;
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
  label: 'pre-tool response v1 | SKILL.md',
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
  description: `Bloom pre-tool response v1 across the ${modelSuiteName} model suite`,
  prompts: [prompt],
  providers,
  defaultTest: {
    assert: [
      {
        type: 'javascript',
        value: 'file://assertions/pre-tool.cjs',
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
    metadata: { currentPrompt: vars.userRequest ?? currentPrompt, responseContract: 'pre-tool-v1' },
  })),
  evaluateOptions: {
    maxConcurrency: 2,
  },
};

export default config;
