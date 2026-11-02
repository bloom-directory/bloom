import { execFile } from 'node:child_process';
import { accessSync, constants } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, join, sep } from 'node:path';

const SUPPORTED_CLIS = new Set(['claude', 'codex']);
const BIN_OVERRIDES = { claude: 'BLOOM_CLAUDE_BIN', codex: 'BLOOM_CODEX_BIN' };

// npm and bun put node_modules/.bin first on PATH, and Promptfoo's optional
// @openai/codex-sdk installs its own, older `codex` there. That copy does not
// know current models, so the ChatGPT backend rejects them as model_not_found.
// Evaluate the agent CLI the user actually runs: skip node_modules/.bin unless
// BLOOM_CLAUDE_BIN or BLOOM_CODEX_BIN names an exact executable.
export function resolveCli(cli, env = process.env) {
  const override = env[BIN_OVERRIDES[cli]];
  if (override) return override;
  const nodeBin = `${sep}node_modules${sep}.bin`;
  for (const dir of (env.PATH ?? '').split(delimiter)) {
    if (!dir || dir.endsWith(nodeBin) || dir.includes(`${nodeBin}${sep}`)) continue;
    const candidate = join(dir, cli);
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {}
  }
  throw new Error(`${cli} CLI not found on PATH outside node_modules/.bin; set ${BIN_OVERRIDES[cli]}`);
}

function runCommand(command, args, input, cwd, timeoutMs, signal) {
  return new Promise((resolve, reject) => {
    const child = execFile(
      command,
      args,
      {
        cwd,
        env: process.env,
        maxBuffer: 20 * 1024 * 1024,
        signal,
        timeout: timeoutMs,
      },
      (error, stdout, stderr) => {
        if (error) {
          error.stderr = stderr;
          reject(error);
          return;
        }
        resolve({ stderr, stdout });
      },
    );

    child.stdin.end(input);
  });
}

function errorMessage(error) {
  const stderr = typeof error?.stderr === 'string' ? error.stderr.trim() : '';
  const detail = stderr ? `: ${stderr.slice(-2000)}` : '';
  return `${error?.message ?? String(error)}${detail}`;
}

export default class AgentCliProvider {
  constructor(options) {
    this.config = options.config ?? {};
    this.providerId = options.id ?? 'agent-cli';
  }

  id() {
    return this.providerId;
  }

  async callApi(prompt, _context, options) {
    const cli = this.config.cli;
    const model = this.config.model || '';
    const timeoutMs = Number(this.config.timeoutMs) || 180_000;

    if (!SUPPORTED_CLIS.has(cli)) {
      return { error: `Unsupported local agent CLI: ${cli}` };
    }

    let bin;
    try {
      bin = resolveCli(cli);
    } catch (error) {
      return { error: error.message };
    }
    const workdir = await mkdtemp(join(tmpdir(), 'bloom-onboarding-eval-'));

    try {
      if (cli === 'claude') {
        const args = [
          '-p',
          '--tools',
          '',
          '--permission-mode',
          'default',
          '--no-session-persistence',
          '--disable-slash-commands',
          '--no-chrome',
          '--output-format',
          'text',
        ];
        if (model) {
          args.push('--model', model);
        }

        const { stdout } = await runCommand(
          bin,
          args,
          prompt,
          workdir,
          timeoutMs,
          options?.abortSignal,
        );
        return {
          output: stdout.trim(),
          metadata: { cli, bin, model: model || 'default' },
        };
      }

      const outputPath = join(workdir, 'last-message.txt');
      const args = [
        'exec',
        '--ephemeral',
        '--ignore-user-config',
        '--ignore-rules',
        '--skip-git-repo-check',
        '--sandbox',
        'read-only',
        '--color',
        'never',
        '-C',
        workdir,
        '--output-last-message',
        outputPath,
      ];
      if (model) {
        args.push('--model', model);
      }
      args.push('-');

      await runCommand(
        bin,
        args,
        prompt,
        workdir,
        timeoutMs,
        options?.abortSignal,
      );
      return {
        output: (await readFile(outputPath, 'utf8')).trim(),
        metadata: { cli, bin, model: model || 'default' },
      };
    } catch (error) {
      return { error: `${cli} evaluation failed${model ? ` (${model})` : ''}: ${errorMessage(error)}` };
    } finally {
      await rm(workdir, { force: true, recursive: true });
    }
  }
}
