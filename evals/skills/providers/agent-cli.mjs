import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SUPPORTED_CLIS = new Set(['claude', 'codex']);

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
          'claude',
          args,
          prompt,
          workdir,
          timeoutMs,
          options?.abortSignal,
        );
        return {
          output: stdout.trim(),
          metadata: { cli, model: model || 'default' },
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
        'codex',
        args,
        prompt,
        workdir,
        timeoutMs,
        options?.abortSignal,
      );
      return {
        output: (await readFile(outputPath, 'utf8')).trim(),
        metadata: { cli, model: model || 'default' },
      };
    } catch (error) {
      return { error: `${cli} evaluation failed${model ? ` (${model})` : ''}: ${errorMessage(error)}` };
    } finally {
      await rm(workdir, { force: true, recursive: true });
    }
  }
}
