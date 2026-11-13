import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { resolveCli, runCommand } from './agent-cli.mjs';

// Promptfoo bundles an older `codex` in node_modules/.bin, which npm puts first
// on PATH. The provider must skip it and run the user's CLI.
const root = mkdtempSync(join(tmpdir(), 'bloom-agent-cli-test-'));
try {
  const bundled = join(root, 'node_modules', '.bin');
  const user = join(root, 'user-bin');
  for (const dir of [bundled, user]) {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'codex'), '#!/bin/sh\n');
    chmodSync(join(dir, 'codex'), 0o755);
  }
  const PATH = [bundled, user].join(delimiter);
  assert.equal(resolveCli('codex', { PATH }), join(user, 'codex'));
  assert.equal(resolveCli('codex', { PATH, BLOOM_CODEX_BIN: '/opt/codex' }), '/opt/codex');
  assert.throws(() => resolveCli('codex', { PATH: bundled }), /BLOOM_CODEX_BIN/);
  console.log('agent CLI resolution: 3 passed');
} finally {
  rmSync(root, { force: true, recursive: true });
}

// Preserve enough process information to distinguish a failure from a timeout.
const successful = await runCommand('/bin/sh', ['-c', 'printf output'], '', '/tmp', 2000);
assert.equal(successful.stdout, 'output');
assert.equal(successful.diagnostics.exitCode, 0);
assert.equal(successful.diagnostics.timedOut, false);
for (const [args, timeoutMs, check] of [
  [['-c', 'printf details >&2; exit 7'], 2000, (error) => {
    assert.equal(error.diagnostics.exitCode, 7);
    assert.equal(error.stderr, 'details');
    assert.equal(error.diagnostics.timedOut, false);
  }],
  [['-c', 'exec /bin/sleep 10'], 100, (error) => {
    assert.equal(error.diagnostics.timedOut, true);
    assert.equal(error.diagnostics.signal, 'SIGTERM');
    assert.equal(error.diagnostics.killed, true);
    assert.ok(error.diagnostics.elapsedMs >= 100);
    assert.equal(error.diagnostics.timeoutMs, 100);
  }],
]) {
  await assert.rejects(runCommand('/bin/sh', args, '', '/tmp', timeoutMs), (error) => { check(error); return true; });
}
console.log('CLI process diagnostics: 3 passed');
