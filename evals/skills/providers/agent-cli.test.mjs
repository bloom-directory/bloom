import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { resolveCli } from './agent-cli.mjs';

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
