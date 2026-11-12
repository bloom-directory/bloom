const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } = require('node:fs');
const { join, resolve } = require('node:path');

// Execute the published helper and review/staging sequence on any host. Stub
// only account switching and the download; real Linux acceptance uses runuser.
const skillDir = resolve(__dirname, '../../../skills/bloom');
const install = readFileSync(join(skillDir, 'references/install.md'), 'utf8');
const setup = readFileSync(join(skillDir, 'scripts/setup.sh'), 'utf8');
const helper = install.match(/^as_bloom\(\) \{\n[\s\S]*?^\}/m)[0];
const review = install.match(/^cd \/tmp\nreview_dir="\$\(as_bloom[^`]+/m)[0].trim();
const stage = install.match(/^as_bloom sh "\$review_dir\/setup.sh"[^`]+/m)[0].trim();
const root = mkdtempSync('/tmp/bloom argv fixture.');
const home = join(root, 'home with spaces');
mkdirSync(home);
const fixture = join(root, 'fixture.sh');
const stageTemp = setup.match(/^  tmp_dir=\$\(mktemp .+$/m)[0].trim();
writeFileSync(fixture, `set -eu\n${stageTemp}\nprintf 'STAGED_TMPDIR=%s\\n' "$TMPDIR"\nrmdir "$tmp_dir"\n`);
const shims = {
  runuser: '#!/bin/sh\nset -eu\ntest "$1" = -u\ntest "$2" = fixture\ntest "$3" = --\nshift 3\nexec "$@"\n',
  curl: '#!/bin/sh\nset -eu\ntest "$1" = -fsSL\ntest "$2" = fixture://setup\ntest "$3" = -o\ncp "$TASK_SETUP_FIXTURE" "$4"\n',
};
for (const [name, source] of Object.entries(shims)) {
  writeFileSync(join(root, name), source);
  chmodSync(join(root, name), 0o755);
}
const env = { PATH: `${root}:/usr/bin:/bin`, TMPDIR: join(root, 'unavailable'), TASK_SETUP_FIXTURE: fixture, login_home: home, login_user: 'fixture', login_uid: '1000', setup_url: 'fixture://setup' };
// Retain the parent variable after review and stage the very same file. Cleanup
// runs on failure too, using only exact paths created by this fixture.
const script = `set -eu\n${helper}\n${review}\ntest -d "$review_dir"\ntrap 'rm -f "$review_dir/setup.sh"; rmdir "$review_dir"' EXIT\n${stage}\ntrap - EXIT\n`;
try {
  const inherited = spawnSync('/bin/sh', [fixture], { env, encoding: 'utf8' });
  assert.notEqual(inherited.status, 0, 'An unusable inherited TMPDIR must reproduce the failure');
  const result = spawnSync('/bin/sh', ['-c', script], { env, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /STAGED_TMPDIR=\/tmp/);
  const broken = spawnSync('/bin/sh', ['-c', script.replace(' TMPDIR=/tmp', '')], { env, encoding: 'utf8' });
  assert.notEqual(broken.status, 0, 'Dropping the helper override must break staging');
  console.log('documented argv staging workflow: 4 passed');
} finally {
  for (const name of Object.keys(shims)) unlinkSync(join(root, name));
  unlinkSync(fixture);
  rmdirSync(home);
  rmdirSync(root);
}
