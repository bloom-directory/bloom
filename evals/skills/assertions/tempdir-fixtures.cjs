const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } = require('node:fs');
const { join, resolve } = require('node:path');

// Exercise the documented post-runuser environment on any host, without root
// or Linux. The caller's unusable scratch path stands in for a root-private
// TMPDIR that the selected account cannot use. No release is downloaded.
const skillDir = resolve(__dirname, '../../../skills/bloom');
const install = readFileSync(join(skillDir, 'references/install.md'), 'utf8');
const setup = readFileSync(join(skillDir, 'scripts/setup.sh'), 'utf8');
const root = mkdtempSync('/tmp/bloom-tempdir-test.');
const script = join(root, 'setup.sh');
const commands = install.match(/^runuser -u "\$login_user" -- env .+$/gm);
assert.equal(commands.length, 2);
const reviewTemp = install.match(/^review_dir="\$\(mktemp .+$/m)[0];
const stageTemp = setup.match(/^  tmp_dir=\$\(mktemp .+$/m)[0].trim();
writeFileSync(script, `set -eu\n${reviewTemp}\n${stageTemp}\nrmdir "$review_dir" "$tmp_dir"\n`);
const env = { PATH: process.env.PATH, TMPDIR: join(root, 'unavailable'), review_dir: root, login_home: root, login_user: 'fixture', login_uid: '1000' };
try {
  const inherited = spawnSync('/bin/sh', [script], { env, encoding: 'utf8' });
  assert.notEqual(inherited.status, 0, 'An unusable inherited TMPDIR must reproduce the failure');
  for (const command of commands) {
    // Only runuser's child payload is exercised; account switching itself needs
    // live Linux acceptance. These env assignments run after runuser/PAM.
    const payload = command.split(' -- ')[1].replace("'COMMAND'", `'sh "${script}"'`);
    const result = spawnSync('/bin/sh', ['-c', payload], { env, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    const broken = spawnSync('/bin/sh', ['-c', payload.replace(' TMPDIR=/tmp', '')], { env, encoding: 'utf8' });
    assert.notEqual(broken.status, 0, 'Removing the TMPDIR override must break each documented payload');
  }
  console.log('temporary-directory environment fixtures: 5 passed');
} finally {
  unlinkSync(script);
  rmdirSync(root);
}
