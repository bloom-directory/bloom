const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } = require('node:fs');
const { join, resolve } = require('node:path');
const grade = require('./onboarding.cjs');

// Execute the actual documentation blocks as separate, stateless shell calls.
// Only account switching/download/service commands are stubbed; env -i is real.
const skillDir = resolve(__dirname, '../../../skills/bloom');
const install = readFileSync(join(skillDir, 'references/install.md'), 'utf8');
const setup = readFileSync(join(skillDir, 'scripts/setup.sh'), 'utf8');
const blocks = [...install.matchAll(/```sh\n([\s\S]*?)```/g)].map(m => m[1].trim());
const review = blocks.find(s => s.includes('review_dir="$(as_bloom mktemp'));
const stage = blocks.find(s => s.includes('as_bloom sh "$review_dir/setup.sh"'));
const nonrootStage = blocks.find(s => s.includes("review_dir='REVIEW_DIR'") && !s.includes('as_bloom'));
const refresh = blocks.find(s => s.includes('case "$relogin_required"'));
const services = blocks.find(s => s.includes('as_bloom systemctl --user is-active'));
const mount = blocks.find(s => s.includes('as_bloom cat "$login_home/bloom/AGENTS.md"'));
const helpers = [...install.matchAll(/^as_bloom\(\) \{\n[\s\S]*?^\}/gm)].map(m => m[0]);
assert.equal(helpers.length, 4);
assert.ok(helpers.every(h => h === helpers[0]), 'Each fresh root call restores the same helper');
assert.doesNotMatch(install, /BLOOM_SKILL_URL|skill_url=/);
assert.equal(grade(`${"I'll install Bloom for a dedicated non-root account and refresh its user manager, checking VFS and audit health."}\n${review}\n${stage}\n${grade.ROOT_HANDOFF_COMMAND}\n${services}\n${mount}\nSetup excludes wallet/passkey creation and transaction staging, signing and broadcasting.`, { vars: { platform: 'linux-root' } }).pass, true);
const root = mkdtempSync('/tmp/bloom argv fixture.');
const quote = s => `'${s.replaceAll("'", "'\\''")}'`;
const home = join(root, "home with 'quotes' and spaces");
mkdirSync(home);
mkdirSync(join(home, 'bloom'));
mkdirSync(join(home, 'bloom/status'));
writeFileSync(join(home, 'bloom/AGENTS.md'), 'GUIDANCE_FIXTURE');
writeFileSync(join(home, 'bloom/status/daemon.json'), '{"ready":true}');
const fixture = join(root, 'fixture.sh');
const serviceLog = join(root, 'services.log');
const stageTemp = setup.match(/^  tmp_dir=\$\(mktemp .+$/m)[0].trim();
const accountGuard = `test "$HOME" = ${quote(home)}\ntest "$TMPDIR" = /tmp\ntest "$USER" = fixture\ntest "$LOGNAME" = fixture\ntest "$XDG_RUNTIME_DIR" = /run/user/1000\ntest "$DBUS_SESSION_BUS_ADDRESS" = unix:path=/run/user/1000/bus\ntest "\${BLOOM_TEST_CANARY-unset}" = unset\n`;
writeFileSync(fixture, `set -eu\n${accountGuard}${stageTemp}\nprintf 'STAGED_TMPDIR=%s\\n' "$TMPDIR"\nrmdir "$tmp_dir"\n`);
const shims = {
  // Validate the documented PATH, then prepend fixture binaries for this test
  // only. Retain real env -i so arbitrary caller variables are actually cleared.
  runuser: `#!/bin/sh\nset -eu\ntest "$1" = -u\ntest "$2" = fixture\ntest "$3" = --\nshift 3\ntest "$1" = env\ntest "$2" = -i\ntest "$3" = PATH=/usr/sbin:/usr/bin:/sbin:/bin\nshift 3\nexec /usr/bin/env -i PATH=${quote(`${root}:/usr/sbin:/usr/bin:/sbin:/bin`)} "$@"\n`,
  systemctl: `#!/bin/sh\nset -eu\ncase "$1" in\n --user)\n${accountGuard}test "$2" = start -o "$2" = is-active\ntest "$3" = bloom-session.service\ntest "$4" = bloom-machine.service;;\n is-active) test "$2" = bloom-signer@1000.service; test "$3" = bloom-broker@1000.service;;\n restart) test "$2" = user@1000.service;;\n *) exit 2;;\nesac\nprintf '%s\\n' "$*" >> ${quote(serviceLog)}\n`,
  bloom: `#!/bin/sh\nset -eu\n${accountGuard}test "$1 $2" = 'audit status'\nprintf AUDIT_FIXTURE\n`,
  curl: `#!/bin/sh\nset -eu\n${accountGuard}test "$1" = -fsSL\ntest "$2" = https://bloom.directory/scripts/setup.sh\ntest "$3" = -o\ncp ${quote(fixture)} "$4"\n`,
};
for (const [name, source] of Object.entries(shims)) {
  writeFileSync(join(root, name), source);
  chmodSync(join(root, name), 0o755);
}
const env = { PATH: `${root}:/usr/bin:/bin`, TMPDIR: join(root, 'unavailable'), HOME: join(root, 'root-home'), BLOOM_MOUNT: join(root, 'wrong-mount'), BLOOM_TEST_CANARY: 'synthetic' };
const literalize = (script, values = {}) => {
  const substitutions = { SELECTED_USER: 'fixture', SELECTED_UID: '1000', SELECTED_HOME: home, ...values };
  for (const [key, value] of Object.entries(substitutions)) script = script.replaceAll(quote(key), quote(value));
  return script;
};
const call = (script, values) => spawnSync('/bin/sh', ['-c', literalize(script, values)], { env, encoding: 'utf8' });
const reviewed = [];
function reviewCall() {
  const result = call(review);
  assert.equal(result.status, 0, result.stderr);
  const directory = result.stdout.match(/^BLOOM_REVIEW_DIR=(.+)$/m)?.[1];
  assert.match(directory, /^\/tmp\/bloom-review\.[A-Za-z0-9]+$/);
  reviewed.push(directory);
  return directory;
}
let scenarios = 0;
const scenario = (name, check) => { check(); scenarios++; };
try {
  scenario('inherited private TMPDIR fails', () => {
    assert.notEqual(spawnSync('/bin/sh', ['-c', `set -eu\n${stageTemp}`], { env, encoding: 'utf8' }).status, 0);
  });
  scenario('review and stage in independent shells', () => {
    const directory = reviewCall();
    const result = call(stage, { REVIEW_DIR: directory });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /STAGED_TMPDIR=\/tmp/);
    assert.equal(existsSync(directory), false);
  });
  scenario('fresh service check call', () => {
    const result = call(services);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /bloom/);
  });
  scenario('fresh mounted/audit check call', () => {
    const result = call(mount);
    assert.equal(result.status, 0, result.stderr);
    for (const output of ['GUIDANCE_FIXTURE', 'AUDIT_FIXTURE', '"ready":true']) assert.ok(result.stdout.includes(output));
  });
  for (const [name, mutate] of [
    ['caller HOME', s => s.replaceAll('$login_home/bloom/', '$HOME/bloom/')],
    ['caller UID', s => s.replaceAll('bloom-signer@$login_uid.service', 'bloom-signer@$(id -u).service')],
    ['no TMPDIR', s => s.replaceAll(' TMPDIR=/tmp', '')],
    ['no clean environment', s => s.replaceAll('env -i ', 'env ')],
    ['no user bus', s => s.replaceAll(' DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$login_uid/bus"', '')],
  ]) scenario(`reject ${name}`, () => assert.notEqual(call(mutate(name === 'caller HOME' ? mount : services)).status, 0));
  writeFileSync(fixture, 'exit 42\n');
  const failedDirectory = reviewCall();
  for (const [name, block] of [['root', stage], ['non-root', nonrootStage]]) scenario(`${name} stage failure retains reviewed script`, () => {
    assert.equal(call(block, { REVIEW_DIR: failedDirectory }).status, 42);
    assert.equal(existsSync(join(failedDirectory, 'setup.sh')), true);
  });
  for (const value of ['0', '1', 'invalid']) scenario(`refresh flag ${value}`, () => {
    if (existsSync(serviceLog)) unlinkSync(serviceLog);
    const result = call(refresh, { RELOGIN_REQUIRED: value });
    assert.equal(result.status, value === 'invalid' ? 1 : 0, result.stderr);
    assert.equal(existsSync(serviceLog), value === '1');
    if (value === '1') assert.equal(readFileSync(serviceLog, 'utf8'), 'restart user@1000.service\n');
  });
  console.log(`documented staging/readiness workflow: ${scenarios} scenarios passed`);
} finally {
  for (const directory of reviewed) if (existsSync(directory)) {
    if (existsSync(join(directory, 'setup.sh'))) unlinkSync(join(directory, 'setup.sh'));
    rmdirSync(directory);
  }
  for (const name of Object.keys(shims)) unlinkSync(join(root, name));
  for (const file of [fixture, serviceLog, join(home, 'bloom/AGENTS.md'), join(home, 'bloom/status/daemon.json')]) if (existsSync(file)) unlinkSync(file);
  rmdirSync(join(home, 'bloom/status')); rmdirSync(join(home, 'bloom')); rmdirSync(home); rmdirSync(root);
}
