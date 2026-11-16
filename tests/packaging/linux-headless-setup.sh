#!/bin/bash
# Live acceptance on a disposable Linux/systemd host only. No wallet operations.
# Run from the checkout as root: bash tests/packaging/linux-headless-setup.sh first-install
# Then rerun with upgrade (against an older enrollment for a version upgrade).
set -euo pipefail
[[ ${BLOOM_DISPOSABLE_INSTALL_TEST:-} == 1 && $EUID == 0 ]] || {
  echo 'Requires root and BLOOM_DISPOSABLE_INSTALL_TEST=1 on a disposable host.' >&2
  exit 64
}
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd /tmp
case ${1:-} in
  first-install)
    [[ ! -e /etc/bloom ]] || { echo 'Existing installation; use upgrade.' >&2; exit 1; }
    ! getent passwd bloom >/dev/null || { echo 'bloom account already exists.' >&2; exit 1; }
    useradd --create-home --shell /bin/bash bloom
    user=bloom
    ;;
  upgrade)
    # Public root-owned enrollment only; never read service identity/config contents.
    user=$(python3 - <<'PY'
import glob, json, os, pwd
records = glob.glob('/etc/bloom/enrollments/*.json')
assert len(records) == 1, 'Expected one unambiguous active enrollment'
path = records[0]
assert not os.path.islink(path)
assert os.stat(path).st_uid == 0 and not os.stat(path).st_mode & 0o022
record = json.load(open(path))
assert record['schema'] == 'bloom.linux-enrollment.1'
uid, user = record['login_uid'], record['login_user']
assert uid != 0 and os.path.basename(path) == f'{uid}.json'
assert pwd.getpwnam(user) == pwd.getpwuid(uid)
print(user)
PY
)
    ;;
  *) echo 'Expected first-install or upgrade.' >&2; exit 64 ;;
esac
uid=$(id -u "$user")
home=$(getent passwd "$uid" | cut -d: -f6)
[[ $uid != 0 && $home == /* && $home != / ]]
if [[ $1 == first-install ]]; then loginctl enable-linger "$user"; fi
systemctl start "user@$uid.service"
test -S "/run/user/$uid/bus"

# Retain evidence, without removing shared paths or printing private contents.
evidence=$(mktemp -d /var/tmp/bloom-headless-test.XXXXXX)
chmod 711 "$evidence"
install -m 644 "$repo/install/setup.sh" "$evidence/setup.sh"
if sh "$evidence/setup.sh" > "$evidence/root-staging.txt" 2>&1; then
  echo 'FAIL: staging accepted root.' >&2; exit 1
fi
grep -q 'Stage Bloom as the verified non-root' "$evidence/root-staging.txt"
mkdir -m 700 "$evidence/root-private-tmp"
as_login() {
  runuser -u "$user" -- env -i HOME="$home" USER="$user" LOGNAME="$user" \
    PATH="$PATH" TMPDIR="$evidence/root-private-tmp" \
    XDG_RUNTIME_DIR="/run/user/$uid" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" "$@"
}
if [[ $1 == upgrade ]]; then
  # Metadata checks detect replacement of enrollment identities; no secret reads.
  find "/etc/bloom/$uid" -name '*identity.json' -type f -printf '%p %i %s %T@\n' | sort > "$evidence/before.metadata"
  [[ -s $evidence/before.metadata ]]
  # shellcheck disable=SC2016 # HOME belongs to the selected login.
  as_login sh -c 'printf preserve-me > "$HOME/.bloom/headless-test-marker"'
  as_login /usr/bin/bloom vfs cat /status/version > "$evidence/before.version"
fi
as_login sh "$evidence/setup.sh" > "$evidence/staging.txt"
cat "$evidence/staging.txt"
stage=$(sed -n 's/^BLOOM_STAGE=//p' "$evidence/staging.txt")
tag=$(sed -n 's/^BLOOM_RELEASE_TAG=//p' "$evidence/staging.txt")
[[ -n $stage && -n $tag ]]
grep -qx "BLOOM_LOGIN_UID=$uid" "$evidence/staging.txt"
grep -qx "BLOOM_LOGIN_USER=$user" "$evidence/staging.txt"

# Execute exactly the guide's root script; only the three captured values change.
python3 - "$repo/install/install.md" "$stage" "$uid" "$user" <<'PY'
import re, shlex, subprocess, sys
guide = open(sys.argv[1]).read()
command = shlex.split(re.search(r'^pkexec /bin/sh -c [^\n]+', guide, re.M)[0])[1:]
command[-3:] = sys.argv[2:]
subprocess.run(command, check=True, cwd='/tmp')
PY
if [[ $1 == first-install ]]; then
  systemctl restart "user@$uid.service"
fi
as_login systemctl --user start bloom-session.service bloom-machine.service
ready() {
  local unit
  for unit in "bloom-session@$uid.path" "bloom-broker@$uid.service" "bloom-signer@$uid.service"; do
    systemctl is-active --quiet "$unit" || return 1
  done
  for unit in bloom-session.service bloom-machine.service; do
    as_login systemctl --user is-active --quiet "$unit" || return 1
  done
  as_login /usr/bin/bloom vfs cat /status/version > "$evidence/after.version" 2>/dev/null
}
for ((attempt = 0; attempt < 60; attempt++)); do
  if ready; then break; fi
  sleep 0.5
done
ready || { echo "FAIL readiness; inspect systemctl/journalctl. Evidence: $evidence" >&2; exit 1; }
grep -qx "${tag#v}" "$evidence/after.version"
as_login /usr/bin/bloom --version | tee "$evidence/cli.version"
grep -qx "bloom ${tag#v}" "$evidence/cli.version"
as_login cat "$home/bloom/AGENTS.md" > "$evidence/mounted-agents.md"
as_login cat "$home/bloom/status/daemon.json" > "$evidence/mounted-daemon.json"
as_login /usr/bin/bloom audit status | tee "$evidence/audit.json"
python3 - "$evidence/audit.json" <<'PYTEST'
import json, sys
audit = json.load(open(sys.argv[1]))
assert audit['mutation_degradation'] is None, 'Audit is degraded'
assert audit['pending_effect_correlations'] == [], 'Startup effects are still pending'
PYTEST
if [[ $1 == upgrade ]]; then
  find "/etc/bloom/$uid" -name '*identity.json' -type f -printf '%p %i %s %T@\n' | sort > "$evidence/after.metadata"
  cmp "$evidence/before.metadata" "$evidence/after.metadata"
  [[ $(as_login cat "$home/.bloom/headless-test-marker") == preserve-me ]]
  if cmp -s "$evidence/before.version" "$evidence/after.version"; then
    echo 'NOTE: same-release reinstall, not a version upgrade'
  else
    echo "PASS version upgrade: $(cat "$evidence/before.version") -> ${tag#v}"
  fi
fi
echo "PASS $1 checks: installed versions, services, VFS, and audit; evidence: $evidence"
