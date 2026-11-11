#!/usr/bin/env bash
# Cases for the headless Linux login resolution in
# skills/bloom/scripts/setup.sh: upgrade of an existing distinct Bloom login,
# first install, and temporary-directory selection when the inherited TMPDIR
# is not writable by that login.
#
# Everything runs against a fixture system root with a stubbed password
# database, so no account, service, or installed Bloom state is touched. The
# script is invoked with BLOOM_SYSTEM_ROOT set, which resolves and reports the
# plan without creating a login, enabling linger, or staging a release.
# Needs only POSIX tools. Run: ./scripts/test-headless-setup.sh
set -uo pipefail

workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
setup="$workspace/skills/bloom/scripts/setup.sh"
install_reference="$workspace/skills/bloom/references/install.md"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
stubs="$work/bin"
passwd_file="$work/passwd"
log="$work/stub.log"
root="$work/system"
out="$work/stdout"
err="$work/stderr"
status=0
passed=0
failed=0

check() {
  # check NAME COMMAND...
  local name="$1"
  shift
  if "$@"; then
    passed=$((passed + 1))
    printf 'ok - %s\n' "$name"
  else
    failed=$((failed + 1))
    printf 'not ok - %s\n' "$name"
    printf '  status: %s\n  stdout: %s\n  stderr: %s\n' \
      "$status" "$(cat "$out")" "$(cat "$err")"
  fi
}
contains() { grep -Fq -- "$2" "$1"; }
lacks() { ! grep -Fq -- "$2" "$1"; }
lacks_line() { ! grep -Fqx -- "$2" "$1"; }
exited() { [[ "$status" == "$1" ]]; }

mkdir -p "$stubs"

# `id` reports root so the headless path is exercised without running as root.
cat >"$stubs/id" <<'STUB'
#!/bin/sh
if [ $# -eq 1 ]; then
  case "$1" in
    -u) printf '0\n'; exit 0 ;;
    -un) printf 'root\n'; exit 0 ;;
  esac
fi
exec /usr/bin/id "$@"
STUB

# `getent passwd` answers from the fixture password database only.
cat >"$stubs/getent" <<'STUB'
#!/bin/sh
[ "${1:-}" = passwd ] || exit 2
awk -F: -v key="${2:-}" '
  $1 == key || $3 == key { print; found = 1; exit }
  END { exit found ? 0 : 2 }
' "$BLOOM_TEST_PASSWD"
STUB

# `runuser` records the identity switch and runs the command as the test user,
# so the writability probes are real. BLOOM_TEST_REFUSE_DIRS simulates a
# directory the Bloom login cannot write.
cat >"$stubs/runuser" <<'STUB'
#!/bin/sh
switched=
if [ "${1:-}" = -u ]; then
  switched=$2
  shift 2
fi
if [ "${1:-}" = -- ]; then
  shift
fi
printf 'runuser %s %s\n' "$switched" "$*" >>"$BLOOM_TEST_LOG"
last=
for argument in "$@"; do
  last=$argument
done
case ":${BLOOM_TEST_REFUSE_DIRS:-}:" in
  *":$last:"*) exit 1 ;;
esac
exec "$@"
STUB

# Nothing in these cases may create a login or start a session.
for forbidden in useradd loginctl; do
  cat >"$stubs/$forbidden" <<STUB
#!/bin/sh
printf '$forbidden %s\n' "\$*" >>"\$BLOOM_TEST_LOG"
exit 1
STUB
done
chmod 0755 "$stubs"/*

fresh_fixture() {
  rm -rf -- "$root" "$passwd_file" "$log"
  mkdir -p "$root/etc/bloom/enrollments" "$root/etc/bloom/retained"
  : >"$log"
  cat >"$passwd_file" <<PASSWD
root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
PASSWD
}

add_login() {
  # add_login NAME UID
  mkdir -p "$work/home/$1"
  printf '%s:x:%s:%s:%s:%s:/bin/sh\n' "$1" "$2" "$2" "$1" "$work/home/$1" \
    >>"$passwd_file"
}

add_record() {
  # add_record enrollments|retained UID LOGIN_USER STATE
  printf '{"schema":"bloom.linux-enrollment.1","state":"%s","login_uid":%s,"login_user":"%s","release_digest":"%s","nfs_port":20490}\n' \
    "$4" "$2" "$3" "$(printf 'a%.0s' $(seq 64))" >"$root/etc/bloom/$1/$2.json"
}

run_setup() {
  # run_setup [VAR=VALUE ...]: resolve the plan against the fixture root.
  status=0
  env -i \
    PATH="$stubs:/usr/bin:/bin:/usr/sbin:/sbin" \
    HOME="$work/home/root" \
    BLOOM_TEST_PASSWD="$passwd_file" \
    BLOOM_TEST_LOG="$log" \
    BLOOM_SYSTEM_ROOT="$root" \
    "$@" \
    sh "$setup" >"$out" 2>"$err" || status=$?
}

# An existing Bloom login is identified from its enrollment record, verified
# against the password database, and reused exactly.
fresh_fixture
add_login bloomsvc 4242
add_record enrollments 4242 bloomsvc active
run_setup
check 'upgrade resolves the enrolled login' exited 0
check 'upgrade reports the enrolled source' contains "$out" 'BLOOM_HEADLESS_LOGIN=enrolled'
check 'upgrade keeps the enrolled login name' contains "$out" 'BLOOM_LOGIN_USER=bloomsvc'
check 'upgrade keeps the enrolled login UID' contains "$out" 'BLOOM_LOGIN_UID=4242'
check 'upgrade keeps the enrolled login home' contains "$out" "BLOOM_LOGIN_HOME=$work/home/bloomsvc"
check 'upgrade creates no login' lacks "$out" 'BLOOM_HEADLESS_CREATE_LOGIN'
check 'upgrade runs nothing privileged' lacks "$log" 'useradd'
check 'resolution alone stages no release' lacks "$out" 'BLOOM_STAGE='

# A dedicated `bloom` account that is not the enrolled login is not adopted.
fresh_fixture
add_login bloomsvc 4242
add_login bloom 5000
add_record enrollments 4242 bloomsvc active
run_setup
check 'upgrade prefers the enrolled login over a bloom account' \
  contains "$out" 'BLOOM_LOGIN_USER=bloomsvc'
check 'upgrade ignores the unrelated bloom account' \
  lacks_line "$out" 'BLOOM_LOGIN_USER=bloom'

# A record that disagrees with the password database fails closed.
fresh_fixture
add_login bloomsvc 4243
add_record enrollments 4242 bloomsvc active
run_setup
check 'enrollment UID mismatch stops the run' exited 1
check 'enrollment UID mismatch is reported' contains "$err" 'does not match'
check 'a blocker uses the documented prefix' \
  contains "$err" 'Bloom headless setup blocker:'
check 'the documented prefix is in the reference' \
  contains "$install_reference" 'Bloom headless setup blocker:'
check 'enrollment UID mismatch stages nothing' lacks "$out" 'BLOOM_LOGIN_USER'

fresh_fixture
add_record enrollments 4242 bloomsvc active
run_setup
check 'missing enrolled login stops the run' exited 1
check 'missing enrolled login is named' contains "$err" 'bloomsvc'

# Ambiguity fails closed and is resolvable by naming the login.
fresh_fixture
add_login bloomsvc 4242
add_login other 4243
add_record enrollments 4242 bloomsvc active
add_record enrollments 4243 other active
run_setup
check 'two enrolled logins stop the run' exited 1
check 'two enrolled logins are named' contains "$err" 'more than one enrolled Bloom login'
run_setup BLOOM_LOGIN_USER=other
check 'the named enrolled login is selected' exited 0
check 'the named enrolled login is used' contains "$out" 'BLOOM_LOGIN_USER=other'
run_setup BLOOM_LOGIN_USER=bloom
check 'an unenrolled login is refused while Bloom is enrolled' exited 1
check 'the enrolled logins are reported instead' contains "$err" 'is enrolled for'

# An unreadable or unexpected record is never treated as "no Bloom here".
fresh_fixture
add_login bloomsvc 4242
printf '{"schema":"bloom.linux-enrollment.1","state":"draft","login_uid":4242,"login_user":"bloomsvc"}\n' \
  >"$root/etc/bloom/enrollments/4242.json"
run_setup
check 'an unrecognized record stops the run' exited 1
check 'an unrecognized record is reported' contains "$err" 'unrecognized Bloom enrollment record'

fresh_fixture
add_login bloomsvc 4242
add_record enrollments 4242 bloomsvc active
mv "$root/etc/bloom/enrollments/4242.json" "$work/record.json"
ln -s "$work/record.json" "$root/etc/bloom/enrollments/4242.json"
run_setup BLOOM_PREPARE_LOGIN_USER=1
check 'a symlinked record stops the run' exited 1
check 'a symlinked record is reported' contains "$err" 'unrecognized Bloom enrollment record'
check 'a symlinked record prepares no login' lacks "$out" 'BLOOM_HEADLESS_CREATE_LOGIN'

# First install: an explicitly named non-root login is used as it is.
fresh_fixture
add_login deploy 1001
run_setup BLOOM_LOGIN_USER=deploy
check 'first install uses the named login' exited 0
check 'first install reports an existing login' contains "$out" 'BLOOM_HEADLESS_LOGIN=existing'
check 'first install keeps the named login' contains "$out" 'BLOOM_LOGIN_USER=deploy'
check 'first install creates no login' lacks "$out" 'BLOOM_HEADLESS_CREATE_LOGIN'

fresh_fixture
run_setup BLOOM_LOGIN_USER=root
check 'root is refused as the Bloom login' exited 1
check 'root refusal is reported' contains "$err" 'not a usable non-root login'

fresh_fixture
run_setup BLOOM_LOGIN_USER=absent
check 'an unknown login is refused' exited 1
check 'an unknown login is reported' contains "$err" 'absent is not a usable non-root login'

# First install with no Bloom login present needs explicit authorization.
fresh_fixture
run_setup
check 'an unauthorized first install stops' exited 1
check 'the authorization is named' contains "$err" 'BLOOM_PREPARE_LOGIN_USER=1'
check 'no login is created without authorization' lacks "$log" 'useradd'

fresh_fixture
run_setup BLOOM_PREPARE_LOGIN_USER=1
check 'an authorized first install plans the dedicated login' exited 0
check 'the dedicated login is reported as prepared' contains "$out" 'BLOOM_HEADLESS_LOGIN=prepared'
check 'the dedicated login is named' contains "$out" 'BLOOM_HEADLESS_CREATE_LOGIN=bloom'
check 'the plan creates nothing' lacks "$log" 'useradd'

# An existing dedicated Bloom login is adopted instead of a second one.
fresh_fixture
add_login bloom 5000
run_setup BLOOM_PREPARE_LOGIN_USER=1
check 'the existing dedicated login is adopted' exited 0
check 'the existing dedicated login is reported' contains "$out" 'BLOOM_HEADLESS_LOGIN=existing'
check 'the existing dedicated login is used' contains "$out" 'BLOOM_LOGIN_UID=5000'

# Custody retained by an uninstall is never orphaned silently.
fresh_fixture
add_login bloomsvc 4242
add_record retained 4242 bloomsvc retained
run_setup BLOOM_PREPARE_LOGIN_USER=1
check 'retained custody stops a new login' exited 1
check 'retained custody is reported' contains "$err" 'custody is retained for bloomsvc'
run_setup BLOOM_LOGIN_USER=bloomsvc
check 'the retained login can be named' exited 0
check 'the retained login is used' contains "$out" 'BLOOM_LOGIN_UID=4242'

fresh_fixture
add_login bloomsvc 4243
add_record retained 4242 bloomsvc retained
run_setup BLOOM_LOGIN_USER=bloomsvc
check 'a retained record UID mismatch stops the run' exited 1

# The inherited TMPDIR is only used when the Bloom login can write it.
fresh_fixture
add_login bloomsvc 4242
add_record enrollments 4242 bloomsvc active
mkdir -p "$work/writable" "$work/unwritable"
chmod 0500 "$work/unwritable"
run_setup "TMPDIR=$work/writable"
check 'a writable inherited TMPDIR is kept' exited 0
check 'the writable TMPDIR is reported' contains "$out" "BLOOM_HEADLESS_TMPDIR=$work/writable"
# The fixture directory is mode 0500, which the probe rejects when this suite
# runs unprivileged; the refusal list keeps the case deterministic for root
# too, since root can write any mode.
run_setup "TMPDIR=$work/unwritable" BLOOM_TEST_REFUSE_DIRS="$work/unwritable"
check 'an unwritable inherited TMPDIR still stages' exited 0
check 'an unwritable inherited TMPDIR is replaced' contains "$out" 'BLOOM_HEADLESS_TMPDIR=/tmp'
check 'the unwritable TMPDIR was probed as the Bloom login' \
  contains "$log" "runuser bloomsvc /bin/sh -c"
check 'the unwritable TMPDIR is not reported' lacks "$out" "BLOOM_HEADLESS_TMPDIR=$work/unwritable"
run_setup "TMPDIR=$work/unwritable" \
  BLOOM_TEST_REFUSE_DIRS="$work/unwritable:/tmp:/var/tmp"
check 'an unwritable TMPDIR falls back to the login home' exited 0
check 'the login home temporary directory is used' \
  contains "$out" "BLOOM_HEADLESS_TMPDIR=$work/home/bloomsvc/.cache/bloom/tmp"
run_setup "TMPDIR=$work/unwritable" \
  BLOOM_TEST_REFUSE_DIRS="$work/unwritable:/tmp:/var/tmp:$work/home/bloomsvc/.cache/bloom/tmp"
check 'no writable temporary directory stops the run' exited 1
check 'the temporary directory blocker is reported' \
  contains "$err" 'no temporary directory is writable by bloomsvc'

# Every documented elevation runs the identical fixed root script.
root_scripts="$(grep -o "'set -eu; s=\$(mktemp -d /var/tmp/bloom-install\.XXXXXX);[^']*'" \
  "$install_reference" | sort -u | wc -l)"
check 'one fixed root script is documented' [ "$root_scripts" == 1 ]
for form in '^pkexec /bin/sh -c ' '^sudo /bin/sh -c ' "^  'set -eu; s=" '^/bin/sh -c '; do
  check "the privileged form $form is documented" \
    grep -q -- "$form" "$install_reference"
done
for documented in BLOOM_LOGIN_USER BLOOM_PREPARE_LOGIN_USER BLOOM_HEADLESS_LOGIN 'sudo -n'; do
  check "$documented is documented" contains "$install_reference" "$documented"
done

# Staging drops privilege and never elevates, and the login user never has to
# read the reviewed script: root opens it and the login shell reads it from
# standard input, the mechanism checked here against this host's /bin/sh.
check 'staging re-runs itself as the login user' \
  contains "$setup" 'exec runuser -u "$headless_user" -- env -i'
check 'staging passes only the login environment' contains "$setup" '/bin/sh -s < "$0"'
no_elevation() {
  # Comments name the privileged handoff; no command in the script performs it.
  ! grep -v '^[[:space:]]*#' "$setup" |
    grep -Eq '(^|[^[:alnum:]_-])(sudo|pkexec|osascript)([^[:alnum:]_-]|$)'
}
check 'staging never elevates' no_elevation
printf 'printf "%%s\\n" "$TMPDIR"\n' >"$work/stdin-child.sh"
chmod 0400 "$work/stdin-child.sh"
env -i TMPDIR=/bloom-stdin-probe /bin/sh -s <"$work/stdin-child.sh" >"$out" 2>"$err"
check 'a login shell runs the script from standard input' \
  contains "$out" '/bloom-stdin-probe'

# Nothing in this suite may have changed an account or a session.
check 'no account was created' lacks "$log" 'useradd'
check 'no session was started' lacks "$log" 'loginctl'

printf '\n%s passed, %s failed\n' "$passed" "$failed"
[[ "$failed" == 0 ]]
