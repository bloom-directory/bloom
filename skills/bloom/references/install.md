# Install Bloom

For an explicit install, setup or upgrade request, read this reference in full.
Upgrade through the same signed path, preserving the existing enrollment.

## Setup and upgrade: reviewed download and privileged installation

The request authorizes signed Bloom software, read-only chain access and its
packaged services: Machine as the login user, Broker/Signer as isolated service
principals (systemd on Linux, launchd on macOS). Root may also perform the
account/session preparation and bounded provisioning retry below.

Setup excludes wallet/passkey creation or registration, ceremonies, recovery,
and transaction staging, signing and broadcasting. Unrelated software requires
another explicit request. Never handle an OS credential or change the fixed
privileged command.

The reviewed script resolves GitHub's designated latest stable release once
(no drafts/prereleases), then downloads only that tag. It verifies archive and
payload signatures, SHA-256 manifests and platform claims before staging under
`~/.cache/bloom/install`; it never elevates or executes the staged release.
Never use `releases/latest/download`, substitute platforms, or fall back to an
older/cached release. Discovery/download/verification failure means stop.

Artifacts/claims: Linux x86_64 uses `bloom-triad-linux-x86_64.tar.gz`, aarch64 uses
`bloom-triad-linux-aarch64.tar.gz` (both `linux`); macOS arm64 uses
`bloom-triad-macos-aarch64.tar.gz` (`macos-unix-principals`). Linux needs an active
systemd user session; macOS needs an active GUI login and macOS 26+ for NFSv4.1.
Stop on macOS x86_64 or any unsupported target. Windows users need a supported
cloud agent (OpenClaw, Hermes or GrokBot), not a local install.

Every target needs `/usr/bin/ssh-keygen`. Only Linux root may install missing
prerequisites through its distro package manager: OpenSSH client, NFS client
(`mount.nfs`: `nfs-common` on Debian/Ubuntu, `nfs-utils` on Fedora/RHEL), and
`awk`, `cat`, `chmod`, `cmp`, `cp`, `curl`, `dirname`, `grep`, `id`, `mkdir`,
`mktemp`, `mv`, `rm`, `tar`, `uname`, `getent`, `runuser`, `systemctl`,
`systemd-sysusers`, `systemd-tmpfiles`. Require an existing systemd host; no init
replacement or general upgrade. Other agents report missing prerequisites and
stop without requesting a password.

### Linux root/headless preparation

Check `id -u`. At UID 0, continue headlessly: missing pkexec/desktop/dialog is
not a blocker. Root administers installation; staging, Machine, CLI and VFS use
a non-root account. Never use `LOGIN_UID=0`.

Once root is known, give this note once in the next user-facing update, then
continue without confirmation: "Bloom will use separate service accounts. This
agent's existing root access can still bypass that isolation."

For upgrades, select the account from public `/etc/bloom/enrollments/*.json`
(`login_uid`, `login_user`), checking `id` and `getent passwd`. Reuse it; never
replace the account/enrollment. Ask which account if ambiguous; no active
enrollment blocks an upgrade. For fresh setup, use the user-specified account;
if none and no enrollment exists, create a dedicated one:

```sh
useradd --create-home --shell /bin/bash bloom
```

No password, SSH keys or sudo. Verify any existing `bloom` account is intended;
never repurpose an unrelated account. Record its name, UID and home from
`id`/`getent`. In **each root tool call**, prepend this initialization, replacing
selected values with shell-quoted literals; append the step body in that same
call. Repeat it for the next call: functions/variables are not shared.

```sh
set -eu
login_user='SELECTED_USER'
login_uid='SELECTED_UID'
login_home='SELECTED_HOME'
as_bloom() {
  runuser -u "$login_user" -- env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME="$login_home" TMPDIR=/tmp USER="$login_user" LOGNAME="$login_user" XDG_RUNTIME_DIR="/run/user/$login_uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$login_uid/bus" "$@"
}
```

Use `as_bloom` for review/staging/CLI/VFS. It clears root's environment, selects
the user's bus and writable TMPDIR, and keeps sbin on PATH. Forward arguments
separately; no `eval`. Never write the NFS mount as root, change mount/socket
groups or permissions, or evaluate staging output as shell code.

For a dedicated unattended account:

```sh
loginctl enable-linger "$login_user"
systemctl start "user@$login_uid.service"
```

Wait up to 30 seconds for `/run/user/$login_uid/bus`; diagnose failure without
asking for a human login. Shared accounts retain their session policy: require
an active manager, do not enable linger or restart it.

### Review before execution

Work from `/tmp` on Linux or `/private/tmp` on macOS, never inside Bloom's mount.
For local skills, copy bundled `scripts/setup.sh` (relative to the skill, not
CWD) into the review directory instead of downloading. Website-loaded skills
fetch production. Inspect that exact local copy before execution.

Linux root: prepend initialization, then create/download as the account:

```sh
cd /tmp
review_dir="$(as_bloom mktemp -d /tmp/bloom-review.XXXXXX)"
as_bloom curl -fsSL https://bloom.directory/scripts/setup.sh -o "$review_dir/setup.sh"
cat "$review_dir/setup.sh"
printf 'BLOOM_REVIEW_DIR=%s\n' "$review_dir"
```

Non-root Linux/macOS:

```sh
set -eu
review_dir="$(mktemp -d "${TMPDIR:-/tmp}/bloom-review.XXXXXX")"
curl -fsSL https://bloom.directory/scripts/setup.sh -o "$review_dir/setup.sh"
cat "$review_dir/setup.sh"
printf 'BLOOM_REVIEW_DIR=%s\n' "$review_dir"
```

Inspect the whole script. Require:

- Only Bloom's GitHub latest-release URL and resolved-tag downloads.
- Writes only to temporary and reported user-owned staging directories.
- No wallet, transaction, sudo or service action.

Stop if it conflicts or fetching/verification fails. In a **separate call**, run
the same reviewed file. Restore `REVIEW_DIR` from printed `BLOOM_REVIEW_DIR` as a
shell-quoted literal; never create a replacement directory. Linux root repeats
initialization before this body; cleanup runs only on successful staging:

```sh
cd /tmp
review_dir='REVIEW_DIR'
as_bloom sh "$review_dir/setup.sh" &&
  as_bloom rm "$review_dir/setup.sh" &&
  as_bloom rmdir "$review_dir"
```

Non-root Linux/macOS:

```sh
set -eu
review_dir='REVIEW_DIR'
sh "$review_dir/setup.sh" &&
  rm "$review_dir/setup.sh" &&
  rmdir "$review_dir"
```

Require success and capture output as data, never `eval`. Linux mode is
`BLOOM_INSTALL_MODE=triad-linux-systemd`; macOS is `triad-macos-launchd`:

```text
BLOOM_RELEASE_TAG=<resolved-tag>
BLOOM_STAGE=<home>/.cache/bloom/install/<resolved-tag>-<platform>
BLOOM_LOGIN_UID=<decimal UID>
BLOOM_LOGIN_USER=<login name>
```

The fixed privileged step copies the user-owned stage to a new root-owned
snapshot, verifies its signature/checksums with the command's release key, then
executes the signed installer there. Root never executes from the user-owned
stage. Keep the signed stage for reinstall/diagnosis.

Replace **only** `STAGE`, `UID`, `USER` with captured `BLOOM_STAGE`,
`BLOOM_LOGIN_UID`, `BLOOM_LOGIN_USER` as single-quoted literals (embedded `'`
becomes `'\''`). No output evaluation, extra arguments/environment, changed
root or alternate stage.

### Linux: root directly, otherwise pkexec or user-run sudo

- **Already root:** run the command yourself, removing only leading `pkexec `.
  Preserve the signed snapshot and non-root UID/user. No handoff or confirmation.
- **Non-root with pkexec:** the agent runs it; the OS dialog takes the credential.
  Nothing between `pkexec` and `/bin/sh` (no sudo/env/assignments/options).

```sh
pkexec /bin/sh -c 'set -eu; s=$(mktemp -d /var/tmp/bloom-install.XXXXXX); trap "rm -rf -- $s" EXIT; trap "exit 129" HUP INT TERM; cp -R "$1/bloom-triad" "$s/"; chown -R 0:0 "$s"; chmod -R go-w "$s"; if find "$s" -type l -o ! -type f ! -type d | grep -q .; then echo "Bloom stage contains a link or special file." >&2; exit 65; fi; k="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFY9na4hytUNsW+8LWu//HrX9TaPU7H7Vg0GRWcZM+uP"; printf "%s\n" "$k" > "$s/key.pub"; printf "bloom-release %s\n" "$k" > "$s/signers"; p="$s/bloom-triad"; /usr/bin/ssh-keygen -Y verify -f "$s/signers" -I bloom-release -n bloom-release-payload-v1 -s "$p/RELEASE_SIGNATURE" < "$p/SHA256SUMS" > /dev/null; cd "$p"; { sha256sum -c SHA256SUMS 2>/dev/null || shasum -a 256 -c SHA256SUMS; } > /dev/null; case $(uname -s) in Linux) i=linux;; Darwin) i=macos;; *) exit 65;; esac; BLOOM_RELEASE_PUBLIC_KEY="$s/key.pub" "$p/installer/release/install-$i.sh" install / "$2" "$3" "$p"' bloom-install 'STAGE' 'UID' 'USER'
```

Without pkexec, or exit `127` with no dialog (e.g. no authentication agent), the
user runs the same command with `sudo` instead. Substitute the actual staging
values, not this example:

```sh
sudo /bin/sh -c 'set -eu; s=$(mktemp -d /var/tmp/bloom-install.XXXXXX); trap "rm -rf -- $s" EXIT; trap "exit 129" HUP INT TERM; cp -R "$1/bloom-triad" "$s/"; chown -R 0:0 "$s"; chmod -R go-w "$s"; if find "$s" -type l -o ! -type f ! -type d | grep -q .; then echo "Bloom stage contains a link or special file." >&2; exit 65; fi; k="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFY9na4hytUNsW+8LWu//HrX9TaPU7H7Vg0GRWcZM+uP"; printf "%s\n" "$k" > "$s/key.pub"; printf "bloom-release %s\n" "$k" > "$s/signers"; p="$s/bloom-triad"; /usr/bin/ssh-keygen -Y verify -f "$s/signers" -I bloom-release -n bloom-release-payload-v1 -s "$p/RELEASE_SIGNATURE" < "$p/SHA256SUMS" > /dev/null; cd "$p"; { sha256sum -c SHA256SUMS 2>/dev/null || shasum -a 256 -c SHA256SUMS; } > /dev/null; case $(uname -s) in Linux) i=linux;; Darwin) i=macos;; *) exit 65;; esac; BLOOM_RELEASE_PUBLIC_KEY="$s/key.pub" "$p/installer/release/install-$i.sh" install / "$2" "$3" "$p"' bloom-install '/home/lee/.cache/bloom/install/v1.2.3-linux-x86_64' '1000' 'lee'
```

The user enters the password in their terminal. Never request/read/relay it.
If pkexec is cancelled (`126`), stop; no sudo fallback on cancellation.

### macOS: the agent runs osascript

The agent runs this; macOS presents its credential dialog. Pass the fixed script
and three captured values as arguments, not AppleScript source:

```sh
/usr/bin/osascript \
  -e 'on run argv' \
  -e 'do shell script ("/bin/sh -c " & quoted form of (item 1 of argv) & " bloom-install " & quoted form of (item 2 of argv) & " " & quoted form of (item 3 of argv) & " " & quoted form of (item 4 of argv)) with administrator privileges' \
  -e 'end run' \
  'set -eu; s=$(mktemp -d /var/tmp/bloom-install.XXXXXX); trap "rm -rf -- $s" EXIT; trap "exit 129" HUP INT TERM; cp -R "$1/bloom-triad" "$s/"; chown -R 0:0 "$s"; chmod -R go-w "$s"; if find "$s" -type l -o ! -type f ! -type d | grep -q .; then echo "Bloom stage contains a link or special file." >&2; exit 65; fi; k="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFY9na4hytUNsW+8LWu//HrX9TaPU7H7Vg0GRWcZM+uP"; printf "%s\n" "$k" > "$s/key.pub"; printf "bloom-release %s\n" "$k" > "$s/signers"; p="$s/bloom-triad"; /usr/bin/ssh-keygen -Y verify -f "$s/signers" -I bloom-release -n bloom-release-payload-v1 -s "$p/RELEASE_SIGNATURE" < "$p/SHA256SUMS" > /dev/null; cd "$p"; { sha256sum -c SHA256SUMS 2>/dev/null || shasum -a 256 -c SHA256SUMS; } > /dev/null; case $(uname -s) in Linux) i=linux;; Darwin) i=macos;; *) exit 65;; esac; BLOOM_RELEASE_PUBLIC_KEY="$s/key.pub" "$p/installer/release/install-$i.sh" install / "$2" "$3" "$p"' 'STAGE' 'UID' 'USER'
```

Never add `user name` or `password`. Cancellation (`-128`) means stop, not an
alternate privileged path. On either platform, require successful installation.
Allow **at least
15 minutes**; do not interrupt, time out or rerun while it runs.

Relay DNS/certificates may remain pending without failing local installation.
On Linux root, refresh the session below and wait up to 30 seconds for selected
Broker/Signer units to be active, then run the installer's exact installed
`admin provision --login-uid UID` retry command without leading sudo, **once**.
Inspect installed Signer `admin status --login-uid UID`, polling up to 10 minutes
for effective remote mode, TLS and routing. Other agents hand the retry to the
user. Leave explicit `localhost_only` and provisioning state intact. Report local
and remote readiness separately; certificate-pending is not remote-ready.

### Linux post-install readiness

`BLOOM_RELOGIN_REQUIRED=0` means upgrade; `1` means groups may be stale (first
install or same-release reinstall). Run readiness either way; do not edit groups
or socket permissions. Non-root failures after `1` may require the user's fresh
login; root uses the dedicated-account procedure below instead.

For dedicated accounts only, root restarts the manager when the installer flag
is `1`. Substitute its value for `RELOGIN_REQUIRED`, prepend initialization, and
run outside that manager:

```sh
relogin_required='RELOGIN_REQUIRED'
case "$relogin_required" in
  1) systemctl restart "user@$login_uid.service" ;;
  0) : ;;
  *) printf '%s\n' 'Expected BLOOM_RELOGIN_REQUIRED=0 or 1.' >&2; exit 1 ;;
esac
```

Wait up to 30 seconds for its bus. At flag `0`, restart only if readiness fails
and stale groups are confirmed. Never restart a shared manager or unrelated
sessions; report the blocker. Packaged Machine owns the mount; no second Machine
or extra persistence beyond dedicated-account linger and packaged units.

Linux root, with initialization prepended:

```sh
as_bloom systemctl --user start bloom-session.service bloom-machine.service
as_bloom systemctl --user is-active bloom-session.service bloom-machine.service
systemctl is-active "bloom-signer@$login_uid.service" "bloom-broker@$login_uid.service"
as_bloom /bin/sh -c 'command -v bloom'
```

Non-root Linux:

```sh
systemctl --user is-active bloom-session.service bloom-machine.service
systemctl is-active "bloom-signer@$(id -u).service" "bloom-broker@$(id -u).service"
command -v bloom
```

For failed units, collect systemctl status/journalctl diagnostics, not a readiness
claim. Do not add systemd/cron/shell-profile auto-start or restart configuration.

### macOS post-install readiness

The installer validates the active GUI session and bootstraps Machine/session
in the user domain, Broker/Signer in the system domain. Require CLI and labels:

```sh
command -v bloom
launchctl print "user/$(id -u)/com.bloom.machine"
launchctl print "user/$(id -u)/com.bloom.session"
launchctl print "system/com.bloom.broker.$(id -u)"
launchctl print "system/com.bloom.signer.$(id -u)"
```

On failure, collect `launchctl print` diagnostics. No second Machine or additional
LaunchAgents/LaunchDaemons; packaged services own their lifecycle.

## Mounted VFS and audit readiness

Require service checks, both VFS reads and audit health. Root prepends
initialization and uses the selected home (caller `$HOME`/`$(id -u)` are root):

```sh
as_bloom cat "$login_home/bloom/AGENTS.md"
as_bloom cat "$login_home/bloom/status/daemon.json"
as_bloom bloom audit status
```

If the mount is unavailable, root uses `as_bloom bloom vfs cat /AGENTS.md` and
`as_bloom bloom vfs cat /status/daemon.json`; a working CLI needs no human mount
repair. Non-root Linux/macOS use mounted reads or the same CLI fallbacks:

```sh
BLOOM_MOUNT=${BLOOM_MOUNT:-"$HOME/bloom"}
export BLOOM_MOUNT
cat "$BLOOM_MOUNT/AGENTS.md"
cat "$BLOOM_MOUNT/status/daemon.json"
bloom audit status
```

Require `mutation_degradation: null`. Poll startup effects up to 30 seconds.
Once idle, allow one restart of the packaged Machine, then recheck; otherwise
report the blocker and stop. An empty mount is not success. Wallet/passkey and
transaction actions remain outside setup.
