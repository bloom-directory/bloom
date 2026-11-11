# Install Bloom

Read this entire reference only when a new Bloom installation or an upgrade is
needed.

## Setup: reviewed download and one privileged handoff

A request to set up Bloom authorizes installing the signed Bloom software,
read-only chain access, and starting the components required for an active Bloom
session. Bloom is a triad: Machine runs as the login user while Broker and Signer
run as isolated service principals, under systemd on Linux and under launchd on
macOS. Setup therefore authorizes enabling those packaged Bloom services, but it
never authorizes the agent to handle a sudo password, a polkit credential, or a
macOS administrator credential, or to broaden the reviewed privileged command.

Setup does not authorize creating or registering a wallet, starting a passkey
ceremony, adding a passkey, recovering a wallet, staging/signing/broadcasting
a transaction, or installing unrelated software. Those actions require a
separate, explicit user request.

The reviewed setup script resolves GitHub's latest published stable Bloom release
on every run, then uses that exact tag for all downloads and staging paths. Latest
means GitHub's designated latest release, excluding drafts and prereleases; it
does not mean the newest bare Git tag. All supported targets use signed triad
artifacts:

| Target | Signed release artifact | Platform claim |
| --- | --- | --- |
| Linux x86_64 | `bloom-triad-linux-x86_64.tar.gz` | `linux` |
| Linux aarch64 | `bloom-triad-linux-aarch64.tar.gz` | `linux` |
| macOS arm64 | `bloom-triad-macos-aarch64.tar.gz` | `macos-unix-principals` |

The script verifies both the archive and internal payload signatures against
Bloom's reviewed release key, verifies their SHA-256 manifests, checks the
platform claim, and stages the payload below `~/.cache/bloom/install`. It does
not execute the staged release or invoke sudo. Resolve `releases/latest` only once
and keep every artifact download on the resolved tag; do not use moving
`releases/latest/download` URLs or substitute one platform's artifact for the
other. If discovery, download, or verification fails, stop and report the failure;
never fall back to an older release or cached payload.

This setup script supports only the targets above. On macOS x86_64 or any other
platform the script stops; report that instead of improvising an install.
Linux also needs systemd with a user session, and every target needs
`/usr/bin/ssh-keygen` to verify release signatures. If setup reports a missing
command, tell the user which package provides it (OpenSSH's client for
`ssh-keygen`) and stop; do not install packages yourself.
Bloom requires macOS 26 or later: it mounts `~/bloom` over NFSv4.1, which
earlier versions lack, and the privileged installer refuses an older macOS
before changing anything. Report that the user must update macOS first.
Windows is not supported. Do not attempt a local Windows installation.
Instead, direct Windows users to use Bloom through a cloud agent
running on a supported platform, such as OpenClaw, Hermes, or GrokBot.

Use this review-before-execute path instead of piping a remote response directly
into a shell. When this skill is installed locally, copy its bundled
`scripts/setup.sh` to `$review_dir/setup.sh` instead of downloading it, then inspect
and execute that exact copy. Resolve the bundled path relative to the skill
directory, not the current working directory.

Staging runs as the Bloom login user, never as root, and `setup.sh` refuses to
run as root. If your session is already root, follow
[Linux: an authorized agent already running as root](#linux-an-authorized-agent-already-running-as-root)
for the staging and privileged steps instead of the commands below.

When the user supplies a specific `SKILL.md` URL, use the `scripts/setup.sh`
beside that document; never silently replace a preview or custom origin with
production.
For a website-loaded skill, fetch the script as follows:

For every setup or privileged handoff invocation, set the working directory to
`/private/tmp` on macOS or `/tmp` on Linux. Never run from inside the Bloom mount:
installation can restart it and invalidate the current working directory.

```sh
skill_url=${BLOOM_SKILL_URL:-https://bloom.directory/SKILL.md}
setup_url=${skill_url%/SKILL.md}/scripts/setup.sh
review_dir="$(mktemp -d "${TMPDIR:-/tmp}/bloom-review.XXXXXX")"
curl -fsSL "$setup_url" -o "$review_dir/setup.sh"
cat "$review_dir/setup.sh"
```

Set `BLOOM_SKILL_URL` to the exact URL the user supplied when it is not the
production URL. The setup script must come from the same origin and path
prefix as that skill.

Inspect the complete downloaded script before execution. It should contact only the
Bloom repository's GitHub latest-release URL and the resolved release downloads,
write only to a temporary directory and the reported
user-owned staging directory, and perform no wallet, transaction, sudo, or
service action. If it matches, run:

```sh
sh "$review_dir/setup.sh"
rm "$review_dir/setup.sh"
rmdir "$review_dir"
```

Stop and report if the fetch or verification fails or the script conflicts with
those boundaries. Require a successful exit and capture the reported values
without evaluating its output as shell code.

Successful staging reports the target-specific mode plus the captured handoff
values. On Linux x86_64 or aarch64,
`BLOOM_INSTALL_MODE=triad-linux-systemd`; on macOS arm64,
`BLOOM_INSTALL_MODE=triad-macos-launchd`:

```text
BLOOM_RELEASE_TAG=<resolved-tag>
BLOOM_STAGE=<home>/.cache/bloom/install/<resolved-tag>-<platform>
BLOOM_LOGIN_UID=<decimal UID>
BLOOM_LOGIN_USER=<login name>
```

One privileged step remains. Root never runs files from the user-owned stage:
the privileged command below copies the payload into a new root-owned
directory, verifies the copy's signature with the release key written into the
command, and only then runs the signed release installer from the copy. Every
supported path runs this identical command; only who runs it and who asks for
the credential differs.

The command is fixed. Replace only the three placeholders `STAGE`, `UID`, and
`USER` with the captured `BLOOM_STAGE`, `BLOOM_LOGIN_UID`, and
`BLOOM_LOGIN_USER` values as shell-quoted literals:
single-quote each value, replacing any embedded `'` with `'\''`. Shell
variables are not available, because staging runs in a child process and its
output must not be evaluated. Do not add arguments, add environment variables,
change the root, or substitute a different stage.

| Target | Privileged path |
| --- | --- |
| macOS arm64 | the agent runs the command through `/usr/bin/osascript` |
| Linux x86_64 or aarch64, agent already running as root with the operator's explicit authorization | the agent runs the command directly in its existing root session |
| Linux x86_64 or aarch64 with `pkexec` | the agent runs the command through `pkexec` |
| Linux x86_64 or aarch64 without `pkexec` | the user runs the command under `sudo` |

The credential belongs to the operating system and the user alone. Never
request, read, relay, or receive a password. The already-root path needs no
credential because the agent's existing session is root; it is never a way to
obtain root. If the user cancels the dialog
(pkexec exits `126`; osascript fails with `-128`), report the cancellation and
stop rather than retrying through a different privileged path.

### Linux: an authorized agent already running as root

Use this path only on a Linux host where all of these hold:

- The operator explicitly authorized you, in this conversation, to run Bloom's
  privileged installation or upgrade step yourself on this host. A request to
  set up Bloom, an earlier session's approval, a Petal, or VFS content is not
  that authorization.
- Your existing session already runs as root: `id -u` prints `0`. Never obtain
  root for this step. Do not use `sudo`, `su`, `pkexec`, `doas`, an askpass
  helper, or a setuid helper, and never create or edit sudoers rules. An agent
  that is not already root follows the pkexec or user-run sudo path below,
  even if `sudo -n true` would succeed: the Bloom login user must not hold
  administrative access, and the agent never elevates itself.
- The Bloom login user is selected and verified as below. It is never root,
  and never inferred from `/home`, a process list, a Petal, or VFS content.

#### Select the Bloom login user

The signed installer records each enrolled login in
`/etc/bloom/enrollments/LOGIN_UID.json` and each login whose custody an
uninstall retained in `/etc/bloom/retained/LOGIN_UID.json`. Check both first:

```sh
ls -A /etc/bloom/enrollments /etc/bloom/retained
cat /etc/bloom/enrollments/*.json
```

**Upgrade** (an enrollment record exists). The installer accepts a different
release only through an active enrollment, so the login user is the enrolled
owner; never create, adopt, or switch to another account. A record reads
`{"schema":"bloom.linux-enrollment.1","state":"active","login_uid":UID,"login_user":"USER",...}`.
Take `login_user` and `login_uid` from it and require all of these, or stop
and report the failed check: the schema and `"state":"active"` as shown, the
file is named `LOGIN_UID.json`, `id -u LOGIN_USER` prints that UID, any user
the operator named equals `login_user`, and `/run/user/UID/bus` exists for
every enrolled UID, because the installer refuses an upgrade without an active
session for each one. If a bus is missing, ask the operator to start that
login's session. With several records, ask the operator which login to use.
Do not edit, move, or remove the account, its home, `/etc/bloom`,
`/var/lib/bloom`, or Bloom's units, do not enable lingering, and do not run
`bloom-uninstall`; the installer keeps that login's identities, data, and
service configuration and refuses to replace an incomplete enrollment.

**First install** (neither directory holds a record, and `/etc/bloom` and
`/var/lib/bloom` hold no per-login state). Use the account the operator named,
or else the dedicated account `bloom`. If that account exists, verify it before
adopting it, or stop and report the failed check; never modify it to make it
fit: `id -u USER` is at least `UID_MIN` from `/etc/login.defs` (normally
1000), `id -nG USER` lists none of `root`, `sudo`, `wheel`, or `admin`, and
the home directory from `getent passwd USER` exists and is owned by that UID.
If no account was named and `bloom` does not exist, create it with a home, its
own group, no password, and no administrative group:

```sh
useradd --create-home --user-group --shell /bin/sh 'bloom'
```

If `/run/user/UID/bus` does not exist for the selected account, start its
systemd user session with `loginctl enable-linger 'USER'` and wait until the
bus exists. If a retained record exists, or `/etc/bloom` holds anything without
an active record, stop and report it; it is neither a first install nor an
upgrade.

#### Stage, hand off, and check readiness

Staging still belongs to the login user, never to root. Fetch and inspect the
setup script as above, but in a review directory below `/tmp` that the login
user can read and cannot change. Then drop to the login user for staging only.
`runuser` lowers privilege from root without a password or prompt, but keeps
most of root's environment, so the command resets the temporary directory and
clears any stage override:

```sh
cd /tmp
review_dir="$(mktemp -d /tmp/bloom-review.XXXXXX)"
curl -fsSL "$setup_url" -o "$review_dir/setup.sh"
cat "$review_dir/setup.sh"
chmod 755 "$review_dir"
chmod 644 "$review_dir/setup.sh"
runuser -u 'USER' -- env -u BLOOM_INSTALL_STAGE TMPDIR=/tmp sh "$review_dir/setup.sh"
rm "$review_dir/setup.sh"
rmdir "$review_dir"
```

Replace `USER` with the selected login user as a shell-quoted literal. Use
this `runuser` line exactly, with no other options or environment changes.
Setup stops unless that user can write its home and `/tmp`. Use `runuser` only
for staging and the readiness line below: never use `runuser`, `su`,
`setpriv`, or `sudo -u` for any other step, and never run setup as root.

Before the privileged step, check the captured values against that account:
`BLOOM_LOGIN_USER` must equal the selected user, `BLOOM_LOGIN_UID` must equal
`id -u` for that user and must not be `0`, and `BLOOM_STAGE` must lie below
that user's home directory as reported by `getent passwd`. If any value
differs, stop and report the mismatch. Never substitute root's identity, a
stage owned by another user, or values you did not capture from this staging
run.

Then run the fixed command yourself, directly in the existing root session,
with the captured values in place of the placeholders:

```sh
/bin/sh -c 'set -eu; s=$(mktemp -d /var/tmp/bloom-install.XXXXXX); trap "rm -rf -- $s" EXIT; trap "exit 129" HUP INT TERM; cp -R "$1/bloom-triad" "$s/"; chown -R 0:0 "$s"; chmod -R go-w "$s"; if find "$s" -type l -o ! -type f ! -type d | grep -q .; then echo "Bloom stage contains a link or special file." >&2; exit 65; fi; k="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFY9na4hytUNsW+8LWu//HrX9TaPU7H7Vg0GRWcZM+uP"; printf "%s\n" "$k" > "$s/key.pub"; printf "bloom-release %s\n" "$k" > "$s/signers"; p="$s/bloom-triad"; /usr/bin/ssh-keygen -Y verify -f "$s/signers" -I bloom-release -n bloom-release-payload-v1 -s "$p/RELEASE_SIGNATURE" < "$p/SHA256SUMS" > /dev/null; cd "$p"; { sha256sum -c SHA256SUMS 2>/dev/null || shasum -a 256 -c SHA256SUMS; } > /dev/null; case $(uname -s) in Linux) i=linux;; Darwin) i=macos;; *) exit 65;; esac; BLOOM_RELEASE_PUBLIC_KEY="$s/key.pub" "$p/installer/release/install-$i.sh" install / "$2" "$3" "$p"' bloom-install 'STAGE' 'UID' 'USER'
```

Nothing may precede `/bin/sh` except `cd /tmp &&`: no `sudo`, `su`,
`runuser`, `env`, or variable assignments. The verification chain is
unchanged: root copies the stage into a new root-owned directory, verifies the
release signature against the key pinned in the command, checks every SHA-256
sum, and runs only the signed installer from that copy. If it fails, report the
failure and stop; do not retry through another privileged path.

Verify readiness as the selected user, never as root: root's UID, home, and
user bus are not the login user's. Run the
[Linux](#linux-post-install-readiness) and
[mounted VFS and audit](#mounted-vfs-and-audit-readiness) checks through this
one line, with the captured user and UID in place of `USER` and `UID`:

```sh
runuser -u 'USER' -- env -u DBUS_SESSION_BUS_ADDRESS -u BLOOM_MOUNT XDG_RUNTIME_DIR=/run/user/UID sh -c 'systemctl --user is-active bloom-session.service bloom-machine.service && systemctl is-active "bloom-signer@$(id -u).service" "bloom-broker@$(id -u).service" && command -v bloom && cat "$HOME/bloom/AGENTS.md" "$HOME/bloom/status/daemon.json" && bloom audit status'
```

Apply those sections' rules to the output. If it fails after
`BLOOM_RELOGIN_REQUIRED=1` and you created the account in this run, its fresh
login is `systemctl restart 'user@UID.service'`; then rerun the line. For any
other account, ask the operator for a fresh login instead.

Without the operator's explicit authorization, an agent already running as
root creates no account and enables no lingering; it selects and verifies the
login user, stages with `runuser` as above, and gives the operator the user-run
`sudo` command below instead of running the privileged step.

### Linux: pkexec when installed, otherwise user-run sudo

Check `command -v pkexec`. If it is installed, run the command yourself; the
system authentication agent shows its own credential dialog:

```sh
pkexec /bin/sh -c 'set -eu; s=$(mktemp -d /var/tmp/bloom-install.XXXXXX); trap "rm -rf -- $s" EXIT; trap "exit 129" HUP INT TERM; cp -R "$1/bloom-triad" "$s/"; chown -R 0:0 "$s"; chmod -R go-w "$s"; if find "$s" -type l -o ! -type f ! -type d | grep -q .; then echo "Bloom stage contains a link or special file." >&2; exit 65; fi; k="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFY9na4hytUNsW+8LWu//HrX9TaPU7H7Vg0GRWcZM+uP"; printf "%s\n" "$k" > "$s/key.pub"; printf "bloom-release %s\n" "$k" > "$s/signers"; p="$s/bloom-triad"; /usr/bin/ssh-keygen -Y verify -f "$s/signers" -I bloom-release -n bloom-release-payload-v1 -s "$p/RELEASE_SIGNATURE" < "$p/SHA256SUMS" > /dev/null; cd "$p"; { sha256sum -c SHA256SUMS 2>/dev/null || shasum -a 256 -c SHA256SUMS; } > /dev/null; case $(uname -s) in Linux) i=linux;; Darwin) i=macos;; *) exit 65;; esac; BLOOM_RELEASE_PUBLIC_KEY="$s/key.pub" "$p/installer/release/install-$i.sh" install / "$2" "$3" "$p"' bloom-install 'STAGE' 'UID' 'USER'
```

Nothing may sit between `pkexec` and `/bin/sh`: no `sudo`, `env`, variable
assignments, or `pkexec` options. Do not fall back to sudo when the user
cancels the dialog.

If `pkexec` is not installed, or it exits `127` with no dialog shown (for
example "No authentication agent found" over SSH), give the user the same command with `sudo` in
place of `pkexec` to run in their terminal, values already substituted. For
example, if staging reported these values:

```sh
sudo /bin/sh -c 'set -eu; s=$(mktemp -d /var/tmp/bloom-install.XXXXXX); trap "rm -rf -- $s" EXIT; trap "exit 129" HUP INT TERM; cp -R "$1/bloom-triad" "$s/"; chown -R 0:0 "$s"; chmod -R go-w "$s"; if find "$s" -type l -o ! -type f ! -type d | grep -q .; then echo "Bloom stage contains a link or special file." >&2; exit 65; fi; k="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFY9na4hytUNsW+8LWu//HrX9TaPU7H7Vg0GRWcZM+uP"; printf "%s\n" "$k" > "$s/key.pub"; printf "bloom-release %s\n" "$k" > "$s/signers"; p="$s/bloom-triad"; /usr/bin/ssh-keygen -Y verify -f "$s/signers" -I bloom-release -n bloom-release-payload-v1 -s "$p/RELEASE_SIGNATURE" < "$p/SHA256SUMS" > /dev/null; cd "$p"; { sha256sum -c SHA256SUMS 2>/dev/null || shasum -a 256 -c SHA256SUMS; } > /dev/null; case $(uname -s) in Linux) i=linux;; Darwin) i=macos;; *) exit 65;; esac; BLOOM_RELEASE_PUBLIC_KEY="$s/key.pub" "$p/installer/release/install-$i.sh" install / "$2" "$3" "$p"' bloom-install '/home/lee/.cache/bloom/install/v1.2.3-linux-x86_64' '1000' 'lee'
```

Use the actual captured values, not the example values. The user types their
sudo password into their own terminal.

### macOS: the agent runs osascript

Run the command yourself through `/usr/bin/osascript`; macOS shows its own
administrator dialog. Pass the fixed script and the three values as arguments so
they stay out of the AppleScript source:

```sh
/usr/bin/osascript \
  -e 'on run argv' \
  -e 'do shell script ("/bin/sh -c " & quoted form of (item 1 of argv) & " bloom-install " & quoted form of (item 2 of argv) & " " & quoted form of (item 3 of argv) & " " & quoted form of (item 4 of argv)) with administrator privileges' \
  -e 'end run' \
  'set -eu; s=$(mktemp -d /var/tmp/bloom-install.XXXXXX); trap "rm -rf -- $s" EXIT; trap "exit 129" HUP INT TERM; cp -R "$1/bloom-triad" "$s/"; chown -R 0:0 "$s"; chmod -R go-w "$s"; if find "$s" -type l -o ! -type f ! -type d | grep -q .; then echo "Bloom stage contains a link or special file." >&2; exit 65; fi; k="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFY9na4hytUNsW+8LWu//HrX9TaPU7H7Vg0GRWcZM+uP"; printf "%s\n" "$k" > "$s/key.pub"; printf "bloom-release %s\n" "$k" > "$s/signers"; p="$s/bloom-triad"; /usr/bin/ssh-keygen -Y verify -f "$s/signers" -I bloom-release -n bloom-release-payload-v1 -s "$p/RELEASE_SIGNATURE" < "$p/SHA256SUMS" > /dev/null; cd "$p"; { sha256sum -c SHA256SUMS 2>/dev/null || shasum -a 256 -c SHA256SUMS; } > /dev/null; case $(uname -s) in Linux) i=linux;; Darwin) i=macos;; *) exit 65;; esac; BLOOM_RELEASE_PUBLIC_KEY="$s/key.pub" "$p/installer/release/install-$i.sh" install / "$2" "$3" "$p"' 'STAGE' 'UID' 'USER'
```

Never add a `user name` or `password` parameter to `do shell script`.

Require a successful privileged installer exit on either target. Keep the signed
staging directory available for reinstall or diagnosis.

The privileged step can run for several minutes. Besides installing the
services, it prepares Bloom's hosted ceremony relay, which lets the human
approve from another device such as a phone; DNS and certificate issuance can
take a while, and on macOS the installer waits up to 10 minutes for it. Allow
the command at least 15 minutes, and do not interrupt, time out, or rerun it
while it runs. A relay that is not ready yet does not fail the install: approvals
in a browser on this computer still work, and the installer prints a
`sudo ... admin provision` retry command. Pass that command to the user; do not
run it yourself or broaden the reviewed invocation to include it.

### Linux post-install readiness

On Linux, success includes `BLOOM_RELOGIN_REQUIRED`. `0` means an upgrade. `1`
means the session may lack Bloom's access groups: it is printed for first
installs and for reinstalls of the same release. Either way, run the checks
below. If they fail after `1`, tell the user that Bloom was installed but needs
a fresh login. Do not attempt a group workaround; resume after the login.

Once the session has the groups, the package starts Machine and mounts `~/bloom` through
`bloom-machine.service`; the agent must not launch a second Machine. Require:

```sh
systemctl --user is-active bloom-session.service bloom-machine.service
systemctl is-active "bloom-signer@$(id -u).service" "bloom-broker@$(id -u).service"
command -v bloom
```

For a failed unit, capture `systemctl status` and `journalctl` diagnostics rather
than declaring readiness. The packaged Linux mount is the only persistence this
setup authorizes; do not create additional systemd, launchd, cron, shell-profile
auto-start, or restart configuration.

### macOS post-install readiness

On macOS, an active GUI login session is required and validated by the privileged
installer. The installer bootstraps the packaged launchd Machine and session
services in the user domain, and Broker and Signer in the system domain. Do not
launch a second Machine or create extra LaunchAgents/LaunchDaemons. Require the
installed CLI and the following user-domain and system-domain labels for the
captured login UID to be loaded before declaring readiness:

```sh
command -v bloom
launchctl print "user/$(id -u)/com.bloom.machine"
launchctl print "user/$(id -u)/com.bloom.session"
launchctl print "system/com.bloom.broker.$(id -u)"
launchctl print "system/com.bloom.signer.$(id -u)"
```

If any check fails, capture `launchctl print` diagnostics for that label. The
packaged launchd triad owns its own lifecycle; do not add auto-start or restart
configuration beyond it.

## Mounted VFS and audit readiness

On either supported target, require the service checks above, both VFS reads,
and audit health before reporting Bloom fully ready. Use the mounted reads below
when available. If native mounting is unavailable, run `bloom vfs cat /AGENTS.md`
and `bloom vfs cat /status/daemon.json` instead; a working CLI VFS connection
does not require the human to repair the mount first:

```sh
BLOOM_MOUNT=${BLOOM_MOUNT:-"$HOME/bloom"}
export BLOOM_MOUNT
cat "$BLOOM_MOUNT/AGENTS.md"
cat "$BLOOM_MOUNT/status/daemon.json"
bloom audit status
```

Require `mutation_degradation: null` for readiness. Poll startup effects for up to 30 seconds.
Once idle, allow one restart of the existing packaged Machine as a workaround, not a root-cause fix.
Recheck audit health/startup completion; continue only if healthy, otherwise report the blocker and stop.
An empty mount directory is not a successful mount. Wallet onboarding and
transaction actions remain outside this setup scope even while Bloom is running.
