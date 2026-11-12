# Install Bloom

Read this entire reference for an explicit request to install, set up, or upgrade Bloom.
An upgrade uses the same signed installation path and preserves the existing enrollment.

## Setup and upgrade: reviewed download and privileged installation

A request to set up or upgrade Bloom authorizes installing the signed Bloom software,
read-only chain access, and starting the components required for an active Bloom
session. Bloom is a triad: Machine runs as the login user while Broker and Signer
run as isolated service principals, under systemd on Linux and under launchd on
macOS. Setup therefore authorizes enabling those packaged Bloom services, but it
never authorizes the agent to handle a sudo password, a polkit credential, or a
macOS administrator credential, or to change the reviewed installer command.
The Linux root path below also authorizes the listed account/session preparation and provisioning retry.

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
command, a Linux agent already running as root may install only the missing
Bloom prerequisites from the distribution package manager: OpenSSH client
(`ssh-keygen`), NFS client (`mount.nfs`; `nfs-common` on Debian/Ubuntu or
`nfs-utils` on Fedora/RHEL), and the commands the setup script checks. This requires an already running
systemd host; do not replace its init system. Do not perform a general system upgrade. Other agents report the missing prerequisite
and stop; do not request a password.
Bloom requires macOS 26 or later: it mounts `~/bloom` over NFSv4.1, which
earlier versions lack, and the privileged installer refuses an older macOS
before changing anything. Report that the user must update macOS first.
Windows is not supported. Do not attempt a local Windows installation.
Instead, direct Windows users to use Bloom through a cloud agent
running on a supported platform, such as OpenClaw, Hermes, or GrokBot.

### Linux root/headless preparation

Check `id -u` before choosing the installation path. If it is `0`, continue
headlessly using the authority already granted by the setup or upgrade request.
Missing `pkexec`, a desktop, or a credential dialog is not a blocker for root.
Root administers the install; Machine, CLI, and VFS operations use a non-root
login account. Never pass UID `0` as `LOGIN_UID`.

Once root access is known, include this brief note in your next user-facing
setup or upgrade update: "Bloom will use separate service accounts. This
agent's existing root access can still bypass that isolation." Give it once,
then continue the authorized setup or upgrade without asking for confirmation.

For an existing installation, select the intended account from the public
`/etc/bloom/enrollments/*.json` records (`login_uid`, `login_user`), and confirm
both against `id` and `getent passwd`. Reuse that enrollment for upgrades; do
not create a replacement account or enrollment. If several accounts exist and
the request does not identify one, ask which account. An upgrade with no active
enrollment is a blocker, not permission to create a fresh installation.

For a fresh setup, use the non-root account the user specified. If none was
specified and there is no existing enrollment, create a dedicated account:

```sh
useradd --create-home --shell /bin/bash bloom
```

Do not set a password, add SSH keys, or grant sudo. If `bloom` already exists,
verify it is the intended dedicated account before reusing it; never repurpose
an unrelated account. Record the selected name, UID, and home from `getent`
and `id` as `login_user`, `login_uid`, and `login_home` (not `$HOME`). For a
dedicated unattended Bloom account, enable its packaged user manager:

```sh
loginctl enable-linger "$login_user"
systemctl start "user@$login_uid.service"
```

Wait up to 30 seconds for `/run/user/$login_uid/bus`; diagnose failure rather
than requesting a human login. For an existing shared account, retain its
session policy and require its active user manager instead of enabling linger.

Run the review/download/staging sequence below **as the selected account**,
with its home, from `/tmp`. Explicitly set `TMPDIR=/tmp` inside each
`runuser` invocation: `runuser -u` can preserve root's `TMPDIR`, and changing
`HOME` alone does not make a root-private scratch directory writable. Both
review-directory creation and staging use `TMPDIR`. Create the review directory
as that account too.
Define this argument-forwarding helper in the root shell, and use it for
staging and all later CLI/VFS checks. Keep the selected account values available
in each subsequent tool call. Pass commands and arguments separately; never
store a shell command in a variable or use `eval` to invoke it.

```sh
as_bloom() {
  runuser -u "$login_user" -- env HOME="$login_home" TMPDIR=/tmp USER="$login_user" LOGNAME="$login_user" XDG_RUNTIME_DIR="/run/user/$login_uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$login_uid/bus" "$@"
}
```

Do not evaluate staging output. Capture the non-root staging values for the root
installer. Keep this account/home context for future Bloom operations. Never
write to its NFS mount as root: refused writes can leave pending kernel NFS
requests. Do not change mount permissions or add root to Bloom access groups.

### Review before execution

Use this review-before-execute path instead of piping a remote response directly
into a shell. When this skill is installed locally, copy its bundled
`scripts/setup.sh` to `$review_dir/setup.sh` instead of downloading it, then inspect
and execute that exact copy. Resolve the bundled path relative to the skill
directory, not the current working directory.

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
```

For Linux root, use the helper above. Capture `review_dir` in the parent root
shell so it remains available after the account-switch command exits:

```sh
cd /tmp
review_dir="$(as_bloom mktemp -d /tmp/bloom-review.XXXXXX)"
as_bloom curl -fsSL "$setup_url" -o "$review_dir/setup.sh"
cat "$review_dir/setup.sh"
```

For non-root Linux or macOS:

```sh
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
service action. If it matches, execute the same file in a subsequent tool call.
For Linux root, retain the captured `review_dir` and selected account values:

```sh
as_bloom sh "$review_dir/setup.sh"
as_bloom rm "$review_dir/setup.sh"
as_bloom rmdir "$review_dir"
```

For non-root Linux or macOS:

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
| Linux x86_64 or aarch64, effective UID `0` | the agent runs the same command directly through `/bin/sh`; omit only the leading `pkexec` |
| Linux x86_64 or aarch64, non-root with `pkexec` | the agent runs the command through `pkexec` |
| Linux x86_64 or aarch64, non-root without `pkexec` | the user runs the command under `sudo` |

The credential belongs to the operating system and the user alone. Never
request, read, relay, or receive a password. If the user cancels the dialog
(pkexec exits `126`; osascript fails with `-128`), report the cancellation and
stop rather than retrying through a different privileged path.

### Linux: root directly, otherwise pkexec or user-run sudo

If effective UID is `0`, run the command below yourself with only its leading
`pkexec ` removed. Preserve the root-owned snapshot, signature/checksum checks,
and captured non-root UID and user. Do not hand the command to the user or
request confirmation or credentials.

For non-root agents, check `command -v pkexec`. If it is installed, run the
command yourself; the system authentication agent shows its own credential dialog:

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
`sudo ... admin provision` retry command. On Linux, if already root, complete
the post-install session refresh below and wait up to 30 seconds for the
selected Broker/Signer units to be active, then run that exact installed `admin provision --login-uid UID` retry
without its leading `sudo`. Allow one retry, then inspect the installed
Signer's `admin status --login-uid UID`, polling for up to 10 minutes for
effective remote mode, TLS and routing readiness; report any remaining blocker.
Do not alter an explicit `localhost_only` choice or delete provisioning state.
Other agents pass the retry command to the user. This administration step does
not authorize wallet ceremonies or transactions. Report local readiness and
remote approval readiness separately; certificate-pending is not remote readiness.

### Linux post-install readiness

On Linux, success includes `BLOOM_RELOGIN_REQUIRED`. `0` means an upgrade. `1`
means the session may lack Bloom's access groups: it is printed for first
installs and for reinstalls of the same release. Either way, run the checks
below. If they fail after `1`, tell the user that Bloom was installed but needs
a fresh login, except for the root/headless dedicated-account path below.
Do not edit Bloom's groups or loosen socket permissions as a workaround.

If already root and the selected account is dedicated to Bloom, refresh stale
group membership by restarting only that account's user manager, from the root
shell (not from a process in that user manager):

```sh
systemctl restart "user@$login_uid.service"
```

Wait up to 30 seconds for its bus, then run the following as that account using
the wrapper above; the package has already enabled these units:

```sh
systemctl --user start bloom-session.service bloom-machine.service
```

Recheck readiness. Never restart a shared account's user manager or terminate
unrelated login sessions. If its session is stale, report that specific blocker.

Once the session has the groups, the package starts Machine and mounts `~/bloom` through
`bloom-machine.service`; the agent must not launch a second Machine. Require:

```sh
systemctl --user is-active bloom-session.service bloom-machine.service
systemctl is-active "bloom-signer@$(id -u).service" "bloom-broker@$(id -u).service"
command -v bloom
```

For a failed unit, capture `systemctl status` and `journalctl` diagnostics rather
than declaring readiness. Besides lingering for a dedicated headless account,
the packaged Linux mount is the only persistence this setup authorizes; do not
create additional systemd, launchd, cron, shell-profile auto-start, or restart
configuration.

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
