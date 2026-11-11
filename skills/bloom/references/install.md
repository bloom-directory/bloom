# Install Bloom

Read this entire reference only when a new Bloom installation is needed.

## Setup: reviewed download and one privileged handoff

A request to set up Bloom authorizes installing the signed Bloom software,
read-only chain access, and starting the components required for an active Bloom
session. Bloom is a triad: Machine runs as the login user while Broker and Signer
run as isolated service principals, under systemd on Linux and under launchd on
macOS. Setup therefore authorizes enabling those packaged Bloom services, and on
a headless Linux host the login user and systemd user session they need, but it
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
not execute the staged release or invoke sudo. Run as root on Linux it first
resolves the Bloom login user and re-runs itself as that login, as
[Headless Linux](#headless-linux-the-authorized-agent-runs-the-handoff)
describes. Resolve `releases/latest` only once and keep every artifact
download on the resolved tag; do not use moving
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
service action. Its one root-only path is the headless Linux login resolution
below: as root it may create the dedicated `bloom` login and enable that
login's systemd user session, when that was authorized, and then re-runs
itself as that login. If it matches, run:

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
| Linux x86_64 or aarch64 with `pkexec` | the agent runs the command through `pkexec` |
| Linux x86_64 or aarch64 without `pkexec` | the user runs the command under `sudo` |

The credential belongs to the operating system and the user alone. Never
request, read, relay, or receive a password. If the user cancels the dialog
(pkexec exits `126`; osascript fails with `-128`), report the cancellation and
stop rather than retrying through a different privileged path.

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

### Headless Linux: the authorized agent runs the handoff

A headless host has no authentication agent and often nobody at a terminal, so
`pkexec` exits `127` without showing a dialog. When the agent already holds the
administrative access this step needs — it runs as root, or `sudo -n true`
succeeds — it runs the same fixed command itself. Nothing is relaxed: the same
reviewed `setup.sh`, the same resolved release, the same signature, checksum,
and root-owned-copy verification, and the same three values. If elevation would
prompt for a password, do not answer it; hand the user the `sudo` command above
and stop.

Run the reviewed staging as root. Machine never runs as root, so on Linux
`setup.sh` first resolves which non-root login Bloom belongs to, using
`getent passwd` and the privileged installer's own enrollment records, and then
stages as that login:

- **Upgrade.** It reuses the login recorded in `/etc/bloom/enrollments`,
  verified against this host's password database, and preserves that login's
  existing installation, data, and configuration. It never creates a
  replacement login. If the host has more than one enrolled login, or custody
  retained by an uninstall, it stops and names them; add
  `BLOOM_LOGIN_USER=<login>` to choose one of them.
- **First install.** Add `BLOOM_LOGIN_USER=<login>` to use an existing non-root
  login. With no Bloom login on the host and no `BLOOM_LOGIN_USER`, it stops
  unless `BLOOM_PREPARE_LOGIN_USER=1` authorizes creating the dedicated `bloom`
  login and its lingering systemd user session. It adopts an existing `bloom`
  login, never an unrelated account, and never stages for root.

```sh
BLOOM_PREPARE_LOGIN_USER=1 sh "$review_dir/setup.sh"
```

Staging reports `BLOOM_HEADLESS_LOGIN=enrolled`, `=existing`, or `=prepared`
ahead of the usual captured values, and gives that login a temporary directory
it can write even when the inherited `TMPDIR` is one it cannot. An unmet
prerequisite is reported as a `Bloom headless setup blocker:` line; report that
blocker and stop rather than working around it.

Then run the identical fixed command with the captured values substituted as
before. As root, run it with no elevation prefix at all:

```sh
/bin/sh -c 'set -eu; s=$(mktemp -d /var/tmp/bloom-install.XXXXXX); trap "rm -rf -- $s" EXIT; trap "exit 129" HUP INT TERM; cp -R "$1/bloom-triad" "$s/"; chown -R 0:0 "$s"; chmod -R go-w "$s"; if find "$s" -type l -o ! -type f ! -type d | grep -q .; then echo "Bloom stage contains a link or special file." >&2; exit 65; fi; k="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFY9na4hytUNsW+8LWu//HrX9TaPU7H7Vg0GRWcZM+uP"; printf "%s\n" "$k" > "$s/key.pub"; printf "bloom-release %s\n" "$k" > "$s/signers"; p="$s/bloom-triad"; /usr/bin/ssh-keygen -Y verify -f "$s/signers" -I bloom-release -n bloom-release-payload-v1 -s "$p/RELEASE_SIGNATURE" < "$p/SHA256SUMS" > /dev/null; cd "$p"; { sha256sum -c SHA256SUMS 2>/dev/null || shasum -a 256 -c SHA256SUMS; } > /dev/null; case $(uname -s) in Linux) i=linux;; Darwin) i=macos;; *) exit 65;; esac; BLOOM_RELEASE_PUBLIC_KEY="$s/key.pub" "$p/installer/release/install-$i.sh" install / "$2" "$3" "$p"' bloom-install 'STAGE' 'UID' 'USER'
```

If the agent is not root but `sudo -n true` succeeds, prefix exactly `sudo -n`
and nothing else. Do not add environment, arguments, or a different root, and
do not retry a password-prompting elevation through another path.

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

Also require matching CLI and daemon versions, which `bloom --version` prints
together. `bloom-daemon unavailable` or `bloom-daemon incompatible` is a failed
check, not readiness.

When the agent staged as root for another login, run every check as that login,
with a writable `TMPDIR`, and read the service units for its UID. Substitute
the captured `BLOOM_LOGIN_USER` and `BLOOM_LOGIN_UID` as shell-quoted literals,
as for the privileged command; staging's output is still not evaluated:

```sh
login_user='USER'
login_uid='UID'
bloom_login() {
  runuser -u "$login_user" -- env \
    HOME="$(getent passwd "$login_user" | cut -d: -f6)" \
    TMPDIR=/tmp \
    XDG_RUNTIME_DIR="/run/user/$login_uid" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$login_uid/bus" "$@"
}
bloom_login systemctl --user is-active bloom-session.service bloom-machine.service
systemctl is-active "bloom-signer@$login_uid.service" "bloom-broker@$login_uid.service"
bloom_login bloom --version
```

`BLOOM_RELOGIN_REQUIRED=1` after `BLOOM_HEADLESS_LOGIN=prepared` means the user
manager this run started predates Bloom's groups. Restart that one prepared
login's session, wait for `/run/user/$login_uid/bus` again, and recheck:

```sh
loginctl disable-linger "$login_user"
loginctl enable-linger "$login_user"
```

Never do that to a login a human or another workload is using, and never for
`BLOOM_HEADLESS_LOGIN=enrolled` or `=existing`: report that the login needs a
fresh session instead.

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

On a headless host, run these through the `bloom_login` wrapper above; the
mount belongs to the Bloom login, not to root. The daemon's `version` in
`status/daemon.json` is the version `bloom --version` must agree with.

Require `mutation_degradation: null` for readiness. Poll startup effects for up to 30 seconds.
Once idle, allow one restart of the existing packaged Machine as a workaround, not a root-cause fix.
Recheck audit health/startup completion; continue only if healthy, otherwise report the blocker and stop.
An empty mount directory is not a successful mount. Wallet onboarding and
transaction actions remain outside this setup scope even while Bloom is running.
