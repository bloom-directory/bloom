# Install Bloom

Read this entire reference only when a new Bloom installation is needed.

## How to communicate

Use simple language and be concise. Use a table, checklist, or other visual
structure when it makes a longer explanation easier to scan; do not force one
into a short answer.

Offer **expert mode** as an option. Unless the user selects it, assume they are
non-technical: perform setup and operations for them. On macOS, and on Linux when
`pkexec` is installed, you run the reviewed privileged command yourself and the
operating system asks the user for their credential. Only on Linux without
`pkexec` do you ask them to run the single reviewed sudo command themselves. In
expert mode, treat the user as technical and show commands or implementation
detail when useful.

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

When the user supplies a specific `SKILL.md` URL, use that document's sibling
`setup.sh`; never silently replace a preview or custom origin with production.
For a website-loaded skill, fetch the script as follows:

For every setup or privileged handoff invocation, set the working directory to
`/private/tmp` on macOS or `/tmp` on Linux. Never run from inside the Bloom mount:
installation can restart it and invalidate the current working directory.

```sh
skill_url=${BLOOM_SKILL_URL:-https://bloom.directory/SKILL.md}
setup_url=${skill_url%/SKILL.md}/setup.sh
review_dir="$(mktemp -d "${TMPDIR:-/tmp}/bloom-review.XXXXXX")"
curl -fsSL "$setup_url" -o "$review_dir/setup.sh"
cat "$review_dir/setup.sh"
```

Set `BLOOM_SKILL_URL` to the exact URL the user supplied when it is not the
production URL. The sibling setup script must come from the same origin and path
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
BLOOM_INSTALLER=<home>/.cache/bloom/install/<resolved-tag>-<platform>/install-reviewed-triad.sh
BLOOM_PAYLOAD=<home>/.cache/bloom/install/<resolved-tag>-<platform>/bloom-triad
BLOOM_LOGIN_UID=<decimal UID>
BLOOM_LOGIN_USER=<login name>
BLOOM_SUDO_REQUIRED=1
```

`BLOOM_SUDO_REQUIRED=1` means the staged installer still needs one privileged
step. Every supported path runs the identical reviewed installer invocation with
the captured values; only who runs it and who asks for the credential differs.
The privileged command must stay exactly that invocation. Do not add arguments,
add environment variables, change the root, or substitute a different payload.

The platform distinction is exact:

| Target | Privileged path |
| --- | --- |
| macOS arm64 | the agent runs the invocation through `/usr/bin/osascript` |
| Linux x86_64 or aarch64 with `pkexec` | the agent runs the invocation through `pkexec` |
| Linux x86_64 or aarch64 without `pkexec` | the user runs the invocation under `sudo` |

### Linux privileged handoff: pkexec when installed, otherwise user-run sudo

On Linux, first check whether `pkexec` is installed:

```sh
command -v pkexec
```

If it is installed, do not ask the user to paste a command into another terminal.
Execute the reviewed invocation yourself through `pkexec`, so the system
authentication agent presents its own credential dialog directly to the user:

```sh
pkexec "$BLOOM_INSTALLER" install / "$BLOOM_LOGIN_UID" "$BLOOM_LOGIN_USER" "$BLOOM_PAYLOAD"
```

`pkexec` is what elevates, so the elevated command must not also contain `sudo`,
and nothing may sit between `pkexec` and `"$BLOOM_INSTALLER"`: no environment
variable assignments, no `env`, and no `pkexec` options. The four captured values
are the only arguments.

The credential belongs to the authentication agent and the user alone. The dialog
is drawn by the operating system, and the agent must never request, read, relay,
or receive the password. If the user dismisses the dialog, pkexec exits `126`;
report the cancellation and stop rather than retrying through a different
privileged path.

If `pkexec` is not installed, present this exact command and ask the user to
execute it themselves:

```sh
sudo "$BLOOM_INSTALLER" install / "$BLOOM_LOGIN_UID" "$BLOOM_LOGIN_USER" "$BLOOM_PAYLOAD"
```

The user may enter their sudo password directly into their terminal; the agent
must never request, read, or relay it. Do not fall back to sudo when `pkexec` is
available, and never combine the two.

### macOS privileged handoff: the agent runs osascript

On macOS, do not ask the user to paste a command into another terminal. Execute
the same reviewed invocation yourself through `/usr/bin/osascript`, so macOS
presents its own administrator credential dialog directly to the user:

```sh
/usr/bin/osascript \
  -e 'on run argv' \
  -e 'do shell script (quoted form of (item 1 of argv) & " install / " & quoted form of (item 2 of argv) & " " & quoted form of (item 3 of argv) & " " & quoted form of (item 4 of argv)) with administrator privileges' \
  -e 'end run' \
  "$BLOOM_INSTALLER" "$BLOOM_LOGIN_UID" "$BLOOM_LOGIN_USER" "$BLOOM_PAYLOAD"
```

Passing the captured values after the script keeps them out of the AppleScript
source, and `quoted form of` quotes each one for the shell that `do shell script`
starts. `with administrator privileges` is what elevates, so the elevated command
must not also contain `sudo`.

The credential belongs to macOS and the user alone. The dialog is drawn by the
operating system, and the agent must never request, read, relay, or receive the
password: never add a `user name` or `password` parameter to `do shell script`,
and never collect the password through any other prompt. If the user cancels the
dialog, osascript fails with error `-128`; report the cancellation and stop
rather than retrying through a different privileged path.

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

On Linux, success includes `BLOOM_RELOGIN_REQUIRED=1`. Tell the user that Bloom
was installed but the current login session does not yet have its new access
groups. Do not attempt a group workaround; resume after a fresh login.

After that fresh login, the package starts Machine and mounts `~/bloom` through
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

On either supported target, require the service checks above, both mounted reads,
and audit health before reporting Bloom fully ready:

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
