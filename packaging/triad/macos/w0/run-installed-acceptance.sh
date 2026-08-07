#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: run-installed-acceptance.sh PAYLOAD LOGIN_UID LOGIN_USER MAIN_ROOT BROKER_ROOT SIGNER_ROOT EVIDENCE_DIR" >&2
  exit 64
}

[[ $# -eq 7 ]] || usage
payload="$(cd "$1" && pwd -P)"
login_uid="$2"
login_user="$3"
main_root="$(cd "$4" && pwd -P)"
broker_root="$(cd "$5" && pwd -P)"
signer_root="$(cd "$6" && pwd -P)"
evidence_dir="$(cd "$7" && pwd -P)"
[[ "$login_uid" =~ ^[1-9][0-9]*$ ]] || usage
[[ "$login_user" =~ ^[a-z_][a-z0-9_-]*$ ]] || usage

[[ "$EUID" -eq 0 && "$(uname -s)" == "Darwin" ]] || {
  echo "installed acceptance requires root on a disposable macOS host" >&2
  exit 77
}
marker="/private/var/db/bloom-w0-disposable-host"
if [[ "${BLOOM_RUN_MACOS_UNIX_W0:-}" != "true" ]] ||
  [[ ! -f "$marker" || -L "$marker" ]] ||
  ! grep -Fx 'bloom-macos-unix-w0-disposable-v1' "$marker" >/dev/null
then
  echo "installed acceptance host is not explicitly marked disposable" >&2
  exit 77
fi
[[ "$(<"$payload/PLATFORM_CLAIM")" == "macos-unix-principals-w0" ]] || {
  echo "installed acceptance payload has the wrong platform claim" >&2
  exit 65
}
[[ "$(id -u "$login_user")" == "$login_uid" ]] || {
  echo "installed acceptance login name and UID do not match" >&2
  exit 65
}
[[ -d "$evidence_dir" && ! -L "$evidence_dir" ]] || {
  echo "installed acceptance evidence directory is unsafe" >&2
  exit 65
}

static_work="$(mktemp -d /private/tmp/bloom-w0-static-conformance.XXXXXX)"
cleanup() {
  status=$?
  rm -rf -- "$static_work"
  exit "$status"
}
trap cleanup EXIT

enrollment="/Library/Application Support/BloomTriad/enrollments/$login_uid.json"
[[ -f "$enrollment" && ! -L "$enrollment" ]] || {
  echo "installed acceptance requires an active enrollment" >&2
  exit 69
}
[[ "$(stat -f '%u:%g:%Lp:%l' "$enrollment")" == "0:0:644:1" ]]
[[ "$(plutil -extract state raw -o - "$enrollment")" == "active" ]]
release_digest="$(plutil -extract release_digest raw -o - "$enrollment")"
payload_release_digest="$(
  shasum -a 256 "$payload/SHA256SUMS" |
    awk '{print $1}'
)"
[[ "$release_digest" == "$payload_release_digest" ]]
release_root="/usr/local/libexec/bloom/releases/$release_digest"
[[ "$(readlink /usr/local/libexec/bloom/current)" == "releases/$release_digest" ]]
for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
  installed="$release_root/$binary"
  [[ "$(stat -f '%u:%g:%Lp:%l' "$installed")" == "0:0:755:1" ]]
  cmp "$payload/bin/$binary" "$installed" >/dev/null || {
    echo "installed $binary does not match the tested payload" >&2
    exit 1
  }
done
[[ ! -e "$release_root/bloom-machine" ]] || {
  echo "installed payload unexpectedly has an alternate Machine executable" >&2
  exit 1
}

if find "$payload" \
  \( -name embedded.provisionprofile \
  -o -name '*.provisionprofile' \
  -o -name '*.mobileprovision' \
  -o -name '_CodeSignature' \) |
  grep . >/dev/null
then
  echo "tested payload contains an Apple Developer Program artifact" >&2
  exit 1
fi
for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
  codesign_report="$static_work/$binary.codesign"
  codesign -d --verbose=4 "$payload/bin/$binary" \
    >"$codesign_report" 2>&1 || true
  team_identifier="$(sed -n 's/^TeamIdentifier=//p' "$codesign_report")"
  if grep -E '^Authority=' "$codesign_report" >/dev/null ||
    [[ -n "$team_identifier" && "$team_identifier" != "not set" ]]
  then
    echo "$binary unexpectedly depends on an Apple signing identity" >&2
    exit 1
  fi
done

# Prove the same Mach-O binaries cannot be relabelled as production without
# supplying the separately reviewed conformance report and pinned public key.
mkdir -p "$static_work/staging/bin"
for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
  cp "$payload/bin/$binary" "$static_work/staging/bin/$binary"
done
printf '%s\n' 'intentionally invalid: conformance rejection must precede signing' \
  > "$static_work/release-key.pem"
chmod 0600 "$static_work/release-key.pem"
set +e
env \
  BLOOM_PLATFORM_CLAIM=macos-unix-principals \
  BLOOM_MACOS_CONFORMANCE_REPORT= \
  BLOOM_MACOS_CONFORMANCE_SIGNATURE= \
  BLOOM_MACOS_CONFORMANCE_PUBLIC_KEY= \
  BLOOM_MACOS_CONFORMANCE_KEY_SHA256= \
  "$main_root/packaging/triad/release/build-bundle.sh" \
  "$static_work/staging" \
  "$static_work/forbidden-production.tar.gz" \
  "$static_work/release-key.pem" \
  1700000000 \
  >"$static_work/production-gate.log" 2>&1
production_gate_status=$?
set -e
[[ "$production_gate_status" -ne 0 ]] || {
  echo "release gate emitted a production macOS claim without conformance evidence" >&2
  exit 1
}
grep -F \
  'BLOOM_MACOS_CONFORMANCE_REPORT must name a regular conformance input' \
  "$static_work/production-gate.log" >/dev/null

assert_installed_process() {
  process_name="$1"
  service_uid="$2"
  expected_binary="$3"
  process_ids="$(pgrep -u "$service_uid" -x "$process_name" || true)"
  [[ "$(wc -w <<<"$process_ids" | tr -d ' ')" == "1" ]] || {
    echo "installed acceptance expected one $process_name for UID $service_uid" >&2
    exit 1
  }
  process_id="$process_ids"
  [[ "$(ps -p "$process_id" -o uid= | tr -d ' ')" == "$service_uid" ]]
  lsof -nP -a -p "$process_id" -d txt -Fn |
    grep -Fx \
      -e "n$expected_binary" \
      -e "n/usr/local/libexec/bloom/current/$process_name" >/dev/null || {
    echo "$process_name is not executing the installed release binary" >&2
    exit 1
  }
}

broker_uid="$(plutil -extract broker_uid raw -o - "$enrollment")"
signer_uid="$(plutil -extract signer_uid raw -o - "$enrollment")"
assert_installed_process bloom-broker "$broker_uid" "$release_root/bloom-broker"
assert_installed_process bloom-signer "$signer_uid" "$release_root/bloom-signer"
sudo -u "$login_user" \
  "$release_root/bloom" serve triad-health-check "$release_digest"

machine_identity="/Library/Application Support/BloomTriad/config/$login_uid/machine/identity.json"
edge_manifest="/Library/Application Support/BloomTriad/config/$login_uid/edge-manifest.json"
"$main_root/packaging/triad/macos/w0/run-packaged-machine-negative.sh" \
  "$release_root/bloom" \
  "$login_uid" \
  "$login_user" \
  "$broker_uid" \
  "$signer_uid" \
  "$machine_identity" \
  "$edge_manifest" \
  "$broker_root"

# The runtime negative restores the installed Broker before returning.
deadline=$((SECONDS + 20))
while [[ $SECONDS -lt $deadline ]]; do
  if sudo -u "$login_user" \
    "$release_root/bloom" serve triad-health-check "$release_digest"
  then
    break
  fi
  sleep 1
done
sudo -u "$login_user" \
  "$release_root/bloom" serve triad-health-check "$release_digest"

source_revision() {
  key="$1"
  sed -n "s/^$key=//p" "$payload/SOURCE_REVISIONS"
}

assert_source() {
  local root="$1"
  local revision_key="$2"
  local expected_revision tracked_status
  expected_revision="$(source_revision "$revision_key")"
  [[ "$expected_revision" =~ ^[0-9a-f]{40}$ ]]
  [[ "$(sudo -H -u "$login_user" /usr/bin/git -C "$root" rev-parse HEAD)" == \
    "$expected_revision" ]] || {
    echo "$revision_key source does not match the installed payload" >&2
    exit 65
  }
  if ! tracked_status="$(
    sudo -H -u "$login_user" \
      /usr/bin/git -C "$root" status --porcelain --untracked-files=no
  )"
  then
    echo "$revision_key source cleanliness inspection failed" >&2
    exit 65
  fi
  [[ -z "$tracked_status" ]] || {
    echo "$revision_key source has tracked modifications" >&2
    exit 65
  }
}

assert_source "$main_root" BLOOM_MACHINE_SHA
assert_source "$broker_root" BLOOM_BROKER_SHA
assert_source "$signer_root" BLOOM_SIGNER_SHA

cargo_binary="${BLOOM_MACOS_ACCEPTANCE_CARGO:-}"
[[ -n "$cargo_binary" ]] || cargo_binary="$(command -v cargo)"
[[ "$cargo_binary" == /* && -x "$cargo_binary" ]] || {
  echo "installed acceptance requires an absolute executable cargo path" >&2
  exit 69
}
cargo_home="${BLOOM_MACOS_ACCEPTANCE_CARGO_HOME:-}"
rustup_home="${BLOOM_MACOS_ACCEPTANCE_RUSTUP_HOME:-}"
cargo_target_dir="${BLOOM_MACOS_ACCEPTANCE_CARGO_TARGET_DIR:-}"
[[ -z "$cargo_home" || "$cargo_home" == /* ]] || exit 65
[[ -z "$rustup_home" || "$rustup_home" == /* ]] || exit 65
[[ -z "$cargo_target_dir" || "$cargo_target_dir" == /* ]] || exit 65
run_as_login() {
  tool_environment=(
    "BLOOM_ACCEPTANCE_BUNDLE_ROOT=$payload"
    "BLOOM_ALLOW_MACOS_UNIX_W0=true"
  )
  [[ -z "$cargo_home" ]] || tool_environment+=("CARGO_HOME=$cargo_home")
  [[ -z "$rustup_home" ]] || tool_environment+=("RUSTUP_HOME=$rustup_home")
  [[ -z "$cargo_target_dir" ]] ||
    tool_environment+=("CARGO_TARGET_DIR=$cargo_target_dir")
  sudo -H -u "$login_user" \
    env \
    "${tool_environment[@]}" \
    "$cargo_binary" "$@"
}

# Machine-side fault injection remains linked only into the test executable;
# installed production services stay running under their real principals.
run_as_login test \
  --manifest-path "$main_root/Cargo.toml" \
  --locked \
  -p bloom-machine-client
run_as_login test \
  --manifest-path "$main_root/Cargo.toml" \
  --locked \
  -p bloom-petals \
  ac35_legacy_v0_1
run_as_login test \
  --manifest-path "$main_root/Cargo.toml" \
  --locked \
  -p bloom-vfs \
  --test triad_policy_update
run_as_login test \
  --manifest-path "$main_root/Cargo.toml" \
  --locked \
  -p bloom-vfs \
  --lib \
  approval_prepare_projection
run_as_login test \
  --manifest-path "$main_root/Cargo.toml" \
  --locked \
  -p bloom \
  --bin bloom \
  ac26_every_custody_kind
run_as_login test \
  --manifest-path "$broker_root/Cargo.toml" \
  --workspace \
  --locked
run_as_login test \
  --manifest-path "$signer_root/Cargo.toml" \
  --workspace \
  --locked

# The local APFS clones are the exact commit-bound sources used to build the
# package. Recheck them after every acceptance executable has run so a test
# cannot silently mutate tracked source and weaken the provenance claim.
assert_source "$main_root" BLOOM_MACHINE_SHA
assert_source "$broker_root" BLOOM_BROKER_SHA
assert_source "$signer_root" BLOOM_SIGNER_SHA

# Recheck the installed boundary after all fault-injection executables finish.
assert_installed_process bloom-broker "$broker_uid" "$release_root/bloom-broker"
assert_installed_process bloom-signer "$signer_uid" "$release_root/bloom-signer"
sudo -u "$login_user" \
  "$release_root/bloom" serve triad-health-check "$release_digest"

subject_digest="$(
  "$main_root/packaging/triad/release/macos-conformance-subject.sh" "$payload"
)"
for criterion in mui_01 mui_11 installed_ac_01_35 mui_12; do
  temporary="$evidence_dir/.$criterion.$$.new"
  printf '%s\n' "$subject_digest" > "$temporary"
  chmod 0644 "$temporary"
  mv -f "$temporary" "$evidence_dir/$criterion.pass"
done

echo "installed AC-01 through AC-35 rerun passed"
