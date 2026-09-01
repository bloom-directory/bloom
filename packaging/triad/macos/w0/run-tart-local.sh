#!/bin/bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
main_root="$(cd "$script_dir/../../../.." && pwd)"
workspace_root="$(dirname "$main_root")"
broker_root="${BLOOM_TART_BROKER_ROOT:-$workspace_root/bloom-broker}"
signer_root="${BLOOM_TART_SIGNER_ROOT:-$workspace_root/bloom-signer}"
development_base="${BLOOM_TART_DEVELOPMENT_BASE:-bloom-macos-w0-dev-base}"
guest_password="${BLOOM_TART_GUEST_PASSWORD:-admin}"
keep_failed="${BLOOM_TART_KEEP_FAILED:-false}"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
run_name="bloom-macos-w0-run-$run_id"
local_output_root="${BLOOM_TART_OUTPUT_ROOT:-$workspace_root/.w0-local/runs/$run_id}"
build_vm_log="$local_output_root/build-vm.log"
run_vm_log="$local_output_root/run-vm.log"
build_log="$local_output_root/build.log"
w0_log="$local_output_root/w0.log"

for command_name in tart jq sshpass ssh nc git; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "missing local Tart W0 dependency: $command_name" >&2
    exit 69
  }
done

for repository_root in "$main_root" "$broker_root" "$signer_root"; do
  git -C "$repository_root" rev-parse --git-dir >/dev/null 2>&1 || {
    echo "missing local Bloom repository: $repository_root" >&2
    exit 69
  }
done

vm_status() {
  local vm_name="$1"
  local listing status
  if ! listing="$(tart list --format json)"; then
    echo "failed to list local Tart VMs" >&2
    return 70
  fi
  if ! status="$(
    jq -er --arg name "$vm_name" '
      if type != "array" then error("Tart VM list is not an array") else . end
      | [ .[] | select(.Source == "local" and .Name == $name) ]
      | if length == 0 then "missing"
        elif length != 1 then error("duplicate local Tart VM")
        elif .[0].Running then "running"
        else "stopped"
        end
    ' <<<"$listing"
  )"
  then
    echo "failed to query local Tart VM state: $vm_name" >&2
    return 70
  fi
  printf '%s\n' "$status"
}

if ! development_base_status="$(vm_status "$development_base")"; then
  exit 70
fi
case "$development_base_status" in
  missing)
    echo "missing local Tart W0 development base: $development_base" >&2
    echo "run $script_dir/provision-tart-local.sh first" >&2
    exit 69
    ;;
  running)
    echo "local Tart W0 development base is already running: $development_base" >&2
    exit 69
    ;;
  stopped) ;;
  *)
    echo "invalid local Tart VM state: $development_base_status" >&2
    exit 70
    ;;
esac

mkdir -p "$local_output_root"

source_bundle_root="$local_output_root/source-bundles"
mkdir -p "$source_bundle_root"

prepare_source_bundle() {
  local repository_root="$1"
  local bundle_name="$2"
  local tracked_status revision temporary bundle_path bundle_heads
  local bundled_revision bundled_ref extra
  if ! tracked_status="$(
    git -C "$repository_root" status --porcelain --untracked-files=no
  )"
  then
    echo "failed to inspect Tart source repository: $repository_root" >&2
    return 65
  fi
  if [[ -n "$tracked_status" ]]; then
    echo "tracked source changes must be committed before Tart validation: $repository_root" >&2
    return 65
  fi
  if ! revision="$(git -C "$repository_root" rev-parse HEAD)"; then
    echo "failed to resolve Tart source revision: $repository_root" >&2
    return 65
  fi
  [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || {
    echo "invalid source revision for Tart validation: $repository_root" >&2
    return 65
  }
  bundle_path="$source_bundle_root/$bundle_name.bundle"
  temporary="$source_bundle_root/.$bundle_name.bundle.$$.new"
  git -C "$repository_root" bundle create "$temporary" HEAD
  git -C "$repository_root" bundle verify "$temporary" >/dev/null
  if ! bundle_heads="$(
    git -C "$repository_root" bundle list-heads "$temporary"
  )"
  then
    echo "failed to enumerate Tart source bundle heads: $repository_root" >&2
    return 65
  fi
  read -r bundled_revision bundled_ref extra <<<"$bundle_heads"
  if [[ "$bundled_revision" != "$revision" || "$bundled_ref" != HEAD || -n "$extra" ]] ||
    [[ "$bundle_heads" == *$'\n'* ]]
  then
    echo "Tart source bundle is not bound to the captured HEAD: $repository_root" >&2
    return 65
  fi
  mv -f "$temporary" "$bundle_path"
}

prepare_source_bundle "$main_root" bloom
prepare_source_bundle "$broker_root" bloom-broker
prepare_source_bundle "$signer_root" bloom-signer

ssh_options=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=10
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -o IdentitiesOnly=yes
  -o NumberOfPasswordPrompts=1
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=4
)

active_vm=""
run_pid=""
completed=false

stop_active_vm() {
  local attempt
  if [[ -n "$active_vm" ]]; then
    if ! tart stop "$active_vm" >/dev/null 2>&1; then
      echo "failed to stop active Tart VM cleanly: $active_vm" >&2
      [[ -z "$run_pid" ]] || kill "$run_pid" >/dev/null 2>&1 || true
    fi
  fi
  if [[ -n "$run_pid" ]]; then
    for attempt in {1..15}; do
      kill -0 "$run_pid" >/dev/null 2>&1 || break
      sleep 1
    done
    if kill -0 "$run_pid" >/dev/null 2>&1; then
      echo "Tart run process did not exit after stop; terminating pid $run_pid" >&2
      kill "$run_pid" >/dev/null 2>&1 || true
      sleep 1
    fi
    if kill -0 "$run_pid" >/dev/null 2>&1; then
      kill -KILL "$run_pid" >/dev/null 2>&1 || true
    fi
    wait "$run_pid" >/dev/null 2>&1 || true
  fi
  run_pid=""
  active_vm=""
}

cleanup() {
  local status=$?
  trap - EXIT
  stop_active_vm
  if [[ "$status" -eq 0 || "$keep_failed" != true ]]; then
    tart delete "$run_name" >/dev/null 2>&1 || true
  else
    echo "preserved failed disposable VM if it was created: $run_name" >&2
  fi
  if [[ "$completed" == true ]]; then
    echo "local macOS W0 passed; evidence: $local_output_root"
  else
    echo "local macOS W0 failed; diagnostics: $local_output_root" >&2
  fi
  exit "$status"
}
trap cleanup EXIT

start_vm() {
  local vm_name="$1"
  local log_path="$2"
  active_vm="$vm_name"
  tart run \
    --no-graphics \
    --no-audio \
    --no-clipboard \
    --dir="output:$local_output_root" \
    "$vm_name" >"$log_path" 2>&1 &
  run_pid=$!

  guest_ip=""
  for _ in {1..90}; do
    if ! kill -0 "$run_pid" >/dev/null 2>&1; then
      local run_status=0
      wait "$run_pid" || run_status=$?
      run_pid=""
      active_vm=""
      echo "Tart VM process exited before SSH was ready: $vm_name (status $run_status)" >&2
      return 1
    fi
    guest_ip="$(tart ip "$vm_name" 2>/dev/null || true)"
    if [[ -n "$guest_ip" ]] &&
      nc -z -w 1 "$guest_ip" 22 >/dev/null 2>&1 &&
      sshpass -p "$guest_password" \
        ssh "${ssh_options[@]}" "admin@$guest_ip" /usr/bin/true \
        >/dev/null 2>&1
    then
      # Tahoe guests can accept SSH while child-side fork initialization is
      # still unstable. Wait past the observed early-boot window, then prove
      # fresh processes can execute before attributing a failure to Bloom.
      sleep 60
      if printf '%s\n' \
        'set -e' \
        'for _fork_probe in {1..200}; do /usr/bin/true; done' |
        sshpass -p "$guest_password" \
          ssh "${ssh_options[@]}" "admin@$guest_ip" /bin/bash -s \
        >/dev/null 2>&1
      then
        return 0
      fi
    fi
    sleep 2
  done
  echo "Tart VM did not expose SSH: $vm_name" >&2
  return 1
}

run_guest() {
  local guest_ip="$1"
  local guest_script="$2"
  local log_path="$3"
  sshpass -p "$guest_password" \
    ssh "${ssh_options[@]}" "admin@$guest_ip" \
    /bin/bash -s <"$guest_script" 2>&1 |
    tee "$log_path"
}

echo "building W0 candidate in local Tart base $development_base"
start_vm "$development_base" "$build_vm_log"
builder_ip="$guest_ip"
run_guest \
  "$builder_ip" \
  "$script_dir/tart-build-guest.sh" \
  "$build_log"
stop_active_vm

echo "creating disposable local macOS W0 clone $run_name"
tart clone "$development_base" "$run_name"
tart set "$run_name" --random-mac
start_vm "$run_name" "$run_vm_log"
runner_ip="$guest_ip"
run_guest \
  "$runner_ip" \
  "$script_dir/tart-run-guest.sh" \
  "$w0_log"

completed=true
