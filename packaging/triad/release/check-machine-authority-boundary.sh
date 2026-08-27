#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
workspace="$(cd "$script_dir/../../.." && pwd -P)"
feature_sets="${BLOOM_MACHINE_PRODUCTION_FEATURE_SETS:-$script_dir/machine-production-feature-sets.tsv}"
mode="${1:-}"
scanner="$script_dir/machine-authority-scan.py"

usage() {
  echo "usage: $0 --inventory|--require-clean" >&2
  exit 64
}

case "$mode" in
  --inventory|--require-clean) ;;
  *) usage ;;
esac

for command_name in cargo jq python3 awk sed sort uniq find; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "machine authority boundary check requires $command_name" >&2
    exit 69
  }
done
test -f "$scanner" || {
  echo "missing Machine authority scanner: $scanner" >&2
  exit 66
}
test -f "$feature_sets" || {
  echo "missing Machine production feature sets: $feature_sets" >&2
  exit 66
}

# VirtioFS-backed macOS guests can transiently terminate a reader while a new
# directory share is settling immediately after boot. Retry only scanner
# failures (exit >= 2 or signal); exit 1 remains the scanner's valid no-match
# result. Exhausted retries are returned to the caller and always fail closed.
run_scanner() {
  local attempt status=2
  for attempt in 1 2 3; do
    if python3 "$scanner" "$@"; then
      return 0
    else
      status=$?
    fi
    (( status == 1 )) && return 1
    echo "Machine authority scanner attempt $attempt failed with status $status" >&2
    (( attempt == 3 )) || sleep 2
  done
  return "$status"
}

rustc_host_triple() {
  local attempt status=1 verbose line
  for attempt in 1 2 3; do
    if verbose="$(rustc -vV)"; then
      while IFS= read -r line; do
        if [[ "$line" == host:\ * ]]; then
          printf '%s\n' "${line#host: }"
          return 0
        fi
      done <<<"$verbose"
      status=65
      echo "rustc host discovery attempt $attempt returned no host triple" >&2
    else
      status=$?
      echo "rustc host discovery attempt $attempt failed with status $status" >&2
    fi
    (( attempt == 3 )) || sleep 2
  done
  return "$status"
}

cargo_tree_for_set() {
  local package="$1"
  local defaults="$2"
  local features="$3"
  local args=(
    tree
    --manifest-path "$workspace/Cargo.toml"
    -p "$package"
    -e "normal,build"
    --prefix none
  )
  [[ "$defaults" == "no" ]] && args+=(--no-default-features)
  [[ "$features" != "-" ]] && args+=(--features "$features")
  local attempt status=1
  for attempt in 1 2 3; do
    if cargo "${args[@]}"; then
      return 0
    else
      status=$?
    fi
    echo "Cargo tree attempt $attempt failed with status $status" >&2
    (( attempt == 3 )) || sleep 2
  done
  return "$status"
}

cargo_feature_tree_for_set() {
  local package="$1"
  local defaults="$2"
  local features="$3"
  if [[ -n "${BLOOM_MACHINE_FEATURE_TREE_FIXTURE:-}" ]]; then
    [[ -f "$BLOOM_MACHINE_FEATURE_TREE_FIXTURE" ]] || {
      echo "missing synthetic Machine feature-tree fixture: $BLOOM_MACHINE_FEATURE_TREE_FIXTURE" >&2
      return 1
    }
    command cat "$BLOOM_MACHINE_FEATURE_TREE_FIXTURE"
    return
  fi
  local args=(
    tree
    --manifest-path "$workspace/Cargo.toml"
    -p "$package"
    -e "normal,build,features"
    --prefix none
  )
  [[ "$defaults" == "no" ]] && args+=(--no-default-features)
  [[ "$features" != "-" ]] && args+=(--features "$features")
  local attempt status=1
  for attempt in 1 2 3; do
    if cargo "${args[@]}"; then
      return 0
    else
      status=$?
    fi
    echo "Cargo feature tree attempt $attempt failed with status $status" >&2
    (( attempt == 3 )) || sleep 2
  done
  return "$status"
}

cargo_metadata_for_set() {
  local package="$1"
  local defaults="$2"
  local features="$3"
  local host_triple
  if [[ -n "${BLOOM_MACHINE_METADATA_FIXTURE:-}" ]]; then
    [[ -f "$BLOOM_MACHINE_METADATA_FIXTURE" ]] || {
      echo "missing synthetic Machine metadata fixture: $BLOOM_MACHINE_METADATA_FIXTURE" >&2
      return 1
    }
    command cat "$BLOOM_MACHINE_METADATA_FIXTURE"
    return
  fi
  if ! host_triple="$(rustc_host_triple)"; then
    echo "failed to resolve rustc host triple" >&2
    return 1
  fi
  local args=(
    metadata
    --format-version 1
    --locked
    --manifest-path "$workspace/Cargo.toml"
    --filter-platform "$host_triple"
  )
  [[ "$defaults" == "no" ]] && args+=(--no-default-features)
  [[ "$features" != "-" ]] && args+=(--features "$package/$features")
  local attempt status=1
  for attempt in 1 2 3; do
    if cargo "${args[@]}"; then
      return 0
    else
      status=$?
    fi
    echo "Cargo metadata attempt $attempt failed with status $status" >&2
    (( attempt == 3 )) || sleep 2
  done
  return "$status"
}

# Print the exact normal/build closure selected for one Machine root. Cargo
# metadata includes all workspace members, so selecting packages from the
# top-level package list is insufficient. Traverse from the named root through
# only non-dev resolved edges instead.
metadata_reachable_packages() {
  local package="$1"
  jq -r --arg root_name "$package" '
    . as $metadata
    | ($metadata.packages | map({ key: .id, value: . }) | from_entries) as $packages
    | ($metadata.resolve.nodes | map({ key: .id, value: . }) | from_entries) as $nodes
    | ([ $metadata.packages[] | select(.name == $root_name) | .id ]) as $roots
    | (if ($roots | length) != 1 then
        error("expected exactly one Machine root package named \($root_name)")
      else $roots[0] end) as $root
    | def children($id):
        $nodes[$id].deps[]
        | select(any(.dep_kinds[]; .kind == null or .kind == "build"))
        | .pkg;
      def closure($frontier; $seen):
        if ($frontier | length) == 0 then $seen
        else ([ $frontier[] as $id | children($id) ] | unique - $seen) as $next
        | closure($next; (($seen + $next) | unique))
        end;
      closure([$root]; [$root])[]
      | $packages[.] as $package
      | [ $package.name, $package.id, $package.manifest_path ]
      | @tsv
  '
}

metadata_reachable_features() {
  local package="$1"
  jq -r --arg root_name "$package" '
    . as $metadata
    | ($metadata.packages | map({ key: .id, value: . }) | from_entries) as $packages
    | ($metadata.resolve.nodes | map({ key: .id, value: . }) | from_entries) as $nodes
    | ([ $metadata.packages[] | select(.name == $root_name) | .id ]) as $roots
    | (if ($roots | length) != 1 then
        error("expected exactly one Machine root package named \($root_name)")
      else $roots[0] end) as $root
    | def children($id):
        $nodes[$id].deps[]
        | select(any(.dep_kinds[]; .kind == null or .kind == "build"))
        | .pkg;
      def closure($frontier; $seen):
        if ($frontier | length) == 0 then $seen
        else ([ $frontier[] as $id | children($id) ] | unique - $seen) as $next
        | closure($next; (($seen + $next) | unique))
        end;
      closure([$root]; [$root])[]
      | . as $id
      | $nodes[$id].features[]?
      | "\($packages[$id].name):\(.)"
  '
}

forbidden_dependencies() {
  if [[ -n "${BLOOM_MACHINE_FORBIDDEN_DEPENDENCIES:-}" ]]; then
    printf '%s\n' "${BLOOM_MACHINE_FORBIDDEN_DEPENDENCIES//,/$'\n'}"
    return
  fi
  printf '%s\n' \
    bloom-keystore bloom-auth bloom-auth-api bloom-hyperliquid \
    bloom-triad-protocol bloom-signer-api bloom-signer
}

feature_is_forbidden() {
  case "${1#*:}" in
    local-integration|unsafe-debug-signer|unsafe-debug-approver|triad-dev-harness|mainnet-canary|unsigned-audit-test-seam|audit-test-seam)
      return 0
      ;;
    *) return 1 ;;
  esac
}

production_source_roots() {
  local label package defaults features tree_output all_tree_output=""
  while IFS=$'\t' read -r label package defaults features; do
    [[ -z "$label" || "$label" == \#* ]] && continue
    if ! tree_output="$(cargo_tree_for_set "$package" "$defaults" "$features")"; then
      echo "failed to enumerate production Machine source roots for $label" >&2
      return 1
    fi
    all_tree_output+="$tree_output"$'\n'
  done < "$feature_sets"
  printf '%s' "$all_tree_output" |
    sed -n -E 's#^.* \((/[^)]*)\)( \(\*\))?$#\1#p' |
    sort -u |
    awk -v workspace="$workspace" '
      index($0, workspace "/crates/") == 1
    '
}

source_roots=()
if ! source_roots_output="$(production_source_roots)"; then
  echo "failed to resolve production Machine source roots" >&2
  exit 1
fi
while IFS= read -r source_root; do
  [[ -n "$source_root" ]] && source_roots+=("$source_root")
done <<<"$source_roots_output"
if [[ -n "${BLOOM_MACHINE_AUTHORITY_EXTRA_SOURCE_ROOTS:-}" ]]; then
  IFS=':' read -r -a extra_source_roots <<<"$BLOOM_MACHINE_AUTHORITY_EXTRA_SOURCE_ROOTS"
  source_roots+=("${extra_source_roots[@]}")
fi

inventory_dependencies() {
  local label package defaults features dependency metadata reachable
  while IFS=$'\t' read -r label package defaults features; do
    [[ -z "$label" || "$label" == \#* ]] && continue
    echo "feature-set: $label package=$package default-features=$defaults features=$features"
    metadata="$(cargo_metadata_for_set "$package" "$defaults" "$features")"
    if ! reachable="$(
      printf '%s\n' "$metadata" | metadata_reachable_packages "$package" | cut -f1
    )"
    then
      echo "failed to resolve production Machine dependency closure in $label" >&2
      return 1
    fi
    while IFS= read -r dependency; do
      if printf '%s\n' "$reachable" | grep -Fx "$dependency" >/dev/null; then
        echo "  reachable-forbidden-dependency: $dependency"
      fi
    done < <(forbidden_dependencies)
  done < "$feature_sets"
}

require_clean_dependencies() {
  local failed=0
  local label package defaults features dependency metadata reachable observed_feature scan_status
  local observed_features observed_dependency dependency_reachable
  while IFS=$'\t' read -r label package defaults features; do
    [[ -z "$label" || "$label" == \#* ]] && continue
    case ",${features}," in
      *,unsafe-debug-signer,*|*,unsafe-debug-approver,*|*,local-integration,*|*,triad-dev-harness,*|*,mainnet-canary,*|*,unsigned-audit-test-seam,*|*,audit-test-seam,*)
        echo "forbidden production Machine feature in $label: $features" >&2
        failed=1
        ;;
    esac
    if ! metadata="$(cargo_metadata_for_set "$package" "$defaults" "$features")"; then
      echo "failed to resolve production Machine feature set $label" >&2
      failed=1
      continue
    fi
    if ! reachable="$(
      printf '%s\n' "$metadata" | metadata_reachable_packages "$package" | cut -f1
    )"
    then
      echo "failed to resolve production Machine dependency closure in $label" >&2
      failed=1
      continue
    fi
    while IFS= read -r dependency; do
      dependency_reachable=false
      while IFS= read -r observed_dependency; do
        if [[ "$observed_dependency" == "$dependency" ]]; then
          dependency_reachable=true
          break
        fi
      done <<<"$reachable"
      if [[ "$dependency_reachable" == true ]]; then
        echo "forbidden production Machine dependency in $label: $dependency" >&2
        failed=1
      fi
    done < <(forbidden_dependencies)
    if ! observed_features="$(
      cargo_feature_tree_for_set "$package" "$defaults" "$features" |
        sed -n -E 's/^([^ ]+) feature "([^"]+)".*$/\1:\2/p' |
        sort -u
    )"
    then
      echo "failed to resolve production Machine features in $label" >&2
      failed=1
      continue
    fi
    while IFS= read -r observed_feature; do
      if feature_is_forbidden "$observed_feature"; then
        echo "forbidden resolved Machine feature in $label: $observed_feature" >&2
        failed=1
      fi
    done <<<"$observed_features"
  done < "$feature_sets"

  for manifest in \
    crates/bloom/Cargo.toml \
    crates/bloom-daemon/Cargo.toml \
    crates/bloom-vfs/Cargo.toml \
    crates/bloom-tx/Cargo.toml
  do
    [[ -f "$workspace/$manifest" ]] || continue
    if run_scanner regex \
      --pattern '^(unsafe-debug-signer|local-integration)\s*=' \
      "$workspace/$manifest" >&2
    then
      echo "forbidden authority-restoring production feature remains in $manifest" >&2
      failed=1
    else
      scan_status=$?
      if (( scan_status != 1 )); then
        echo "failed to scan production Machine manifest: $manifest" >&2
        failed=1
      fi
    fi
  done
  (( failed == 0 ))
}

forbidden_source_markers() {
  printf '%s\n' \
    bloom_triad_protocol bloom_signer_api bloom_signer \
    bloom-keystore bloom-auth bloom-auth-api bloom_hyperliquid \
    bloom_keystore bloom_auth KeystorePetalHost StoreApprovalVerifier \
    KeystoreApprovalSignatureVerifier SignerCache EphemeralAgentKey \
    PrivateKeySigner RegistrationCoordinator AuthServices InMemoryGrantStore \
    SessionStore ActiveSession SessionActionFacts authorize_and_debit \
    PetalHost::sign_hash sign_hash_sync backend_policy_for_wallet \
    policy_override unsafe-debug-signer local-integration policy-session \
    bloom.sign-hash
}

require_clean_sources() {
  local failed=0
  local marker absolute relative source_root matches legacy_files
  while IFS= read -r marker; do
    [[ -z "$marker" ]] && continue
    for source_root in "${source_roots[@]}"; do
      [[ -d "$source_root/src" ]] || continue
      if ! matches="$(
        run_scanner files \
          --marker "$marker" \
          --suffix .rs \
          --suffix .html \
          "$source_root/src"
      )"
      then
        echo "Machine authority source scan failed for marker: $marker" >&2
        failed=1
        continue
      fi
      while IFS= read -r absolute; do
        [[ -z "$absolute" ]] && continue
        relative="${absolute#"$workspace/"}"
        echo "forbidden production Machine source marker: $marker in $relative" >&2
        failed=1
      done <<<"$matches"
    done
  done < <(forbidden_source_markers)

  for source_root in "${source_roots[@]}"; do
    [[ -d "$source_root/src" ]] || continue
    if ! legacy_files="$(
      find "$source_root/src" -type f \
        \( -name 'registration.rs' -o -name 'sealed_ceremony.rs' -o \
           -name 'sign_hash.rs' -o -name 'auth.sqlite' \) -print
    )"
    then
      echo "failed to enumerate legacy authority source files in $source_root" >&2
      failed=1
      continue
    fi
    while IFS= read -r absolute; do
      [[ -z "$absolute" ]] && continue
      relative="${absolute#"$workspace/"}"
      echo "forbidden legacy authority source file: $relative" >&2
      failed=1
    done <<<"$legacy_files"
    if [[ -d "$source_root/src/ceremony_server" ]]; then
      relative="${source_root#"$workspace/"}/src/ceremony_server"
      echo "forbidden legacy authority source directory: $relative" >&2
      failed=1
    fi
    if [[ "$source_root" == "$workspace/crates/bloom-tx" && \
      -e "$source_root/src/session.rs" ]]
    then
      echo "forbidden legacy authority source file: crates/bloom-tx/src/session.rs" >&2
      failed=1
    fi
  done
  (( failed == 0 ))
}

require_clean_current_entry_docs() {
  local failed=0
  local configured relative path scan_status
  local -a entry_docs
  if [[ -n "${BLOOM_MACHINE_CURRENT_ENTRY_DOCS:-}" ]]; then
    IFS=':' read -r -a entry_docs <<<"$BLOOM_MACHINE_CURRENT_ENTRY_DOCS"
  else
    entry_docs=("QUICKSTART.md" "EXAMPLES.md")
  fi

  for configured in "${entry_docs[@]}"; do
    [[ "$configured" = /* ]] && path="$configured" || path="$workspace/$configured"
    relative="${path#"$workspace/"}"
    if [[ ! -f "$path" ]]; then
      echo "missing current Machine entry documentation: $relative" >&2
      failed=1
      continue
    fi
    if run_scanner regex --ignore-case \
      --pattern '\bgrant(s|ed|ing)?\b' \
      --pattern 'policy\.toml(\.sig)?' \
      --pattern 'keystore' \
      --pattern 'passphrase' \
      --pattern 'wallet\s+unlock' \
      --pattern 'in-process' \
      --pattern '/sign/(message|hash|typed_data)' \
      "$path" >&2
    then
      echo "forbidden legacy authority instruction in current entry documentation: $relative" >&2
      failed=1
    else
      scan_status=$?
      if (( scan_status != 1 )); then
        echo "failed to scan current Machine entry documentation: $relative" >&2
        failed=1
      fi
    fi
  done
  (( failed == 0 ))
}

require_no_legacy_wallet_secret_inputs() {
  local failed=0 marker path count matches
  local secret_word="pass""phrase"
  local secret_word_upper="PASS""PHRASE"
  local -a markers=(
    "$secret_word"
    "BLOOM_${secret_word_upper}"
    "BLOOM_TEST_WALLET_${secret_word_upper}"
    "--allow-${secret_word}-wallet"
    "--${secret_word}-file"
    "--${secret_word}"
  )
  local -a paths=(
    "$workspace/scripts/play.sh"
    "$workspace/scripts/acceptance.sh"
    "$workspace/tests/docker/lib.sh"
    "$workspace/tests/docker/test_fork_mount.sh"
    "$workspace/tests/docker/test_mempool_mock.sh"
    "$workspace/tests/docker/docker-compose.yml"
  )
  if [[ -n "${BLOOM_MACHINE_WALLET_SECRET_EXTRA_PATHS:-}" ]]; then
    local -a extra_paths
    IFS=':' read -r -a extra_paths <<<"$BLOOM_MACHINE_WALLET_SECRET_EXTRA_PATHS"
    paths+=("${extra_paths[@]}")
  fi
  for marker in "${markers[@]}"; do
    if ! matches="$(
      run_scanner files --marker="$marker" --suffix .rs --suffix .html \
        "$workspace/crates/bloom/src" "$workspace/crates/bloom-daemon/src"
    )"; then
      echo "failed to scan production sources for legacy wallet-secret input" >&2
      failed=1
    elif [[ -n "$matches" ]]; then
      while IFS= read -r path; do
        [[ -z "$path" ]] || echo "forbidden legacy wallet-secret input in ${path#"$workspace/"}" >&2
      done <<<"$matches"
      failed=1
    fi
    for path in "${paths[@]}"; do
      [[ -f "$path" ]] || continue
      if ! count="$(run_scanner count --marker="$marker" "$path")"; then
        echo "failed to scan legacy wallet-secret inputs in ${path#"$workspace/"}" >&2
        failed=1
      elif (( count > 0 )); then
        echo "forbidden legacy wallet-secret input in ${path#"$workspace/"}" >&2
        failed=1
      fi
    done
  done
  (( failed == 0 ))
}

case "$mode" in
  --inventory)
    echo "schema: bloom.machine-authority-inventory.v1"
    echo "observed-revision: $(git -C "$workspace" rev-parse --short=12 HEAD)"
    inventory_dependencies
    ;;
  --require-clean)
    failed=0
    require_clean_dependencies || failed=1
    require_clean_sources || failed=1
    require_clean_current_entry_docs || failed=1
    require_no_legacy_wallet_secret_inputs || failed=1
    (( failed == 0 )) || exit 1
    echo "Machine production authority boundary is clean"
    ;;
esac
