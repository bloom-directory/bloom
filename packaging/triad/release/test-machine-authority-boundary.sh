#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
checker="$script_dir/check-machine-authority-boundary.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/bloom-machine-authority-test.XXXXXX")"
trap 'find "$work" -depth -delete' EXIT

"$checker" --inventory >"$work/inventory.out"
grep -Fx 'schema: bloom.machine-authority-inventory.v1' "$work/inventory.out" >/dev/null
grep -F 'feature-set: bloom-default package=bloom ' "$work/inventory.out" >/dev/null
grep -F 'feature-set: bloom-portable package=bloom ' "$work/inventory.out" >/dev/null
grep -F 'feature-set: bloom-machine package=bloom-machine ' "$work/inventory.out" >/dev/null

if BLOOM_MACHINE_FORBIDDEN_DEPENDENCIES=bloom-proto \
  "$checker" --require-clean >"$work/forbidden-dependency.out" 2>&1
then
  echo "synthetic forbidden resolved dependency unexpectedly passed" >&2
  exit 1
fi
grep -F 'forbidden production Machine dependency in bloom-default: bloom-proto' \
  "$work/forbidden-dependency.out" >/dev/null

cat >"$work/forbidden-authority-dependency-metadata.json" <<'EOF'
{
  "packages": [
    {"id":"bloom-id","name":"bloom","manifest_path":"/synthetic/bloom/Cargo.toml"},
    {"id":"triad-id","name":"bloom-triad-protocol","manifest_path":"/synthetic/bloom-triad-protocol/Cargo.toml"},
    {"id":"api-id","name":"bloom-signer-api","manifest_path":"/synthetic/bloom-signer-api/Cargo.toml"},
    {"id":"signer-id","name":"bloom-signer","manifest_path":"/synthetic/bloom-signer/Cargo.toml"}
  ],
  "resolve": {"nodes": [
    {"id":"bloom-id","deps":[
      {"pkg":"triad-id","dep_kinds":[{"kind":null}]},
      {"pkg":"api-id","dep_kinds":[{"kind":"build"}]},
      {"pkg":"signer-id","dep_kinds":[{"kind":null}]}
    ],"features":[]},
    {"id":"triad-id","deps":[],"features":[]},
    {"id":"api-id","deps":[],"features":[]},
    {"id":"signer-id","deps":[],"features":[]}
  ]}
}
EOF
printf '%s\t%s\t%s\t%s\n' forbidden-authority-dependencies bloom yes - \
  >"$work/forbidden-authority-dependency-feature-sets.tsv"
if BLOOM_MACHINE_PRODUCTION_FEATURE_SETS="$work/forbidden-authority-dependency-feature-sets.tsv" \
  BLOOM_MACHINE_METADATA_FIXTURE="$work/forbidden-authority-dependency-metadata.json" \
  "$checker" --require-clean >"$work/forbidden-authority-dependencies.out" 2>&1
then
  echo "synthetic forbidden authority dependencies unexpectedly passed" >&2
  exit 1
fi
for dependency in bloom-triad-protocol bloom-signer-api bloom-signer; do
  grep -F "forbidden production Machine dependency in forbidden-authority-dependencies: $dependency" \
    "$work/forbidden-authority-dependencies.out" >/dev/null
done

cat >"$work/forbidden-feature-sets.tsv" <<'EOF'
# label	package	default-features	features
forbidden-dev-harness	bloom	no	triad-dev-harness
forbidden-mainnet-canary	bloom	no	mainnet-canary
EOF
if BLOOM_MACHINE_PRODUCTION_FEATURE_SETS="$work/forbidden-feature-sets.tsv" \
  "$checker" --require-clean >"$work/forbidden-feature.out" 2>&1
then
  echo "synthetic forbidden production feature unexpectedly passed" >&2
  exit 1
fi
grep -F 'forbidden production Machine feature in forbidden-dev-harness: triad-dev-harness' \
  "$work/forbidden-feature.out" >/dev/null
grep -F 'forbidden production Machine feature in forbidden-mainnet-canary: mainnet-canary' \
  "$work/forbidden-feature.out" >/dev/null

for audit_feature in audit-test-seam; do
  printf '%s\t%s\t%s\t%s\n' \
    "forbidden-$audit_feature" bloom-proto no "$audit_feature" \
    >"$work/forbidden-audit-feature-sets.tsv"
  if BLOOM_MACHINE_PRODUCTION_FEATURE_SETS="$work/forbidden-audit-feature-sets.tsv" \
    "$checker" --require-clean >"$work/forbidden-$audit_feature.out" 2>&1
  then
    echo "synthetic direct $audit_feature production feature unexpectedly passed" >&2
    exit 1
  fi
  grep -F "forbidden production Machine feature in forbidden-$audit_feature: $audit_feature" \
    "$work/forbidden-$audit_feature.out" >/dev/null
done
printf '%s\t%s\t%s\t%s\n' forbidden-unsigned-audit-seam bloom-daemon no unsigned-audit-test-seam \
  >"$work/forbidden-unsigned-audit-feature-sets.tsv"
if BLOOM_MACHINE_PRODUCTION_FEATURE_SETS="$work/forbidden-unsigned-audit-feature-sets.tsv" \
  "$checker" --require-clean >"$work/forbidden-unsigned-audit-feature.out" 2>&1
then
  echo "synthetic direct unsigned-audit-test-seam unexpectedly passed" >&2
  exit 1
fi
grep -F 'forbidden production Machine feature in forbidden-unsigned-audit-seam: unsigned-audit-test-seam' \
  "$work/forbidden-unsigned-audit-feature.out" >/dev/null

cat >"$work/resolved-audit-feature-metadata.json" <<'EOF'
{
  "packages": [
    {"id":"bloom-id","name":"bloom","manifest_path":"/synthetic/bloom/Cargo.toml"},
    {"id":"proto-id","name":"bloom-proto","manifest_path":"/synthetic/bloom-proto/Cargo.toml"},
    {"id":"daemon-id","name":"bloom-daemon","manifest_path":"/synthetic/bloom-daemon/Cargo.toml"}
  ],
  "resolve": {"nodes": [
    {"id":"bloom-id","deps":[{"pkg":"proto-id","dep_kinds":[{"kind":null}]},{"pkg":"daemon-id","dep_kinds":[{"kind":null}]}],"features":[]},
    {"id":"proto-id","deps":[],"features":["audit-test-seam"]},
    {"id":"daemon-id","deps":[],"features":[]}
  ]}
}
EOF
printf '%s\n' \
  bloom \
  'bloom-proto feature "audit-test-seam"' \
  >"$work/resolved-audit-feature-tree.txt"
printf '%s\t%s\t%s\t%s\n' resolved-audit-seam bloom yes - \
  >"$work/resolved-audit-feature-sets.tsv"
if BLOOM_MACHINE_PRODUCTION_FEATURE_SETS="$work/resolved-audit-feature-sets.tsv" \
  BLOOM_MACHINE_METADATA_FIXTURE="$work/resolved-audit-feature-metadata.json" \
  BLOOM_MACHINE_FEATURE_TREE_FIXTURE="$work/resolved-audit-feature-tree.txt" \
  "$checker" --require-clean >"$work/resolved-audit-feature.out" 2>&1
then
  echo "synthetic resolved audit-test-seam unexpectedly passed" >&2
  exit 1
fi
grep -F 'forbidden resolved Machine feature in resolved-audit-seam: bloom-proto:audit-test-seam' \
  "$work/resolved-audit-feature.out" >/dev/null

printf '%s\n' \
  bloom \
  'bloom-daemon feature "unsigned-audit-test-seam"' \
  >"$work/resolved-unsigned-audit-feature-tree.txt"
if BLOOM_MACHINE_PRODUCTION_FEATURE_SETS="$work/resolved-audit-feature-sets.tsv" \
  BLOOM_MACHINE_METADATA_FIXTURE="$work/resolved-audit-feature-metadata.json" \
  BLOOM_MACHINE_FEATURE_TREE_FIXTURE="$work/resolved-unsigned-audit-feature-tree.txt" \
  "$checker" --require-clean >"$work/resolved-unsigned-audit-feature.out" 2>&1
then
  echo "synthetic resolved unsigned-audit-test-seam unexpectedly passed" >&2
  exit 1
fi
grep -F 'forbidden resolved Machine feature in resolved-audit-seam: bloom-daemon:unsigned-audit-test-seam' \
  "$work/resolved-unsigned-audit-feature.out" >/dev/null

mkdir "$work/forbidden-clean-source"
mkdir "$work/forbidden-clean-source/src"
printf 'struct PrivateKeySigner;\nstruct EphemeralAgentKey;\nstruct SessionStore;\nfn backend_policy_for_wallet() {}\n' \
  >"$work/forbidden-clean-source/src/lib.rs"
if BLOOM_MACHINE_AUTHORITY_EXTRA_SOURCE_ROOTS="$work/forbidden-clean-source" \
  "$checker" --require-clean >"$work/forbidden-clean-source.out" 2>&1
then
  echo "synthetic forbidden production source unexpectedly passed" >&2
  exit 1
fi
grep -F 'forbidden production Machine source marker: EphemeralAgentKey' \
  "$work/forbidden-clean-source.out" >/dev/null
grep -F 'forbidden production Machine source marker: PrivateKeySigner' \
  "$work/forbidden-clean-source.out" >/dev/null
grep -F 'forbidden production Machine source marker: SessionStore' \
  "$work/forbidden-clean-source.out" >/dev/null
grep -F 'forbidden production Machine source marker: backend_policy_for_wallet' \
  "$work/forbidden-clean-source.out" >/dev/null

mkdir "$work/forbidden-authority-imports"
mkdir "$work/forbidden-authority-imports/src"
printf 'use bloom_triad_protocol::Request;\nuse bloom_signer_api::SignerClient;\nuse bloom_signer::Signer;\n' \
  >"$work/forbidden-authority-imports/src/lib.rs"
if BLOOM_MACHINE_AUTHORITY_EXTRA_SOURCE_ROOTS="$work/forbidden-authority-imports" \
  "$checker" --require-clean >"$work/forbidden-authority-imports.out" 2>&1
then
  echo "synthetic forbidden authority imports unexpectedly passed" >&2
  exit 1
fi
for marker in bloom_triad_protocol bloom_signer_api bloom_signer; do
  grep -F "forbidden production Machine source marker: $marker" \
    "$work/forbidden-authority-imports.out" >/dev/null
done

printf '%s\n' \
  'Run the in-process daemon, unlock the keystore, and mint a grant.' \
  >"$work/stale-entry-doc.md"
if BLOOM_MACHINE_CURRENT_ENTRY_DOCS="$work/stale-entry-doc.md" \
  "$checker" --require-clean >"$work/stale-entry-doc.out" 2>&1
then
  echo "synthetic stale current entry documentation unexpectedly passed" >&2
  exit 1
fi
grep -F 'forbidden legacy authority instruction in current entry documentation:' \
  "$work/stale-entry-doc.out" >/dev/null

printf '\377\n' >"$work/undecodable-entry-doc.md"
if BLOOM_MACHINE_CURRENT_ENTRY_DOCS="$work/undecodable-entry-doc.md" \
  "$checker" --require-clean >"$work/undecodable-entry-doc.out" 2>&1
then
  echo "failed current-entry documentation scan unexpectedly passed" >&2
  exit 1
fi
grep -F 'failed to scan current Machine entry documentation:' \
  "$work/undecodable-entry-doc.out" >/dev/null

real_cargo="$(command -v cargo)"
mkdir "$work/failing-cargo-bin"
printf '0\n' >"$work/cargo-tree-count"
cat >"$work/failing-cargo-bin/cargo" <<EOF
#!/bin/bash
if [[ "\${1:-}" == tree ]]; then
  count="\$(<"$work/cargo-tree-count")"
  count="\$((count + 1))"
  printf '%s\\n' "\$count" >"$work/cargo-tree-count"
  if (( count <= 3 )); then
    exit 42
  fi
fi
exec "$real_cargo" "\$@"
EOF
chmod +x "$work/failing-cargo-bin/cargo"
if PATH="$work/failing-cargo-bin:$PATH" \
  "$checker" --require-clean >"$work/failed-tree.out" 2>&1
then
  echo "failed non-final Cargo tree feature set unexpectedly passed" >&2
  exit 1
fi
grep -F 'failed to enumerate production Machine source roots for bloom-default' \
  "$work/failed-tree.out" >/dev/null
grep -F 'failed to resolve production Machine source roots' \
  "$work/failed-tree.out" >/dev/null

"$checker" --require-clean >"$work/strict.out"
grep -Fx 'Machine production authority boundary is clean' "$work/strict.out" >/dev/null

binary_checker="$script_dir/check-production-machine-binary.sh"
printf '#!/bin/sh\nprintf "production\\n"\n' >"$work/clean-machine"
chmod +x "$work/clean-machine"
"$binary_checker" "$work/clean-machine" >"$work/clean-machine.out"
grep -Fx 'Production Machine binary contains no developer or canary capability' \
  "$work/clean-machine.out" >/dev/null

for marker in \
  BLOOM_TRIAD_DEVELOPER_ROOT \
  triad-dev-harness \
  unsafe-debug-approver \
  BLOOM_SOLANA_MAINNET_CANARY_AUTHORIZATION \
  NON-PRODUCTION-MAINNET-CANARY
do
  printf '#!/bin/sh\n%s\n' "$marker" >"$work/forbidden-machine"
  chmod +x "$work/forbidden-machine"
  if "$binary_checker" "$work/forbidden-machine" \
    >"$work/forbidden-machine.out" 2>&1
  then
    echo "synthetic production binary containing $marker unexpectedly passed" >&2
    exit 1
  fi
  grep -F "forbidden developer/canary marker in production Machine binary: $marker" \
    "$work/forbidden-machine.out" >/dev/null
done

echo "Machine authority boundary M6 tests passed"
