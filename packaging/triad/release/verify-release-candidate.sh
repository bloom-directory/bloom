#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 CANDIDATE_ARCHIVE VERSION MACHINE_SHA BROKER_SHA SIGNER_SHA" >&2
  exit 64
fi

candidate="$1"
expected_version="$2"
expected_machine_sha="$3"
expected_broker_sha="$4"
expected_signer_sha="$5"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

[[ "$expected_version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  echo "expected Machine version is invalid" >&2
  exit 64
}
for revision in "$expected_machine_sha" "$expected_broker_sha" "$expected_signer_sha"; do
  [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || {
    echo "expected source revision is not a full lowercase commit ID" >&2
    exit 64
  }
done
for input in "$candidate" "$candidate.sha256" "$candidate.sig" "$candidate.pub"; do
  [[ -f "$input" && ! -L "$input" ]] || {
    echo "candidate input must be a regular file: $input" >&2
    exit 66
  }
done

work="$(mktemp -d)"
trap 'find "$work" -depth -delete' EXIT
BLOOM_ALLOW_TEST_UNCLAIMED=true \
  "$script_dir/verify-bundle.sh" \
  "$candidate" \
  "$candidate.sha256" \
  "$candidate.sig" \
  "$candidate.pub"
tar -xzf "$candidate" -C "$work"
payload="$work/bloom-triad"
[[ "$(<"$payload/PLATFORM_CLAIM")" == "test-unclaimed" ]] || {
  echo "candidate must retain the test-unclaimed platform claim" >&2
  exit 65
}
machine_version="$(sed -n -E 's/^machine = "([^"]+)"$/\1/p' \
  "$payload/compatibility-v1.toml")"
[[ "$machine_version" == "$expected_version" ]] || {
  echo "candidate Machine version does not match the release tag" >&2
  exit 65
}
for expected in \
  "BLOOM_MACHINE_SHA=$expected_machine_sha" \
  "BLOOM_BROKER_SHA=$expected_broker_sha" \
  "BLOOM_SIGNER_SHA=$expected_signer_sha"
do
  grep -Fx "$expected" "$payload/SOURCE_REVISIONS" >/dev/null || {
    echo "candidate source revisions do not match the resolved triad" >&2
    exit 65
  }
done
[[ "$(wc -l < "$payload/SOURCE_REVISIONS" | tr -d ' ')" == 3 ]] || {
  echo "candidate source revisions contain unexpected entries" >&2
  exit 65
}
