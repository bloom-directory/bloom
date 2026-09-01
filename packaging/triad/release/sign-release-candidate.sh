#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 9 ]]; then
  echo "usage: $0 CANDIDATE_ARCHIVE OUTPUT_ARCHIVE ED25519_SIGNING_KEY PINNED_PUBLIC_KEY SOURCE_DATE_EPOCH VERSION MACHINE_SHA BROKER_SHA SIGNER_SHA" >&2
  exit 64
fi

candidate="$1"
output="$2"
signing_key="$3"
pinned_public_key="$4"
source_date_epoch="$5"
expected_version="$6"
expected_machine_sha="$7"
expected_broker_sha="$8"
expected_signer_sha="$9"
tar_command="${TAR:-tar}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

tar_help="$("$tar_command" --help 2>&1 || true)"
if [[ "$tar_help" == *"--owner"* ]]; then
  tar_identity_args=(--owner=0 --group=0)
else
  tar_identity_args=(--uid=0 --gid=0 --uname=root --gname=root)
fi

for input in "$candidate" "$signing_key" "$pinned_public_key"; do
  [[ -f "$input" && ! -L "$input" ]] || {
    echo "release signing input must be a regular file: $input" >&2
    exit 66
  }
done
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || {
  echo "SOURCE_DATE_EPOCH must be an unsigned decimal integer" >&2
  exit 64
}

"$script_dir/verify-release-candidate.sh" \
  "$candidate" \
  "$expected_version" \
  "$expected_machine_sha" \
  "$expected_broker_sha" \
  "$expected_signer_sha"

work="$(mktemp -d)"
trap 'find "$work" -depth -delete' EXIT

# The candidate has already passed the full release gate. This signing pass is
# deliberately data-only: it never invokes a binary or script from the archive.
"$tar_command" -xzf "$candidate" -C "$work"
payload="$work/bloom-triad"
[[ -d "$payload" && ! -L "$payload" ]] || {
  echo "candidate does not contain a regular bloom-triad payload" >&2
  exit 65
}
if find "$payload" -type l -o \( ! -type f ! -type d \) | grep . >/dev/null; then
  echo "candidate contains a symlink or non-regular filesystem entry" >&2
  exit 65
fi
for required in PLATFORM_CLAIM compatibility-v1.toml SOURCE_REVISIONS; do
  [[ -f "$payload/$required" ]] || {
    echo "candidate is missing $required" >&2
    exit 65
  }
done
[[ "$(<"$payload/PLATFORM_CLAIM")" == "test-unclaimed" ]] || {
  echo "production signing requires a test-unclaimed candidate" >&2
  exit 65
}
printf 'linux\n' > "$payload/PLATFORM_CLAIM"

rm -f -- \
  "$payload/RELEASE_PUBLIC_KEY.pem" \
  "$payload/RELEASE_SIGNATURE" \
  "$payload/SHA256SUMS"
"$script_dir/ssh-ed25519-public-key.sh" \
  "$signing_key" \
  "$payload/RELEASE_PUBLIC_KEY.pem"
cmp -s "$pinned_public_key" "$payload/RELEASE_PUBLIC_KEY.pem" || {
  echo "release signing key does not match the reviewed public key" >&2
  exit 65
}

(
  cd "$payload"
  find . -type f ! -name SHA256SUMS ! -name RELEASE_SIGNATURE -print |
    LC_ALL=C sort |
    while IFS= read -r file; do
      shasum -a 256 "$file"
    done
) > "$payload/SHA256SUMS"
"$script_dir/ssh-ed25519-sign.sh" \
  "$signing_key" \
  bloom-release-payload-v1 \
  "$payload/SHA256SUMS" \
  "$payload/RELEASE_SIGNATURE"

# Normalize after signing so the same candidate, key, and epoch repack to the
# same bytes. No candidate-owned executable is run while the key is present.
# The single-quoted expression is Perl source, not a shell interpolation.
# shellcheck disable=SC2016
find "$payload" -print0 |
  xargs -0 perl -e '$timestamp = shift; utime $timestamp, $timestamp, @ARGV' \
    "$source_date_epoch"

mkdir -p "$(dirname "$output")"
output_dir="$(cd "$(dirname "$output")" && pwd -P)"
output="$output_dir/$(basename "$output")"
[[ ! -e "$output" && ! -e "$output.sha256" && ! -e "$output.sig" && ! -e "$output.pub" ]] || {
  echo "release signing output already exists" >&2
  exit 65
}
archive_tmp="$work/archive.tar"
(
  cd "$work"
  find bloom-triad -print | LC_ALL=C sort > archive-files
  "$tar_command" \
    --format=ustar \
    "${tar_identity_args[@]}" \
    --no-recursion \
    -cf "$archive_tmp" \
    -T archive-files
)
gzip -n -9 < "$archive_tmp" > "$output"
(
  cd "$output_dir"
  shasum -a 256 "$(basename "$output")" > "$(basename "$output").sha256"
)
"$script_dir/ssh-ed25519-sign.sh" \
  "$signing_key" \
  bloom-release-archive-v1 \
  "$output.sha256" \
  "$output.sig"
install -m 0644 "$pinned_public_key" "$output.pub"
