#!/usr/bin/env bash
# Single-quoted $(...) and backticks are commit titles that must stay literal.
# shellcheck disable=SC2016
# Cases for packaging/triad/release/release-notes.sh against a throwaway git
# history: baseline selection (first release, unpublished and non-version tags,
# newer releases, retries, dry runs), component links, commit subjects that
# look like shell, and splicing into new, retried and hand-edited bodies.
# Needs only git. Run: ./scripts/test-release-notes.sh
set -uo pipefail

notes="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/packaging/triad/release/release-notes.sh"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
passed=0
failed=0

check() {
  # check NAME COMMAND...
  local name="$1"
  shift
  if "$@"; then
    passed=$((passed + 1))
    printf 'ok - %s\n' "$name"
  else
    failed=$((failed + 1))
    printf 'not ok - %s\n' "$name"
  fi
}
contains() { grep -Fq -- "$2" "$1"; }
lacks() { ! grep -Fq -- "$2" "$1"; }

repo="$work/repo"
git init -q -b master "$repo"
g() { git -C "$repo" -c user.name=t -c user.email=t@example.invalid "$@"; }
pin() {
  # pin BROKER_CHAR SIGNER_CHAR: write a compatibility record and commit it
  mkdir -p "$repo/packaging/triad/release"
  printf 'broker_commit = "%s"\nsigner_commit = "%s"\n' \
    "$(printf "%040d" 0 | tr 0 "$1")" "$(printf "%040d" 0 | tr 0 "$2")" \
    >"$repo/packaging/triad/release/compatibility-v1.toml"
  g add -A
  g commit -q -m "$3"
}
changes() {
  # changes OUT TAG SHA PUBLISHED...
  local out="$1" tag="$2" sha="$3"
  shift 3
  printf '%s\n' "$@" >"$work/published"
  "$notes" changes --repo example/bloom --tag "$tag" --sha "$sha" \
    --published "$work/published" --git-dir "$repo" >"$out"
}

pin a a "Initial import"
g tag v0.1.0
first_sha="$(g rev-parse HEAD)"
changes "$work/first" v0.1.0 "$first_sha" latest v0.1.0
check "first release has no baseline" contains "$work/first" "First published release"
check "first release ignores its own tag and non-version tags" lacks "$work/first" "Changes since"

pin b a "Pin Broker (#2)"
g commit -q --allow-empty -m 'Handle $(touch pwned) and `id` in titles (#3)'
g tag v0.1.1-unpublished
g commit -q --allow-empty -m "Third change (#4)"
g tag v0.2.0
release_sha="$(g rev-parse HEAD)"
changes "$work/second" v0.2.0 "$release_sha" latest v0.2.0 v0.1.0
check "baseline is the previous published release" contains "$work/second" "### Changes since v0.1.0"
check "lists every commit since the baseline" contains "$work/second" "- Third change (#4) ("
check "links each commit" contains "$work/second" "https://github.com/example/bloom/commit/$release_sha"
check "excludes the baseline's own commit" lacks "$work/second" "Initial import"
check "unpublished tags do not become the baseline" lacks "$work/second" "v0.1.1-unpublished"
check "titles are printed literally" contains "$work/second" 'Handle $(touch pwned) and `id` in titles (#3)'
check "titles are never executed" test ! -e "$repo/pwned" -a ! -e "$work/pwned" -a ! -e pwned
check "changed component links a compare" \
  contains "$work/second" "https://github.com/bloom-directory/bloom-broker/compare/$(printf "%040d" 0 | tr 0 a)...$(printf "%040d" 0 | tr 0 b)"
check "unchanged component says so" contains "$work/second" "- Signer: unchanged at"
check "full diff links both commits" contains "$work/second" "compare/$first_sha...$release_sha"

changes "$work/retry" v0.2.0 "$release_sha" latest v0.2.0 v0.1.0
check "a retry reproduces the same section" cmp -s "$work/second" "$work/retry"

g checkout -q -b maintenance "$first_sha"
g commit -q --allow-empty -m "Backport (#5)"
g tag v0.1.2
backport_sha="$(g rev-parse HEAD)"
g checkout -q master
changes "$work/backport" v0.1.2 "$backport_sha" latest v0.2.0 v0.1.0
check "newer releases off this history are not the baseline" contains "$work/backport" "### Changes since v0.1.0"
check "a backport lists only its own commits" lacks "$work/backport" "Third change"

g commit -q --allow-empty -m "Unreleased work (#6)"
changes "$work/dry" dry-run-v0.3.0 "$(g rev-parse HEAD)" latest v0.2.0 v0.1.0
check "a dry run compares with the latest published ancestor" contains "$work/dry" "### Changes since v0.2.0"

changes "$work/empty" v0.2.1 "$release_sha" v0.2.0
check "a release on its baseline's commit says nothing changed" contains "$work/empty" "No commits since v0.2.0."

printf '## Bloom v0.2.0\n\nSignature verification text.\n' >"$work/header"
"$notes" splice --changes "$work/second" --header "$work/header" >"$work/new-body"
check "a new body starts with the header" contains "$work/new-body" "Signature verification text."
check "a new body carries the changes" contains "$work/new-body" "### Changes since v0.1.0"

{
  printf 'Hand-written summary.\r\n\r\n'
  sed 's/$/\r/' "$work/first"
  printf '\r\nKnown issues written later.\r\n'
} >"$work/edited"
"$notes" splice --changes "$work/second" --existing "$work/edited" --header "$work/header" >"$work/retried"
check "a retry keeps text above the section" contains "$work/retried" "Hand-written summary."
check "a retry keeps text below the section" contains "$work/retried" "Known issues written later."
check "a retry replaces the old section" lacks "$work/retried" "First published release"
check "a retry carries the new section once" \
  test "$(grep -c 'bloom-release-changes:start' "$work/retried")" -eq 1

printf 'Notes written before markers existed.\n' >"$work/legacy"
"$notes" splice --changes "$work/second" --existing "$work/legacy" --header "$work/header" >"$work/legacy-out"
check "a body without markers is kept" contains "$work/legacy-out" "Notes written before markers existed."
check "a body without markers gains the section" contains "$work/legacy-out" "### Changes since v0.1.0"

printf 'Broken\n<!-- bloom-release-changes:start -->\nno end\n' >"$work/broken"
check "an unterminated section fails closed" \
  bash -c '! "$0" splice --changes "$1" --existing "$2" --header "$3" >/dev/null 2>&1' \
  "$notes" "$work/second" "$work/broken" "$work/header"

printf '%d passed, %d failed\n' "$passed" "$failed"
((failed == 0))
