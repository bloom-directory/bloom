#!/usr/bin/env bash
# Backticks in printf formats are literal Markdown code spans.
# shellcheck disable=SC2016
# Generate the changes section of a Bloom triad release body, or splice it
# into an existing body.
#
#   release-notes.sh changes --repo OWNER/REPO --tag TAG --sha SHA \
#     --published FILE [--git-dir DIR]
#   release-notes.sh splice --changes FILE [--existing FILE] --header FILE
#
# `changes` lists every first-parent commit since the baseline: the highest
# vX.Y.Z tag named in FILE (published, non-draft, non-prerelease releases,
# one tag per line) that is an ancestor of SHA, other than TAG itself and
# older than TAG. Excluding TAG keeps a retry on the baseline its first run
# used. It also links the Broker and Signer changes between the two releases'
# compatibility records. The section is fenced by markers so `splice` can
# replace it on a retry while keeping everything a maintainer wrote around it.
#
# Commit subjects are data: they are only ever printed with printf '%s'.
set -euo pipefail

readonly START_MARKER='<!-- bloom-release-changes:start -->'
readonly END_MARKER='<!-- bloom-release-changes:end -->'
readonly COMPATIBILITY='packaging/triad/release/compatibility-v1.toml'
readonly BROKER_REPO='bloom-directory/bloom-broker'
readonly SIGNER_REPO='bloom-directory/bloom-signer'

die() {
  printf 'release-notes: %s\n' "$*" >&2
  exit 1
}

is_version_tag() {
  [[ "$1" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

# Succeeds when version tag $1 sorts strictly before version tag $2.
version_lt() {
  [[ "$1" != "$2" ]] &&
    [[ "$(printf '%s\n%s\n' "${1#v}" "${2#v}" | sort -t. -k1,1n -k2,2n -k3,3n | head -n 1)" == "${1#v}" ]]
}

component_commit() {
  # $1 revision, $2 key (broker_commit or signer_commit)
  git show "$1:$COMPATIBILITY" 2>/dev/null |
    sed -n -E "s/^$2 = \"([0-9a-f]{40})\"\$/\\1/p" |
    head -n 1
}

component_line() {
  # $1 label, $2 repository, $3 baseline commit, $4 release commit
  local label="$1" repo="$2" old="$3" new="$4"
  if [[ -z "$new" ]]; then
    printf -- '- %s: not recorded in this release\n' "$label"
  elif [[ -z "$old" ]]; then
    printf -- '- %s: [`%s`](https://github.com/%s/commit/%s), not recorded in the previous release\n' \
      "$label" "${new:0:7}" "$repo" "$new"
  elif [[ "$old" == "$new" ]]; then
    printf -- '- %s: unchanged at [`%s`](https://github.com/%s/commit/%s)\n' \
      "$label" "${new:0:7}" "$repo" "$new"
  else
    printf -- '- %s: [`%s...%s`](https://github.com/%s/compare/%s...%s)\n' \
      "$label" "${old:0:7}" "${new:0:7}" "$repo" "$old" "$new"
  fi
}

changes() {
  local repo="" tag="" sha="" published=""
  while (($#)); do
    case "$1" in
      --repo) repo="$2"; shift 2 ;;
      --tag) tag="$2"; shift 2 ;;
      --sha) sha="$2"; shift 2 ;;
      --published) published="$2"; shift 2 ;;
      --git-dir) cd "$2"; shift 2 ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  [[ -n "$repo" && -n "$tag" && -n "$sha" && -n "$published" ]] ||
    die "changes needs --repo, --tag, --sha and --published"
  [[ -r "$published" ]] || die "cannot read published release list: $published"
  sha="$(git rev-parse --verify -q "$sha^{commit}")" || die "unknown commit: $sha"

  # A dry run's tag is not a version, so any published ancestor qualifies.
  local base="" candidate candidate_sha
  while IFS= read -r candidate || [[ -n "$candidate" ]]; do
    is_version_tag "$candidate" || continue
    [[ "$candidate" != "$tag" ]] || continue
    if is_version_tag "$tag"; then
      version_lt "$candidate" "$tag" || continue
    fi
    candidate_sha="$(git rev-parse --verify -q "refs/tags/$candidate^{commit}")" || continue
    git merge-base --is-ancestor "$candidate_sha" "$sha" || continue
    if [[ -z "$base" ]] || version_lt "$base" "$candidate"; then
      base="$candidate"
    fi
  done <"$published"

  printf '%s\n' "$START_MARKER"
  if [[ -z "$base" ]]; then
    printf '### Changes\n\nFirst published release: there is no earlier release to compare against.\n'
    printf '%s\n' "$END_MARKER"
    return
  fi

  local base_sha subject commit count=0
  base_sha="$(git rev-parse "refs/tags/$base^{commit}")"
  printf '### Changes since %s\n\n' "$base"
  while IFS=$'\t' read -r commit subject; do
    count=$((count + 1))
    printf -- '- %s ([`%s`](https://github.com/%s/commit/%s))\n' \
      "$subject" "${commit:0:7}" "$repo" "$commit"
  done < <(git log --first-parent --format='%H%x09%s' "$base_sha..$sha")
  if ((count == 0)); then
    printf 'No commits since %s.\n' "$base"
  fi
  printf '\n### Components\n\n'
  component_line Broker "$BROKER_REPO" \
    "$(component_commit "$base_sha" broker_commit)" "$(component_commit "$sha" broker_commit)"
  component_line Signer "$SIGNER_REPO" \
    "$(component_commit "$base_sha" signer_commit)" "$(component_commit "$sha" signer_commit)"
  printf '\nFull diff: https://github.com/%s/compare/%s...%s\n' "$repo" "$base_sha" "$sha"
  printf '%s\n' "$END_MARKER"
}

splice() {
  local changes_file="" existing="" header=""
  while (($#)); do
    case "$1" in
      --changes) changes_file="$2"; shift 2 ;;
      --existing) existing="$2"; shift 2 ;;
      --header) header="$2"; shift 2 ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  [[ -r "$changes_file" && -r "$header" ]] || die "splice needs readable --changes and --header"
  # A new release: the workflow's header, then the changes.
  if [[ -z "$existing" ]]; then
    cat "$header"
    printf '\n'
    cat "$changes_file"
    return
  fi
  [[ -r "$existing" ]] || die "cannot read existing body: $existing"
  # A retry keeps whatever a maintainer wrote and replaces only the changes;
  # a body from before the markers gains them at the end.
  awk -v start="$START_MARKER" -v end="$END_MARKER" -v changes="$changes_file" '
    function emit_changes(  line) {
      while ((getline line < changes) > 0) print line
      close(changes)
    }
    # Bodies edited in the browser come back with CRLF line endings.
    { sub(/\r$/, "") }
    $0 == start { if (!done) emit_changes(); done = 1; skipping = 1; next }
    skipping && $0 == end { skipping = 0; next }
    skipping { next }
    { print }
    END {
      if (skipping) exit 2
      if (!done) { print ""; emit_changes() }
    }
  ' "$existing" || die "existing body has an unterminated changes section"
}

case "${1:-}" in
  changes) shift; changes "$@" ;;
  splice) shift; splice "$@" ;;
  *) die "usage: release-notes.sh changes|splice ..." ;;
esac
