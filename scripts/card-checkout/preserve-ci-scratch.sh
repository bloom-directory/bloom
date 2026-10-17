# BASH_ENV for explicitly disposable card-checkout conformance runs.
# Preserve recursive cleanup by renaming its target beside the original path.
# No production service uses this file or environment variable.
# macOS mktemp otherwise uses /var/folders, outside the disposable runner root.
export TMPDIR="${RUNNER_TEMP:?}"
mktemp() {
  # Darwin's no-template mode prefers confstr over TMPDIR. An explicit
  # absolute template is portable and keeps these disposable files scoped.
  if [[ "$#" == 0 ]]; then
    command mktemp "$RUNNER_TEMP/card-scratch.XXXXXXXXXX"
  elif [[ "$#" == 1 && "$1" == -d ]]; then
    command mktemp -d "$RUNNER_TEMP/card-scratch.XXXXXXXXXX"
  else
    command mktemp "$@"
  fi
}
card_preserve_path() {
  local path="$1" destination
  [[ -e "$path" || -L "$path" ]] || return 0
  case "$path" in
    "${RUNNER_TEMP:?}"/*|/private/tmp/bloom-*|/private/var/tmp/bloom-*|/private/etc/.bloom-pf-cleanup.*|/private/var/db/bloom/*|/private/var/run/bloom/*|/private/var/log/bloom/*|/var/db/bloom/*|/var/run/bloom/*|/var/log/bloom/*|/Library/Application\ Support/BloomTriad/*|/usr/local/libexec/bloom)
      ;;
    *) printf 'Refused recursive cleanup outside disposable conformance paths: %q (runner root %q)\n' "$path" "$RUNNER_TEMP" >&2; return 65 ;;
  esac
  destination="$path.card-retained-$$-${RANDOM}"
  [[ ! -e "$destination" && ! -L "$destination" ]] || return 65
  command mv -- "$path" "$destination" || return
  echo "Preserved conformance scratch: $destination" >&2
}
rm() {
  local recursive=false argument
  for argument in "$@"; do
    case "$argument" in --recursive) recursive=true;; --*) ;; -*r*|-*R*) recursive=true;; esac
  done
  if ! $recursive; then command rm "$@"; return; fi
  for argument in "$@"; do
    [[ "$argument" == -* ]] || card_preserve_path "$argument" || return
  done
}
find() {
  local argument deleting=false
  for argument in "$@"; do [[ "$argument" != -delete ]] || deleting=true; done
  if ! $deleting; then command find "$@"; return; fi
  [[ "$#" == 3 && "$2" == -depth && "$3" == -delete ]] || { echo "Refused unsupported deleting find" >&2; return 65; }
  card_preserve_path "$1"
}
