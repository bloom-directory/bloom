# BASH_ENV for explicitly disposable card-checkout conformance runs.
# Preserve recursive cleanup by renaming its target beside the original path.
# No production service uses this file or environment variable.
card_preserve_path() {
  local path="$1" destination
  [[ -e "$path" || -L "$path" ]] || return 0
  case "$path" in
    "${RUNNER_TEMP:?}"/*|/private/tmp/bloom-*|/private/var/tmp/bloom-*|/private/var/db/bloom/*|/private/var/run/bloom/*|/var/db/bloom/*|/var/run/bloom/*|/Library/Application\ Support/BloomTriad/*|/usr/local/libexec/bloom)
      ;;
    *) echo "Refused recursive cleanup outside disposable conformance paths" >&2; return 65 ;;
  esac
  destination="$path.card-retained-$$-${RANDOM}"
  [[ ! -e "$destination" && ! -L "$destination" ]] || return 65
  command mv -- "$path" "$destination" || return
  echo "Preserved conformance scratch: $destination" >&2
}
rm() {
  local recursive=false argument
  for argument in "$@"; do
    case "$argument" in --recursive|-*r*|-*R*) recursive=true;; esac
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
