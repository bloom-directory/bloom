#!/usr/bin/env bash
set -euo pipefail

# Regression: quarantine removal and verification must use the system
# /usr/bin/xattr, never whichever `xattr` comes first on PATH. A shadowing
# xattr (e.g. a Python package script) with an incompatible CLI made the
# installer fail to strip quarantine, or misread a failed probe as clean.

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
installer="$root/packaging/triad/release/install-macos.sh"
# Exercise the actual installer function without running installation.
function_text="$(awk '/^prepare_verified_payload_for_execution\(\)/,/^}/' "$installer")"
[[ -n "$function_text" ]]

# Every xattr invocation in the function names the absolute system path.
if grep -nE '(^|[^/[:alnum:]_-])xattr[[:space:]]' <<<"$function_text" | grep -v '^[0-9]*:[[:space:]]*#'; then
  echo "prepare_verified_payload_for_execution resolves xattr through PATH" >&2
  exit 1
fi
[[ "$(grep -c '/usr/bin/xattr ' <<<"$function_text")" == 2 ]]

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

# A shadowing xattr first on PATH that records any call and fails without
# touching anything, as an incompatible CLI would.
mkdir -p "$work/shadow"
cat >"$work/shadow/xattr" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$work/shadow-calls"
exit 1
EOF
chmod 0755 "$work/shadow/xattr"

payload="$work/payload"
mkdir -p "$payload/bin"
for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
  printf '#!/bin/sh\nexit 0\n' >"$payload/bin/$binary"
  chmod 0755 "$payload/bin/$binary"
done

if [[ "$(uname -s)" == Darwin ]]; then
  # Real system tool: quarantine the payload and confirm it is removed.
  system_xattr=/usr/bin/xattr
  for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
    "$system_xattr" -w com.apple.quarantine '0081;00000000;Safari;' "$payload/bin/$binary"
  done
  "$system_xattr" -p com.apple.quarantine "$payload/bin/bloom" >/dev/null
  under_test="$function_text"
else
  # No /usr/bin/xattr off macOS: retarget only the absolute path to a stub
  # that models quarantine with marker files. The shadow on PATH stays live,
  # so any bare `xattr` call would still be caught.
  system_xattr="$work/system/xattr"
  mkdir -p "$work/system"
  cat >"$system_xattr" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  -dr) [[ "$2" == com.apple.quarantine ]]; find "$3" -name '*.quarantine' -delete ;;
  -p) [[ "$2" == com.apple.quarantine ]]; [[ -e "$3.quarantine" ]] ;;
  *) exit 2 ;;
esac
EOF
  chmod 0755 "$system_xattr"
  for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
    : >"$payload/bin/$binary.quarantine"
  done
  under_test="${function_text//\/usr\/bin\/xattr/$system_xattr}"
fi

eval "$under_test"
die() { echo "$*" >&2; exit 65; }
live=true

PATH="$work/shadow:$PATH" prepare_verified_payload_for_execution

[[ ! -e "$work/shadow-calls" ]] || {
  echo "installer invoked the PATH-shadowing xattr:" >&2
  cat "$work/shadow-calls" >&2
  exit 1
}
for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
  if "$system_xattr" -p com.apple.quarantine "$payload/bin/$binary" >/dev/null 2>&1; then
    echo "quarantine remains on $binary" >&2
    exit 1
  fi
done

echo 'macOS quarantine xattr PATH regression passed'
