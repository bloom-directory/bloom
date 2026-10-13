#!/bin/bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
main_root="$(cd "$script_dir/../../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/bloom-tart-local-test.XXXXXX")"
trap 'find "$work" -depth -delete' EXIT
candidate="$work/candidate.tar.gz"
touch "$candidate" "$candidate.sha256" "$candidate.sig" "$candidate.pub"

mkdir -p "$work/bin"
printf '#!/bin/sh\nexit 0\n' >"$work/bin/sshpass"
chmod +x "$work/bin/sshpass"
cat >"$work/bin/git" <<'EOF'
#!/bin/bash
if [[ "${1:-}" == -C ]]; then
  case "${3:-}" in
    status)
      [[ "${BLOOM_FAKE_GIT_FAIL_STATUS:-false}" != true ]] || exit 42
      exit 0
      ;;
    rev-parse) printf '%040d\n' 0; exit 0 ;;
    bundle)
      case "${4:-}" in
        create) printf 'fake bundle\n' >"$5"; exit 0 ;;
        verify) exit 0 ;;
        list-heads) printf '%040d HEAD\n' 0; exit 0 ;;
      esac
      ;;
  esac
fi
exit 64
EOF
chmod +x "$work/bin/git"
cat >"$work/bin/tart" <<'EOF'
#!/bin/bash
case "${1:-}" in
  list) exit 42 ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$work/bin/tart"

status=0
(
  cd "$work"
  PATH="$work/bin:$PATH" \
    BLOOM_TART_BROKER_ROOT="$main_root" \
    BLOOM_TART_SIGNER_ROOT="$main_root" \
    "$script_dir/run-tart-local.sh" "$candidate"
) >"$work/list-failure.out" 2>&1 || status=$?
if [[ "$status" -ne 70 ]]; then
  echo "Tart list failure returned $status instead of 70" >&2
  cat "$work/list-failure.out" >&2
  exit 1
fi
grep -Fx 'failed to list local Tart VMs' "$work/list-failure.out" >/dev/null

cat >"$work/bin/tart" <<'EOF'
#!/bin/bash
case "${1:-}" in
  list)
    printf '%s\n' '[{"Source":"local","Name":"fake-base","Running":false}]'
    ;;
  run) exit 23 ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$work/bin/tart"

status=0
(
  cd "$work"
  PATH="$work/bin:$PATH" \
    BLOOM_FAKE_GIT_FAIL_STATUS=true \
    BLOOM_TART_BROKER_ROOT="$main_root" \
    BLOOM_TART_SIGNER_ROOT="$main_root" \
    BLOOM_TART_DEVELOPMENT_BASE=fake-base \
    BLOOM_TART_OUTPUT_ROOT="$work/status-failure-output" \
    "$script_dir/run-tart-local.sh" "$candidate"
) >"$work/status-failure.out" 2>&1 || status=$?
if [[ "$status" -ne 65 ]]; then
  echo "Git status failure returned $status instead of 65" >&2
  cat "$work/status-failure.out" >&2
  exit 1
fi
grep -F 'failed to inspect Tart source repository:' \
  "$work/status-failure.out" >/dev/null

echo 'local Tart orchestration failure tests passed'
