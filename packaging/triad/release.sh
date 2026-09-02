#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
main_root="$(cd "$script_dir/../.." && pwd -P)"
release_dir="$script_dir/release"

usage() {
  cat >&2 <<'EOF'
usage:
  packaging/triad/release.sh build (linux|macos) --output-dir DIR [--broker-root DIR] [--signer-root DIR] [--source-date-epoch INTEGER] [--candidate-signing-key FILE]
  packaging/triad/release.sh sign (linux|macos) CANDIDATE --output-dir DIR --signing-key FILE --pinned-public-key FILE --source-date-epoch INTEGER --version X.Y.Z --machine-sha SHA --broker-sha SHA --signer-sha SHA [macOS conformance options]
EOF
  exit 64
}

die() {
  echo "$1" >&2
  exit "${2:-65}"
}

require_platform() {
  case "$1" in
    linux|macos) ;;
    *) die "platform must be linux or macos" 64 ;;
  esac
}

require_regular_file() {
  [[ -f "$1" && ! -L "$1" ]] || die "required input must be a regular file: $1" 66
}

require_clean_repository() {
  local root="$1" status untracked
  [[ -f "$root/Cargo.toml" ]] || die "missing triad workspace: $root" 66
  git -C "$root" rev-parse --git-dir >/dev/null 2>&1 ||
    die "missing Git repository: $root" 66
  status="$(git -C "$root" status --porcelain --untracked-files=no)"
  [[ -z "$status" ]] || die "tracked source changes prevent source attribution: $root"
  untracked="$(git -C "$root" ls-files --others --exclude-standard)"
  [[ -z "$untracked" ]] || die "untracked source changes prevent source attribution: $root"
}

repository_head() {
  local revision
  revision="$(git -C "$1" rev-parse HEAD)"
  [[ "$revision" =~ ^[0-9a-f]{40}$ ]] ||
    die "repository HEAD is not a full lowercase commit ID: $1"
  printf '%s\n' "$revision"
}

target_binary() {
  local root="$1" binary="$2"
  if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
    printf '%s/release/%s\n' "$CARGO_TARGET_DIR" "$binary"
  else
    printf '%s/target/release/%s\n' "$root" "$binary"
  fi
}

require_host_platform() {
  local platform="$1" kernel architecture
  kernel="$(uname -s)"
  architecture="$(uname -m)"
  case "$platform" in
    linux)
      [[ "$kernel" == Linux && "$architecture" == x86_64 ]] ||
        die "linux release builds require a Linux x86_64 host" 69
      ;;
    macos)
      [[ "$kernel" == Darwin && "$architecture" == arm64 ]] ||
        die "macos release builds require a Darwin arm64 host" 69
      ;;
  esac
}

require_staged_architecture() {
  local platform="$1" staging="$2" binary description
  for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
    description="$(file -b -- "$staging/bin/$binary")"
    case "$platform" in
      linux)
        [[ "$description" == *"ELF 64-bit"* &&
          ( "$description" == *"x86-64"* || "$description" == *"x86_64"* ) ]] ||
          die "$binary is not an x86-64 ELF release binary"
        ;;
      macos)
        [[ "$description" == *"Mach-O 64-bit executable arm64"* ]] ||
          die "$binary is not an arm64 Mach-O release binary"
        ;;
    esac
  done
}

resolved_compatibility() {
  local output="$1" broker_sha="$2" signer_sha="$3"
  awk -v broker_sha="$broker_sha" -v signer_sha="$signer_sha" '
    /^broker_commit = / { print "broker_commit = \"" broker_sha "\""; next }
    /^signer_commit = / { print "signer_commit = \"" signer_sha "\""; next }
    { print }
  ' "$release_dir/compatibility-v1.toml" >"$output"
}

smoke_linux_installer() {
  local bundle="$1" work="$2" payload="$work/install-payload" config
  cp -R "$bundle" "$payload"
  mkdir -p "$payload/config"
  for config in \
    edge-manifest.json \
    broker.json \
    signer.json \
    machine-identity.json \
    broker-identity.json \
    signer-identity.json \
    revoke-identity.json \
    session-identity.json \
    installer-identity.json \
    provenance-catalog.json
  do
    printf '{}\n' >"$payload/config/$config"
  done
  mkdir -p "$work/linux-root"
  "$payload/installer/release/install-linux.sh" \
    install "$work/linux-root" 1000 releaseuser "$payload"
  [[ -x "$work/linux-root/usr/libexec/bloom/bloom-broker" ]] ||
    die "staged Linux installer did not install Broker"
  [[ -f "$work/linux-root/etc/bloom/1000/signer/config.json" ]] ||
    die "staged Linux installer did not install Signer configuration"
  "$payload/installer/release/install-linux.sh" \
    uninstall "$work/linux-root" 1000 delete-bloom-login-1000
  [[ ! -e "$work/linux-root/etc/bloom/1000" ]] ||
    die "staged Linux uninstaller retained login configuration"
}

smoke_macos_installer() {
  local bundle="$1" work="$2" payload="$work/install-payload" config
  local release_digest
  cp -R "$bundle" "$payload"
  mkdir -p "$payload/config"
  for config in \
    edge-manifest.json \
    broker.json \
    signer.json \
    machine-identity.json \
    broker-identity.json \
    signer-identity.json \
    revoke-identity.json \
    session-identity.json \
    installer-identity.json \
    provenance-catalog.json
  do
    printf '{}\n' >"$payload/config/$config"
  done
  mkdir -p "$work/macos-root"
  release_digest="$(shasum -a 256 "$payload/SHA256SUMS" | awk '{print $1}')"
  BLOOM_ALLOW_TEST_UNCLAIMED=true \
    BLOOM_MACOS_BROKER_UID=250501 \
    BLOOM_MACOS_SIGNER_UID=250502 \
    BLOOM_MACOS_BROKER_GID=260499 \
    BLOOM_MACOS_SIGNER_GID=260500 \
    BLOOM_MACOS_MACHINE_BROKER_GID=260501 \
    BLOOM_MACOS_BROKER_SIGNER_GID=260502 \
    BLOOM_MACOS_REVOKE_GID=260503 \
    BLOOM_MACOS_LOG_GID=260504 \
    BLOOM_RELEASE_DIGEST="$release_digest" \
    "$payload/installer/release/install-macos.sh" \
      install "$work/macos-root" 501 releaseuser "$payload"
  [[ -x "$work/macos-root/usr/local/libexec/bloom/current/bloom-broker" ]] ||
    die "staged macOS installer did not install Broker"
  [[ -f "$work/macos-root/Library/Application Support/BloomTriad/enrollments/501.json" ]] ||
    die "staged macOS installer did not install enrollment"
  "$payload/installer/release/install-macos.sh" \
    uninstall "$work/macos-root" 501 delete-bloom-login-501
  [[ ! -e "$work/macos-root/Library/Application Support/BloomTriad/enrollments/501.json" ]] ||
    die "staged macOS uninstaller retained enrollment"
}

build_candidate() {
  [[ $# -ge 1 ]] || usage
  local platform="$1"
  shift
  require_platform "$platform"

  local workspace_root broker_root signer_root output_dir="" source_date_epoch
  local candidate_signing_key=""
  workspace_root="$(dirname "$main_root")"
  broker_root="$workspace_root/bloom-broker"
  signer_root="$workspace_root/bloom-signer"
  source_date_epoch="${SOURCE_DATE_EPOCH:-1700000000}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --output-dir)
        [[ $# -ge 2 && -n "$2" ]] || usage
        output_dir="$2"
        shift 2
        ;;
      --broker-root)
        [[ $# -ge 2 && -n "$2" ]] || usage
        broker_root="$2"
        shift 2
        ;;
      --signer-root)
        [[ $# -ge 2 && -n "$2" ]] || usage
        signer_root="$2"
        shift 2
        ;;
      --source-date-epoch)
        [[ $# -ge 2 && -n "$2" ]] || usage
        source_date_epoch="$2"
        shift 2
        ;;
      --candidate-signing-key)
        [[ $# -ge 2 && -n "$2" ]] || usage
        candidate_signing_key="$2"
        shift 2
        ;;
      *) usage ;;
    esac
  done
  [[ -n "$output_dir" ]] || usage
  [[ "$source_date_epoch" =~ ^[0-9]+$ ]] ||
    die "source date epoch must be an unsigned decimal integer" 64

  require_host_platform "$platform"
  broker_root="$(cd "$broker_root" && pwd -P)"
  signer_root="$(cd "$signer_root" && pwd -P)"
  require_clean_repository "$main_root"
  require_clean_repository "$broker_root"
  require_clean_repository "$signer_root"

  local machine_sha broker_sha signer_sha artifact_name suffix
  machine_sha="$(repository_head "$main_root")"
  broker_sha="$(repository_head "$broker_root")"
  signer_sha="$(repository_head "$signer_root")"
  artifact_name="bloom-triad-test-unclaimed.tar.gz"
  mkdir -p "$output_dir"
  output_dir="$(cd "$output_dir" && pwd -P)"
  for suffix in "" .sha256 .sig .pub; do
    [[ ! -e "$output_dir/$artifact_name$suffix" ]] ||
      die "release output already exists: $output_dir/$artifact_name$suffix"
  done

  local resolved_machine_features forbidden_feature
  resolved_machine_features="$(cargo tree --manifest-path "$main_root/Cargo.toml" -p bloom -e normal,build,features --prefix none)"
  for forbidden_feature in unsigned-audit-test-seam audit-test-seam; do
    [[ "$resolved_machine_features" != *"feature \"$forbidden_feature\""* ]] ||
      die "forbidden production Machine feature resolved: $forbidden_feature"
  done

  cargo build --manifest-path "$main_root/Cargo.toml" --release -p bloom --locked
  cargo build --manifest-path "$broker_root/Cargo.toml" --release -p bloom-broker --locked
  cargo build --manifest-path "$signer_root/Cargo.toml" --release -p bloom-signer --locked

  local work signing_key compatibility builder verifier output bundle binary source
  work="$(mktemp -d)"
  trap 'find "$work" -depth -delete' EXIT
  mkdir -p "$work/staging/bin" "$work/dist-a" "$work/dist-b" "$work/verified"
  for source in \
    "$main_root:bloom" \
    "$broker_root:bloom-broker" \
    "$signer_root:bloom-signer" \
    "$signer_root:bloom-signer-migrate"
  do
    local source_root="${source%%:*}"
    binary="${source#*:}"
    install -m 0755 "$(target_binary "$source_root" "$binary")" "$work/staging/bin/$binary"
  done
  require_staged_architecture "$platform" "$work/staging"

  if [[ -n "$candidate_signing_key" ]]; then
    require_regular_file "$candidate_signing_key"
    signing_key="$candidate_signing_key"
  else
    signing_key="$work/test-only-release-key"
    ssh-keygen -q -t ed25519 -N '' -f "$signing_key"
  fi
  compatibility="$work/compatibility-v1.toml"
  resolved_compatibility "$compatibility" "$broker_sha" "$signer_sha"
  builder="$release_dir/build-bundle.sh"
  verifier="$release_dir/verify-bundle.sh"
  export BLOOM_MACHINE_SHA="$machine_sha"
  export BLOOM_BROKER_SHA="$broker_sha"
  export BLOOM_SIGNER_SHA="$signer_sha"
  export BLOOM_PLATFORM_CLAIM=test-unclaimed
  export BLOOM_ALLOW_TEST_UNCLAIMED=true
  export BLOOM_COMPATIBILITY_FILE="$compatibility"
  for output in \
    "$work/dist-a/$artifact_name" \
    "$work/dist-b/$artifact_name"
  do
    "$builder" "$work/staging" "$output" "$signing_key" "$source_date_epoch"
    "$verifier" "$output" "$output.sha256" "$output.sig" "$output.pub"
  done
  cmp "$work/dist-a/$artifact_name" "$work/dist-b/$artifact_name"
  tar -xzf "$work/dist-a/$artifact_name" -C "$work/verified"
  bundle="$work/verified/bloom-triad"
  case "$platform" in
    linux) smoke_linux_installer "$bundle" "$work" ;;
    macos) smoke_macos_installer "$bundle" "$work" ;;
  esac

  for suffix in "" .sha256 .sig .pub; do
    install -m 0644 \
      "$work/dist-a/$artifact_name$suffix" \
      "$output_dir/$artifact_name$suffix"
  done
  trap - EXIT
  find "$work" -depth -delete
  echo "Bloom triad $platform candidate: $output_dir/$artifact_name"
  echo "Sources: $machine_sha / $broker_sha / $signer_sha"
}

sign_candidate() {
  [[ $# -ge 2 ]] || usage
  local platform="$1" candidate="$2"
  shift 2
  require_platform "$platform"

  local output_dir="" signing_key="" pinned_public_key=""
  local source_date_epoch="" version="" machine_sha="" broker_sha="" signer_sha=""
  local macos_report="" macos_signature="" macos_public_key="" macos_key_sha256=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --output-dir) [[ $# -ge 2 ]] || usage; output_dir="$2"; shift 2 ;;
      --signing-key) [[ $# -ge 2 ]] || usage; signing_key="$2"; shift 2 ;;
      --pinned-public-key) [[ $# -ge 2 ]] || usage; pinned_public_key="$2"; shift 2 ;;
      --source-date-epoch) [[ $# -ge 2 ]] || usage; source_date_epoch="$2"; shift 2 ;;
      --version) [[ $# -ge 2 ]] || usage; version="$2"; shift 2 ;;
      --machine-sha) [[ $# -ge 2 ]] || usage; machine_sha="$2"; shift 2 ;;
      --broker-sha) [[ $# -ge 2 ]] || usage; broker_sha="$2"; shift 2 ;;
      --signer-sha) [[ $# -ge 2 ]] || usage; signer_sha="$2"; shift 2 ;;
      --macos-conformance-report) [[ $# -ge 2 ]] || usage; macos_report="$2"; shift 2 ;;
      --macos-conformance-signature) [[ $# -ge 2 ]] || usage; macos_signature="$2"; shift 2 ;;
      --macos-conformance-public-key) [[ $# -ge 2 ]] || usage; macos_public_key="$2"; shift 2 ;;
      --macos-conformance-key-sha256) [[ $# -ge 2 ]] || usage; macos_key_sha256="$2"; shift 2 ;;
      *) usage ;;
    esac
  done

  [[ -n "$output_dir" && -n "$signing_key" && -n "$pinned_public_key" &&
    -n "$source_date_epoch" && -n "$version" && -n "$machine_sha" &&
    -n "$broker_sha" && -n "$signer_sha" ]] || usage
  [[ "$source_date_epoch" =~ ^[0-9]+$ ]] ||
    die "source date epoch must be an unsigned decimal integer" 64
  [[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
    die "expected Machine version is invalid" 64
  local revision
  for revision in "$machine_sha" "$broker_sha" "$signer_sha"; do
    [[ "$revision" =~ ^[0-9a-f]{40}$ ]] ||
      die "expected source revision is not a full lowercase commit ID" 64
  done
  for revision in "$candidate" "$candidate.sha256" "$candidate.sig" "$candidate.pub" \
    "$signing_key" "$pinned_public_key"
  do
    require_regular_file "$revision"
  done
  case "$platform" in
    linux)
      [[ -z "$macos_report$macos_signature$macos_public_key$macos_key_sha256" ]] ||
        die "Linux signing does not accept macOS conformance evidence" 64
      ;;
    macos)
      [[ -n "$macos_report" && -n "$macos_signature" &&
        -n "$macos_public_key" && "$macos_key_sha256" =~ ^[0-9a-f]{64}$ ]] ||
        die "macOS signing requires complete pinned conformance evidence" 64
      require_regular_file "$macos_report"
      require_regular_file "$macos_signature"
      require_regular_file "$macos_public_key"
      ;;
  esac

  BLOOM_ALLOW_TEST_UNCLAIMED=true "$release_dir/verify-bundle.sh" \
    "$candidate" "$candidate.sha256" "$candidate.sig" "$candidate.pub"

  local work payload expected source_line artifact_name output archive_tmp
  local tar_command="${TAR:-tar}" tar_help
  local -a tar_identity_args
  work="$(mktemp -d)"
  trap 'find "$work" -depth -delete' EXIT
  "$tar_command" -xzf "$candidate" -C "$work"
  payload="$work/bloom-triad"
  [[ -d "$payload" && ! -L "$payload" ]] ||
    die "candidate does not contain a regular bloom-triad payload"
  if find "$payload" -type l -o \( ! -type f ! -type d \) | grep . >/dev/null; then
    die "candidate contains a symlink or non-regular filesystem entry"
  fi
  [[ "$(<"$payload/PLATFORM_CLAIM")" == test-unclaimed ]] ||
    die "production signing requires a test-unclaimed candidate"
  expected="$(sed -n -E 's/^machine = "([^"]+)"$/\1/p' "$payload/compatibility-v1.toml")"
  [[ "$expected" == "$version" ]] ||
    die "candidate Machine version does not match the release version"
  for source_line in \
    "BLOOM_MACHINE_SHA=$machine_sha" \
    "BLOOM_BROKER_SHA=$broker_sha" \
    "BLOOM_SIGNER_SHA=$signer_sha"
  do
    grep -Fx "$source_line" "$payload/SOURCE_REVISIONS" >/dev/null ||
      die "candidate source revisions do not match the resolved triad"
  done
  [[ "$(wc -l < "$payload/SOURCE_REVISIONS" | tr -d ' ')" == 3 ]] ||
    die "candidate source revisions contain unexpected entries"
  require_staged_architecture "$platform" "$payload"

  case "$platform" in
    linux)
      printf 'linux\n' >"$payload/PLATFORM_CLAIM"
      artifact_name="bloom-triad-linux-x86_64.tar.gz"
      ;;
    macos)
      printf 'macos-unix-principals\n' >"$payload/PLATFORM_CLAIM"
      install -m 0644 "$macos_report" "$payload/MACOS_CONFORMANCE_REPORT.json"
      install -m 0644 "$macos_signature" "$payload/MACOS_CONFORMANCE_REPORT.sig"
      install -m 0644 "$macos_public_key" "$payload/MACOS_CONFORMANCE_REPORT.pub"
      "$release_dir/verify-macos-conformance.sh" "$payload" "$macos_key_sha256"
      artifact_name="bloom-triad-macos-aarch64.tar.gz"
      ;;
  esac

  rm -f -- "$payload/RELEASE_PUBLIC_KEY.pem" "$payload/RELEASE_SIGNATURE" "$payload/SHA256SUMS"
  "$release_dir/ssh-ed25519-public-key.sh" "$signing_key" "$payload/RELEASE_PUBLIC_KEY.pem"
  cmp -s "$pinned_public_key" "$payload/RELEASE_PUBLIC_KEY.pem" ||
    die "release signing key does not match the reviewed public key"
  (
    cd "$payload"
    find . -type f ! -path ./SHA256SUMS ! -path ./RELEASE_SIGNATURE -print |
      LC_ALL=C sort |
      while IFS= read -r source_line; do
        shasum -a 256 "$source_line"
      done
  ) >"$payload/SHA256SUMS"
  "$release_dir/ssh-ed25519-sign.sh" \
    "$signing_key" bloom-release-payload-v1 "$payload/SHA256SUMS" "$payload/RELEASE_SIGNATURE"
  # shellcheck disable=SC2016
  find "$payload" -print0 |
    xargs -0 perl -e '$timestamp = shift; utime $timestamp, $timestamp, @ARGV' \
      "$source_date_epoch"

  mkdir -p "$output_dir"
  output_dir="$(cd "$output_dir" && pwd -P)"
  output="$output_dir/$artifact_name"
  local suffix
  for suffix in "" .sha256 .sig .pub; do
    [[ ! -e "$output$suffix" ]] || die "release signing output already exists: $output$suffix"
  done
  tar_help="$("$tar_command" --help 2>&1 || true)"
  if [[ "$tar_help" == *"--owner"* ]]; then
    tar_identity_args=(--owner=0 --group=0)
  else
    tar_identity_args=(--uid=0 --gid=0 --uname=root --gname=root)
  fi
  archive_tmp="$work/archive.tar"
  (
    cd "$work"
    find bloom-triad -print | LC_ALL=C sort >archive-files
    "$tar_command" --format=ustar "${tar_identity_args[@]}" --no-recursion \
      -cf "$archive_tmp" -T archive-files
  )
  gzip -n -9 <"$archive_tmp" >"$output"
  (
    cd "$output_dir"
    shasum -a 256 "$artifact_name" >"$artifact_name.sha256"
  )
  "$release_dir/ssh-ed25519-sign.sh" \
    "$signing_key" bloom-release-archive-v1 "$output.sha256" "$output.sig"
  install -m 0644 "$pinned_public_key" "$output.pub"
  trap - EXIT
  find "$work" -depth -delete
  echo "Bloom triad $platform release: $output"
}

[[ $# -ge 1 ]] || usage
command_name="$1"
shift
case "$command_name" in
  build) build_candidate "$@" ;;
  sign) sign_candidate "$@" ;;
  *) usage ;;
esac
