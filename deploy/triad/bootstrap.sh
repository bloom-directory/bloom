#!/usr/bin/env bash
#
# bloom-triad-bootstrap -- DEVELOPMENT / SANDBOX ONLY triad enrollment for the
# Docker Compose stack.
#
# ============================================================================
# THIS IS NOT A PRODUCTION INSTALLER. It mints a fresh developer signing
# identity inside Docker named volumes. The keys it generates are for a
# throwaway sandbox. Do not point it at, and do not copy its output into, an
# installation that holds value.
# ============================================================================
#
# What it does, and why each step exists
# --------------------------------------
#  1. Computes the release digest over the exact bloom / bloom-broker /
#     bloom-signer binaries that the Compose services will execute. The
#     formula is byte-for-byte the one in scripts/triad-dev-launch.sh:
#         sha256(each binary) -> take hex column -> sha256 of that stream
#     in the fixed order machine, Broker, Signer. The binaries arrive in this
#     image through BuildKit named contexts pointing at the three service
#     images, so "the digest" and "what runs" cannot drift apart.
#  2. Renders enrollment material with `bloom init
#     triad-render-developer-enrollment`, from the same templates the dev
#     launcher uses (Linux edge manifest, macOS Broker/Signer/catalog
#     templates -- see TEMPLATE NOTE below). That command refuses to run as
#     root, so it is executed under the service UID via setpriv.
#  3. Applies only the config rewrites the canonical dev launcher already
#     proves, retargeted at this stack's socket and database paths.
#  4. Distributes each file to a per-service config volume with the ownership
#     and mode that the *production* trust path in bloom-broker /
#     bloom-signer / bloom requires: root-owned trust anchors, service-owned
#     mode-0600 identity and seed-bearing config.
#  5. Stamps the socket directories 0710 service-owned, which is what
#     bloom_service_activation::bind_owned_unix_listener demands, and
#     pre-creates the one nested mount point Docker cannot create itself --
#     `session/` inside the read-only session-config volume.
#
# Secrets discipline: seeds exist only inside the tmpfs enrollment area and
# inside files this script writes with umask 077. Nothing here ever cats,
# echoes, or logs a config file's contents, and the installer signing seed is
# deliberately destroyed with the tmpfs rather than handed to any service.
#
# Subcommands:
#   bootstrap   provision (or re-conform) every volume            [default]
#   status      report what is provisioned, without changing it
#   reset       destroy developer custody, guarded by a confirmation token

set -euo pipefail
export LC_ALL=C
umask 077

# ---------------------------------------------------------------------------
# Image-baked inputs
# ---------------------------------------------------------------------------
bin_dir=/opt/bloom-triad/bin
template_dir=/opt/bloom-triad/templates
tool_source=/opt/bloom-triad/tools/bloom-ceremony-activate

# ---------------------------------------------------------------------------
# Mount points inside THIS container (see docker-compose.yml `bootstrap`)
# ---------------------------------------------------------------------------
config_root=/state/config
run_root=/state/run
db_root=/state/db
machine_home=/state/machine-home
tools_root=/state/tools
enrollment_root=/state/enrollment

stamp_name=.bloom-triad-stamp.json
stamp_schema=bloom.triad-compose-bootstrap.1

# Volumes that carry a provisioning stamp. Socket and database volumes carry
# ownership only -- they are re-stampable at any time and hold no identity.
stamped_roles=(signer broker machine session machine-home tools)

# ---------------------------------------------------------------------------
# Paths as the SERVICE containers see them. These must match docker-compose.yml
# exactly; scripts/test-triad-compose-stack.sh asserts that they do.
# ---------------------------------------------------------------------------
service_signer_socket=/run/bloom-signer-rpc/signer.sock
service_signer_control=/run/bloom-signer-control/signer-control.sock
service_broker_socket=/run/bloom-broker-rpc/broker.sock
service_broker_control=/run/bloom-broker-control/broker-control.sock
service_signer_db=/var/db/bloom/signer/signer.db
service_broker_journal=/var/db/bloom/broker/journal.db
service_broker_authority=/var/db/bloom/broker/authority.db
service_broker_ceremony=/var/db/bloom/broker/ceremonies.db
service_broker_catalog=/etc/bloom/provenance-catalog.json

# The dev launcher raises this ceiling because an interactive developer session
# trips the production 1200/minute quota during ordinary exploration.
developer_request_ceiling=10000

service_uid="${BLOOM_SERVICE_UID:-10001}"
service_gid="${BLOOM_SERVICE_GID:-10001}"

die() { printf 'bloom-triad-bootstrap: %s\n' "$*" >&2; exit 1; }
note() { printf 'bloom-triad-bootstrap: %s\n' "$*"; }

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
require_environment() {
  [ "$(uname -s)" = Linux ] ||
    die "this stack is Linux-only"
  [ "$(id -u)" -eq 0 ] ||
    die "the bootstrap container must run as root so it can install root-owned trust files"
  case "$service_uid" in ''|*[!0-9]*|0)
    die "BLOOM_SERVICE_UID must be a positive integer" ;;
  esac
  case "$service_gid" in ''|*[!0-9]*|0)
    die "BLOOM_SERVICE_GID must be a positive integer" ;;
  esac
  command -v jq >/dev/null 2>&1 || die "jq is missing from the bootstrap image"
  command -v setpriv >/dev/null 2>&1 || die "setpriv is missing from the bootstrap image"
  for binary in bloom bloom-broker bloom-signer; do
    [ -x "${bin_dir}/${binary}" ] ||
      die "release binary was not staged into the bootstrap image: ${binary}"
  done
  [ -x "$tool_source" ] || die "ceremony activation shim was not built into the image"
  for mount_point in \
    "${config_root}/signer" "${config_root}/broker" "${config_root}/machine" \
    "${config_root}/session" "${run_root}/signer-rpc" "${run_root}/signer-control" \
    "${run_root}/broker-rpc" "${run_root}/broker-control" "${run_root}/session-rpc" \
    "${db_root}/signer" "${db_root}/broker" "$machine_home" "$tools_root"
  do
    [ -d "$mount_point" ] ||
      die "expected volume is not mounted: ${mount_point} (run this through docker compose)"
  done
}

# ---------------------------------------------------------------------------
# Release digest -- identical construction to scripts/triad-dev-launch.sh
# ---------------------------------------------------------------------------
compute_release_digest() {
  sha256sum "${bin_dir}/bloom" "${bin_dir}/bloom-broker" "${bin_dir}/bloom-signer" |
    awk '{print $1}' | sha256sum | awk '{print $1}'
}

# ---------------------------------------------------------------------------
# State inspection
#
# Fail-closed rule: every stamped volume must be either uniformly absent
# (fresh) or uniformly present and mutually agreeing (provisioned). Anything
# else is a half-built stack -- most often one volume removed by hand, or a
# `down -v` that only caught some of them -- and is refused rather than
# repaired, because "repairing" it means minting a new identity over the top of
# durable state signed by the old one.
# ---------------------------------------------------------------------------
stamp_path_for() {
  case "$1" in
    signer|broker|machine|session) printf '%s/%s/%s' "$config_root" "$1" "$stamp_name" ;;
    machine-home) printf '%s/%s' "$machine_home" "$stamp_name" ;;
    tools) printf '%s/%s' "$tools_root" "$stamp_name" ;;
    *) die "unknown stamp role: $1" ;;
  esac
}

# Sets: state_kind (fresh|provisioned), state_enrollment_id, state_digest
inspect_state() {
  local present=() absent=() role path ids
  for role in "${stamped_roles[@]}"; do
    path="$(stamp_path_for "$role")"
    if [ -e "$path" ]; then present+=("$role"); else absent+=("$role"); fi
  done

  if [ "${#present[@]}" -eq 0 ]; then
    # No stamps at all. Insist the config volumes are genuinely empty, so a
    # hand-populated or externally managed config tree is never overwritten.
    for role in signer broker machine session; do
      if find "${config_root}/${role}" -mindepth 1 -print -quit | grep -q .; then
        die "config volume for ${role} has content but no bootstrap stamp; refusing to overwrite unknown material (use 'reset' if it is disposable)"
      fi
    done
    state_kind=fresh
    state_enrollment_id=""
    state_digest=""
    return
  fi

  if [ "${#absent[@]}" -ne 0 ]; then
    die "inconsistent state: provisioned [${present[*]}] but missing [${absent[*]}]; run 'reset' and bootstrap again (this destroys the developer identity)"
  fi

  for role in "${stamped_roles[@]}"; do
    path="$(stamp_path_for "$role")"
    jq -e --arg schema "$stamp_schema" --arg role "$role" \
      '.schema == $schema and .role == $role' "$path" >/dev/null 2>&1 ||
      die "bootstrap stamp for ${role} is unreadable or has the wrong schema; run 'reset'"
  done

  ids="$(
    for role in "${stamped_roles[@]}"; do
      jq -r '.enrollment_id' "$(stamp_path_for "$role")"
    done | sort -u | tr '\n' ' '
  )"
  case "$ids" in
    *' '*' '*) die "volumes carry different enrollment ids (${ids}); they were provisioned by separate bootstraps. Run 'reset' and bootstrap again (this destroys the developer identity)" ;;
  esac

  state_kind=provisioned
  state_enrollment_id="$(jq -r '.enrollment_id' "$(stamp_path_for signer)")"
  state_digest="$(jq -r '.release_digest' "$(stamp_path_for signer)")"
  local stamped_uid
  stamped_uid="$(jq -r '.service_uid' "$(stamp_path_for signer)")"
  [ "$stamped_uid" = "$service_uid" ] ||
    die "this enrollment pins service uid ${stamped_uid}, but BLOOM_SERVICE_UID is ${service_uid}. The uid is baked into the edge manifest and cannot be changed without a reset."
}

# ---------------------------------------------------------------------------
# File placement helpers
# ---------------------------------------------------------------------------
# Trust anchors the services verify as root-owned and not group/other writable.
install_root_owned() {
  install -o 0 -g 0 -m 0644 "$1" "$2"
}
# Identity and seed-bearing config: readable only by the service uid.
install_service_owned() {
  install -o "$service_uid" -g "$service_gid" -m 0600 "$1" "$2"
}

write_stamp() {
  local role="$1" enrollment_id="$2" digest="$3" path
  path="$(stamp_path_for "$role")"
  jq -n --arg schema "$stamp_schema" --arg role "$role" \
        --arg enrollment_id "$enrollment_id" --arg digest "$digest" \
        --argjson uid "$service_uid" --argjson gid "$service_gid" \
        --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{schema:$schema, role:$role, enrollment_id:$enrollment_id,
      service_uid:$uid, service_gid:$gid, release_digest:$digest,
      bootstrapped_at:$at, profile:"development-sandbox"}' > "${path}.new"
  chmod 0644 "${path}.new"
  chown 0:0 "${path}.new"
  mv -f "${path}.new" "$path"
}

# ---------------------------------------------------------------------------
# Fresh enrollment
# ---------------------------------------------------------------------------
render_enrollment() {
  local developer_root="${enrollment_root}/root"
  local staging="${developer_root}/templates"
  local rendered="${developer_root}/config"

  [ ! -e "$developer_root" ] ||
    die "enrollment work area already exists; it must be a fresh tmpfs"
  # The tmpfs arrives root-owned 0700. The renderer runs as the service uid and
  # has to traverse into it; 0711 grants exactly that and no listing.
  chmod 0711 "$enrollment_root"
  mkdir -p "$staging" "$rendered"
  # `bloom init triad-render-developer-enrollment` requires every template and
  # the (empty) output directory to be owned by the *calling* uid.
  chown "${service_uid}:${service_gid}" "$developer_root" "$staging" "$rendered"
  chmod 0700 "$developer_root" "$staging" "$rendered"

  # TEMPLATE NOTE: the Linux edge manifest is the Linux one; the Broker,
  # Signer and provenance-catalog templates live only under
  # packaging/triad/macos/config and are platform-neutral in content (every
  # platform-specific value is an @PLACEHOLDER@). This is exactly the same
  # selection scripts/triad-dev-launch.sh makes on Linux.
  local name
  for name in edge-manifest.json.in broker.json.in signer.json.in \
              provenance-catalog.unsigned.json
  do
    install -o "$service_uid" -g "$service_gid" -m 0600 \
      "${template_dir}/${name}" "${staging}/${name}"
  done

  setpriv --reuid="$service_uid" --regid="$service_gid" --clear-groups \
    env HOME="$developer_root" \
    "${bin_dir}/bloom" init triad-render-developer-enrollment \
      "$staging" "$rendered" "$release_digest"

  rm -rf -- "$staging"

  # Everything the renderer is contracted to produce. A missing file here means
  # the enrollment command changed shape; fail rather than ship a partial tree.
  for name in edge-manifest.json broker.json signer.json provenance-catalog.json \
              machine-identity.json broker-identity.json signer-identity.json \
              session-identity.json
  do
    [ -f "${rendered}/${name}" ] && [ ! -L "${rendered}/${name}" ] ||
      die "developer enrollment did not produce ${name}"
  done

  # The authority-edge application-key history starts empty. The dev launcher
  # writes the identical stub; the services verify it is owned by uid 0 (their
  # production trust path), which is why it is installed root-owned below.
  printf '%s\n' \
    '{' \
    '  "schema": "bloom.authority-edge-application-history.1",' \
    '  "historical_keys": [],' \
    '  "handovers": []' \
    '}' > "${rendered}/authority-edge-history.json"
}

# ---------------------------------------------------------------------------
# Config rewrites
#
# Exactly the rewrites the canonical dev launcher performs
# (rewrite_broker_config / rewrite_signer_config), plus the durable-path fields
# that render_developer_runtime_paths pointed at a host developer root and that
# must instead name this stack's container paths. No other field is touched.
# ---------------------------------------------------------------------------
rewrite_broker_config() {
  local source="$1" temporary="$1.new"
  jq --arg signer_socket "$service_signer_socket" \
     --arg digest "$release_digest" \
     --arg journal "$service_broker_journal" \
     --arg authority "$service_broker_authority" \
     --arg ceremony "$service_broker_ceremony" \
     --arg catalog "$service_broker_catalog" \
     --argjson ceiling "$developer_request_ceiling" \
    '.signer_socket_path = $signer_socket
     | .build_digest = $digest
     | .journal_path = $journal
     | .authority_path = $authority
     | .ceremony_path = $ceremony
     | .provenance_catalog_path = $catalog
     | .network_containment = null
     | .maximum_requests_per_window = $ceiling' \
    "$source" > "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$source"
}

rewrite_signer_config() {
  local source="$1" temporary="$1.new"
  jq --arg digest "$release_digest" \
     --arg database "$service_signer_db" \
     --argjson ceiling "$developer_request_ceiling" \
    '.build_digest = $digest
     | .database_path = $database
     | .network_containment = null
     | .maximum_requests_per_window = $ceiling' \
    "$source" > "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$source"
}

assert_no_placeholders() {
  # A surviving @PLACEHOLDER@ means a template gained a field the renderer does
  # not substitute. Catch it here rather than as an opaque parse failure at
  # service startup.
  local path="$1"
  if grep -q '@[A-Z_]\{2,\}@' "$path"; then
    die "$(basename "$path") still contains an unresolved packaging placeholder"
  fi
}

# ---------------------------------------------------------------------------
# Distribution to the per-service config volumes
# ---------------------------------------------------------------------------
distribute() {
  local rendered="${enrollment_root}/root/config"

  # --- Signer -------------------------------------------------------------
  # /etc/bloom itself stays root-owned: the Signer only needs to read.
  chown 0:0 "${config_root}/signer"; chmod 0755 "${config_root}/signer"
  install_root_owned    "${rendered}/edge-manifest.json"          "${config_root}/signer/edge-manifest.json"
  install_root_owned    "${rendered}/authority-edge-history.json" "${config_root}/signer/authority-edge-history.json"
  install_service_owned "${rendered}/signer-identity.json"        "${config_root}/signer/signer-identity.json"
  install_service_owned "${rendered}/signer.json"                 "${config_root}/signer/signer.json"

  # --- Broker -------------------------------------------------------------
  chown 0:0 "${config_root}/broker"; chmod 0755 "${config_root}/broker"
  install_root_owned    "${rendered}/edge-manifest.json"          "${config_root}/broker/edge-manifest.json"
  install_root_owned    "${rendered}/authority-edge-history.json" "${config_root}/broker/authority-edge-history.json"
  install_root_owned    "${rendered}/provenance-catalog.json"     "${config_root}/broker/provenance-catalog.json"
  install_service_owned "${rendered}/broker-identity.json"        "${config_root}/broker/broker-identity.json"
  install_service_owned "${rendered}/broker.json"                 "${config_root}/broker/broker.json"

  # --- Machine ------------------------------------------------------------
  # No broker.json/signer.json equivalent: the Machine holds no signing seed.
  chown 0:0 "${config_root}/machine"; chmod 0755 "${config_root}/machine"
  install_root_owned    "${rendered}/edge-manifest.json"          "${config_root}/machine/edge-manifest.json"
  install_root_owned    "${rendered}/authority-edge-history.json" "${config_root}/machine/authority-edge-history.json"
  install_root_owned    "${rendered}/provenance-catalog.json"     "${config_root}/machine/provenance-catalog.json"
  install_service_owned "${rendered}/machine-identity.json"       "${config_root}/machine/machine-identity.json"

  # --- Session sentinel ---------------------------------------------------
  # The odd one out, and deliberately so. bloom-broker and bloom-signer both
  # block at startup on an authenticated connection to the session sentinel, so
  # the stack cannot omit it. But `bloom serve session-sentinel` has only two
  # modes: a macOS-enrollment lookup (which would mean fabricating a
  # `bloom.macos-enrollment.1` record on Linux) or the dev-harness mode keyed
  # off BLOOM_TRIAD_DEVELOPER_ROOT. The dev-harness mode is the honest choice
  # for a dev-only stack, and it demands the mirror image of the production
  # contract: one service-UID-owned mode-0700 root holding service-UID-owned
  # mode-0600 files. Hence a second, byte-identical copy of the edge manifest
  # with different ownership. It carries public keys only.
  chown "${service_uid}:${service_gid}" "${config_root}/session"
  chmod 0700 "${config_root}/session"
  install -d -o "$service_uid" -g "$service_gid" -m 0700 "${config_root}/session/config"
  install_service_owned "${rendered}/edge-manifest.json"    "${config_root}/session/config/edge-manifest.json"
  install_service_owned "${rendered}/session-identity.json" "${config_root}/session/config/session-identity.json"
}

# ---------------------------------------------------------------------------
# Session socket mount point
#
# The sentinel mounts session-config READ-ONLY at /var/lib/bloom-session and
# session-rpc *nested* inside it at /var/lib/bloom-session/session. Docker
# creates a missing mount point in the parent before the container starts, and
# on a read-only parent that mkdirat fails -- the container never starts:
#
#     mkdirat .../var/lib/bloom-session/session: read-only file system
#
# So the directory has to already exist in the session-config volume. It is
# only ever a mount point: session-rpc is mounted over it and its own 0710
# service-owned stamp (see stamp_runtime_directories) is what
# require_session_directory actually inspects. It is stamped identically here
# so the shadowed directory never contradicts the one that shadows it.
#
# This does not widen config secrecy: the parent ${config_root}/session stays
# 0700 service-owned, so nothing outside the service uid can traverse into it.
# ---------------------------------------------------------------------------
provision_session_socket_mount_point() {
  install -d -o "$service_uid" -g "$service_gid" -m 0710 \
    "${config_root}/session/session"
}

# ---------------------------------------------------------------------------
# Runtime directory ownership
#
# bloom_service_activation::bind_owned_unix_listener refuses any parent that is
# not owned by the effective uid with mode *exactly* 0710. The service images
# create these directories 0700 or 0755, and a fresh named volume inherits the
# image's ownership and mode, so every one of them has to be re-stamped here.
# 0710 is what makes the socket group-reachable while keeping the directory
# unlistable to others; the sockets themselves are created 0660 group-owned.
#
# The `.keep` file is load-bearing, not tidiness. Docker only copies an image
# directory's contents *and its uid/gid/mode* into a named volume while that
# volume is still empty. A socket directory is empty by nature, so without a
# marker file the very next container to mount one would silently restamp it
# with the image's 0700/0755 and the Broker or Signer would then refuse to bind.
# ---------------------------------------------------------------------------
stamp_runtime_directories() {
  local directory
  for directory in signer-rpc signer-control broker-rpc broker-control session-rpc; do
    install -o 0 -g 0 -m 0644 /dev/null "${run_root}/${directory}/.keep"
    chown "${service_uid}:${service_gid}" "${run_root}/${directory}"
    chmod 0710 "${run_root}/${directory}"
  done
  # Durable service state: private to the service uid.
  for directory in signer broker; do
    chown -R "${service_uid}:${service_gid}" "${db_root}/${directory}"
    chmod 0700 "${db_root}/${directory}"
  done
  install -d -o "$service_uid" -g "$service_gid" -m 0700 \
    "${db_root}/signer/audit-checkpoints" "${db_root}/broker/audit-checkpoints"
}

# ---------------------------------------------------------------------------
# Machine home
#
# `bloom init` cannot be used here: it opens the authenticated Machine->Broker
# edge, so it only works once the triad is already up. The sandbox config must
# contain a real chain (Config validates against an empty map) but must opt out
# of network-fetched release Petals. This is the canonical ChainSpec::anvil_default
# shape, rendered in TOML with serde-defaulted fields omitted.
# ---------------------------------------------------------------------------
provision_machine_home() {
  chown "${service_uid}:${service_gid}" "$machine_home"
  chmod 0700 "$machine_home"
  install -d -o "$service_uid" -g "$service_gid" -m 0700 \
    "${machine_home}/audit-checkpoints" "${machine_home}/audit-checkpoints/machine"

  if [ ! -e "${machine_home}/config.toml" ]; then
    cat > "${machine_home}/config.toml" <<'TOML'
# Bloom Machine configuration -- DEVELOPMENT SANDBOX.
# Anvil is deliberately local-only. Start an Anvil-compatible endpoint at
# 127.0.0.1:8545 inside the Machine network namespace before using chain I/O.
default_chain = "anvil"

[petals]
preinstalled = []

[chains.anvil]
name = "anvil"
chain_id = 31337
rpc_urls = ["http://127.0.0.1:8545"]
TOML
    chown "${service_uid}:${service_gid}" "${machine_home}/config.toml"
    chmod 0600 "${machine_home}/config.toml"
  else
    chown "${service_uid}:${service_gid}" "${machine_home}/config.toml"
    chmod 0600 "${machine_home}/config.toml"
  fi
}

# ---------------------------------------------------------------------------
# Operational tools volume (non-secret)
# ---------------------------------------------------------------------------
provision_tools() {
  chown 0:0 "$tools_root"; chmod 0755 "$tools_root"
  install -o 0 -g 0 -m 0755 "$tool_source" "${tools_root}/bloom-ceremony-activate"
}

# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------
cmd_bootstrap() {
  require_environment
  release_digest="$(compute_release_digest)"
  case "$release_digest" in
    *[!0-9a-f]*) die "computed release digest is not lowercase hex" ;;
  esac
  [ "${#release_digest}" -eq 64 ] || die "computed release digest is malformed"

  inspect_state

  if [ "$state_kind" = provisioned ]; then
    # Re-conform. Identity is NEVER regenerated here: the durable Broker and
    # Signer stores are signed by the existing keys, and silently rotating them
    # would strand that state. Only the fields the dev launcher itself rewrites
    # on every launch are refreshed, which is what lets you rebuild the images
    # and restart without a reset.
    if [ "$state_digest" != "$release_digest" ]; then
      note "release digest changed (${state_digest:0:12}... -> ${release_digest:0:12}...); re-pinning configs, keeping the existing developer identity"
    else
      note "already provisioned (enrollment ${state_enrollment_id:0:12}...); re-conforming ownership and paths"
    fi
    rewrite_broker_config "${config_root}/broker/broker.json"
    rewrite_signer_config "${config_root}/signer/signer.json"
    chown "${service_uid}:${service_gid}" \
      "${config_root}/broker/broker.json" "${config_root}/signer/signer.json"
    chmod 0600 \
      "${config_root}/broker/broker.json" "${config_root}/signer/signer.json"
    provision_session_socket_mount_point
    stamp_runtime_directories
    provision_machine_home
    provision_tools
    local role
    for role in "${stamped_roles[@]}"; do
      write_stamp "$role" "$state_enrollment_id" "$release_digest"
    done
    note "re-conformed. Developer identity ${state_enrollment_id:0:12}... is unchanged."
    return
  fi

  note "no existing enrollment; minting a fresh DEVELOPMENT-ONLY triad identity"
  local enrollment_id
  enrollment_id="$(od -vAn -N16 -tx1 /dev/urandom | tr -d ' \n')"

  render_enrollment
  local rendered="${enrollment_root}/root/config"
  rewrite_broker_config "${rendered}/broker.json"
  rewrite_signer_config "${rendered}/signer.json"
  assert_no_placeholders "${rendered}/broker.json"
  assert_no_placeholders "${rendered}/signer.json"
  assert_no_placeholders "${rendered}/edge-manifest.json"

  distribute
  provision_session_socket_mount_point
  stamp_runtime_directories
  provision_machine_home
  provision_tools
  local role
  for role in "${stamped_roles[@]}"; do
    write_stamp "$role" "$enrollment_id" "$release_digest"
  done

  # The tmpfs mount is discarded with the container, but do not rely on that:
  # the installer signing seed and the revoke identity live here and are
  # intentionally never distributed to any service.
  rm -rf -- "${enrollment_root}/root"

  note "bootstrap complete."
  note "  enrollment id : ${enrollment_id}"
  note "  release digest: ${release_digest}"
  note "  service uid   : ${service_uid}:${service_gid}"
  note "This identity lives only in Docker named volumes. 'docker compose down -v' destroys it."
}

cmd_status() {
  require_environment
  release_digest="$(compute_release_digest)"
  inspect_state
  printf 'profile         : development-sandbox (Linux, Docker Compose)\n'
  printf 'state           : %s\n' "$state_kind"
  printf 'image digest    : %s\n' "$release_digest"
  if [ "$state_kind" = provisioned ]; then
    printf 'enrollment id   : %s\n' "$state_enrollment_id"
    printf 'pinned digest   : %s\n' "$state_digest"
    if [ "$state_digest" != "$release_digest" ]; then
      printf 'drift           : YES -- rerun bootstrap to re-pin the configs\n'
    else
      printf 'drift           : no\n'
    fi
    printf 'service uid/gid : %s:%s\n' "$service_uid" "$service_gid"
  else
    printf 'next step       : docker compose --profile bootstrap run --rm bootstrap\n'
  fi
}

cmd_reset() {
  require_environment
  local token="${BLOOM_TRIAD_RESET_CONFIRM:-}"
  local expected="destroy-developer-custody"
  [ "$token" = "$expected" ] ||
    die "reset destroys the developer signing identity and all triad state in these volumes. Re-run with -e BLOOM_TRIAD_RESET_CONFIRM=${expected}"

  local role directory
  for role in signer broker machine session; do
    find "${config_root}/${role}" -mindepth 1 -delete
  done
  for directory in signer-rpc signer-control broker-rpc broker-control session-rpc; do
    find "${run_root}/${directory}" -mindepth 1 -delete
  done
  for directory in signer broker; do
    find "${db_root}/${directory}" -mindepth 1 -delete
  done
  find "$machine_home" -mindepth 1 -delete
  find "$tools_root" -mindepth 1 -delete
  note "reset complete; every triad volume is empty. Run bootstrap to mint a new identity."
}

case "${1:-bootstrap}" in
  bootstrap) cmd_bootstrap ;;
  status) cmd_status ;;
  reset) cmd_reset ;;
  *) die "unknown subcommand: ${1} (expected bootstrap, status, or reset)" ;;
esac
