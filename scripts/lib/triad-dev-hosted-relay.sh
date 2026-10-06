#!/usr/bin/env bash
# Sourced by triad-dev-launch.sh after authenticated Triad health succeeds.
wait_for_hosted_relay() {
  relay_deadline=$(( $(date +%s) + relay_timeout_seconds ))
  relay_status_file="${log_dir}/relay-admin-status.json"
  relay_error_file="${log_dir}/relay-admin-error.log"
  signer_uid="$(id -u)"
  relay_admin() {
    "$signer_bin" admin "$1" --signer-uid "$signer_uid" \
      > "$relay_status_file" 2> "$relay_error_file" &
    relay_admin_pid=$!
    while kill -0 "$relay_admin_pid" 2>/dev/null; do
      if [ "$(date +%s)" -ge "$relay_deadline" ]; then
        kill "$relay_admin_pid" 2>/dev/null || true
        sleep 1
        kill -9 "$relay_admin_pid" 2>/dev/null || true
        wait "$relay_admin_pid" 2>/dev/null || true
        relay_admin_pid=""
        printf 'Signer admin %s exceeded the hosted relay timeout (%ss)\n' \
          "$1" "$relay_timeout_seconds" > "$relay_error_file"
        return 1
      fi
      sleep 0.2
    done
    if wait "$relay_admin_pid"; then
      relay_admin_pid=""
      return 0
    fi
    relay_admin_pid=""
    return 1
  }
  relay_ready() {
    jq -e '
      .installation_id != null and
      .desired_mode == "remote_enabled" and
      .effective_mode == "remote_enabled" and
      .desired_revision == .effective_revision and
      .remote_tls_ready == true and
      .remote_routing_ready == true and
      any(.surfaces[]; .identity.surface_id == "remote" and .lifecycle == "ACTIVE")
    ' "$relay_status_file" >/dev/null 2>&1
  }
  relay_admin status || {
    cat "$relay_error_file" >&2
    die "Signer administrator status failed; inspect ${log_dir}/signer.log"
  }
  jq -e '.desired_mode == "remote_enabled"' "$relay_status_file" >/dev/null ||
    die "Signer is set to localhost_only; use the Signer administrator to enable remote mode explicitly"
  if ! relay_ready; then
    # Signer keeps the admin key and exact allocation/ACME operation IDs in
    # its private state. Once its ACME bind is durable, certificate/routing
    # reconciliation needs only status polling, even after a restart.
    if [ -n "$(jq -r '.installation_id // empty' "$relay_status_file")" ] &&
       [ -f "${developer_root}/state/admin/acme-account-bound.json" ]; then
      relay_retry_provision=0
    else
      if ! relay_admin provision; then
        if grep -Fq 'Broker ACME account URI is pending; retry provision after account creation' "$relay_error_file"; then
          relay_retry_provision=1
        elif grep -Fq 'remote certificate and routing are pending; retry status or provision' "$relay_error_file"; then
          relay_retry_provision=0
        else
          cat "$relay_error_file" >&2
          die "hosted relay provisioning failed; inspect ${log_dir}/signer.log and retry with the same developer root"
        fi
      else
        relay_retry_provision=0
      fi
    fi
    while :; do
      relay_admin status || {
        cat "$relay_error_file" >&2
        die "Signer administrator status failed during hosted relay readiness"
      }
      jq -e '.desired_mode == "remote_enabled"' "$relay_status_file" >/dev/null ||
        die "Signer switched to localhost_only during hosted relay provisioning"
      relay_ready && break
      kill -0 "$session_pid" 2>/dev/null &&
        kill -0 "$machine_pid" 2>/dev/null &&
        kill -0 "$signer_pid" 2>/dev/null &&
        kill -0 "$broker_pid" 2>/dev/null ||
        die "a Triad service exited during hosted relay readiness; inspect ${log_dir}"
      [ "$(date +%s)" -lt "$relay_deadline" ] || {
        cat "$relay_status_file" >&2
        die "hosted relay did not become effective within ${relay_timeout_seconds}s; check enrollment, ACME certificate, and relay routing, then retry with the same developer root"
      }
      if [ "$relay_retry_provision" -eq 1 ]; then
        if relay_admin provision; then
          relay_retry_provision=0
        elif grep -Fq 'Broker ACME account URI is pending; retry provision after account creation' "$relay_error_file"; then
          :
        elif grep -Fq 'remote certificate and routing are pending; retry status or provision' "$relay_error_file"; then
          relay_retry_provision=0
        else
          cat "$relay_error_file" >&2
          die "hosted relay provisioning retry failed; inspect ${log_dir}/signer.log"
        fi
      fi
      sleep 1
    done
  fi
  printf 'Bloom hosted relay is effective and its TLS and routing are ready.\n'
  machine_cli serve triad-health-check "$release_digest" >/dev/null 2>&1 ||
    die "Triad lost authenticated health during hosted relay provisioning"
}
