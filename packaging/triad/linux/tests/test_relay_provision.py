import os
import pathlib
import socket
import subprocess
import tempfile
import unittest

BASE = pathlib.Path(__file__).resolve().parents[1]
RELEASE = BASE.parent / "release/install-linux.sh"

class RelayBehavior(unittest.TestCase):
    def test_path_is_edge_triggered_and_failure_retries(self):
        path = (BASE / "systemd/bloom-relay-provision@.path").read_text()
        service = (BASE / "systemd/bloom-relay-provision@.service").read_text()
        self.assertIn("PathChanged=/run/bloom/%i/session/session.sock", path)
        self.assertNotIn("PathExists=", path)
        self.assertIn("Restart=on-failure", service)
        self.assertIn("RestartSec=", service)

    def test_transient_provision_failure_retries_until_ready(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "current").mkdir()
            sock = socket.socket(socket.AF_UNIX)
            sock.bind(str(root / "admin.sock"))
            helper = (BASE / "bin/bloom-relay-provision").read_text().replace("/run/bloom/$login_uid/signer/admin/admin.sock", str(root / "admin.sock"))
            (root / "helper").write_text(helper)
            signer = root / "current/bloom-signer"
            signer.write_text("""#!/bin/bash
if [[ $2 == status ]]; then
 if [[ -e \"$TEST_ROOT/ready\" ]]; then
 printf '  \"desired_mode\": \"remote_enabled\",\\n  \"effective_mode\": \"remote_enabled\",\\n  \"remote_tls_ready\": true,\\n  \"remote_routing_ready\": true\\n'
 else echo '{}'; fi
else
 echo attempt >> \"$TEST_ROOT/attempts\"
 if [[ $(wc -l < \"$TEST_ROOT/attempts\") -eq 1 ]]; then echo temporary >&2; exit 1; fi
 touch \"$TEST_ROOT/ready\"
fi
""".replace('\\"', '"'))
            signer.chmod(0o755)
            env = dict(os.environ, TEST_ROOT=d, BLOOM_RELAY_PROVISION_TIMEOUT_SECONDS="4", BLOOM_RELAY_PROVISION_POLL_SECONDS="1")
            result = subprocess.run(["bash", str(root / "helper"), "1000"], env=env, capture_output=True, text=True, timeout=10)
            sock.close()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "attempts").read_text().count("attempt"), 2)

    def installer_run(self, root, body):
        source = RELEASE.read_text().split('\ncase "$action" in', 1)[0]
        script = source + "\n" + body
        return subprocess.run(["bash", "-c", script, "test", "test"], env=dict(os.environ, ROOT=str(root)), capture_output=True, text=True, timeout=10)

    def test_legacy_snapshot_restores_and_removes_new_relay_files(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            script = r'''
mkdir -p "$ROOT/tx/units/files"
printf 'bloom.linux-upgrade-transaction.2\n' > "$ROOT/tx/schema"
linux_upgrade_unit_paths | while read -r path; do
  case "$path" in *bloom-relay-provision*) continue;; esac
  printf 'absent - %s\n' "$path"
done > "$ROOT/tx/units/manifest"
while read -r path; do
  case "$path" in *bloom-relay-provision*) mkdir -p "$ROOT/$(dirname "$path")"; touch "$ROOT/$path";; esac
done < <(linux_upgrade_unit_paths)
restore_linux_upgrade_units "$ROOT" "$ROOT/tx"
while read -r path; do
  case "$path" in *bloom-relay-provision*) [[ ! -e "$ROOT/$path" ]] || exit 1;; esac
done < <(linux_upgrade_unit_paths)
'''
            result = self.installer_run(root, script)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_upgrade_stops_relay_before_signer(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            script = r'''
mkdir -p "$ROOT/etc/bloom/enrollments" "$ROOT/usr/lib/systemd/system"
touch "$ROOT/etc/bloom/enrollments/test.json" "$ROOT/usr/lib/systemd/system/bloom-relay-provision@.path"
linux_root_is_live() { return 0; }
linux_record_number() { echo 1000; }
linux_record_string() { echo testuser; }
systemctl() { printf '%s\n' "$*" >> "$ROOT/log"; }
stop_linux_release_set "$ROOT"
'''
            result = self.installer_run(root, script)
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = (root / "log").read_text().splitlines()
            self.assertLess(lines.index("disable --now bloom-relay-provision@1000.path"), lines.index("stop bloom-relay-provision@1000.service"))
            self.assertLess(lines.index("stop bloom-relay-provision@1000.service"), lines.index("stop bloom-signer@1000.service"))

    def test_installer_uses_single_systemd_job(self):
        text = RELEASE.read_text()
        body = text.split("provision_linux_remote_ceremonies() {",1)[1].split("\n}",1)[0]
        self.assertIn('systemctl start --no-block "bloom-relay-provision@$login_uid.service"', body)
        self.assertNotIn('/usr/libexec/bloom/bloom-relay-provision ', body)

if __name__ == "__main__":
    unittest.main()
