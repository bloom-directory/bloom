"""Stage 0 runner for a root-created DynamicUser unit, not a checkout service.

Run via systemd-run --pipe with DynamicUser=yes and a RuntimeDirectory.
Does not access installed Bloom services or personal browser profiles.
Emits metadata, then waits 60 seconds for login-user negative access probes.
The caller must test /proc/PID/fd, ptrace and profile access while it is alive.
"""
import argparse
import json
import os
import pathlib
import select
import signal
import time

args = argparse.ArgumentParser()
args.add_argument('--fixture-root', help='Same-UID pipe test only; not an isolation result')
options = args.parse_args()
if not options.fixture_root and os.getuid() in (0, 1000):
    raise RuntimeError('Run the isolation spike as a dedicated service UID')
profile = pathlib.Path(options.fixture_root or '/run/bloom-card-spike-1008') / 'profile'
profile.mkdir(mode=0o700)
read_browser, write_controller = os.pipe()
read_controller, write_browser = os.pipe()
null = os.open('/dev/null', os.O_RDWR)
pid = os.posix_spawn('/usr/lib/chromium/chromium', [
    '/usr/lib/chromium/chromium', '--headless', '--remote-debugging-pipe',
    '--no-first-run', '--disable-extensions', '--enable-automation',
    f'--user-data-dir={profile}', 'about:blank',
], {'PATH': '/usr/bin', 'HOME': str(profile.parent)}, file_actions=[
    (os.POSIX_SPAWN_DUP2, read_browser, 3),
    (os.POSIX_SPAWN_DUP2, write_browser, 4),
    (os.POSIX_SPAWN_CLOSE, read_controller),
    (os.POSIX_SPAWN_CLOSE, write_browser),
    (os.POSIX_SPAWN_DUP2, null, 0),
    (os.POSIX_SPAWN_DUP2, null, 1),
    (os.POSIX_SPAWN_DUP2, null, 2),
])
os.close(read_browser)
os.close(write_browser)
try:
    os.write(write_controller, b'{"id":1,"method":"Browser.getVersion"}\0')
    ready, _, _ = select.select([read_controller], [], [], 15)
    if not ready:
        raise RuntimeError('Chromium pipe did not respond')
    reply = os.read(read_controller, 65536).split(b'\0')[0]
    version = json.loads(reply)['result']['product']
    print(json.dumps({'uid': os.getuid(), 'browser_pid': pid,
                      'browser': version, 'profile': str(profile),
                      'transport': 'pipe',
                      'probe_window_seconds': 1 if options.fixture_root else 60}), flush=True)
    time.sleep(1 if options.fixture_root else 60)
finally:
    # Only the child owned by this spike. RuntimeDirectory is retained.
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    os.close(write_controller)
    os.close(read_controller)
    os.close(null)
