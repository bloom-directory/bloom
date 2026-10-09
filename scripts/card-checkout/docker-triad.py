#!/usr/bin/env python3
"""Fresh Linux enrollment with real services under four UIDs. Never mounts a home.

Run as container root, with /candidate binaries, /templates release templates,
/seed-config.toml (fresh default Machine config), and an empty state root.
The container is the process handle: stop only that named container to finish.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

root = Path(sys.argv[1]).resolve()
ceremony_port, view_port = map(int, sys.argv[2:4])
login, broker, signer, checkout, group = 1000, 31002, 31003, 31004, 31000
assert os.geteuid() == 0 and ceremony_port != view_port
root.mkdir(mode=0o711, parents=True, exist_ok=True)
assert not (root / 'material').exists(), 'Use a fresh root; preserve prior sessions'
children = []

def directory(path, uid=0, mode=0o700):
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, uid, group)
    path.chmod(mode)
    return path

def write(path, value, uid=0, mode=0o600):
    path.write_text(json.dumps(value))
    os.chown(path, uid, group)
    path.chmod(mode)

def launch(role, uid, command, env, pass_fds=()):
    def principal():
        os.setgroups([])
        os.setgid(group)
        os.setuid(uid)
    stream = open(root / 'logs' / (role + '.log'), 'wb')
    child = subprocess.Popen(command, env={**os.environ, **env}, preexec_fn=principal, pass_fds=pass_fds,
                             stdin=subprocess.DEVNULL, stdout=stream, stderr=stream)
    stream.close()
    children.append(child)
    return child

def wait_socket(path, child):
    for _ in range(300):
        if path.is_socket():
            return
        if child.poll() is not None:
            raise RuntimeError('Service exited before readiness; inspect its safe diagnostic log')
        time.sleep(0.1)
    raise RuntimeError('Service socket readiness timed out')

try:
    directory(root / 'logs', mode=0o755)
    directory(root / 'templates')
    directory(root / 'material')
    for name in ['edge-manifest.json.in', 'broker.json.in', 'signer.json.in', 'provenance-catalog.unsigned.json']:
        shutil.copyfile(Path('/templates') / name, root / 'templates' / name)
        (root / 'templates' / name).chmod(0o644)
    digest = hashlib.sha256(b''.join(hashlib.sha256((Path('/candidate') / name).read_bytes()).digest()
                                  for name in ['bloom', 'bloom-broker', 'bloom-signer', 'bloom-checkout'])).hexdigest()
    subprocess.run(['/candidate/bloom', 'init', 'triad-render-linux-enrollment', str(root / 'templates'),
                    str(root / 'material'), str(login), str(broker), str(signer), str(group), digest],
                   check=True, stdout=subprocess.DEVNULL)
    material = root / 'material'
    config = directory(root / 'config', mode=0o711)
    state = directory(root / 'state', mode=0o711)
    runtime = directory(root / 'run', mode=0o711)
    login_config = directory(config / str(login), mode=0o711)
    for role, uid in [('machine', login), ('session', login), ('broker', broker), ('signer', signer)]:
        directory(config / role, uid)
        directory(state / role, uid)
        directory(state / role / 'audit-checkpoints', uid)
        identity = config / role / 'identity.json'
        shutil.copyfile(material / (role + '-identity.json'), identity)
        os.chown(identity, uid, group)
        identity.chmod(0o600)
    directory(state / 'checkout', checkout)
    directory(login_config / 'session', login)
    shutil.copyfile(config / 'session' / 'identity.json', login_config / 'session' / 'identity.json')
    os.chown(login_config / 'session' / 'identity.json', login, group)
    (login_config / 'session' / 'identity.json').chmod(0o600)
    for target in [config / 'edge-manifest.json', login_config / 'edge-manifest.json']:
        shutil.copyfile(material / 'edge-manifest.json', target)
        target.chmod(0o644)
    history = config / 'authority-edge-history.json'
    write(history, {'schema': 'bloom.authority-edge-application-history.1', 'historical_keys': [], 'handovers': []}, mode=0o644)
    catalog = config / 'provenance-catalog.json'
    shutil.copyfile(material / 'provenance-catalog.json', catalog)
    catalog.chmod(0o644)
    enrollment = directory(root / 'enrollments', mode=0o755)
    write(enrollment / (str(login) + '.json'), {'schema': 'bloom.linux-enrollment.1', 'state': 'active', 'login_uid': login}, mode=0o644)
    directory(runtime / str(login), mode=0o711)
    directory(runtime / str(login) / 'session', login, 0o710)
    for role, uid in [('broker', broker), ('signer', signer), ('checkout', checkout)]:
        directory(runtime / role, uid, 0o711 if role == 'checkout' else 0o710)
    session_socket = runtime / str(login) / 'session' / 'session.sock'
    broker_socket = runtime / 'broker' / 'rpc.sock'
    signer_socket = runtime / 'signer' / 'rpc.sock'
    intake_socket = runtime / 'broker' / 'checkout.sock'
    checkout_socket = runtime / 'checkout' / 'api.sock'
    for role, uid in [('broker', broker), ('signer', signer)]:
        value = json.loads((material / (role + '.json')).read_text())
        value.update(ceremony_port=ceremony_port, build_digest=digest, network_containment=None)
        if role == 'broker':
            value.update(journal_path=str(state / role / 'journal.db'), authority_path=str(state / role / 'authority.db'),
                         ceremony_path=str(state / role / 'ceremonies.db'), signer_socket_path=str(signer_socket),
                         provenance_catalog_path=str(catalog), checkout_socket_path=str(intake_socket), checkout_uid=checkout)
        else:
            value['database_path'] = str(state / role / 'signer.db')
        write(config / role / 'config.json', value, uid)
    home = directory(state / 'machine' / 'home', login)
    text = Path('/seed-config.toml').read_text()
    (home / 'config.toml').write_text(text + f'\n[checkout]\nsocket="{checkout_socket}"\nuid={checkout}\n')
    os.chown(home / 'config.toml', login, group)
    (home / 'config.toml').chmod(0o600)
    common = {'BLOOM_EDGE_MANIFEST': str(config / 'edge-manifest.json'), 'BLOOM_AUTHORITY_EDGE_HISTORY': str(history),
              'BLOOM_SESSION_SOCKET': str(session_socket)}
    session = launch('session', login, ['/candidate/bloom', '--home', str(home), 'serve', 'session-sentinel'],
                     {'BLOOM_ENROLLMENT_ROOT': str(enrollment), 'BLOOM_CONFIG_ROOT': str(config), 'BLOOM_RUNTIME_ROOT': str(runtime)})
    wait_socket(session_socket, session)
    for role, uid, socket in [('signer', signer, signer_socket), ('broker', broker, broker_socket)]:
        prefix = 'BLOOM_' + role.upper()
        activation=[]
        command=['/candidate/bloom-' + role]
        if role=='broker':
            import socket as net
            for family,address in [(net.AF_INET,('127.0.0.1',ceremony_port)),(net.AF_INET6,('::1',ceremony_port))]:
                listener=net.socket(family,net.SOCK_STREAM)
                if family==net.AF_INET6:listener.setsockopt(net.IPPROTO_IPV6,net.IPV6_V6ONLY,1)
                listener.bind(address);listener.listen(128)
                activation.append(listener)
            assert [s.fileno() for s in activation]==[3,4], 'Activation wrapper needs fd 3 and 4'
            command=['python','/harness/activated-broker.py','/candidate/bloom-broker']
        process = launch(role, uid, command, {**common,
                         prefix + '_IDENTITY': str(config / role / 'identity.json'), prefix + '_CONFIG': str(config / role / 'config.json'),
                         prefix + '_SOCKET': str(socket), prefix + '_CONTROL_SOCKET': str(runtime / role / 'control.sock'),
                         prefix + '_AUDIT_CHECKPOINT_DIR': str(state / role / 'audit-checkpoints')},tuple(s.fileno() for s in activation))
        for listener in activation:listener.close()
        wait_socket(socket, process)
    browser = launch('checkout', checkout, ['/candidate/bloom-checkout', '--chromium', '/usr/lib/chromium/chromium',
                    '--profile', str(state / 'checkout' / 'profile'), '--state', str(state / 'checkout' / 'operations.sqlite3'),
                    '--socket', str(checkout_socket), '--broker-socket', str(intake_socket), '--broker-uid', str(broker),
                    '--machine-uid', str(login), '--view-port', str(view_port)], {})
    wait_socket(checkout_socket, browser)
    machine_socket = runtime / 'machine.sock'
    # Login alone owns Machine's socket directory.
    machine_runtime = directory(runtime / 'machine', login, 0o711)
    machine_socket = machine_runtime / 'rpc.sock'
    machine_env = {**common, 'BLOOM_BROKER_SOCKET': str(broker_socket), 'BLOOM_MACHINE_IDENTITY': str(config / 'machine' / 'identity.json'),
                   'BLOOM_PROVENANCE_CATALOG': str(catalog), 'BLOOM_MACHINE_AUDIT_CHECKPOINT_DIR': str(state / 'machine' / 'audit-checkpoints')}
    machine = launch('machine', login, ['/candidate/bloom', '--home', str(home), 'serve', '--endpoint', 'unix:' + str(machine_socket)], machine_env)
    wait_socket(machine_socket, machine)
    settings = {**machine_env, 'BLOOM_BIN': '/candidate/bloom', 'BLOOM_HOME': str(home), 'BLOOM_RPC_ENDPOINT': 'unix:' + str(machine_socket)}
    write(root / 'connection.json', settings, login, 0o644)
    write(root / 'ready.json', {'checkout_pid': browser.pid, 'machine_pid': machine.pid, 'broker_pid': children[2].pid,
                              'signer_pid': children[1].pid, 'login_uid': login, 'checkout_uid': checkout, 'broker_uid': broker,
                              'signer_uid': signer, 'ceremony_port': ceremony_port, 'view_port': view_port,
                              'release_digest': digest}, login, 0o644)
    print('Separate-UID checkout Triad ready', flush=True)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    while all(child.poll() is None for child in children):
        time.sleep(1)
    raise RuntimeError('A Triad process exited; stop the container and inspect safe diagnostics')
finally:
    for child in reversed(children):
        if child.poll() is None:
            child.terminate()
    for child in children:
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
