#!/usr/bin/env python3
"""Run as the login UID against the fresh four-UID Docker fixture.

Reports only denied operations and public status, never file contents.
"""
import ctypes
import errno
import json
import os
from pathlib import Path
import socket
import sys

root = Path(sys.argv[1])
ready = json.loads((root / 'ready.json').read_text())
assert os.getuid() == ready['login_uid'] and os.getuid() != ready['checkout_uid']
results = {}

def denied_file(name, path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as error:
        assert error.errno in (errno.EACCES, errno.EPERM), (name, error.errno)
        results[name] = 'denied'
    else:
        os.close(fd)
        raise AssertionError(name + ' was accessible')

denied_file('checkout_profile', root / 'state/checkout/profile/Default/Preferences')
denied_file('signer_card_file', root / 'state/signer/cards.sqlite3')
denied_file('checkout_proc_fds', f"/proc/{ready['checkout_pid']}/fd")
chrome_pid = int(sys.argv[2])
denied_file('chromium_proc_fds', f'/proc/{chrome_pid}/fd')
denied_file('cdp_pipe', f'/proc/{chrome_pid}/fd/3')
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
assert libc.ptrace(16, chrome_pid, 0, 0) == -1  # PTRACE_ATTACH
assert ctypes.get_errno() in (errno.EPERM, errno.EACCES)
results['ptrace_chromium'] = 'denied'

with socket.socket(socket.AF_UNIX) as stream:
    stream.settimeout(3)
    stream.connect(str(root / 'run/broker/checkout.sock'))
    try:
        stream.sendall(b'{"method":"prepare"}\n')
        response = stream.recv(1024)
    except (ConnectionResetError, BrokenPipeError):
        response = b''
    assert not response, 'Wrong-UID fact intake returned a response'
results['fact_socket_wrong_peer'] = 'rejected'

# The permitted shopping endpoint remains usable by Machine's principal.
with socket.socket(socket.AF_UNIX) as stream:
    stream.settimeout(5)
    stream.connect(str(root / 'run/checkout/api.sock'))
    stream.sendall(b'{"method":"browse","request":{"action":"snapshot"}}\n')
    response = json.loads(stream.recv(16384))
    assert response['url'] == 'about:blank'
results['public_browse'] = 'available'
print(json.dumps({'result': 'passed', 'checks': results}, indent=2))
