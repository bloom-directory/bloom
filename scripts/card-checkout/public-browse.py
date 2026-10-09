#!/usr/bin/env python3
"""Public VFS client for the isolated Docker dev session; no card input."""
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
env = {**os.environ, **json.loads((root / 'connection.json').read_text())}
slot = secrets.token_hex(32)

def vfs(command, path, value=None):
    result = subprocess.run(
        ['/candidate/bloom', '--quiet', 'vfs', command, path], env=env,
        input=json.dumps(value) if value is not None else None,
        text=True, capture_output=True, check=True)
    return json.loads(result.stdout) if command == 'cat' else None

def browse(request):
    path = f'/checkout/browse/{slot}'
    vfs('write', path + '/in.json', request)
    return vfs('cat', path + '/out.json')

action = sys.argv[2] if len(sys.argv) > 2 else 'snapshot'
if action == 'open':
    browse({'action': 'open', 'url': sys.argv[3]})
elif action == 'click':
    snapshot = browse({'action': 'snapshot'})
    matches = [element for element in snapshot['elements']
               if element['label'].casefold() == sys.argv[3].casefold()]
    if len(sys.argv) <= 4 and len(matches) != 1:
        raise SystemExit('Ambiguous or missing control; specify a matching index')
    browse({'action': 'click', 'element_ref': matches[int(sys.argv[4]) if len(sys.argv) > 4 else 0]['ref']})
elif action in ('type', 'select'):
    browse({'action': action, 'element_ref': sys.argv[3],
            'text' if action == 'type' else 'value': sys.argv[4]})
elif action != 'snapshot':
    raise SystemExit('Use open URL, snapshot, click LABEL [INDEX], type REF TEXT, or select REF VALUE')
time.sleep(3)
print(json.dumps(browse({'action': 'snapshot'})))
