#!/usr/bin/env python3
"""Create public card requests. Enter secrets only in the Broker ceremony UI."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

root = Path(sys.argv[1])
env = {**os.environ, **json.loads((root / 'connection.json').read_text())}
action = sys.argv[2]

def vfs(command, path, value=None):
    result = subprocess.run(
        ['/candidate/bloom', '--quiet', 'vfs', command, path], env=env,
        input=json.dumps(value) if value is not None else None,
        text=True, capture_output=True, check=True)
    return json.loads(result.stdout) if command == 'cat' else None

if action == 'list':
    result = vfs('cat', '/cards/index.json')
elif action in ('add', 'delete'):
    operation = secrets.token_hex(32)
    request = {'operation_id': operation, 'card_id': sys.argv[3]}
    if action == 'add':
        request['label'] = sys.argv[4] if len(sys.argv) > 4 else 'Personal card'
    vfs('write', f'/cards/{action}.json', request)
    result = {'operation_id': operation, **vfs('cat', f'/cards/operations/{operation}/ceremony.json')}
elif action == 'checkout':
    operation = secrets.token_hex(32)
    vfs('write', f'/checkout/requests/{operation}/in.json', {
        'card_id': sys.argv[3], 'agent_description': sys.argv[4]})
    result = vfs('cat', f'/checkout/requests/{operation}/status.json')
elif action == 'status':
    result = vfs('cat', f'/checkout/requests/{sys.argv[3]}/status.json')
elif action == 'card-status':
    result = vfs('cat', f'/cards/operations/{sys.argv[3]}/status.json')
elif action == 'cancel':
    vfs('write', f'/checkout/requests/{sys.argv[3]}/cancel', {})
    result = vfs('cat', f'/checkout/requests/{sys.argv[3]}/status.json')
else:
    raise SystemExit('Use add CARD [LABEL], list, delete CARD, checkout CARD DESCRIPTION, status OP, card-status OP, or cancel OP')
print(json.dumps(result, indent=2))
