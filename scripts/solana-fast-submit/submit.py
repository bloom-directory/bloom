"""Bounded, one-entry approval-to-confirm coordinator (no staging)."""

import re


def run(client, entry, clock, before_write):
    match = re.fullmatch(r'wallets/([A-Za-z0-9_-]+)/((?:0|[1-9][0-9]*))/chains/(solana-[A-Za-z0-9_-]+)/outbox/pending/([A-Za-z0-9_-]+)', entry)
    if not match:
        raise RuntimeError('challenge entry must be one exact numbered Solana pending path')
    wallet, account, chain, tx_id = match.groups()
    challenge = client.read(entry + '/approval_challenge.json', 3)
    expected = dict(schema='bloom.solana-approval-challenge/1', wallet=wallet, chain=chain,
                    tx_id=tx_id, action_id=tx_id, retry_path=entry + '/confirm')
    if (not isinstance(challenge, dict)
            or any(challenge.get(key) != value for key, value in expected.items())
            or not isinstance(challenge.get('approval_id'), str)
            or not re.fullmatch('[0-9a-f]{64}', challenge['approval_id'])
            or type(challenge.get('expiry_ms')) is not int or challenge['expiry_ms'] <= 0):
        raise RuntimeError('challenge schema or identity mismatch')
    status_path = f"wallets/{wallet}/sealed-approvals/{challenge['approval_id']}/status.json"
    expiry = challenge['expiry_ms']
    deadline = clock.monotonic() + min(60, max(0, (expiry - clock.wall_ms()) / 1000))
    def remaining():
        seconds = min(deadline - clock.monotonic(), (expiry - clock.wall_ms()) / 1000)
        if seconds <= 0:
            raise RuntimeError('approval expired or bounded wait elapsed')
        return seconds
    while True:
        status = client.read(status_path, min(3, remaining()))
        remaining()
        if not isinstance(status, dict) or status.get('wallet_id') != wallet or status.get('approval_id') != challenge['approval_id']:
            raise RuntimeError('approval identity mismatch')
        if status.get('state') not in ('PREPARED', 'AWAITING_CEREMONY', 'ACTIVE'):
            raise RuntimeError('approval is unavailable or terminal')
        if status['state'] == 'ACTIVE':
            before_write()
            remaining()
            client.write(challenge['retry_path'], 20)
            sent = client.read(f'wallets/{wallet}/{account}/chains/{chain}/outbox/sent/{tx_id}/intent.json', 3)
            if not isinstance(sent, dict) or any(sent.get(k) != v for k, v in dict(id=tx_id, wallet=wallet, chain=chain, status='sent').items()):
                raise RuntimeError('sent readback mismatch; do not retry')
            return 'sent (not proof of confirmation)'
        clock.sleep(.25)


class Clock:
    def wall_ms(self):
        return __import__('time').time_ns() // 1_000_000

    def monotonic(self):
        return __import__('time').monotonic()

    def sleep(self, seconds):
        __import__('time').sleep(seconds)


class Client:
    def __init__(self, binary, endpoint):
        self.command = [binary, '--connect', endpoint, 'vfs']

    def invoke(self, operation, path, timeout):
        import subprocess
        try:
            result = subprocess.run(self.command + [operation, path],
                                    input='y\n' if operation == 'write' else '',
                                    capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError(f'{operation} transport failed; no retry; outcome may be unknown') from error
        if result.returncode:
            # Do not echo subprocess output: it may contain a ceremony capability.
            raise RuntimeError(f'{operation} returned exit {result.returncode}; no retry; inspect exact entry')
        return result.stdout

    def read(self, path, timeout):
        import json
        return json.loads(self.invoke('cat', path, timeout))

    def write(self, path, timeout):
        self.invoke('write', path, timeout)


def main():
    import argparse
    import hashlib
    import json
    import os
    from pathlib import Path
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bloom', required=True, help='absolute path to reviewed CLI binary')
    parser.add_argument('--connect', required=True, help='explicit unix:/absolute/socket endpoint')
    parser.add_argument('--entry', required=True, help='exact wallets/.../outbox/pending/id (no leading slash)')
    parser.add_argument('--state-dir', required=True, help='persistent dedicated local guard directory; never delete to retry')
    parser.add_argument('--execute', action='store_true', help='explicitly arm one confirm after ACTIVE')
    args = parser.parse_args()
    if not args.execute:
        parser.error('--execute is required; nothing has been contacted')
    if not os.path.isabs(args.bloom) or not args.connect.startswith('unix:/'):
        parser.error('explicit absolute binary and unix socket required')
    state = Path(args.state_dir)
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = hashlib.sha256((args.connect + '\0' + args.entry).encode()).hexdigest()
    try:
        # O_EXCL is both the concurrent-run lock and a permanent restart guard.
        fd = os.open(state / (key + '.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print('REFUSED: this entry already has a run guard; reconcile, never blindly retry', file=sys.stderr)
        return 2
    with os.fdopen(fd, 'w') as guard:
        def record(phase):
            guard.seek(0)
            json.dump(dict(entry=args.entry, endpoint=args.connect, phase=phase), guard)
            guard.truncate()
            guard.flush()
            os.fsync(guard.fileno())
        record('armed')
        dirfd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        try:
            result = run(Client(args.bloom, args.connect), args.entry, Clock(), lambda: record('confirm-dispatching'))
            record('sent-observed')
            print(result)
            return 0
        except (RuntimeError, ValueError, KeyError, TypeError, OSError, KeyboardInterrupt):
            print('STOPPED: no retry. Read the exact entry and Broker operation before further action; outcome may be unknown.', file=sys.stderr)
            return 2


if __name__ == '__main__':
    raise SystemExit(main())
