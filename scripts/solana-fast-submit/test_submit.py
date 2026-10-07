import importlib.util
import unittest
from pathlib import Path

ENTRY = 'wallets/main/0/chains/solana-mainnet/outbox/pending/0001-test'
APPROVAL = 'a' * 64

class Clock:
    def __init__(self): self.t = 1000
    def wall_ms(self): return self.t
    def monotonic(self): return self.t / 1000
    def sleep(self, seconds): self.t += int(seconds * 1000)

class Client:
    def __init__(self):
        self.states = ['AWAITING_CEREMONY', 'ACTIVE']
        self.reads = []
        self.writes = []
    def read(self, path, timeout):
        self.reads.append(path)
        if path.endswith('approval_challenge.json'):
            return dict(schema='bloom.solana-approval-challenge/1', wallet='main', chain='solana-mainnet', tx_id='0001-test', action_id='0001-test', approval_id=APPROVAL, expiry_ms=61000, retry_path=ENTRY+'/confirm')
        if '/sealed-approvals/' in path:
            return dict(wallet_id='main', approval_id=APPROVAL, state=self.states.pop(0))
        return dict(id='0001-test', wallet='main', chain='solana-mainnet', status='sent')
    def write(self, path, timeout): self.writes.append(path)

class Tests(unittest.TestCase):
    def module(self):
        path = Path(__file__).with_name('submit.py')
        self.assertTrue(path.exists(), 'bounded submit helper is missing')
        spec = importlib.util.spec_from_file_location('submit', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    def test_waits_on_broker_status_then_confirms_once(self):
        m = self.module(); c = Client()
        result = m.run(c, ENTRY, Clock(), lambda: None)
        self.assertEqual(result, 'sent (not proof of confirmation)')
        self.assertEqual(c.writes, [ENTRY+'/confirm'])
        self.assertEqual(c.reads.count('wallets/main/sealed-approvals/'+APPROVAL+'/status.json'), 2)
        self.assertEqual(c.reads.count(ENTRY+'/approval_challenge.json'), 1)

    def test_rejects_mismatched_or_terminal_authority_without_write(self):
        m = self.module()
        for changed in [dict(wallet_id='other'), dict(approval_id='b'*64), dict(state='EXPIRED'), dict(state='unknown'), dict(state='EXHAUSTED')]:
            with self.subTest(changed=changed):
                c = Client(); original = c.read
                def read(path, timeout):
                    value = original(path, timeout)
                    if '/sealed-approvals/' in path: value.update(changed)
                    return value
                c.read = read
                with self.assertRaisesRegex(RuntimeError, 'approval'): m.run(c, ENTRY, Clock(), lambda: None)
                self.assertEqual(c.writes, [])

    def test_deadline_rechecked_after_slow_status(self):
        m = self.module(); c = Client(); clock = Clock(); original = c.read
        c.states = ['ACTIVE']
        def read(path, timeout):
            result = original(path, timeout)
            if '/sealed-approvals/' in path: clock.t = 61000
            return result
        c.read = read
        with self.assertRaisesRegex(RuntimeError, 'expired'): m.run(c, ENTRY, clock, lambda: None)
        self.assertEqual(c.writes, [])

    def test_rejects_challenge_redirect_and_bad_schema(self):
        m = self.module()
        changes = [dict(retry_path=ENTRY+'/restage'), dict(schema='other'), dict(approval_id='bad'), dict(expiry_ms='61000'), dict(wallet='other'), dict(tx_id='other')]
        for changed in changes:
            with self.subTest(changed=changed):
                c = Client(); original = c.read
                def read(path, timeout):
                    value = original(path, timeout)
                    if path.endswith('approval_challenge.json'): value.update(changed)
                    return value
                c.read = read
                with self.assertRaisesRegex(RuntimeError, 'challenge'): m.run(c, ENTRY, Clock(), lambda: None)
                self.assertEqual(c.writes, [])

    def test_cli_executes_once_and_refuses_restart(self):
        import json, os, subprocess, sys, tempfile, time
        with tempfile.TemporaryDirectory() as temp:
            d = Path(temp); fake = d/'fake-bloom'; log = d/'calls'
            fake.write_text('''#!/usr/bin/env python3
import json, os, sys, time
args = sys.argv[1:]
with open(os.environ['TEST_LOG'], 'a') as f: f.write(json.dumps(args)+'\\n')
entry = os.environ['TEST_ENTRY']
if args[-2] == 'cat':
    path = args[-1]
    if path.endswith('approval_challenge.json'):
        value = dict(schema='bloom.solana-approval-challenge/1', wallet='main', chain='solana-mainnet', tx_id='0001-test', action_id='0001-test', approval_id='a'*64, expiry_ms=int(time.time()*1000)+60000, retry_path=entry+'/confirm')
    elif '/sealed-approvals/' in path:
        value = dict(wallet_id='main', approval_id='a'*64, state='ACTIVE')
    else: value = dict(id='0001-test', wallet='main', chain='solana-mainnet', status='sent')
    print(json.dumps(value))
else:
    assert args[-2:] == ['write', entry+'/confirm']
    assert sys.stdin.read() == 'y\\n'
''')
            fake.chmod(0o700)
            env = dict(os.environ, TEST_LOG=str(log), TEST_ENTRY=ENTRY)
            cmd = [sys.executable, str(Path(__file__).with_name('submit.py')), '--bloom', str(fake), '--connect', 'unix:/isolated/nonexistent.sock', '--entry', ENTRY, '--state-dir', str(d/'state'), '--execute']
            first = subprocess.run(cmd, capture_output=True, text=True, env=env)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn('not proof of confirmation', first.stdout)
            second = subprocess.run(cmd, capture_output=True, text=True, env=env)
            self.assertNotEqual(second.returncode, 0)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(sum('write' in args for args in calls), 1)
            self.assertTrue(all(args[:2] == ['--connect', 'unix:/isolated/nonexistent.sock'] for args in calls))

    def test_sent_readback_must_match_entry(self):
        m = self.module(); c = Client(); original = c.read
        def read(path, timeout):
            value = original(path, timeout)
            if '/sent/' in path: value['id'] = 'different'
            return value
        c.read = read
        with self.assertRaisesRegex(RuntimeError, 'sent'): m.run(c, ENTRY, Clock(), lambda: None)
        self.assertEqual(len(c.writes), 1)

    def test_guard_delay_cannot_dispatch_after_expiry(self):
        m = self.module(); c = Client(); clock = Clock()
        def guard(): clock.t = 61000
        with self.assertRaisesRegex(RuntimeError, 'expired'): m.run(c, ENTRY, clock, guard)
        self.assertEqual(c.writes, [])

    def test_malformed_status_fails_closed(self):
        m = self.module(); c = Client(); original = c.read
        def read(path, timeout):
            return [] if '/sealed-approvals/' in path else original(path, timeout)
        c.read = read
        with self.assertRaisesRegex(RuntimeError, 'approval'): m.run(c, ENTRY, Clock(), lambda: None)
        self.assertEqual(c.writes, [])

    def test_unknown_write_outcome_is_never_retried(self):
        m = self.module(); c = Client()
        def write(path, timeout):
            c.writes.append(path)
            raise RuntimeError('transport outcome unknown')
        c.write = write
        with self.assertRaisesRegex(RuntimeError, 'unknown'): m.run(c, ENTRY, Clock(), lambda: None)
        self.assertEqual(c.writes, [ENTRY+'/confirm'])

    def test_read_error_is_not_retried(self):
        m = self.module(); c = Client(); original = c.read
        def read(path, timeout):
            if '/sealed-approvals/' in path: raise RuntimeError('offline')
            return original(path, timeout)
        c.read = read
        with self.assertRaisesRegex(RuntimeError, 'offline'): m.run(c, ENTRY, Clock(), lambda: None)
        self.assertEqual(c.writes, [])

    def test_wait_is_monotonic_bounded_even_if_wall_clock_rolls_back(self):
        m = self.module(); c = Client(); original = c.read
        class RollbackClock(Clock):
            def wall_ms(self): return 1000
        clock = RollbackClock()
        def read(path, timeout):
            if '/sealed-approvals/' in path:
                return dict(wallet_id='main', approval_id=APPROVAL, state='AWAITING_CEREMONY')
            return original(path, timeout)
        c.read = read
        with self.assertRaisesRegex(RuntimeError, 'expired'): m.run(c, ENTRY, clock, lambda: None)
        self.assertEqual(c.writes, [])
        self.assertLessEqual(clock.t, 61000)

class CoreReviewTests(unittest.TestCase):
    module = Tests.module

    def main_with(self, module, state, client):
        import contextlib, io
        from unittest.mock import patch
        args = ['submit.py', '--bloom', '/unused/fake-bloom', '--connect',
                'unix:/isolated/nonexistent.sock', '--entry', ENTRY,
                '--state-dir', str(state), '--execute']
        with patch('sys.argv', args), patch.object(module, 'Client', return_value=client), \
                patch.object(module, 'Clock', return_value=Clock()), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return module.main()

    def test_fsync_failures_before_dispatch_retain_guard_and_never_write(self):
        import json, tempfile
        from unittest.mock import patch
        for failing_call in (1, 2, 3):
            with self.subTest(fsync=failing_call), tempfile.TemporaryDirectory() as temp:
                m = self.module(); c = Client(); calls = []
                def fsync(fd):
                    calls.append(fd)
                    if len(calls) == failing_call:
                        raise OSError('injected durability failure')
                with patch('os.fsync', side_effect=fsync):
                    if failing_call < 3:
                        with self.assertRaises(OSError): self.main_with(m, temp, c)
                    else:
                        self.assertEqual(self.main_with(m, temp, c), 2)
                self.assertEqual(len(calls), failing_call)
                self.assertEqual(c.writes, [])
                if failing_call < 3: self.assertEqual(c.reads, [])
                guards = list(Path(temp).glob('*.json'))
                self.assertEqual(len(guards), 1)
                self.assertEqual(json.loads(guards[0].read_text())['phase'],
                                 'confirm-dispatching' if failing_call == 3 else 'armed')
                untouched = Client()
                self.assertEqual(self.main_with(m, temp, untouched), 2)
                self.assertEqual(untouched.reads, [])
                self.assertEqual(untouched.writes, [])

    def test_durable_guard_order_permissions_and_post_send_failure(self):
        import json, os, stat, tempfile
        from unittest.mock import patch
        for fail_after_send in (False, True):
            with self.subTest(fail_after_send=fail_after_send), tempfile.TemporaryDirectory() as temp:
                m = self.module(); c = Client(); events = []; original = c.write
                state = Path(temp) / 'state'
                real_fsync = os.fsync
                def fsync(fd):
                    if stat.S_ISDIR(os.fstat(fd).st_mode): events.append('directory')
                    else:
                        events.append(json.loads(next(state.glob('*.json')).read_text())['phase'])
                    if fail_after_send and events[-1] == 'sent-observed':
                        raise OSError('post-send durability failure')
                    real_fsync(fd)
                def write(path, timeout):
                    events.append('write')
                    original(path, timeout)
                c.write = write
                with patch('os.fsync', side_effect=fsync):
                    self.assertEqual(self.main_with(m, state, c), 2 if fail_after_send else 0)
                self.assertEqual(events, ['armed', 'directory', 'confirm-dispatching', 'write', 'sent-observed'])
                self.assertEqual(c.writes, [ENTRY + '/confirm'])
                self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(next(state.glob('*.json')).stat().st_mode), 0o600)
                untouched = Client()
                self.assertEqual(self.main_with(m, state, untouched), 2)
                self.assertEqual(untouched.reads, [])

    def test_invalid_exact_entries_never_contact_client(self):
        m = self.module()
        entries = ['', '/' + ENTRY, ENTRY + '/', ENTRY + '\n', ENTRY + '/confirm',
                   ENTRY.replace('/0/', '/00/'), ENTRY.replace('/0/', '/-1/'),
                   ENTRY.replace('/0/', '/latest/'), ENTRY.replace('solana-mainnet', 'ethereum'),
                   ENTRY.replace('0001-test', '..'), ENTRY.replace('0001-test', '*'),
                   ENTRY.replace('0001-test', 'a/b'), ENTRY.replace('/pending/', '/sent/')]
        for entry in entries:
            with self.subTest(entry=entry):
                c = Client()
                with self.assertRaisesRegex(RuntimeError, 'exact'): m.run(c, entry, Clock(), lambda: self.fail('guard called'))
                self.assertEqual(c.reads, [])
                self.assertEqual(c.writes, [])

    def test_all_challenge_identity_fields_and_types_fail_closed(self):
        m = self.module()
        changes = [dict(chain='solana-other'), dict(action_id='different'),
                   dict(retry_path=ENTRY.replace('/0/', '/1/') + '/confirm'),
                   dict(approval_id='A' * 64), dict(approval_id='a' * 63),
                   dict(approval_id='a' * 65), dict(approval_id=1),
                   dict(expiry_ms=True), dict(expiry_ms=61000.0), dict(expiry_ms=None),
                   dict(expiry_ms=0), dict(expiry_ms=-1)]
        for changed in changes:
            with self.subTest(changed=changed):
                c = Client(); original = c.read
                def read(path, timeout):
                    value = original(path, timeout)
                    value.update(changed)
                    return value
                c.read = read
                with self.assertRaisesRegex(RuntimeError, 'challenge'): m.run(c, ENTRY, Clock(), lambda: self.fail('guard called'))
                self.assertEqual(c.reads, [ENTRY + '/approval_challenge.json'])
                self.assertEqual(c.writes, [])

    def test_all_sent_identity_fields_fail_after_only_one_write(self):
        m = self.module()
        for changed in [dict(id='other'), dict(wallet='other'), dict(chain='other'), dict(status='pending'), None, []]:
            with self.subTest(changed=changed):
                c = Client(); original = c.read
                def read(path, timeout):
                    value = original(path, timeout)
                    if '/sent/' in path:
                        if not isinstance(changed, dict): return changed
                        value.update(changed)
                    return value
                c.read = read
                with self.assertRaisesRegex(RuntimeError, 'sent'): m.run(c, ENTRY, Clock(), lambda: None)
                self.assertEqual(c.writes, [ENTRY + '/confirm'])

    def test_forward_wall_jump_stops_before_guard(self):
        m = self.module(); c = Client(); original = c.read
        class IndependentClock(Clock):
            wall = 1000
            def wall_ms(self): return self.wall
        clock = IndependentClock(); c.states = ['ACTIVE']
        def read(path, timeout):
            value = original(path, timeout)
            if '/sealed-approvals/' in path: clock.wall = 61000
            return value
        c.read = read
        with self.assertRaisesRegex(RuntimeError, 'expired'): m.run(c, ENTRY, clock, lambda: self.fail('guard called'))
        self.assertEqual(clock.monotonic(), 1)
        self.assertEqual(c.writes, [])

    def test_expired_challenge_never_polls(self):
        m = self.module()
        for expiry in (999, 1000):
            with self.subTest(expiry=expiry):
                c = Client(); original = c.read
                def read(path, timeout):
                    value = original(path, timeout); value['expiry_ms'] = expiry
                    return value
                c.read = read
                with self.assertRaisesRegex(RuntimeError, 'expired'): m.run(c, ENTRY, Clock(), lambda: self.fail('guard called'))
                self.assertEqual(c.reads, [ENTRY + '/approval_challenge.json'])
                self.assertEqual(c.writes, [])

    def test_read_timeout_budget_shrinks_and_write_budget_stays_twenty(self):
        m = self.module(); c = Client(); original = c.read; clock = Clock(); budgets = []
        def read(path, timeout):
            budgets.append((path, timeout))
            value = original(path, timeout)
            if path.endswith('approval_challenge.json'): value['expiry_ms'] = 1750
            return value
        c.read = read; writes = []
        c.write = lambda path, timeout: writes.append((path, timeout))
        m.run(c, ENTRY, clock, lambda: None)
        self.assertEqual([t for _, t in budgets], [3, .75, .5, 3])
        self.assertEqual(writes, [(ENTRY + '/confirm', 20)])

    def test_terminal_and_wrong_case_states_never_dispatch(self):
        m = self.module()
        for state in ('active', 'prepared', 'CANCELLED', 'REVOKED', 'DENIED', 'CONSUMED', '', None, True, []):
            with self.subTest(state=state):
                c = Client(); c.states = [state]
                with self.assertRaisesRegex(RuntimeError, 'approval'): m.run(c, ENTRY, Clock(), lambda: self.fail('guard called'))
                self.assertEqual(c.writes, [])

    def test_monotonic_cap_is_independent_of_far_future_wall_expiry(self):
        m = self.module(); c = Client(); original = c.read; guards = []
        class IndependentClock(Clock):
            def wall_ms(self): return 1000
        clock = IndependentClock(); c.states = ['ACTIVE']
        def read(path, timeout):
            value = original(path, timeout)
            if path.endswith('approval_challenge.json'): value['expiry_ms'] = 601000
            elif '/sealed-approvals/' in path: clock.t = 61000
            return value
        c.read = read
        with self.assertRaisesRegex(RuntimeError, 'bounded wait'): m.run(c, ENTRY, clock, lambda: guards.append(True))
        self.assertEqual(guards, [])
        self.assertEqual(c.writes, [])

    def test_successful_slow_write_after_dispatch_does_not_trigger_retry(self):
        m = self.module(); c = Client(); original = c.write; clock = Clock()
        c.states = ['ACTIVE']
        def write(path, timeout):
            original(path, timeout)
            clock.t = 62000
        c.write = write
        self.assertEqual(m.run(c, ENTRY, clock, lambda: None), 'sent (not proof of confirmation)')
        self.assertEqual(c.writes, [ENTRY + '/confirm'])
        self.assertEqual(c.reads[-1], ENTRY.replace('/outbox/pending/', '/outbox/sent/') + '/intent.json')

    def test_missing_challenge_fields_and_nonobjects_never_poll(self):
        m = self.module(); template = Client().read(ENTRY + '/approval_challenge.json', 3)
        values = [None, [], 'ACTIVE'] + [{k: v for k, v in template.items() if k != missing} for missing in template]
        for value in values:
            with self.subTest(value=value):
                c = Client(); reads = []
                def read(path, timeout): reads.append(path); return value
                c.read = read
                with self.assertRaisesRegex(RuntimeError, 'challenge'): m.run(c, ENTRY, Clock(), lambda: self.fail('guard called'))
                self.assertEqual(reads, [ENTRY + '/approval_challenge.json'])
                self.assertEqual(c.writes, [])

    def test_wallet_named_pending_preserves_exact_sent_path(self):
        m = self.module(); c = Client(); c.states = ['ACTIVE']
        entry = ENTRY.replace('wallets/main/', 'wallets/pending/')
        original = c.read
        def read(path, timeout):
            value = original(path, timeout)
            if path.endswith('approval_challenge.json'):
                value.update(wallet='pending', retry_path=entry + '/confirm')
            elif '/sealed-approvals/' in path:
                value['wallet_id'] = 'pending'
            else:
                value['wallet'] = 'pending'
            return value
        c.read = read
        self.assertEqual(m.run(c, entry, Clock(), lambda: None), 'sent (not proof of confirmation)')
        self.assertEqual(c.writes, [entry + '/confirm'])
        self.assertEqual(c.reads[-1], 'wallets/pending/0/chains/solana-mainnet/outbox/sent/0001-test/intent.json')


class SubprocessReviewTests(unittest.TestCase):
    module = Tests.module
    main_with = CoreReviewTests.main_with

    def setUp(self):
        import tempfile
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fake = self.root / 'fake-bloom'
        self.log = self.root / 'calls'
        self.fake.write_text('''#!/usr/bin/env python3
import json, sys, time
from pathlib import Path
root = Path(__file__).parent
args = sys.argv[1:]
operation, path = args[-2:]
stdin = sys.stdin.read()
with (root / 'calls').open('a') as f:
    f.write(json.dumps(dict(args=args, stdin=stdin)) + '\\n')
entry = 'wallets/main/0/chains/solana-mainnet/outbox/pending/0001-test'
assert args[:3] == ['--connect', 'unix:/isolated/nonexistent.sock', 'vfs']
assert stdin == ('y\\n' if operation == 'write' else '')
phase = ('write' if operation == 'write' else
         'challenge' if path.endswith('approval_challenge.json') else
         'status' if '/sealed-approvals/' in path else 'sent')
mode = (root / 'mode').read_text()
if mode == 'gate' and phase == 'challenge':
    (root / 'ready').touch()
    deadline = time.monotonic() + 15
    while not (root / 'release').exists():
        if time.monotonic() > deadline: raise SystemExit(90)
        time.sleep(.01)
if mode == phase + '-timeout': time.sleep(10)
if mode == phase + '-failure':
    print('SECRET-CEREMONY-CAPABILITY', file=sys.stderr)
    print('SECRET-CEREMONY-CAPABILITY')
    raise SystemExit(7)
if mode == phase + '-malformed':
    print('not json: SECRET-CEREMONY-CAPABILITY')
    raise SystemExit(0)
if phase == 'challenge':
    value = dict(schema='bloom.solana-approval-challenge/1', wallet='main', chain='solana-mainnet', tx_id='0001-test', action_id='0001-test', approval_id='a'*64, expiry_ms=int(time.time()*1000)+60000, retry_path=entry+'/confirm')
elif phase == 'status':
    value = dict(wallet_id='main', approval_id='a'*64, state='ACTIVE')
elif phase == 'sent':
    assert path == entry.replace('/outbox/pending/', '/outbox/sent/') + '/intent.json'
    value = dict(id='0001-test', wallet='main', chain='solana-mainnet', status='sent')
else:
    assert path == entry + '/confirm'
    value = {}
print(json.dumps(value))
''')
        self.fake.chmod(0o700)
        (self.root / 'mode').write_text('success')

    def calls(self):
        import json
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_concurrent_processes_only_one_guard_owner_contacts_transport(self):
        import json, subprocess, sys, time
        (self.root / 'mode').write_text('gate')
        args = [sys.executable, str(Path(__file__).with_name('submit.py')),
                '--bloom', str(self.fake), '--connect', 'unix:/isolated/nonexistent.sock',
                '--entry', ENTRY, '--state-dir', str(self.root / 'state'), '--execute']
        processes = []
        try:
            for _ in range(8):
                processes.append(subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if sum(p.poll() is not None for p in processes) == 7 and (self.root / 'ready').exists(): break
                time.sleep(.01)
            self.assertEqual(sum(p.poll() is not None for p in processes), 7, 'losers must refuse while winner is blocked')
            self.assertEqual(len(self.calls()), 1)
            (self.root / 'release').touch()
            outputs = [p.communicate(timeout=10) for p in processes]
            self.assertEqual(sorted(p.returncode for p in processes), [0] + [2] * 7)
            self.assertEqual(sum('REFUSED' in stderr for _, stderr in outputs), 7)
            calls = self.calls()
            self.assertEqual([call['args'][-2] for call in calls], ['cat', 'cat', 'write', 'cat'])
            self.assertEqual([call['stdin'] for call in calls], ['', '', 'y\n', ''])
            guards = list((self.root / 'state').glob('*.json'))
            self.assertEqual(len(guards), 1)
            self.assertEqual(json.loads(guards[0].read_text())['phase'], 'sent-observed')
            restart = subprocess.run(args, capture_output=True, text=True, timeout=10)
            self.assertEqual(restart.returncode, 2)
            self.assertEqual(self.calls(), calls)
        finally:
            (self.root / 'release').touch()
            for process in processes:
                if process.poll() is None: process.kill()
                process.communicate(timeout=10)

    def test_real_slow_failing_and_malformed_transport_never_retries(self):
        m = self.module()
        class ShortTimeoutClient(m.Client):
            def invoke(self, operation, path, timeout):
                return super().invoke(operation, path, min(timeout, 1))
        for phase in ('challenge', 'status', 'write', 'sent'):
            for failure in ('timeout', 'failure', 'malformed'):
                if phase == 'write' and failure == 'malformed': continue  # write stdout is intentionally ignored
                mode = phase + '-' + failure
                with self.subTest(mode=mode):
                    (self.root / 'mode').write_text(mode)
                    if self.log.exists(): self.log.unlink()
                    state = self.root / mode
                    client = ShortTimeoutClient(str(self.fake), 'unix:/isolated/nonexistent.sock')
                    self.assertEqual(self.main_with(m, state, client), 2)
                    calls = self.calls()
                    operations = [call['args'][-2] for call in calls]
                    self.assertEqual(operations.count('write'), int(phase in ('write', 'sent')))
                    expected = {'challenge': ['cat'], 'status': ['cat', 'cat'],
                                'write': ['cat', 'cat', 'write'], 'sent': ['cat', 'cat', 'write', 'cat']}
                    self.assertEqual(operations, expected[phase])
                    self.assertEqual(self.main_with(m, state, client), 2)
                    self.assertEqual(self.calls(), calls)

    def test_transport_errors_do_not_echo_subprocess_secrets(self):
        m = self.module(); client = m.Client(str(self.fake), 'unix:/isolated/nonexistent.sock')
        (self.root / 'mode').write_text('write-failure')
        with self.assertRaisesRegex(RuntimeError, 'exit 7') as caught:
            client.write(ENTRY + '/confirm', 1)
        self.assertNotIn('SECRET', str(caught.exception))
        self.assertEqual(len(self.calls()), 1)

    def test_missing_executable_is_a_non_retrying_transport_failure(self):
        m = self.module(); client = m.Client(str(self.root / 'missing'), 'unix:/isolated/nonexistent.sock')
        with self.assertRaisesRegex(RuntimeError, 'transport failed; no retry'):
            client.read(ENTRY + '/approval_challenge.json', .3)
        self.assertEqual(self.calls(), [])


if __name__ == '__main__': unittest.main()
