"""Focused address-switch regressions. No interfaces or services are modified."""
import importlib.machinery
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / 'firmware/oec/rootfs/usr/local/libexec/ty-gateway-network'
sys.path.insert(0, str(HELPER.parent))
module = importlib.machinery.SourceFileLoader('ty_address_readiness', str(HELPER)).load_module()
UUID = '2bc8ca16-6edf-4e78-8051-980376dca258'
OLD = '61169f72-a028-326d-b1d1-c1392fe0411a'


class Clock:
    def __init__(self):
        self.now = 0

    def sleep(self, seconds):
        self.now += seconds


class Tests(unittest.TestCase):
    def setUp(self):
        self.nm = module.NetworkManager('eth0')
        self.tx = {'candidate': 'ty-local-test', 'candidate_uuid': UUID,
                   'address_cidr': '192.168.0.9/24', 'deadline': 1180}
        self.clock = Clock()
        self.fields = []
        self.time_patch = patch.object(module.time, 'time', return_value=1000)
        self.monotonic_patch = patch.object(module.time, 'monotonic', side_effect=lambda: self.clock.now)
        self.sleep_patch = patch.object(module.time, 'sleep', side_effect=self.clock.sleep)
        for item in (self.time_patch, self.monotonic_patch, self.sleep_patch):
            item.start()
            self.addCleanup(item.stop)

    def reader(self, snapshots):
        count = 0

        def read(*args, timeout=25):
            nonlocal count
            self.fields.append(args[1])
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 3)
            row = snapshots[min(count // 3, len(snapshots) - 1)]
            value = (row['before'], row['addresses'], row.get('after', row['before']))[count % 3]
            self.assertEqual(args[1], ('GENERAL.CON-UUID', 'IP4.ADDRESS', 'GENERAL.CON-UUID')[count % 3])
            count += 1
            return value
        self.nm.run = read

    def test_transient_old_snapshot_waits_then_accepts_uuid_and_ip(self):
        self.reader([{'before': OLD, 'addresses': '192.168.0.164/24'},
                     {'before': UUID, 'addresses': ''},
                     {'before': UUID, 'addresses': ' 192.168.0.9/24 \n'}])
        self.nm.verify_target(self.tx)
        self.assertEqual(self.clock.now, 0.5)
        self.assertNotIn('GENERAL.CONNECTION', self.fields)

    def test_extra_old_address_is_not_accepted(self):
        self.reader([{'before': UUID, 'addresses': '192.168.0.9/24\n192.168.0.164/24'}])
        with self.assertRaises(module.NetworkOperationError) as caught:
            self.nm.verify_target(self.tx, timeout=0.5)
        self.assertEqual(caught.exception.code, 'new_address_not_ready')
        self.assertEqual(caught.exception.details['addresses'], ['192.168.0.9/24', '192.168.0.164/24'])
        self.assertEqual(self.clock.now, 0.5)

    def test_correct_ip_on_other_connection_is_not_accepted(self):
        self.reader([{'before': OLD, 'addresses': '192.168.0.9/24'}])
        with self.assertRaises(module.NetworkOperationError):
            self.nm.verify_target(self.tx, timeout=0.5)

    def test_uuid_change_during_query_is_not_accepted(self):
        self.reader([{'before': UUID, 'after': OLD, 'addresses': '192.168.0.9/24'}])
        with self.assertRaises(module.NetworkOperationError):
            self.nm.verify_target(self.tx, timeout=0.5)

    def test_wrong_prefix_is_not_accepted(self):
        self.reader([{'before': UUID, 'addresses': '192.168.0.9/16'}])
        with self.assertRaises(module.NetworkOperationError):
            self.nm.verify_target(self.tx, timeout=0.5)

    def test_query_failure_keeps_safe_diagnostic(self):
        def fail(*args, **kwargs):
            raise module.NetworkOperationError('nmcli_failed', 'failed', {'exit_code': 2})
        self.nm.run = fail
        with self.assertRaises(module.NetworkOperationError) as caught:
            self.nm.verify_target(self.tx, timeout=0.5)
        self.assertEqual(caught.exception.details['read_error'], 'nmcli_failed')

    def test_no_wait_beyond_checkpoint_deadline(self):
        self.tx['deadline'] = 1000.5
        with patch.object(self.nm, 'run') as run:
            with self.assertRaises(module.NetworkOperationError):
                self.nm.verify_target(self.tx)
            run.assert_not_called()

    def test_prepare_captures_cloned_profile_uuid(self):
        calls = []
        tx = dict(self.tx, original=OLD, gateway='192.168.0.1', dns=['192.168.0.1'])
        tx.pop('candidate_uuid')
        def run(*args, **kwargs):
            calls.append(args)
            return UUID if args[0] == '-g' else ''
        self.nm.run = run
        self.nm.prepare(tx)
        self.assertEqual(tx['candidate_uuid'], UUID)
        self.nm.activate(tx)
        self.assertEqual(calls[-1][:4], ('connection', 'up', 'uuid', UUID))

    def test_nmcli_output_is_explicitly_machine_readable(self):
        with patch.object(module.subprocess, 'run') as run:
            run.return_value.returncode = 0
            run.return_value.stdout = '192.168.0.9/24\n'
            self.assertEqual(self.nm.run('-g', 'IP4.ADDRESS', 'device', 'show', 'eth0'), '192.168.0.9/24')
            argv = run.call_args.args[0]
            self.assertEqual(argv[1:5], ['--colors', 'no', '--escape', 'no'])

    def test_unknown_error_does_not_leak_exception_text(self):
        code, details = module.failure_details(RuntimeError('private-token-fixture'))
        self.assertEqual(code, 'network_operation_failed')
        self.assertNotIn('private-token-fixture', str(details))


if __name__ == '__main__':
    unittest.main(verbosity=2)
