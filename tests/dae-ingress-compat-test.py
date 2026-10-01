"""Focused compatibility checks; mocks only, no live process/network changes."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'firmware/oec/rootfs/usr/local/libexec/ty_gateway_dae_compat.py'
spec = importlib.util.spec_from_file_location('dae_compat', SOURCE)
compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compat)


class FakeSocket:
    def __init__(self, flag=1, fail=False):
        self.flag, self.fail = flag, fail

    def getsockopt(self, level, option):
        return self.flag

    def setsockopt(self, level, option, value):
        if self.fail:
            raise OSError('test write failure')
        self.flag = value


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        # Windows has no SO_REUSEPORT, but these tests never open real sockets.
        reuseport = patch.object(compat.socket, 'SO_REUSEPORT', 15, create=True)
        reuseport.start()
        self.addCleanup(reuseport.stop)

    def test_kernel_boundary(self):
        for version in ('5.15.0', '6.1.157-rk35xx-ophub', '6.5.13'):
            self.assertTrue(compat.needs_compatibility(version), version)
        for version in ('6.6.25-spring-plowing', '6.12.0', '6.18.1', '7.0.0'):
            self.assertFalse(compat.needs_compatibility(version), version)
        with self.assertRaises(compat.CompatibilityError):
            compat.needs_compatibility('unknown')

    def test_modern_kernel_never_inspects_other_process(self):
        with patch.object(compat.platform, 'release', return_value='6.12.1'), \
                patch.object(compat, 'ingress_sockets') as inspect:
            self.assertIn('skipped', compat.apply(123))
            inspect.assert_not_called()

    def test_requires_complete_triplet(self):
        candidates = {1: ('tcp4', 12345, FakeSocket()), 2: ('tcp6', 12345, FakeSocket()),
                      3: ('udp', 12345, FakeSocket()), 4: ('udp', 5353, FakeSocket())}
        self.assertEqual(set(compat.choose_listeners(candidates)), compat.EXPECTED_ROLES)
        del candidates[3]
        with self.assertRaises(compat.ListenersNotReady):
            compat.choose_listeners(candidates)

    def test_ambiguous_listeners_refused(self):
        candidates = {1: ('tcp4', 12345, FakeSocket()), 2: ('tcp6', 12345, FakeSocket()),
                      3: ('udp', 12345, FakeSocket()), 4: ('tcp4', 12345, FakeSocket())}
        with self.assertRaises(compat.CompatibilityError):
            compat.choose_listeners(candidates)
        self.assertTrue(all(item[2].flag == 1 for item in candidates.values()))

    def test_repair_idempotent(self):
        sockets = {role: FakeSocket() for role in compat.EXPECTED_ROLES}
        self.assertEqual(compat.fix_listeners(sockets), 3)
        self.assertEqual(compat.fix_listeners(sockets), 0)
        self.assertEqual(compat.fix_listeners(sockets, check_only=True), 0)

    def test_check_is_read_only(self):
        sock = FakeSocket()
        with self.assertRaises(compat.CompatibilityError):
            compat.fix_listeners({'tcp4': sock}, check_only=True)
        self.assertEqual(sock.flag, 1)

    def test_failed_adjustment_restores_previous_flags(self):
        sockets = {'tcp4': FakeSocket(), 'tcp6': FakeSocket(fail=True), 'udp': FakeSocket()}
        with self.assertRaises(OSError):
            compat.fix_listeners(sockets)
        self.assertTrue(all(sock.flag == 1 for sock in sockets.values()))

    def test_unrelated_process_refused(self):
        with patch.object(compat.os.path, 'samefile', return_value=False):
            with self.assertRaises(compat.CompatibilityError):
                compat.verify_process(123)

    def test_installer_and_both_builders_include_helper(self):
        relative = 'usr/local/libexec/ty_gateway_dae_compat.py'
        for script in ('install-oec-overlay.sh', 'restore-oec-overlay.sh',
                       'build-oec-overlay.sh', 'build-oec-overlay.ps1', 'ty-release-publish.py'):
            text = (ROOT / 'scripts' / script).read_text().replace('\\', '/')
            self.assertIn(relative, text, script)
        unit = (ROOT / 'firmware/oec/rootfs/etc/systemd/system/dae.service.d/ty-gateway-forwarding.conf').read_text()
        command = '/usr/bin/python3 /usr/local/libexec/ty_gateway_dae_compat.py $MAINPID'
        self.assertIn('ExecStartPost=' + command, unit)
        self.assertIn('ExecReload=' + command, unit)


if __name__ == '__main__':
    unittest.main()
