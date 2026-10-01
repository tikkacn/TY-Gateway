"""Focused DNS handoff tests: temporary files and mocks, no live networking."""
import contextlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'firmware/oec/rootfs/usr/local/libexec/ty_gateway_lan.py'
spec = importlib.util.spec_from_file_location('lan_dns_test_module', SOURCE)
lan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lan)


class DNSHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        for name, filename in [('CONFIG', 'lan.conf'), ('SETTINGS', 'settings.json'),
                               ('DNS_SERVERS', 'upstream.conf'), ('DNS_PENDING', 'pending'),
                               ('DAE_MANAGED', 'managed.dae')]:
            p = patch.object(lan, name, root / filename)
            p.start(); self.addCleanup(p.stop)
        self.settings = {'plan': {'address_cidr': '192.168.0.9/24', 'gateway': '192.168.0.1',
                                 'dns_mode': 'router', 'dhcp_enabled': True,
                                 'pool_start': '192.168.0.100', 'pool_end': '192.168.0.254'},
                         'dns_enabled': True, 'reservations': []}
        lan.SETTINGS.write_text(json.dumps(self.settings))
        lan.CONFIG.write_text(lan.config_text(self.settings))
        lan.DAE_MANAGED.write_text('# proxy_enabled: true\n')
        self.calls = []
        for name, value in [('dns_service_active', lambda unit: True),
                            ('dae_dns_ready', lambda address: True),
                            ('dns_lock', contextlib.nullcontext),
                            ('atomic', lambda path, text: path.write_text(text)),
                            ('run', lambda *args: self.calls.append(args))]:
            p = patch.object(lan, name, value)
            p.start(); self.addCleanup(p.stop)

    def test_enabled_healthy_uses_only_dae(self):
        self.assertTrue(lan.refresh_dns())
        self.assertEqual(lan.DNS_SERVERS.read_text(), 'server=192.168.0.9#5353\n')
        self.assertEqual(self.calls[0], ('/usr/bin/systemctl', 'kill', '--signal=HUP',
                                        '--kill-whom=main', lan.UNIT))
        self.assertFalse(lan.DNS_PENDING.exists())

    def test_off_stopped_or_unresponsive_keeps_direct(self):
        cases = [('off', '# proxy_enabled: false\n', True, True),
                 ('stopped', '# proxy_enabled: true\n', False, True),
                 ('dns_failed', '# proxy_enabled: true\n', True, False)]
        for name, content, active, ready in cases:
            with self.subTest(name=name):
                lan.DAE_MANAGED.write_text(content)
                with patch.object(lan, 'dns_service_active', lambda unit: active if unit == 'dae.service' else True), \
                     patch.object(lan, 'dae_dns_ready', lambda address: ready):
                    lan.refresh_dns()
                self.assertEqual(lan.DNS_SERVERS.read_text(), 'server=192.168.0.1\n')

    def test_stop_hook_does_not_probe_or_wait_for_proxy(self):
        with patch.object(lan, 'dae_dns_ready') as probe:
            lan.refresh_dns(force_direct=True)
            probe.assert_not_called()
        self.assertEqual(lan.DNS_SERVERS.read_text(), 'server=192.168.0.1\n')

    def test_custom_direct_dns_preserved(self):
        self.settings['plan'].update(dns_mode='custom', dns_servers=['8.8.8.8', '1.1.1.1'])
        lan.SETTINGS.write_text(json.dumps(self.settings))
        before = lan.SETTINGS.read_text()
        lan.refresh_dns(force_direct=True)
        self.assertEqual(lan.DNS_SERVERS.read_text(), 'server=8.8.8.8\nserver=1.1.1.1\n')
        self.assertEqual(lan.SETTINGS.read_text(), before)

    def test_prepare_migrates_upstreams_only(self):
        old = lan.CONFIG.read_text().replace('servers-file='+str(lan.DNS_SERVERS), 'server=192.168.0.1')
        lan.CONFIG.write_text(old)
        lan.refresh_dns(preparing=True)
        preserved = [x for x in old.splitlines() if not x.startswith('server=')]
        actual = [x for x in lan.CONFIG.read_text().splitlines() if not x.startswith('servers-file=')]
        self.assertEqual(actual, preserved)
        self.assertEqual(self.calls, [])

    def test_old_live_config_not_silently_changed_without_restart(self):
        old = 'listen-address=192.168.0.9\nserver=192.168.0.1\n'
        lan.CONFIG.write_text(old)
        self.assertFalse(lan.refresh_dns())
        self.assertEqual(lan.CONFIG.read_text(), old)
        self.assertFalse(lan.DNS_SERVERS.exists())

    def test_unchanged_avoids_signals_and_dhcp_restart(self):
        lan.refresh_dns()
        self.calls.clear()
        self.assertFalse(lan.refresh_dns())
        self.assertEqual(self.calls, [])

    def test_signal_failure_is_retried_without_removing_upstream(self):
        with patch.object(lan, 'run', side_effect=RuntimeError('signal failed')):
            with self.assertRaises(RuntimeError):
                lan.refresh_dns()
        self.assertTrue(lan.DNS_PENDING.exists())
        self.assertTrue(lan.DNS_SERVERS.exists())
        self.calls.clear()
        lan.refresh_dns()
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(lan.DNS_PENDING.exists())

    def test_concurrent_save_wins(self):
        def changed(settings, force_direct):
            self.settings['plan'].update(dns_mode='custom', dns_servers=['8.8.8.8'])
            lan.SETTINGS.write_text(json.dumps(self.settings))
            return 'server=192.168.0.9#5353\n'
        with patch.object(lan, 'dns_upstreams', changed):
            self.assertFalse(lan.refresh_dns())
        self.assertFalse(lan.DNS_SERVERS.exists())
        self.assertEqual(self.calls, [])

    def test_disabled_lan_not_started_by_watcher(self):
        with patch.object(lan, 'dns_service_active', lambda unit: False):
            self.assertFalse(lan.refresh_dns())
        self.assertEqual(self.calls, [])

    def test_software_rollback_materializes_current_direct_dns_only(self):
        self.settings['plan'].update(dns_mode='custom', dns_servers=['8.8.8.8', '1.1.1.1'])
        lan.SETTINGS.write_text(json.dumps(self.settings))
        before = lan.SETTINGS.read_text()
        lan.refresh_dns()
        self.assertTrue(lan.legacy_dns_config())
        self.assertNotIn('servers-file=', lan.CONFIG.read_text())
        self.assertIn('server=8.8.8.8\nserver=1.1.1.1\n', lan.CONFIG.read_text())
        self.assertIn('dhcp-option=option:router,192.168.0.9', lan.CONFIG.read_text())
        self.assertEqual(lan.SETTINGS.read_text(), before)
        self.assertFalse(lan.refresh_dns())


if __name__ == '__main__':
    unittest.main()
