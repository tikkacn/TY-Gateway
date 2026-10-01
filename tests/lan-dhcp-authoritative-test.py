"""Focused DHCP authority tests; no live sockets, services or network changes."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / 'firmware/oec/rootfs/usr/local/libexec/ty_gateway_lan.py'
spec = importlib.util.spec_from_file_location('lan_dhcp_test_module', SOURCE)
lan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lan)


class DHCPAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.settings = {
            'plan': {'address_cidr': '192.168.0.9/24', 'gateway': '192.168.0.1',
                     'dns_mode': 'router', 'dhcp_enabled': True,
                     'pool_start': '192.168.0.100', 'pool_end': '192.168.0.254'},
            'dns_enabled': True, 'reservations': [],
        }
        self.base = [
            'bind-interfaces', 'listen-address=192.168.0.9', 'except-interface=lo',
            'no-resolv', 'no-hosts', 'domain-needed', 'bogus-priv', 'filter-AAAA',
            'cache-size=1000', 'port=53', 'servers-file='+str(lan.DNS_SERVERS),
        ]
        self.dhcp = [
            'dhcp-range=192.168.0.100,192.168.0.254,255.255.255.0,12h',
            'dhcp-option=option:router,192.168.0.9',
            'dhcp-option=option:dns-server,192.168.0.9',
            'dhcp-leasefile='+str(lan.ROOT / 'dnsmasq.leases'),
        ]

    def test_enabled_adds_only_one_authority_directive(self):
        before = copy.deepcopy(self.settings)
        lines = lan.config_text(self.settings).splitlines()
        self.assertEqual(lines.count('dhcp-authoritative'), 1)
        self.assertEqual([x for x in lines if x != 'dhcp-authoritative'], self.base+self.dhcp)
        self.assertEqual(self.settings, before)

    def test_dns_only_config_is_unchanged(self):
        self.settings['plan']['dhcp_enabled'] = False
        self.assertEqual(lan.config_text(self.settings).splitlines(), self.base)

    def test_disabled_services_remain_disabled(self):
        self.settings['plan']['dhcp_enabled'] = False
        self.settings['dns_enabled'] = False
        expected = ['port=0' if x == 'port=53' else x for x in self.base]
        self.assertEqual(lan.config_text(self.settings).splitlines(), expected)

    def test_reservations_remain_unchanged(self):
        self.settings['reservations'] = [{'mac': '30:05:05:7c:72:61', 'ip': '192.168.0.50'}]
        lines = lan.config_text(self.settings).splitlines()
        self.assertEqual([x for x in lines if x != 'dhcp-authoritative'],
                         self.base+self.dhcp+['dhcp-host=30:05:05:7C:72:61,192.168.0.50,infinite'])

    def assert_apply_guard(self, confirmed):
        backend = Mock()
        backend.snapshot.return_value = {'original': 'existing', 'old_address': '192.168.0.9/24'}
        backend.run.side_effect = ['manual', '192.168.0.1']
        with patch.object(lan, 'interface_name', return_value='eth0'), \
             patch.object(lan, 'detect_other_dhcp', side_effect=ValueError('other DHCP server')) as probe, \
             patch.object(lan, 'atomic') as write, \
             patch.object(lan, 'run') as service, \
             patch.object(lan, 'recover') as recover:
            with self.assertRaises(ValueError):
                lan.apply(self.settings, confirmed, backend)
            write.assert_not_called()
            service.assert_not_called()
            recover.assert_not_called()
            if confirmed:
                probe.assert_called_once_with('192.168.0.9')
            else:
                probe.assert_not_called()

    def test_confirmation_still_required_before_any_mutation(self):
        self.assert_apply_guard(False)

    def test_other_dhcp_still_blocks_before_any_mutation(self):
        self.assert_apply_guard(True)


if __name__ == '__main__':
    unittest.main()
