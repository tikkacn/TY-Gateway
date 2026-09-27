"""Run on Linux: python3 network-helper-test.py PATH_TO_HELPER [--nm]

--nm creates only ty-net-test0 with a non-default 198.19.247.0/24 route.
It never modifies eth0. Test profiles and dummy device are cleaned up.
"""
import importlib.machinery
import ipaddress
import json
import os
import socket
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1]).resolve().parent))
module = importlib.machinery.SourceFileLoader('tynet', sys.argv[1]).load_module()
NM_TEST = '--nm' in sys.argv
PLAN = {'address_cidr':'198.19.247.20/24', 'gateway':'198.19.247.1'}

class Fake:
    def __init__(self): self.calls=[]; self.fail=False
    def snapshot(self): return dict(original='original',old_address='198.19.247.10/24',dns=['1.1.1.1'],priority=0)
    def probe(self,*args): self.calls.append('probe')
    def checkpoint(self,seconds): self.calls.append('checkpoint'); return '/checkpoint/1'
    def prepare(self,tx): self.calls.append('prepare')
    def activate(self,tx):
        self.calls.append('activate')
        if self.fail: raise RuntimeError('failure')
    def verify_target(self,tx): self.calls.append('verify')
    def commit(self,tx): self.calls.append('commit')
    def restore(self,tx): self.calls.append('restore')

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.fake=Fake(); self.scheduled=[]
        self.original_lan_status=module.lan.status
        module.lan.status=lambda:{'dhcp_active':False,'lan_dns_active':False}
        self.c=module.Controller(self.fake,Path(self.temp.name)/'state.json',schedule=lambda *x:self.scheduled.append(x))
    def tearDown(self):
        module.lan.status=self.original_lan_status
        self.temp.cleanup()
    def test_default_route_interface_uses_lowest_metric(self):
        routes=('Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n'
                'end0 00000000 012A170A 0003 0 0 100 00000000 0 0 0\n'
                'enP2s0 00000000 012B170A 0003 0 0 50 00000000 0 0 0\n')
        self.assertEqual(module.lan.parse_default_route_interface(routes),'enP2s0')
    def test_default_route_interface_ignores_invalid_rows(self):
        routes=('Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n'
                'lo 00000000 0100007F 0003 0 0 1 00000000 0 0 0\n'
                'end0 00000000 012A170A 0002 0 0 2 00000000 0 0 0\n'
                'enP2s0 00000000 invalid 0003 0 0 3 00000000 0 0 0\n')
        self.assertEqual(module.lan.parse_default_route_interface(routes),'')
    def start(self):
        self.c.start(PLAN); self.c.activate(self.c.tx['candidate'])
    @unittest.skipUnless(os.name == 'posix', 'directory fsync behavior is Linux/POSIX specific')
    def test_commit_requires_new_ip(self):
        self.start()
        with self.assertRaises(ValueError): self.c.handle({'action':'confirm','local_ip':'198.19.247.10'})
        self.c.handle({'action':'confirm','local_ip':'198.19.247.20'})
        self.c.expire(self.c.tx['candidate'])
        self.assertEqual(self.c.tx['phase'],'committed'); self.assertNotIn('restore',self.fake.calls)
    @unittest.skipUnless(os.name == 'posix', 'directory fsync behavior is Linux/POSIX specific')
    def test_timeout_and_reentry(self):
        self.start()
        with self.assertRaises(ValueError): self.c.start(PLAN)
        self.c.expire(self.c.tx['candidate']); self.assertEqual(self.c.tx['phase'],'rolled_back')
    @unittest.skipUnless(os.name == 'posix', 'directory fsync behavior is Linux/POSIX specific')
    def test_crash_recovery(self):
        self.start()
        recovered=module.Controller(self.fake,self.c.path)
        self.assertEqual(recovered.tx['phase'],'rolled_back')
    @unittest.skipUnless(os.name == 'posix', 'directory fsync behavior is Linux/POSIX specific')
    def test_activate_failure(self):
        self.fake.fail=True; self.start(); self.assertEqual(self.c.tx['phase'],'rolled_back')
    def test_validation_before_mutation(self):
        for address in ['127.0.0.1/24','198.19.247.0/24','198.19.247.255/24','198.19.247.20/32','198.19.248.20/24']:
            with self.assertRaises(ValueError): self.c.start(dict(PLAN,address_cidr=address))
        self.assertNotIn('checkpoint',self.fake.calls)
    def test_arp(self):
        ours=b'123456'; other=b'abcdef'; target=socket.inet_aton('198.19.247.20')
        frame=b'\xff'*6+other+b'\x08\x06'+struct.pack('!HHBBH',1,0x0800,6,4,2)+other+target+ours+b'\0'*4
        self.assertTrue(module.arp_conflict(frame,ours,target))
        self.assertFalse(module.arp_conflict(frame,other,target))
        self.assertFalse(module.arp_conflict(frame[:20],ours,target))

def integration():
    nm=module.NetworkManager('ty-net-test0'); original_name='ty-net-test-original'; candidates=[]
    # Refuse to touch an existing interface or profile with the test names.
    if Path('/sys/class/net/ty-net-test0').exists() or original_name in nm.run('-g','NAME','connection','show').splitlines():
        raise RuntimeError('test interface/profile already exists; refusing')
    with tempfile.TemporaryDirectory(prefix='ty-net-test-') as temp:
        try:
            nm.run('connection','add','type','dummy','ifname','ty-net-test0','con-name',original_name,
                   'connection.autoconnect','no','ipv4.method','manual','ipv4.addresses','198.19.247.10/24',
                   'ipv4.never-default','yes','ipv6.method','disabled')
            nm.run('connection','up','id',original_name)
            c=module.Controller(nm,Path(temp)/'state.json',timeout=15,delay=0,schedule=lambda *x:None)
            c.start(PLAN); candidates.append(c.tx['candidate']); c.activate(c.tx['candidate'])
            assert c.tx['phase']=='awaiting_login', c.status()
            assert nm.run('-g','IP4.ADDRESS','device','show',nm.interface)=='198.19.247.20/24'
            # Do not call helper expire: validate NetworkManager's independent rollback.
            end=time.time()+22
            while time.time()<end:
                if nm.run('-g','IP4.ADDRESS','device','show',nm.interface)=='198.19.247.10/24': break
                time.sleep(1)
            assert nm.run('-g','IP4.ADDRESS','device','show',nm.interface)=='198.19.247.10/24'
            c.expire(c.tx['candidate']); assert c.tx['phase']=='rolled_back'
            c.timeout=90
            c.start(PLAN); candidates.append(c.tx['candidate']); c.activate(c.tx['candidate'])
            assert c.tx['phase']=='awaiting_login', c.status()
            c.handle({'action':'confirm','local_ip':'198.19.247.20'})
            assert c.tx['phase']=='committed', c.status()
            assert nm.run('-g','connection.autoconnect','connection','show','id',c.tx['candidate'])=='yes'
            # Reload disk profiles and reactivate candidate to test persistence.
            nm.run('connection','reload')
            nm.run('connection','up','id',c.tx['candidate'])
            nm.verify_target(c.tx)
            print('PASS actual NM: temporary clone, single new address, independent rollback, confirmed persistence')
        finally:
            for candidate in candidates+[original_name]:
                try: nm.run('connection','delete','id',candidate)
                except Exception: pass
            try: nm.run('device','delete','ty-net-test0')
            except Exception: pass

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    if not result.wasSuccessful(): sys.exit(1)
    if NM_TEST: integration()
