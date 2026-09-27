import importlib.util
import pathlib
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('updater',pathlib.Path(__file__).with_name('rule-updater.py'))
u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u)
class RuleUpdaterTests(unittest.TestCase):
    def full_groups(self):
        return [(c, 'DIRECT' if c=='China' else 'PROXY', [('domain_suffix', c.lower()+'.example')]) for c in u.CATEGORIES[:-1]]
    def test_broker_source_is_required_and_precedes_china(self):
        db={key:[('domain_suffix',key+'.example')] for keys in u.CATEGORY_SOURCES.values() for key in keys}
        db['cn']=[('domain_suffix','cn.example')]
        def fetch(url):
            if url==u.BROKER_SOURCE:return b'DOMAIN-SUFFIX,futunn.com\nIP-CIDR,192.0.2.0/24,no-resolve'
            if url.endswith('cn.txt'):return b'192.0.2.0/24'
            return b'fake-geosite'
        with patch.object(u,'fetch',side_effect=fetch),patch.object(u,'geosite',return_value=db):
            p=u.build('managed_loyal')
        self.assertEqual(p['categories'],u.CATEGORIES)
        self.assertEqual(p['counts']['HK-Broker'],2)
        self.assertEqual(p['sources'][0]['url'],u.BROKER_SOURCE)
        broker=next(r for r in p['rules'] if r['category']=='HK-Broker')
        china=next(r for r in p['rules'] if r['category']=='China')
        self.assertLess(broker['priority'],china['priority'])
        with patch.object(u,'fetch',return_value=b''):
            with self.assertRaisesRegex(ValueError,'empty HK-Broker'):u.build('managed_meta')
    def test_compatible_asn_is_explicit_and_audited(self):
        skipped={}
        self.assertEqual(u.parse_list(b'DOMAIN,example.com\nIP-ASN,1234,no-resolve','clash',skipped), [('domain','example.com')])
        self.assertEqual(skipped,{'IP-ASN':1})
        for text in (b'IP-ASN,0',b'IP-ASN,4294967296',b'IP-ASN,1234,PROXY',b'PROCESS-NAME,test'):
            with self.assertRaises(ValueError):u.parse_list(text,'clash',{})
    def test_black_removed(self):
        self.assertNotIn('managed_black',u.NAMES)
        with self.assertRaises(ValueError):u.build('managed_black')
    def test_unknown_directive_rejected(self):
        with self.assertRaises(ValueError): u.parse_list(b'DOMAIN,example.com\nIP-ASN,1234','clash')
    def test_ipv4_policy_explicit(self):
        self.assertEqual(u.parse_list(b'10.0.0.0/8\n2001:db8::/32','cidr'),[('cidr','10.0.0.0/8')])
    def test_version_and_categories(self):
        groups=self.full_groups()
        a=u.pack('managed_loyal',groups,[]); b=u.pack('managed_loyal',groups,[])
        self.assertEqual(a['version'],b['version']);self.assertEqual(a['categories'],u.CATEGORIES)
        self.assertEqual(a['rules'][-1]['action'],'PROXY')
        self.assertEqual(u.pack('managed_gfw',groups,[])['rules'][-1]['action'],'DIRECT')
    def test_regex_and_bad_domains(self):
        with self.assertRaises(ValueError):u.pack('managed_loyal',self.full_groups()+[('AI','PROXY',[('domain_suffix',"evil') -> direct")])],[])
        with self.assertRaises(Exception):u.pack('managed_loyal',self.full_groups()+[('AI','PROXY',[('domain_regex','[')])],[])
if __name__=='__main__':unittest.main()
