"""Signed feature selection and the firewall/runtime projection boundary."""
from copy import deepcopy
from pathlib import Path
import runpy
import unittest

from discovery.router_candidate import VLANS, factory_projection


def feature():
    return {'enabled': True,
            'links': {f'lan-vlan{v}': {'addresses': [f'10.{v}.0.1', f'fd00:{v}::1'],
                                     'prefixes': [f'10.{v}.0.0/24', f'fd00:{v}::/64']} for v in VLANS},
            'gateway': {'interfaces': ['lan-vlan23'], 'address': 'fd00:23::1',
                        'clients': ['fd00:5353::/64'], 'port': 9443},
            'forbidden': ['fd00:5353::/64']}


class FactoryProfileTests(unittest.TestCase):
    def test_optional_publication_has_separate_scoped_listener(self):
        config = feature()
        before = factory_projection(config)
        self.assertNotIn('publication', before['runtime'])
        config['publication'] = dict(config['gateway'], port=9444)
        after = factory_projection(config)
        self.assertEqual(after['runtime']['publication']['port'], 9444)
        for direction, port in (('incoming', 'dport'), ('outgoing', 'sport')):
            self.assertEqual(after[direction][:-1], before[direction])
            self.assertIn(f'tcp {port} 9444', after[direction][-1])
            self.assertIn('fd00:5353::/64', after[direction][-1])
            self.assertNotIn('forward', after[direction][-1])
        for change in ({'port': 9443}, {'clients': ['::/0']}, {'address': 'fd00:23::2'}):
            invalid = deepcopy(config); invalid['publication'].update(change)
            with self.assertRaises(ValueError): factory_projection(invalid)

    def test_disabled_profile_emits_no_admission_or_runtime(self):
        result = factory_projection({'enabled': False})
        self.assertFalse(result['incoming'] or result['outgoing'])
        self.assertEqual(result['runtime'], {'enabled': False})
        for config in ({}, {'enabled': 0}, {'enabled': False, 'gateway': {}}, {'enabled': True}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                factory_projection(config)

    def test_complete_feature_has_scoped_rules_and_no_credentials(self):
        result = factory_projection(feature())
        self.assertEqual(len(result['incoming']), 25)
        self.assertEqual(len(result['outgoing']), 25)
        self.assertEqual(len(result['runtime']['interfaces']), 6)
        self.assertEqual(set(result['runtime']['gateway']), {'enabled', 'listen_address', 'port', 'clients'})
        self.assertNotIn('forward', '\n'.join(result['incoming'] + result['outgoing']))
        self.assertIn('enable-reflector=no', result['avahi'])

    def test_wildcard_scope_unassigned_listener_and_unknown_fields_rejected(self):
        changes = [lambda c: c['links']['lan-vlan1'].update(prefixes=['0.0.0.0/0']),
                   lambda c: c['gateway'].update(address='fd00:23::2'),
                   lambda c: c.update(nodes={}), lambda c: c.update(forbidden=[]),
                   lambda c: c.update(extra=True)]
        for change in changes:
            config = deepcopy(feature()); change(config)
            with self.subTest(change=change), self.assertRaises(ValueError):
                factory_projection(config)


