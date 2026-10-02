"""Acceptance cases for initial pure publication policy; no live services."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
import unittest

from discovery.policy import MappingReadiness, nat46_record, remaining_ttl, service_identifier


class ExpiryTests(unittest.TestCase):
    def test_ttl_never_exceeds_any_validity(self):
        now = datetime(2026, 9, 28, tzinfo=timezone.utc)
        for seconds, expected in [(-1, 0), (0, 0), (0.9, 0), (1, 1), (9.9, 9), (120, 30)]:
            with self.subTest(seconds=seconds):
                self.assertEqual(remaining_ttl(now, now + timedelta(seconds=seconds)), expected)
        self.assertEqual(remaining_ttl(now, now + timedelta(seconds=29), now + timedelta(seconds=4)), 4)

    def test_invalid_validity_is_rejected(self):
        now = datetime(2026, 9, 28, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):
            remaining_ttl(now)
        with self.assertRaises(ValueError):
            remaining_ttl(now, now.replace(tzinfo=None))
        for maximum in [0, -1, True, 0.5]:
            with self.subTest(maximum=maximum), self.assertRaises(ValueError):
                remaining_ttl(now, now + timedelta(seconds=30), maximum=maximum)


class ServiceIdentifierTests(unittest.TestCase):
    def test_generated_names(self):
        for name in ['http', 'ESPHomeLib', 'a', 'a-b', 'a12345678901234']:
            with self.subTest(name=name):
                self.assertEqual(service_identifier(name), name.lower())
        for name in ['', '123', '-http', 'http-', 'a--b', '_http', 'présence',
                     'a123456789012345', 'presence_olpc', 'a.b', 'http\n']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                service_identifier(name)


class NAT46Tests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 9, 28, tzinfo=timezone.utc)
        self.target = ip_address('2001:db8:1000:ff00::42')
        self.mapping = MappingReadiness('service-42', self.target, ip_address('198.19.200.2'),
                                        7, 7, 7, 'ready', self.now + timedelta(seconds=20))
        self.arguments = dict(endpoint_id='service-42', target=self.target, now=self.now,
                              source_until=self.now + timedelta(seconds=60),
                              catalog_until=self.now + timedelta(seconds=30),
                              pool=ip_network('198.19.200.0/24'),
                              reserved=frozenset({ip_address('198.19.200.1')}))

    def test_existing_ready_map_only(self):
        record = nat46_record(self.mapping, **self.arguments)
        self.assertIsNotNone(record)
        self.assertEqual((record.address, record.ttl, record.generation),
                         (ip_address('198.19.200.2'), 20, 7))
        self.assertIsNone(nat46_record(None, **self.arguments))
        cases = {
            'wrong_identity': {'endpoint_id': 'other'},
            'wrong_target': {'target': ip_address('2001:db8:1000:ff00::99')},
            'pending': {'state': 'pending'},
            'failed': {'state': 'failed'},
            'retired': {'state': 'retired'},
            'not_installed': {'installed_generation': 6},
            'stale_ack': {'acknowledged_generation': 6},
            'stale_intent': {'desired_generation': 8},
            'zero_generation': {'desired_generation': 0},
            'boolean_generation': {'desired_generation': True},
            'expired': {'valid_until': self.now},
            'subsecond': {'valid_until': self.now + timedelta(milliseconds=999)},
            'outside_pool': {'alias': ip_address('192.0.2.2')},
            'router_alias': {'alias': ip_address('198.19.200.1')},
            'network_alias': {'alias': ip_address('198.19.200.0')},
            'broadcast_alias': {'alias': ip_address('198.19.200.255')},
            'invalid_family': {'alias': self.target},
        }
        for name, changes in cases.items():
            with self.subTest(name=name):
                self.assertIsNone(nat46_record(replace(self.mapping, **changes), **self.arguments))

    def test_source_and_catalog_expiry_override_mapping(self):
        for field in ['source_until', 'catalog_until']:
            with self.subTest(field=field):
                args = self.arguments | {field: self.now}
                self.assertIsNone(nat46_record(self.mapping, **args))
                args[field] = self.now + timedelta(seconds=3.5)
                self.assertEqual(nat46_record(self.mapping, **args).ttl, 3)

    def test_unusable_targets(self):
        for address in ['::', '::1', 'ff02::fb', 'fe80::1', '::ffff:192.0.2.1',
                        '2001:db8:1000:ff00::42%eth0', '192.0.2.2']:
            with self.subTest(address=address):
                target = ip_address(address)
                mapping = replace(self.mapping, target=target)
                self.assertIsNone(nat46_record(mapping, **(self.arguments | {'target': target})))

    def test_repeated_queries_do_not_mutate_or_refresh_map(self):
        original = replace(self.mapping)
        for offset in range(25):
            result = nat46_record(self.mapping, **(self.arguments | {'now': self.now + timedelta(seconds=offset)}))
            self.assertEqual(result is None, offset >= 20)
        self.assertEqual(self.mapping, original)


if __name__ == '__main__':
    unittest.main()
