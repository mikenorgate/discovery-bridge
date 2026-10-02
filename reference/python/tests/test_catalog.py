"""Native catalog contracts and expiry/replay failure cases, without live I/O."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import json
import unittest

from discovery.catalog import Catalog, SourcePolicy, decode_snapshot

NOW = datetime(2026, 9, 28, 12, tzinfo=timezone.utc)


def stamp(offset):
    return (NOW + timedelta(seconds=offset)).isoformat()


def fixture():
    records = [
        ('type', '_services._dns-sd._udp.local.', 'PTR', '_esphomelib._tcp.local.'),
        ('browse', '_esphomelib._tcp.local.', 'PTR', 'Sensor._esphomelib._tcp.local.'),
        ('srv', 'Sensor._esphomelib._tcp.local.', 'SRV', '0 0 6053 sensor.local.'),
        ('txt', 'Sensor._esphomelib._tcp.local.', 'TXT', r'"name=Sensor" "opaque=\255\000"'),
        ('v4', 'sensor.local.', 'A', '10.22.0.42'),
        ('v6', 'sensor.local.', 'AAAA', '2001:db8:1000:22::42'),
    ]
    return {'schema': 1, 'epoch': 'gateway-boot-1', 'revision': 1,
            'issued_at': stamp(0), 'valid_until': stamp(30), 'records': [
                dict(id=id_, name=name, type=kind, data=data, source_link='vlan22', expires_at=stamp(90))
                for id_, name, kind, data in records]}


def policy():
    return SourcePolicy({'vlan22': ('10.22.0.0/24', '2001:db8:1000:22::/64')},
                        ('10.96.0.0/12',))


def encode(data):
    return json.dumps(data).encode()


class DecoderTests(unittest.TestCase):
    def decode(self, data):
        return decode_snapshot(encode(data), now=NOW, policy=policy())

    def test_full_service_chain_and_opaque_txt(self):
        decoded = self.decode(fixture())
        self.assertEqual(len(decoded.records), 6)
        txt = next(record for record in decoded.records if record.id == 'txt')
        self.assertEqual(txt.data, r'"name=Sensor" "opaque=\255\000"')
        with self.assertRaises(FrozenInstanceError):
            txt.data = 'changed'

    def test_strict_envelope_and_lease(self):
        changes = [{'schema': True}, {'schema': 2}, {'revision': False}, {'revision': 0},
                   {'revision': 2**63}, {'epoch': ''}, {'records': {}}, {'unexpected': 1},
                   {'issued_at': stamp(6)}, {'valid_until': stamp(31)},
                   {'valid_until': stamp(0)}, {'issued_at': '2026-09-28T12:00:00'}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.decode(fixture() | change)
        with self.assertRaises(ValueError):
            decode_snapshot(encode(fixture()).replace(b'"schema": 1', b'"schema": 1, "schema": 1'),
                            now=NOW, policy=policy())

    def test_malformed_records_reject_entire_snapshot(self):
        changes = [{'name': 'example.org.'}, {'name': 'relative'}, {'type': 'CNAME'},
                   {'data': 'not an address'}, {'source_link': 'vlan55'},
                   {'expires_at': 'tomorrow'}, {'extra': True}, {'name': 'a' * 64 + '.local.'}]
        for change in changes:
            data = fixture()
            data['records'][4].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.decode(data)
        data = fixture()
        data['records'].append(deepcopy(data['records'][0]))
        with self.assertRaises(ValueError):
            self.decode(data)
        for position, value in [(0, 'example.org.'), (2, '0 0 6053 example.org.')]:
            data = fixture()
            data['records'][position]['data'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.decode(data)

    def test_address_scope_and_synthetic_records_rejected(self):
        broad = SourcePolicy({'vlan22': ('0.0.0.0/0', '::/0')}, ('10.96.0.0/12',))
        for address in ['::', '::1', 'fe80::1', 'ff02::fb', '::ffff:10.22.0.42',
                        '2001:db8:1000:f000::1', '2001:db8:1000:fd46::1',
                        '2001:db8:1000:fd65::1', '64:ff9b::a16:2a', '198.19.200.2',
                        '10.96.0.1', '127.0.0.1', '169.254.1.1', '224.0.0.251']:
            with self.subTest(address=address), self.assertRaises(ValueError):
                broad.check_address('vlan22', address)
        for address in ['10.22.1.42', '10.22.0.0', '10.22.0.255', '2001:db8:1000:55::42']:
            with self.subTest(address=address), self.assertRaises(ValueError):
                policy().check_address('vlan22', address)

    def test_policy_cannot_be_mutated(self):
        sources = {'vlan22': ['10.22.0.0/24']}
        scopes = SourcePolicy(sources, ())
        sources['vlan22'].append('10.55.0.0/24')
        with self.assertRaises(ValueError):
            scopes.check_address('vlan22', '10.55.0.42')
        with self.assertRaises(TypeError):
            scopes.sources['vlan55'] = ()
        with self.assertRaises(FrozenInstanceError):
            scopes.forbidden = ()

    def test_size_and_record_budgets(self):
        for payload in [b'', b' ' * 1_048_577, b'\xff', b'[' * 2000,
                        json.dumps(fixture()).encode('utf-16')]:
            with self.subTest(length=len(payload)), self.assertRaises(ValueError):
                decode_snapshot(payload, now=NOW, policy=policy())
        data = fixture()
        data['records'] = [{}] * 4097
        with self.assertRaises(ValueError):
            self.decode(data)

    def test_observed_legacy_types_do_not_use_generated_identifier_rules(self):
        data = fixture()
        for record in data['records']:
            record['name'] = record['name'].replace('_esphomelib', '_presence_olpc')
            record['data'] = record['data'].replace('_esphomelib', '_presence_olpc')
        self.assertEqual(len(self.decode(data).records), 6)


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.catalog = Catalog(policy())
        self.data = fixture()

    def install(self, data=None, offset=0, wall=None):
        return self.catalog.install(encode(self.data if data is None else data),
                                    now=NOW + timedelta(seconds=offset if wall is None else wall),
                                    monotonic=100 + offset)

    def records(self, offset, wall=None):
        return self.catalog.records(now=NOW + timedelta(seconds=offset if wall is None else wall),
                                    monotonic=100 + offset)

    def test_feed_expiry_and_floored_ttl(self):
        self.assertTrue(self.install())
        self.assertEqual({ttl for _, ttl in self.records(0.1)}, {29})
        self.assertEqual({ttl for _, ttl in self.records(29)}, {1})
        self.assertEqual(self.records(30), ())
        self.assertEqual(self.catalog.snapshot.revision, 1)

    def test_replay_does_not_refresh(self):
        self.install()
        self.assertFalse(self.install(offset=10))
        self.assertEqual({ttl for _, ttl in self.records(20)}, {10})
        self.assertEqual(self.records(30), ())

    def test_heartbeat_renews_feed_with_same_revision_and_reordered_records(self):
        self.install()
        heartbeat = self.data | {'issued_at': stamp(10), 'valid_until': stamp(40),
                                 'records': list(reversed(self.data['records']))}
        self.assertTrue(self.install(heartbeat, offset=10))
        self.assertEqual({ttl for _, ttl in self.records(31)}, {9})

    def test_individual_expiry_and_watermark_survive_feed_expiry(self):
        self.data['revision'] = 2
        self.data['records'][4]['expires_at'] = stamp(5)
        self.install()
        self.assertEqual(len(self.records(5)), 5)
        self.assertEqual(self.records(30), ())
        stale = self.data | {'revision': 1, 'issued_at': stamp(31), 'valid_until': stamp(61)}
        with self.assertRaises(ValueError):
            self.install(stale, offset=31)

    def test_renewed_feed_cannot_extend_unchanged_source_expiry(self):
        for record in self.data['records']:
            record['expires_at'] = stamp(20)
        self.install()
        renewed = self.data | {'issued_at': stamp(10), 'valid_until': stamp(40)}
        self.install(renewed, offset=10)
        self.assertEqual({ttl for _, ttl in self.records(19)}, {1})
        self.assertEqual(self.records(20), ())

    def test_atomic_rejection_and_version_watermark(self):
        self.install(self.data | {'revision': 2})
        malformed = deepcopy(self.data)
        malformed['revision'] = 3
        malformed['records'][-1]['data'] = 'fe80::42'
        altered = deepcopy(self.data)
        altered['revision'] = 2
        altered['records'][-1]['data'] = '2001:db8:1000:22::99'
        for candidate in [self.data, self.data | {'epoch': 'other'}, malformed, altered,
                          self.data | {'revision': 2, 'valid_until': stamp(29)},
                          self.data | {'revision': 3, 'issued_at': stamp(-1), 'valid_until': stamp(29)}]:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                self.install(candidate, offset=1)
            self.assertEqual(self.catalog.snapshot.revision, 2)
            self.assertEqual(len(self.records(1)), 6)

    def test_omission_withdraws_and_empty_snapshot_keeps_watermark(self):
        self.install()
        self.install(self.data | {'revision': 2, 'records': []}, offset=1)
        self.assertEqual(self.records(1), ())
        with self.assertRaises(ValueError):
            self.install(offset=1)

    def test_clock_discontinuity_latches_closed(self):
        self.install()
        self.assertEqual(self.records(1, wall=7), ())
        self.assertEqual(self.records(2), ())
        with self.assertRaises(ValueError):
            self.install(offset=3)

    def test_monotonic_rollback_after_read_latches_closed(self):
        self.install()
        self.assertTrue(self.records(10))
        self.assertEqual(self.records(9), ())
        self.assertEqual(self.records(11), ())

    def test_small_clock_adjustment_does_not_extend_source_deadline(self):
        for record in self.data['records']:
            record['expires_at'] = stamp(20)
        self.install()
        renewed = self.data | {'issued_at': stamp(8), 'valid_until': stamp(38)}
        self.install(renewed, offset=10, wall=8)
        self.assertEqual({ttl for _, ttl in self.records(19, wall=17)}, {1})
        self.assertEqual(self.records(20, wall=18), ())

    def test_new_observation_revision_can_extend_source_expiry(self):
        for record in self.data['records']:
            record['expires_at'] = stamp(20)
        self.install()
        renewed = fixture() | {'revision': 2, 'issued_at': stamp(10), 'valid_until': stamp(40)}
        self.install(renewed, offset=10)
        self.assertEqual({ttl for _, ttl in self.records(25)}, {15})


if __name__ == '__main__':
    unittest.main()
