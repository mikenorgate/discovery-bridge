"""Readiness expiry, trusted export and actual DNS response section boundaries."""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import dns.message
import dns.rdatatype as rt

from discovery.catalog import Catalog, decode_snapshot
from discovery.feed import GatewayFeed, NodeFeed, encode
from discovery.identity import Identities
from discovery.query import PodQuery, Question
from discovery.records import PublicationPolicy
from discovery.responder import Responder
from discovery.router_candidate import factory_projection
from discovery.router_translation import Readiness, RouterTranslation, immutable_config, installed, observe, parse_config, target_routed
from discovery.translation import translated_records
from test_catalog import NOW, fixture, policy
from test_factory_profile import feature

CONFIG46 = b'''tun-device nat46
ipv4-addr 198.19.200.1
ipv6-addr 2001:db8:1000:fd46:ffff::1
prefix 2001:db8:1000:fd46::/96
map 198.19.200.42 2001:db8:1000:22::42
data-dir /var/lib/tayga-nat46
'''
CONFIG64 = b'''tun-device nat64-internal
ipv4-addr 198.18.0.1
ipv6-addr 2001:db8:1000:fd65:ffff::1
prefix 2001:db8:1000:fd65::/96
dynamic-pool 198.18.0.0/20
udp-cksum-mode calc
data-dir /var/lib/tayga-nat64-internal/198.18.0.0-20
'''


class TranslationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = Catalog(policy())
        self.translation = RouterTranslation()
        self.translation.state = Readiness(NOW, 100, True,
            {IPv6Address('2001:db8:1000:22::42'): IPv4Address('198.19.200.42')}, 42)
        self.gateway = GatewayFeed(self.source, PublicationPolicy(frozenset()),
                                   Path(self.directory.name) / 'gateway', translation=self.translation)
        self.addCleanup(self.gateway.close)
        self.node = NodeFeed(policy())

    def load(self, family=6):
        data = fixture()
        data['records'] = [r for r in data['records'] if r['type'] != ('A' if family == 6 else 'AAAA')]
        self.source.install(encode(data), now=NOW, monotonic=100)
        self.gateway.authority = PublicationPolicy(frozenset(r['id'] for r in data['records']))

    def envelope(self, offset=0):
        return json.loads(self.gateway.read(sources={'vlan22'}, challenge=self.node.begin_request(),
                          now=NOW + timedelta(seconds=offset), monotonic=100 + offset))

    def accept(self, value, offset=0):
        self.node.accept_catalog(encode(value), now=NOW + timedelta(seconds=offset), monotonic=100 + offset)

    def records(self, offset=0):
        return self.node.catalog.records(now=NOW + timedelta(seconds=offset), monotonic=100 + offset)

    def test_nat46_ready_map_only_and_loss_keeps_native_service(self):
        self.load(); self.accept(self.envelope())
        self.assertEqual([r.data for r, _ in self.records() if r.type == rt.A], ['198.19.200.42'])
        self.assertEqual([ttl for r, ttl in self.records() if r.type == rt.A], [10])
        self.translation.state = None
        self.accept(self.envelope(1), 1)
        self.assertNotIn(rt.A, {r.type for r, _ in self.records(1)})
        self.assertTrue({rt.PTR, rt.SRV, rt.TXT, rt.AAAA} <= {r.type for r, _ in self.records(1)})

    def test_missing_map_never_creates_alias(self):
        self.load(); self.translation.state = replace(self.translation.state, maps={})
        self.accept(self.envelope())
        self.assertNotIn(rt.A, {r.type for r, _ in self.records()})

    def test_node_expires_synthetic_record_without_new_feed(self):
        self.load(); self.accept(self.envelope())
        self.assertNotIn(rt.A, {r.type for r, _ in self.records(10)})
        self.assertIn(rt.AAAA, {r.type for r, _ in self.records(10)})

    def test_translated_record_cannot_outlive_native_monotonic_deadline(self):
        self.load(); self.accept(self.envelope())
        derived = next(r for r, _ in self.records() if r.native_id)
        self.node.catalog._record_deadlines[derived.native_id] = 102
        self.assertNotIn(rt.A, {r.type for r, _ in self.records(2)})

    def test_translation_preserves_native_catalog_at_record_budget(self):
        records = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
        host = next(r for r in records if r.type == rt.A)
        full = tuple(replace(host, id=str(i), name=f'host-{i}.local.') for i in range(4096))
        self.assertEqual(self.translation.render(full, now=NOW, monotonic=100), full)

    def test_readiness_heartbeat_cannot_extend_mapping_lease(self):
        self.load(); self.accept(self.envelope())
        self.accept(self.envelope(8), 8)
        self.assertEqual([ttl for r, ttl in self.records(8) if r.type == rt.A], [2])
        self.accept(self.envelope(10), 10)
        self.assertNotIn(rt.A, {r.type for r, _ in self.records(10)})

    def test_nat64_native_preference_and_no_double_translation(self):
        self.load(4); self.accept(self.envelope())
        self.assertEqual([r.data for r, _ in self.records() if r.type == rt.AAAA], ['2001:db8:1000:fd65::c612:162a'])
        records = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
        self.assertEqual(self.translation.render(records, now=NOW, monotonic=100), records)
        rendered = tuple(r for r, _ in self.records())
        self.assertEqual(translated_records(rendered, now=NOW, catalog_until=NOW + timedelta(seconds=10),
                         mappings={}, nat64=True, nat46=True), rendered)

    def test_local_clock_failure_withholds_translation(self):
        records = tuple(r for r in decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records if r.type != rt.A)
        for wall, mono in ((NOW, 99), (NOW + timedelta(seconds=20), 101), (NOW, 110)):
            self.assertEqual(self.translation.render(records, now=wall, monotonic=mono), records)

    def test_native_ingestion_rejects_translated_schema(self):
        self.load(); value = self.envelope()
        with self.assertRaises(ValueError):
            decode_snapshot(encode(value['snapshot']), now=NOW, policy=policy())

    def test_forged_derivation_is_atomic(self):
        self.load(); self.accept(self.envelope()); previous = self.node.catalog
        for changes in ({'native_id': 'missing'}, {'name': 'other.local.'}, {'source_link': 'vlan55'},
                        {'expires_at': (NOW + timedelta(seconds=31)).isoformat()},
                        {'data': '198.19.200.1'}, {'data': '203.0.113.1'}, {'type': 'TXT', 'data': '"bad"'}):
            value = self.envelope(1)
            next(r for r in value['snapshot']['records'] if 'native_id' in r).update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.accept(value, 1)
            self.assertIs(self.node.catalog, previous)

    def test_direct_browse_and_srv_sections_use_same_alias_and_withdraw(self):
        self.load(); self.accept(self.envelope())
        responder = Responder(self.node.catalog)
        for name, kind in [('sensor.local.', rt.A), ('_esphomelib._tcp.local.', rt.PTR), ('Sensor._esphomelib._tcp.local.', rt.SRV)]:
            responder = Responder(self.node.catalog)
            query = PodQuery(0, (Question(name, kind, 1),), (False,))
            result = responder.build(query, policy=self.node.authority, now=NOW, monotonic=100,
                                     source_port=5353, family=6)
            messages = [dns.message.from_wire(reply.wire) for reply in result.replies]
            self.assertTrue(any(rr.rdtype == rt.A and rr[0].address == '198.19.200.42'
                                for m in messages for rr in m.answer + m.additional))
            for reply in result.replies: responder.note_sent(reply, monotonic=100)
        withdrawals = responder.withdrawals(policy=self.node.authority, now=NOW + timedelta(seconds=10), monotonic=110, family=6)
        self.assertTrue(any(a.type == rt.A and a.ttl == 0 for reply in withdrawals for a in reply.records))

    def test_lan_aliases_use_same_renderer(self):
        self.load(); records = tuple(r for r, _ in self.source.records(now=NOW, monotonic=100))
        identities = Identities(Path(self.directory.name) / 'identities'); self.addCleanup(identities.close)
        answers = identities.compile(self.translation.render(records, now=NOW, monotonic=100), now=NOW)
        self.assertTrue(any(a.type == rt.A and a.data.address == '198.19.200.42' for a in answers))
        self.assertFalse(any(a.name.to_text() == 'sensor.local.' for a in answers))


class RouterReadinessTests(unittest.TestCase):
    def test_signed_profile_opt_in_defaults_off(self):
        self.assertNotIn('translation', factory_projection(feature())['runtime'])
        self.assertIs(factory_projection(feature() | {'translation': True})['runtime']['translation'], True)
        with self.assertRaises(ValueError): factory_projection(feature() | {'translation': 1})

    def test_config_requires_static_unique_maps(self):
        values, maps = parse_config(CONFIG46, 'nat46')
        self.assertEqual(maps[IPv6Address('2001:db8:1000:22::42')], IPv4Address('198.19.200.42'))
        for data in (CONFIG46 + b'map-file extra\n', CONFIG46 + b'map 198.19.200.42 fd00::1\n',
                     CONFIG46.replace(b'198.19.200.42', b'198.19.200.1'), CONFIG46.replace(b'2001:db8:1000:22::42', b'fe80::42'),
                     CONFIG46.replace(b'tun-device nat46', b'tun-device eth0')):
            with self.subTest(data=data), self.assertRaises(ValueError): parse_config(data, 'nat46')
        self.assertEqual(parse_config(CONFIG64, 'nat64-internal')[1], {})

    def test_mutable_file_cannot_confirm_installed_maps(self):
        with tempfile.NamedTemporaryFile() as file:
            file.write(CONFIG46); file.flush()
            with self.assertRaises(ValueError): immutable_config(file.name)

    def observations(self):
        links, routes = [], []
        for kind, raw in [('nat46', CONFIG46), ('nat64-internal', CONFIG64)]:
            config, _ = parse_config(raw, kind)
            links.append({'ifname': kind, 'flags': ['UP'], 'linkinfo': {'info_kind': 'tun', 'info_data': {'type': 'tun'}},
                          'addr_info': [{'local': config['ipv4-addr']}, {'local': config['ipv6-addr']}]})
            routes += [{'dst': config['prefix'], 'dev': kind}, {'dst': '198.19.200.0/24' if kind == 'nat46' else config['dynamic-pool'], 'dev': kind}]
        routes.append({'dst': '2001:db8:1000:22::/64', 'dev': 'lan-vlan22'})
        return links, routes

    def test_missing_blackholed_or_default_only_target_route_is_not_ready(self):
        target = IPv6Address('2001:db8:1000:22::42')
        _, routes = self.observations()
        self.assertTrue(target_routed(target, routes))
        self.assertFalse(target_routed(target, routes[:-1]))
        self.assertFalse(target_routed(target, routes + [{'dst': str(target) + '/128', 'type': 'blackhole'}]))
        self.assertFalse(target_routed(target, [{'dst': '::/0', 'dev': 'lan-vlan22'}]))

    def test_tun_routes_and_addresses_required(self):
        config, _ = parse_config(CONFIG46, 'nat46'); links, routes = self.observations()
        self.assertTrue(installed('nat46', config, links, routes))
        self.assertFalse(installed('nat46', config, links, routes[1:]))
        links[0]['linkinfo']['info_kind'] = 'veth'
        self.assertFalse(installed('nat46', config, links, routes))

    def test_observer_is_read_only_and_rejects_service_replacement(self):
        links, routes = self.observations(); calls = []; changed = False
        def run(*argv):
            calls.append(argv)
            if argv[:4] == ('ip', '-j', '-d', 'address'): return json.dumps(links)
            if argv[0] == 'ip': return json.dumps(routes if argv[2] == '-6' else [])
            identity = 'b' if changed and sum(x[0] == 'systemctl' for x in calls) % 2 == 0 else 'a'
            return 'ActiveState=active\nSubState=running\nMainPID=123\nInvocationID=' + identity * 32
        def read(path): return CONFIG46 if path.endswith('nat46.conf') else CONFIG64
        def cmdline(path):
            kind = 'nat46' if 'nat46' in calls[-1][2] else 'nat64-internal'
            binary = '/usr/sbin/tayga' if kind == 'nat46' else '/usr/lib/example-router/tayga-internal'
            return (binary + '\0--nodetach\0--config\0/etc/tayga-' + kind + '.conf\0').encode()
        with patch.object(Path, 'read_bytes', cmdline):
            state = observe(run=run, read=read)
            self.assertTrue(state.nat64); self.assertEqual(len(state.maps), 1)
            changed = True
            state = observe(run=run, read=read)
            self.assertFalse(state.nat64); self.assertFalse(state.maps)
        self.assertTrue(all(c[0] in {'ip', 'systemctl'} for c in calls))
        self.assertTrue(all(c[1] == 'show' for c in calls if c[0] == 'systemctl'))
