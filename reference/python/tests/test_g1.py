"""Provenance, expiry, authority, registry and persistent naming regressions."""
import asyncio
from dataclasses import replace
from datetime import timedelta
import hashlib
from ipaddress import IPv4Address, IPv6Address
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdatatype as rt
import dns.rrset

from discovery.avahi import Link, RecordEvent, RecordQuery
from discovery.catalog import decode_snapshot
from discovery.identity import Identities
from discovery.observation import Packet, Observations, parse_response
from discovery.policy import MappingReadiness
from discovery.publication import Intent, decode, frame
from discovery.registry import Registry, RegistryStore, generated_type, observed_type
from discovery.translation import coherent_translated_view
from test_catalog import NOW, fixture, encode, policy

LINKS = {22: Link('vlan22', 'g1', frozenset({4, 6}))}
REGISTRY = Path(__file__).resolve().parents[1] / 'registry'


def packet(*, ttl=10, flush=True, address='10.22.0.42'):
    message = dns.message.Message(id=0)
    message.flags = dns.flags.QR | dns.flags.AA
    rrset = dns.rrset.from_text('sensor.local.', ttl, 1, 'A', address)
    rrset.rdclass = 0x8001 if flush else 1
    message.answer.append(rrset)
    return Packet(22, 'g1', 4, '10.22.0.42', '224.0.0.251', 255, 5353, 5353, message.to_wire())


def parse(value):
    return parse_response(value, links=LINKS, policy=policy(), local_addresses={22: ('10.22.0.1',)})


def hint(record, *, added=True, epoch='epoch'):
    return RecordEvent(epoch, record.source, record.generation,
                       RecordQuery(22, record.family, record.name, record.type), record.name,
                       added, record.data, False, 0)


class ObservationTests(unittest.TestCase):
    def test_metadata_and_whole_packet_validation(self):
        self.assertTrue(parse(packet())[0].flush)
        for values in ({'hop_limit': 254}, {'interface': 55}, {'generation': 'old'}, {'source_port': 53},
                       {'destination_port': 12345}, {'source': '10.55.0.42'}, {'destination': '10.22.0.5'},
                       {'wire': packet().wire[:-1]}, {'wire': packet().wire + b'junk'}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                parse(replace(packet(), **values))
        self.assertEqual(parse(replace(packet(), source='10.22.0.1')), ())
        self.assertEqual(parse(packet(address='198.19.200.42')), ())
        self.assertEqual(parse_response(packet(), links=LINKS, policy=policy(), local_addresses={}, owns_name=lambda _: True), ())

    def test_wire_and_hint_intersection_no_hint_renewal(self):
        cache = Observations()
        record = parse(packet(ttl=5))[0]
        cache.ingest((record,), now=0)
        self.assertFalse(cache.records(now=0, wall=NOW))
        cache.hint(hint(record))
        self.assertEqual(cache.records(now=1, wall=NOW)[0].expires_at, NOW + timedelta(seconds=4))
        cache.hint(hint(record))
        self.assertFalse(cache.records(now=5, wall=NOW))
        cache.ingest((record,), now=6)
        cache.forget_epoch('epoch')
        self.assertFalse(cache.records(now=6, wall=NOW))

    def test_flush_cross_family_and_one_second_protection(self):
        cache = Observations()
        old = replace(parse(packet())[0], family=6)
        cache.hint(hint(old)); cache.ingest((old,), now=0)
        new = parse(packet(address='10.22.0.43'))[0]
        cache.hint(hint(new)); cache.ingest((new,), now=0.2)
        self.assertEqual(len(cache.records(now=0.2, wall=NOW)), 2)
        cache.ingest((new,), now=2)
        self.assertEqual(len(cache.records(now=3, wall=NOW)), 1)
        cache.ingest((replace(new, family=6, ttl=0),), now=4)
        self.assertFalse(cache.records(now=5, wall=NOW))

    def test_capacity_and_clock_fail_closed(self):
        cache = Observations(limit=1)
        cache.ingest(parse(packet()), now=0)
        with self.assertRaises(ValueError):
            cache.ingest(parse(packet(address='10.22.0.43')), now=0)
        self.assertTrue(cache.failed)
        cache = Observations()
        cache.ingest(parse(packet()), now=2)
        with self.assertRaises(ValueError):
            cache.records(now=1, wall=NOW)

    def test_remove_and_generation_never_join_foreign_evidence(self):
        record = parse(packet())[0]
        cache = Observations()
        cache.ingest((record,), now=0)
        cache.hint(hint(replace(record, generation='g2')))
        self.assertFalse(cache.records(now=0, wall=NOW))
        cache.hint(hint(record)); cache.hint(hint(record, added=False))
        self.assertFalse(cache.records(now=0, wall=NOW))
        cache.hint(hint(record)); cache.forget_link('vlan22', 'g1')
        self.assertFalse(cache.records(now=0, wall=NOW))


class IdentityTests(unittest.TestCase):
    def test_durable_alias_collision_and_escaped_utf8(self):
        from discovery.avahi import local_name
        self.assertEqual(local_name('Café._private._tcp.local.').labels[0], 'Café'.encode())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.db'
            name = dns.name.Name(('Café.with dot'.encode(), b'_presence_olpc', b'_tcp', b'local', b''))
            store = Identities(path)
            first = store.alias('vlan22', name)[1]
            other = store.alias('vlan55', name)[1]
            self.assertNotEqual(first, other)
            second = store.rotate_alias(first.to_text())
            store.close()
            store = Identities(path)
            self.assertEqual(store.alias('vlan22', name)[1], second)
            self.assertTrue(store.owns(first)); self.assertTrue(store.owns(second))
            store.close()

    def test_same_names_on_two_links_keep_complete_independent_graphs(self):
        records = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
        records += tuple(replace(r, id=r.id + ':55', source_link='vlan55') for r in records)
        store = Identities(':memory:')
        view = store.compile(records, now=NOW)
        self.assertEqual(sum(a.type == rt.SRV for a in view), 2)
        for srv in (a for a in view if a.type == rt.SRV):
            self.assertTrue(any(a.name == srv.data.target and a.source == srv.source for a in view))
        store.close()


class RegistryTests(unittest.TestCase):
    def test_complete_raw_rows_locales_and_unknown_legacy_names(self):
        registry = Registry(REGISTRY)
        self.assertGreater(len(registry.rows), 10000)
        self.assertGreater(len(registry.descriptions), 70)
        self.assertEqual(registry.describe('_http._tcp', 'de'), 'Web-Angebot')
        self.assertEqual(registry.describe('_presence_olpc._tcp'), 'OLPC Presence')
        self.assertEqual(registry.describe('_private_thing._udp'), '_private_thing._udp')
        self.assertEqual(observed_type('_MacOSXDupSuppress._tcp.local.'), '_macosxdupsuppress._tcp')
        self.assertTrue(any(r['Port Number'] == '80' for r in registry.metadata('http', 'tcp')))
        self.assertTrue(registry.metadata('http', 'sctp'))
        with self.assertRaises(ValueError):
            generated_type('presence_olpc', 'tcp')
        self.assertEqual(generated_type('esphomelib', 'tcp'), '_esphomelib._tcp')

    def test_atomic_reload_explicit_rollback_and_restart_watermark(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); changed = root / 'changed'; shutil.copytree(REGISTRY, changed)
            data = (changed / 'service-types').read_bytes() + b'\n_private._tcp:Private\n'
            (changed / 'service-types').write_bytes(data)
            manifest = json.loads((changed / 'manifest.json').read_text())
            manifest['files']['service-types']['sha256'] = hashlib.sha256(data).hexdigest()
            (changed / 'manifest.json').write_text(json.dumps(manifest))
            store = RegistryStore(root / 'state.db')
            first = store.activate(REGISTRY, revision=1)
            second = store.activate(changed, revision=2)
            with self.assertRaises(ValueError):
                store.activate(REGISTRY, revision=3)
            self.assertIs(store.active, second)
            self.assertEqual(store.activate(REGISTRY, revision=3, rollback=True).digest, first.digest)
            store.close(); store = RegistryStore(root / 'state.db')
            with self.assertRaises(ValueError):
                store.activate(changed, revision=2)
            store.close()


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.store = Identities(':memory:')
        records = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
        self.view = self.store.compile(records, now=NOW)
        self.payload = frame((Intent(22, 4, 20, self.view),), sequence=1, now=0)

    def tearDown(self):
        self.store.close()

    def decode(self, data):
        return decode(data, now=0.5, previous=0, links=LINKS, owns=self.store.owns)

    def test_authorized_coherent_graph_short_cache_ttl(self):
        _, groups = self.decode(self.payload)
        self.assertEqual(len(groups[0].records), len(self.view))
        self.assertTrue(all(a.ttl == 1 for a in groups[0].records))
        with self.assertRaises(ValueError):
            decode(self.payload, now=0.5, previous=0, links=LINKS, owns=lambda _: False)

    def test_stale_boot_replay_overlong_lease_and_incomplete_dependency(self):
        for change in ({'boot': 'another-boot'}, {'sequence': 0}, {'issued': -5}):
            value = json.loads(self.payload); value.update(change)
            with self.assertRaises(ValueError): self.decode(json.dumps(value).encode())
        value = json.loads(self.payload); value['groups'][0]['deadline'] = 31
        with self.assertRaises(ValueError): self.decode(json.dumps(value).encode())
        value = json.loads(self.payload)
        value['groups'][0]['records'] = [r for r in value['groups'][0]['records'] if r['type'] not in (1, 28)]
        with self.assertRaises(ValueError): self.decode(json.dumps(value).encode())

    def test_translation_preserves_chain_and_never_creates_pending_a(self):
        records = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
        records = tuple(r for r in records if r.type != rt.A)
        mapping = MappingReadiness('v6', IPv6Address(records[-1].data), IPv4Address('198.19.200.42'),
                                   1, 1, 1, 'ready', NOW + timedelta(seconds=4))
        kwargs = dict(now=NOW, catalog_until=NOW + timedelta(seconds=30), nat46=True)
        for maps in ({}, {'v6': replace(mapping, installed_generation=2)}, {'v6': replace(mapping, state='pending')}):
            self.assertFalse(any(a.type == rt.A for a in coherent_translated_view(records, mappings=maps, **kwargs)))
        view = coherent_translated_view(records, mappings={'v6': mapping}, **kwargs)
        self.assertTrue(any(a.type == rt.A and a.data.address == '198.19.200.42' for a in view))
        self.assertTrue(all(a.ttl <= 4 for a in view if a.type in (rt.PTR, rt.SRV, rt.TXT)
                            and a.name.to_text() != '_services._dns-sd._udp.local.'))
        v4 = tuple(r for r in decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records if r.type != rt.AAAA)
        view = coherent_translated_view(v4, now=NOW, catalog_until=NOW + timedelta(seconds=30), mappings={}, nat64=True)
        self.assertTrue(any(a.type == rt.AAAA and a.data.address.startswith('2001:db8:1000:fd65:') for a in view))


class LocalAuthorityTests(unittest.IsolatedAsyncioTestCase):
    async def test_twelve_link_groups_reconcile_within_short_leases(self):
        import time
        from unittest.mock import Mock, patch
        from discovery.publication import Publisher

        for replace_old in (False, True):
            with self.subTest(replace_old=replace_old):
                store = Identities(':memory:')
                self.addCleanup(store.close)
                view = store.compile(decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records, now=NOW)
                links = {i: Link('vlan' + str(i), 'test', frozenset({4, 6})) for i in range(1, 7)}
                publisher = Publisher(links, addresses={i: () for i in links})
                publisher.bus, publisher.owner = Mock(), 'fixture'
                active = peak = serial = 0

                async def call(path, interface, member, *args):
                    nonlocal active, peak, serial
                    active += 1; peak = max(peak, active); serial += 1
                    result = ['/new' + str(serial)] if member == 'EntryGroupNew' else []
                    try:
                        await asyncio.sleep(.02)
                        return result
                    finally:
                        active -= 1

                publisher._call = call
                if replace_old:
                    publisher.groups = {(i, f): (f'/old{i}_{f}', (), time.monotonic() + .15)
                                        for i in links for f in (4, 6)}
                groups = tuple(Intent(i, f, time.monotonic() + 1, view) for i in links for f in (4, 6))
                with patch('discovery.publication.send_goodbyes'):
                    await publisher.reconcile(groups)
                self.assertEqual(len(publisher.groups), 12)
                self.assertEqual(active, 0)
                self.assertGreater(peak, 1)
                self.assertLessEqual(peak, 12)
                publisher.bus.disconnect.assert_not_called()

    async def test_publication_renewal_and_replacement_do_not_reuse_old_deadline(self):
        import os
        import time
        from unittest.mock import patch
        from discovery.publication import LeaseServer, Publisher

        for unchanged in (True, False):
            with self.subTest(unchanged=unchanged), tempfile.TemporaryDirectory() as directory:
                store = Identities(':memory:')
                self.addCleanup(store.close)
                records = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
                view = store.compile(records, now=NOW)
                publisher = Publisher(LINKS, addresses={22: ()})
                publisher.bus = type('Bus', (), {'disconnect': lambda self: None})()
                publisher.owner = 'fixture'
                calls = []

                async def call(path, interface, member, *args, **kwargs):
                    calls.append(member)
                    await asyncio.sleep(0.02)
                    return ['/new'] if member == 'EntryGroupNew' else []

                publisher._call = call
                signature = tuple((a.key, a.unique) for a in view) if unchanged else ()
                publisher.groups[(22, 4)] = ('/old', signature, time.monotonic() + 0.1)
                handler = LeaseServer(publisher, producer_uid=os.getuid(), owns=store.owns)
                with patch('discovery.publication.send_goodbyes'):
                    server = await asyncio.start_unix_server(handler.client, path=directory + '/sock')
                    try:
                        reader, writer = await asyncio.open_unix_connection(directory + '/sock')
                        groups = tuple(Intent(22, family, time.monotonic() + 5, view) for family in (4, 6))
                        writer.write(frame(groups, sequence=1)); await writer.drain()
                        self.assertEqual(await reader.readline(), b'OK\n')
                        self.assertIsNone(publisher.failure)
                        self.assertIn('Commit', calls)
                        if not unchanged:
                            self.assertEqual(calls[:2], ['Reset', 'Free'])
                        writer.close(); await writer.wait_closed()
                        while handler.busy:
                            await asyncio.sleep(0.01)
                    finally:
                        server.close(); await server.wait_closed()

    async def test_publication_still_withdraws_when_old_or_new_lease_expires(self):
        import time
        from unittest.mock import Mock, patch
        from discovery.publication import Publisher

        for old_expired in (True, False):
            with self.subTest(old_expired=old_expired):
                store = Identities(':memory:')
                self.addCleanup(store.close)
                records = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
                view = store.compile(records, now=NOW)
                publisher = Publisher(LINKS, addresses={22: ()})
                publisher.bus = Mock()
                publisher.owner = 'fixture'
                deadline = time.monotonic() - 1
                if old_expired:
                    publisher.groups[(22, 4)] = ('/old', (), deadline)
                    deadline = time.monotonic() + 5

                async def slow_call(*args, **kwargs):
                    await asyncio.sleep(0.03)
                    return ['/new']

                publisher._call = slow_call
                with patch('discovery.publication.send_goodbyes'), self.assertRaises(TimeoutError):
                    await publisher.reconcile((Intent(22, 4, deadline, view),))
                publisher.bus.disconnect.assert_called_once()
                self.assertFalse(publisher.groups)

    async def test_unix_peer_uid_and_single_producer_disconnect(self):
        import os
        from discovery.publication import LeaseServer
        class FakePublisher:
            links = LINKS
            groups = {}
            conflicting_names = set()
            conflicts = set()
            cleared = 0
            accepted = 0
            async def reconcile(self, groups): self.accepted += 1
            async def clear(self): self.cleared += 1
        with tempfile.TemporaryDirectory() as directory:
            publisher = FakePublisher()
            handler = LeaseServer(publisher, producer_uid=os.getuid() + 1, owns=lambda _: True)
            server = await asyncio.start_unix_server(handler.client, path=directory + '/sock')
            try:
                reader, writer = await asyncio.open_unix_connection(directory + '/sock')
                self.assertEqual(await reader.read(), b'')
                writer.close(); await writer.wait_closed()
                self.assertFalse(handler.busy); self.assertEqual(publisher.cleared, 0)
                handler.producer_uid = os.getuid()
                reader, writer = await asyncio.open_unix_connection(directory + '/sock')
                writer.write(frame((), sequence=1)); await writer.drain()
                self.assertEqual(await reader.readline(), b'OK\n')
                r2, w2 = await asyncio.open_unix_connection(directory + '/sock')
                self.assertEqual(await r2.read(), b'')
                w2.close(); await w2.wait_closed()
                writer.close(); await writer.wait_closed(); await asyncio.sleep(0.02)
                self.assertEqual(publisher.accepted, 1); self.assertEqual(publisher.cleared, 1)
            finally:
                server.close(); await server.wait_closed()

    async def test_supervisor_retries_with_fresh_topology_and_closes_monitor(self):
        from unittest.mock import patch, AsyncMock
        from discovery.collector import supervise
        calls, closed = [], []
        stop = asyncio.Event()
        class Monitor:
            def close(self): closed.append(True)
        def topo(config):
            calls.append(True)
            if len(calls) == 2: stop.set()
            raise RuntimeError('fixture link not ready')
        with patch('discovery.collector.LinkMonitor', Monitor), patch('discovery.collector.topology', topo), \
                patch('discovery.collector.asyncio.sleep', AsyncMock()), patch('builtins.print'):
            await supervise({}, None, '/unused', stop=stop)
        self.assertEqual(len(calls), 2); self.assertEqual(len(closed), 2)


class RouterCandidateTests(unittest.TestCase):
    def test_gateway_admission_is_scoped_and_optional(self):
        from discovery.router_candidate import gateway_rules
        config = {'interfaces': ['lan-vlan23'], 'address': 'fd00:23::1',
                  'clients': ['fd00:5353::/64'], 'port': 9443}
        incoming, outgoing = gateway_rules(config)
        self.assertIn('ip6 daddr fd00:23::1 tcp dport 9443', incoming[0])
        self.assertIn('ct state established', outgoing[0])
        for update in ({'clients': ['::/0']}, {'interfaces': ['wan']}, {'clients': []},
                       {'address': '::'}, {'port': True}, {'clients': ['10.0.0.0/8']}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                gateway_rules(config | update)

    def test_exact_lans_scoped_jumps_and_no_forwarding_grant(self):
        from discovery.router_candidate import VLANS, transaction
        config = {f'lan-vlan{v}': {'addresses': [f'10.{v}.0.1', f'fd00:{v}::1'],
                                  'prefixes': [f'10.{v}.0.0/24', f'fd00:{v}::/64']} for v in VLANS}
        candidate = transaction(config)
        self.assertIn('input_local_services jump discovery_input', candidate)
        self.assertIn('output_local_services jump discovery_output', candidate)
        self.assertNotIn('forward', candidate)
        self.assertNotIn('flush', candidate)
        self.assertNotIn('hook', candidate)
        self.assertIn('udp sport 5353', candidate)
        self.assertIn('ip6 hoplimit 255', candidate)
        config['wan'] = config.pop('lan-vlan1')
        with self.assertRaises(ValueError): transaction(config)


class TransportTests(unittest.TestCase):
    def test_udp_checksums_both_families_and_zero_ipv6_rejection(self):
        import struct
        from ipaddress import ip_address
        from discovery.transport import checksum, decode_udp
        for family, src, dst in [(4, '10.22.0.2', '224.0.0.251'), (6, 'fd00:22::2', 'ff02::fb')]:
            payload = packet().wire
            size = len(payload) + 8
            pseudo = ip_address(src).packed + ip_address(dst).packed
            pseudo += struct.pack('!BBH', 0, 17, size) if family == 4 else struct.pack('!I3xB', size, 17)
            udp = struct.pack('!4H', 5353, 5353, size, 0) + payload
            crc = checksum(pseudo + udp) or 65535
            udp = udp[:6] + struct.pack('!H', crc) + udp[8:]
            kwargs = dict(family=family, source=src, destination=dst, interface=22, generation='g1', hop_limit=255)
            self.assertEqual(decode_udp(udp, **kwargs).wire, payload)
            with self.assertRaises(ValueError): decode_udp(udp[:-1] + bytes([udp[-1] ^ 1]), **kwargs)
            zero = udp[:6] + b'\0\0' + udp[8:]
            if family == 4:
                self.assertEqual(decode_udp(zero, **kwargs).wire, payload)
            else:
                with self.assertRaises(ValueError): decode_udp(zero, **kwargs)
