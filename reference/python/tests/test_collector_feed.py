"""Collector output reaches the native feed; demand stays on approved LANs."""
from datetime import timedelta
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import dns.name
import dns.rdatatype as rt

from discovery.avahi import Link
from discovery.catalog import Catalog, decode_snapshot
from discovery.collector import CollectorFeed, lan_groups, lan_hostnames, lan_view, pod_view
from discovery.feed import GatewayFeed, NodeFeed, encode
from discovery.identity import Identities
from discovery.query import Question
from discovery.records import PublicationPolicy
from discovery.transport import send_questions
from test_catalog import NOW, fixture, policy


class Browser:
    healthy = True
    links = {22: Link('vlan22', 'test', {4, 6}), 55: Link('vlan55', 'test', {6})}

    def __init__(self):
        self.queries = []

    async def watch(self, query):
        self.queries.append(query)


class CollectorFeedTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = Path(self.temp.name)
        self.identities = Identities(path / 'identities.db')
        self.addCleanup(self.identities.close)
        self.feed = GatewayFeed(Catalog(policy()), PublicationPolicy(frozenset()), path / 'feed.db')
        self.addCleanup(self.feed.close)
        self.bridge = CollectorFeed(self.feed, self.identities)
        self.bridge.browser = Browser()
        self.bridge.addresses = {22: ('198.18.22.1', 'fd00:22::1'), 55: ('fd00:55::1',)}
        sender = patch('discovery.collector.send_questions')
        self.send_questions = sender.start()
        self.addCleanup(sender.stop)
        native = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
        self.answers = self.identities.compile(native, now=NOW)
        self.node = NodeFeed(policy())

    def refresh(self, offset=0):
        now = NOW + timedelta(seconds=offset)
        payload = self.feed.read(sources={'vlan22'}, challenge=self.node.begin_request(), now=now, monotonic=100 + offset)
        self.node.accept_catalog(payload, now=now, monotonic=100 + offset)
        return self.node.catalog.records(now=now, monotonic=100 + offset)

    async def test_alias_graph_arrives_with_authority_and_source_expiry(self):
        self.bridge.publish(self.answers, now=NOW, monotonic=100)
        records = self.refresh()
        self.assertEqual(len(records), 6)
        host = self.identities.alias('vlan22', dns.name.from_text('sensor.local.'))[1].to_text()
        self.assertTrue(any(r.name == host and r.type == rt.AAAA for r, _ in records))
        self.assertEqual(len(self.node.authority.unique_rrsets), 4)
        self.assertFalse(self.refresh(31))

    async def test_pod_feed_preserves_device_names_without_exclusive_claims(self):
        native = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
        answers = pod_view(native, now=NOW)
        self.bridge.publish(answers, now=NOW, monotonic=100)
        records = self.refresh()
        self.assertEqual({r.name for r, _ in records}, {r.name for r in native})
        self.assertFalse(self.node.authority.unique_rrsets)
        self.assertEqual({a.data.target.to_text() for a in answers if a.type == rt.SRV}, {'sensor.local.'})
        self.assertFalse(self.refresh(31))

    async def test_native_pod_view_withholds_cross_lan_host_and_dependencies(self):
        native = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
        foreign = tuple(replace(r, id='foreign-' + r.id, source_link='vlan55')
                        for r in native if r.type in (rt.A, rt.AAAA))
        answers = pod_view(native + foreign, now=NOW)
        self.assertEqual({a.name.to_text() for a in answers}, {'_services._dns-sd._udp.local.'})

    async def test_native_pod_view_withholds_ambiguous_service_instance(self):
        native = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
        foreign = tuple(replace(r, id='foreign-' + r.id, source_link='vlan55')
                        for r in native if r.type in (rt.SRV, rt.TXT))
        answers = pod_view(native + foreign, now=NOW)
        self.assertEqual({a.type for a in answers}, {rt.A, rt.AAAA, rt.PTR})
        self.assertTrue(all(a.name.to_text() == '_services._dns-sd._udp.local.'
                            for a in answers if a.type == rt.PTR))

    async def test_original_hostnames_resolve_only_on_other_links(self):
        from discovery.publication import decode, frame
        native = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
        aliases = lan_view(native, self.identities, now=NOW)
        hosts = lan_hostnames(native, self.identities, now=NOW)
        self.assertEqual({a.name.to_text() for a in hosts}, {'sensor.local.'})
        self.assertEqual({a.type for a in hosts}, {rt.A, rt.AAAA})
        self.assertTrue(all(a.unique for a in hosts))
        groups = lan_groups(aliases, hosts, Browser.links, now=100)
        for group in groups:
            originals = [a for a in group.records if a.name.to_text() == 'sensor.local.']
            self.assertEqual(bool(originals), group.interface != 22)
        _, accepted = decode(frame(groups, sequence=1, now=100), now=100.5,
                             previous=0, links=Browser.links, owns=self.identities.owns,
                             owns_host=self.identities.owns_host)
        self.assertEqual(len(accepted), 3)

    async def test_original_host_publication_requires_observed_source_and_unique_claim(self):
        import json
        from discovery.publication import decode, frame
        native = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
        aliases = lan_view(native, self.identities, now=NOW)
        groups = lan_groups(aliases, lan_hostnames(native, self.identities, now=NOW), Browser.links, now=100)
        payload = frame(tuple(g for g in groups if g.interface == 55), sequence=1, now=100)
        for change in ({'name': 'invented.local.'}, {'source': 'vlan55'},
                       {'source': []}, {'unique': False}, {'type': int(rt.TXT), 'data': '"x=y"'}):
            with self.subTest(change=change):
                value = json.loads(payload)
                original = next(r for r in value['groups'][0]['records'] if r['name'] == 'sensor.local.')
                original.update(change)
                with self.assertRaises(ValueError):
                    decode(encode(value), now=100.5, previous=0, links=Browser.links,
                           owns=self.identities.owns, owns_host=self.identities.owns_host)

    async def test_original_hostnames_withhold_conflicting_or_expiring_addresses(self):
        native = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
        foreign = tuple(replace(r, id='foreign-' + r.id, source_link='vlan55')
                        for r in native if r.type in (rt.A, rt.AAAA))
        aliases = lan_view(native + foreign, self.identities, now=NOW)
        self.assertTrue(aliases)
        self.assertFalse(lan_hostnames(native + foreign, self.identities, now=NOW))
        expiring = tuple(replace(r, expires_at=NOW + timedelta(seconds=4)) for r in native)
        self.assertFalse(lan_hostnames(expiring, self.identities, now=NOW))

    async def test_hostname_probe_collision_keeps_service_aliases_stable(self):
        native = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
        before = lan_view(native, self.identities, now=NOW)
        alias = self.identities.alias('vlan22', dns.name.from_text('sensor.local.'))[1]
        self.identities.resolve_conflicts(['SENSOR.local.', alias.to_text()])
        self.assertFalse(lan_hostnames(native, self.identities, now=NOW))
        self.assertEqual(lan_view(native, self.identities, now=NOW), before)

    async def test_original_hostnames_use_only_available_translated_addresses(self):
        from discovery.translation import translated_records
        native = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
        for keep, expected in ((rt.A, {rt.A, rt.AAAA}), (rt.AAAA, {rt.AAAA})):
            with self.subTest(native_family=keep):
                records = tuple(r for r in native if r.type not in (rt.A, rt.AAAA) or r.type == keep)
                rendered = translated_records(records, now=NOW, catalog_until=NOW + timedelta(seconds=30),
                                              mappings={}, nat64=True, nat46=True)
                lan_view(rendered, self.identities, now=NOW)
                hosts = lan_hostnames(rendered, self.identities, now=NOW)
                self.assertEqual({a.type for a in hosts}, expected)
                self.assertEqual({a.name.to_text() for a in hosts}, {'sensor.local.'})

    async def test_publisher_delay_does_not_extend_observation_lifetime(self):
        # A feed read during the publisher wait advances its monotonic clock.
        self.refresh(1)
        self.bridge.publish(self.answers, observed_at=NOW, now=NOW + timedelta(seconds=2), monotonic=102)
        self.assertEqual({ttl for _, ttl in self.refresh(2)}, {28})
        self.assertFalse(self.refresh(30))

    async def test_lan_withdraws_short_dependencies_without_shortening_pod_answers(self):
        native = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
        for remaining in (0, 1, 4.999, 5, 6):
            with self.subTest(remaining=remaining):
                records = tuple(replace(r, expires_at=NOW + timedelta(seconds=remaining))
                                if r.type == rt.TXT else r for r in native)
                view = lan_view(records, self.identities, now=NOW)
                self.assertEqual(any(a.type == rt.SRV for a in view), remaining >= 5)
                self.assertTrue(all(a.ttl >= 5 for a in view))
                self.assertEqual(any(a.type == rt.SRV for a in pod_view(records, now=NOW)), remaining >= 1)
        self.assertFalse(lan_view(native, self.identities, now=NOW + timedelta(seconds=90)))

    async def test_expiring_lan_record_cannot_shorten_unrelated_publication_budget(self):
        import asyncio
        import time
        from unittest.mock import Mock
        from discovery.publication import Intent, Publisher
        native = decode_snapshot(encode(fixture()), now=NOW, policy=policy()).records
        # A one-second root PTR used to constrain every link's complete graph.
        records = tuple(replace(r, expires_at=NOW + timedelta(seconds=1))
                        if r.id == 'type' else r for r in native)
        view = lan_view(records, self.identities, now=NOW)
        links = {i: Link('vlan22', 'test', {4, 6}) for i in range(1, 7)}
        publisher = Publisher(links, addresses={i: () for i in links})
        publisher.bus, publisher.owner = Mock(), 'fixture'
        async def call(path, interface, member, *args):
            await asyncio.sleep(.16)
            return ['/new'] if member == 'EntryGroupNew' else []
        publisher._call = call
        deadline = time.monotonic() + min(a.ttl for a in view)
        async with asyncio.timeout(3):
            await publisher.reconcile(tuple(Intent(i, f, deadline, view) for i in links for f in (4, 6)))
        self.assertEqual(len(publisher.groups), 12)
        publisher.bus.disconnect.assert_not_called()

    async def test_epoch_loss_withdraws_catalog_and_rejects_demand(self):
        self.bridge.publish(self.answers, now=NOW, monotonic=100)
        self.assertTrue(self.refresh())
        self.bridge.clear()
        self.assertFalse(self.refresh(1))
        self.assertEqual(self.bridge.addresses, {})
        with self.assertRaises(OSError):
            await self.bridge.demand(Question('sensor.local.', rt.A), {'vlan22'})
        self.bridge.browser = Browser()
        self.bridge.publish(self.answers, now=NOW + timedelta(seconds=2), monotonic=102)
        self.assertTrue(self.refresh(2))

    async def test_alias_lookup_is_case_insensitive_and_source_scoped(self):
        alias = self.identities.alias('vlan22', dns.name.from_text('Sensor._esphomelib._tcp.local.'))[1].to_text()
        await self.bridge.demand(Question(alias.lower(), rt.SRV), {'vlan22', 'vlan55'})
        queries = self.bridge.browser.queries
        self.assertEqual({(q.interface, q.family) for q in queries}, {(22, 4), (22, 6)})
        self.assertEqual({q.name for q in queries}, {'sensor._esphomelib._tcp.local.'})
        self.assertEqual(self.send_questions.call_count, 2)
        for call in self.send_questions.call_args_list:
            self.assertEqual(call.args[2], 'sensor._esphomelib._tcp.local.')
            self.assertEqual(call.args[3], (rt.SRV,))
            self.assertEqual(call.args[4], self.bridge.addresses[22])

    async def test_unknown_name_and_any_use_only_approved_links_and_types(self):
        await self.bridge.demand(Question('unknown.local.', rt.ANY), {'vlan55'})
        queries = self.bridge.browser.queries
        self.assertEqual({q.type for q in queries}, {rt.A, rt.AAAA, rt.PTR, rt.SRV, rt.TXT})
        self.assertEqual({(q.interface, q.family) for q in queries}, {(55, 6)})
        self.send_questions.assert_called_once_with(55, 6, 'unknown.local.',
            sorted((rt.A, rt.AAAA, rt.PTR, rt.SRV, rt.TXT)), self.bridge.addresses[55])

    async def test_translated_host_miss_queries_both_native_families(self):
        for translation in (None, object()):
            self.feed.translation = translation
            for kind in (rt.A, rt.AAAA):
                self.bridge.browser.queries.clear()
                self.send_questions.reset_mock()
                await self.bridge.demand(Question('uncached.local.', kind), {'vlan55'})
                expected = (rt.A, rt.AAAA) if translation is not None else (kind,)
                self.assertEqual({q.type for q in self.bridge.browser.queries}, set(expected))
                self.send_questions.assert_called_once_with(55, 6, 'uncached.local.', expected,
                                                            self.bridge.addresses[55])

    async def test_retired_alias_is_not_queried_or_reimported(self):
        alias = self.identities.alias('vlan22', dns.name.from_text('sensor.local.'))[1].to_text()
        self.identities.rotate_alias(alias)
        await self.bridge.demand(Question(alias, rt.A), {'vlan22'})
        self.assertEqual(self.bridge.browser.queries, [])
        self.send_questions.assert_not_called()
        self.bridge.browser.healthy = False
        with self.assertRaises(RuntimeError):
            self.bridge.publish(self.answers, now=NOW, monotonic=100)


class FreshQuestionTests(unittest.TestCase):
    def test_fresh_query_has_only_questions_for_both_families(self):
        import dns.message
        for family in (4, 6):
            with self.subTest(family=family), patch('discovery.transport._send_multicast') as send:
                send_questions(22, family, '_esphomelib._tcp.local.', (rt.PTR,), ('198.18.22.1', 'fd00:22::1'))
                message = dns.message.from_wire(send.call_args.args[2][0])
                self.assertEqual((message.id, message.flags), (0, 0))
                self.assertEqual(len(message.question), 1)
                self.assertEqual(message.question[0].name.to_text(), '_esphomelib._tcp.local.')
                self.assertEqual(message.question[0].rdclass, 1)
                self.assertEqual(message.question[0].rdtype, rt.PTR)
                self.assertFalse(message.answer or message.authority or message.additional)

    def test_fresh_query_rejects_out_of_scope_names_and_types(self):
        with patch('discovery.transport._send_multicast') as send:
            for name, kinds in [('example.org.', (rt.A,)), ('sensor.local.', (rt.AXFR,)),
                                ('sensor.local.', ())]:
                with self.subTest(name=name, kinds=kinds), self.assertRaises(ValueError):
                    send_questions(22, 4, name, kinds, ('198.18.22.1',))
            send.assert_not_called()
