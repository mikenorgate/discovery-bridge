"""Multipacket known-answer suppression, timing, bounds and local-only state."""
import asyncio
from datetime import datetime, timedelta, timezone
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import dns.flags
import dns.message
import dns.rrset

from discovery.catalog import Catalog
from discovery.feed import encode
from discovery.pod_socket import PodSession
from discovery.query import parse_pod_query
from discovery.records import PublicationPolicy
from test_catalog import fixture, policy
from test_pod_socket import Endpoint
from test_query import query


def first(name='_esphomelib._tcp.local.', kind='PTR'):
    value = query(name, kind); value.flags |= dns.flags.TC
    return value


def continuation(*, truncated=False, private=False):
    value = dns.message.Message()
    value.flags = dns.flags.TC if truncated else 0
    value.answer.append(dns.rrset.from_text(
        'private-pod.local.' if private else '_esphomelib._tcp.local.', 120, 'IN',
        'AAAA' if private else 'PTR',
        '2001:db8:1000:f000::99' if private else 'Sensor._esphomelib._tcp.local.'))
    return value


class ContinuationParserTests(unittest.TestCase):
    def test_tc_and_questionless_packets_require_explicit_opt_in(self):
        for message in (first(), continuation(), continuation(truncated=True)):
            with self.assertRaises(ValueError): parse_pod_query(message.to_wire())
            parsed = parse_pod_query(message.to_wire(), allow_continuation=True)
            with self.assertRaises(ValueError): parsed.lookup_payload()

    def test_continuation_opt_in_never_admits_probes_or_responses(self):
        for field in ('response', 'probe'):
            message = first()
            if field == 'response': message.flags |= dns.flags.QR
            else: message.authority.extend(continuation(private=True).answer)
            with self.assertRaises(ValueError):
                parse_pod_query(message.to_wire(), allow_continuation=True)


class ContinuationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.feed = SimpleNamespace(catalog=Catalog(policy()), authority=None)
        data = fixture(); now = datetime.now(timezone.utc)
        data.update(issued_at=now.isoformat(), valid_until=(now + timedelta(seconds=30)).isoformat())
        for record in data['records']: record['expires_at'] = (now + timedelta(seconds=30)).isoformat()
        self.feed.catalog.install(encode(data), now=now, monotonic=time.monotonic())
        self.feed.authority = PublicationPolicy(frozenset(r['id'] for r in data['records']))
        self.endpoint, self.misses = Endpoint(), []
        async def miss(value): self.misses.append(value.lookup_payload())
        self.session = PodSession([self.endpoint], self.feed, deadline=time.monotonic() + 10, on_miss=miss)
        self.random = patch('discovery.pod_socket.random.uniform', return_value=.45)
        self.random.start()
        self.addCleanup(self.random.stop)

    async def asyncTearDown(self): await self.session.aclose()

    def add(self, message, *, peer=('fd00::2', 5353), size=None):
        wire = message.to_wire()
        self.session._assemble(self.endpoint, parse_pod_query(wire, allow_continuation=True),
                               peer, len(wire) if size is None else size, time.monotonic())

    async def finish(self): await asyncio.gather(*tuple(self.session.tasks), return_exceptions=True)

    async def test_later_known_answer_suppresses_original_question(self):
        original = self.feed.catalog.snapshot
        self.add(first()); self.add(continuation())
        await self.finish()
        self.assertEqual(self.endpoint.sent, [])
        self.assertEqual(self.misses, [{'schema': 1, 'questions': [
            {'name': '_esphomelib._tcp.local.', 'type': 12, 'class': 1}]}])
        self.assertIs(self.feed.catalog.snapshot, original)
        self.assertEqual(self.session.pending, {})

    async def test_tc_delay_is_extended_from_last_truncated_packet(self):
        start = time.monotonic()
        self.add(first('sensor.local.', 'AAAA'))
        await asyncio.sleep(.2)
        self.add(continuation(truncated=True, private=True))
        await asyncio.sleep(.3)
        self.assertEqual(self.endpoint.sent, [])
        await self.finish()
        self.assertGreaterEqual(time.monotonic() - start, .6)
        self.assertTrue(self.endpoint.sent)
        self.assertNotIn(b'private-pod', self.endpoint.sent[0].wire)

    async def test_continuation_never_exports_private_records(self):
        self.add(first('missing.local.', 'AAAA')); self.add(continuation(private=True))
        await self.finish()
        self.assertEqual(self.misses, [{'schema': 1, 'questions': [{'name': 'missing.local.', 'type': 28, 'class': 1}]}])
        self.assertEqual(self.endpoint.sent, [])

    async def test_orphan_legacy_and_foreign_peer_continuations_are_ignored(self):
        self.add(continuation())
        self.add(first(), peer=('fd00::2', 40000))
        self.assertEqual(self.session.pending, {})
        self.add(first())
        self.add(continuation(), peer=('fd00::3', 5353))
        await self.finish()
        self.assertTrue(self.endpoint.sent)
        self.assertEqual(self.misses, [{'schema': 1, 'questions': [
            {'name': '_esphomelib._tcp.local.', 'type': 12, 'class': 1}]}])

    async def test_byte_packet_and_overlap_limits_discard_without_lookup(self):
        for mode in ('bytes', 'packets', 'overlap'):
            with self.subTest(mode=mode):
                self.add(first('missing.local.', 'AAAA'))
                if mode == 'bytes': self.add(continuation(), size=32768)
                elif mode == 'packets':
                    for _ in range(16): self.add(continuation(truncated=True))
                else: self.add(first('other.local.', 'AAAA'))
                await self.finish()
                self.assertEqual(self.session.pending, {})
                self.assertEqual(self.endpoint.sent, [])
                self.assertEqual(self.misses, [])

    async def test_hard_deadline_drops_a_sequence_instead_of_answering_early(self):
        self.add(first())
        batch = next(iter(self.session.pending.values()))
        batch.expires = time.monotonic() + .02
        await self.finish()
        self.assertEqual(self.endpoint.sent, [])
        self.assertEqual(self.session.pending, {})

    async def test_lease_expiry_and_close_cancel_assembly(self):
        self.add(first('missing.local.', 'AAAA'))
        self.session.deadline = time.monotonic() - 1
        await self.finish()
        self.assertEqual(self.misses, [])
        self.add(first())
        await self.session.aclose()
        self.assertFalse(self.session.pending)
        self.assertFalse(self.session.tasks)

    async def test_ingress_limit_discards_in_progress_sequence(self):
        self.add(first('missing.local.', 'AAAA'))
        packets = [continuation().to_wire()]
        def receive():
            if not packets: raise BlockingIOError
            return packets.pop(), ('fd00::2', 5353)
        self.endpoint.receive = receive
        self.session.ingress = SimpleNamespace(take=lambda now: False)
        self.session._receive(self.endpoint)
        await self.finish()
        self.assertFalse(self.session.pending)
        self.assertFalse(self.endpoint.sent)
        self.assertFalse(self.misses)
