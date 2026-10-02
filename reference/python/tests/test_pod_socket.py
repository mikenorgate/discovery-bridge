"""Pod response-loop expiry, fresh-feed use, containment and bounded admission."""
import asyncio
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
import socket
import time
from types import SimpleNamespace
import unittest

import dns.message
import dns.rdatatype as rt
import dns.rrset

from discovery.catalog import Catalog
from discovery.feed import encode
from discovery.pod_socket import PodSession, PodSocket
from discovery.query import parse_pod_query
from discovery.records import PublicationPolicy
from discovery.responder import Reply
from test_catalog import fixture, policy
from test_query import query
from test_local_claims import claim


class Endpoint:
    family = 6
    source = ip_address('fd00::2')
    port = 40000

    def __init__(self):
        self.socket, self.other = socket.socketpair()
        self.sent, self.incoming = [], []

    def send(self, reply, peer):
        self.sent.append(reply)

    def receive(self):
        if not self.incoming:
            raise BlockingIOError()
        return self.incoming.pop(0), ('fd00::2', self.port)

    def close(self):
        self.socket.close()
        self.other.close()


class PodSessionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.feed = SimpleNamespace(catalog=Catalog(policy()), authority=None)
        self.data = fixture()
        now = datetime.now(timezone.utc)
        self.data.update(issued_at=now.isoformat(), valid_until=(now + timedelta(seconds=30)).isoformat())
        for record in self.data['records']:
            record['expires_at'] = (now + timedelta(seconds=30)).isoformat()
        self.feed.catalog.install(encode(self.data), now=now, monotonic=time.monotonic())
        self.feed.authority = PublicationPolicy(frozenset(r['id'] for r in self.data['records']))
        self.endpoint = Endpoint()
        self.calls = []
        async def miss(query):
            self.calls.append(query.lookup_payload())
        self.session = PodSession([self.endpoint], self.feed, deadline=time.monotonic() + 5, on_miss=miss)

    async def asyncTearDown(self):
        await self.session.aclose()

    async def answer(self, message=None):
        await self.session._answer(self.endpoint, parse_pod_query((message or query()).to_wire()), ('fd00::2', 40000))

    async def test_reply_ttl_is_capped_by_eligibility(self):
        await self.answer()
        reply = dns.message.from_wire(self.endpoint.sent[0].wire)
        self.assertTrue(reply.answer)
        self.assertTrue(all(0 < r.ttl <= 4 for r in reply.answer + reply.additional))

    async def test_local_claim_withholds_dependencies_and_never_leaves_pod(self):
        self.endpoint.port = 5353
        await self.session._answer(self.endpoint, parse_pod_query(query().to_wire()), ('fd00::2', 5353))
        self.endpoint.sent.clear()
        self.endpoint.incoming = [claim(probe=True).to_wire()]
        self.session._receive(self.endpoint)
        self.assertTrue(self.endpoint.sent)  # Withdraw the previously delivered chain.
        self.assertTrue(all(a.ttl == 0 for reply in self.endpoint.sent for a in reply.records))
        self.endpoint.sent.clear()
        await self.answer(query('sensor.local.', 'AAAA'))
        await self.answer()
        self.assertFalse(self.endpoint.sent)
        self.assertNotIn('sensor.local.', str(self.calls))
        self.assertNotIn('fd00::2', str(self.calls))
        self.assertFalse(self.feed.authority.blocked_names)  # Other pods remain unaffected.

    async def test_own_multicast_loopback_does_not_claim_gateway_names(self):
        self.endpoint.port = 5353
        await self.session._answer(self.endpoint, parse_pod_query(query().to_wire()), ('fd00::2', 5353))
        self.endpoint.incoming = [r.wire for r in self.endpoint.sent]
        self.session._receive(self.endpoint)
        self.assertFalse(self.session.claims.names)
        self.endpoint.sent.clear()
        await self.answer(query('sensor.local.', 'AAAA'))
        self.assertTrue(self.endpoint.sent)

    async def test_claim_capacity_closes_delivery(self):
        self.endpoint.port = 5353
        self.session.claims.names = {f'pod{i}.local.': time.monotonic() + 10 for i in range(256)}
        self.endpoint.incoming = [claim().to_wire()]
        self.session._receive(self.endpoint)
        self.assertTrue(self.session.closed)

    async def test_feed_replacement_is_used_without_recreating_session(self):
        await self.answer()
        self.endpoint.sent.clear()
        self.feed.catalog = Catalog(policy())
        await self.answer()
        self.assertEqual(self.endpoint.sent, [])
        self.assertEqual(self.calls[0]['questions'][0]['name'], '_esphomelib._tcp.local.')

    async def test_withdrawal_sends_only_previously_answered_records_once(self):
        await self.session._answer(self.endpoint, parse_pod_query(query().to_wire()), ('fd00::2', 5353))
        previous = {a.key for reply in self.endpoint.sent for a in reply.records}
        self.endpoint.sent.clear()
        self.session._withdraw()
        self.assertFalse(self.endpoint.sent)
        self.feed.catalog = Catalog(policy())
        self.session._withdraw()
        self.assertEqual({a.key for reply in self.endpoint.sent for a in reply.records}, previous)
        for reply in self.endpoint.sent:
            message = dns.message.from_wire(reply.wire)
            self.assertFalse(message.question)
            self.assertTrue(all(rr.ttl == 0 for rr in message.answer))
        self.endpoint.sent.clear()
        self.session._withdraw()
        self.assertFalse(self.endpoint.sent)

    async def test_never_withdraw_unsent_or_legacy_only_records(self):
        self.session._withdraw()
        self.assertFalse(self.endpoint.sent)
        await self.answer()
        self.endpoint.sent.clear()
        self.feed.catalog = Catalog(policy())
        self.session._withdraw()
        self.assertFalse(self.endpoint.sent)

    async def test_rate_limited_withdrawal_retries_and_expiry_stops_sends(self):
        await self.session._answer(self.endpoint, parse_pod_query(query().to_wire()), ('fd00::2', 5353))
        self.endpoint.sent.clear()
        self.feed.catalog = Catalog(policy())
        original = self.session.egress
        self.session.egress = SimpleNamespace(take=lambda _: False)
        self.session._withdraw()
        self.assertFalse(self.endpoint.sent)
        self.session.egress = original
        self.session.deadline = time.monotonic() - 1
        self.session._withdraw()
        self.assertFalse(self.endpoint.sent)
        self.session.renew(time.monotonic() + 5)
        self.session._withdraw()
        self.assertTrue(self.endpoint.sent)

    async def test_misses_never_include_pod_records(self):
        request = query('missing.local.', 'AAAA')
        request.answer.append(dns.rrset.from_text('private-pod.local.', 120, 'IN', 'AAAA', '2001:db8:1000:f000::1'))
        await self.answer(request)
        self.assertEqual(self.endpoint.sent, [])
        self.assertNotIn('private-pod', str(self.calls))
        self.assertEqual(self.calls, [{'schema': 1, 'questions': [{'name': 'missing.local.', 'type': 28, 'class': 1}]}])

    async def test_answered_browses_still_refresh_without_exporting_known_answers(self):
        for name in ['_services._dns-sd._udp.local.', '_esphomelib._tcp.local.']:
            with self.subTest(name=name):
                self.calls.clear()
                request = query(name)
                request.answer.append(dns.rrset.from_text('private-pod.local.', 120, 'IN', 'AAAA', 'fd00::2'))
                await self.answer(request)
                self.assertEqual(self.calls, [{'schema': 1, 'questions': [
                    {'name': name, 'type': 12, 'class': 1}]}])

    async def test_answered_host_lookup_does_not_refresh(self):
        await self.answer(query('sensor.local.', 'AAAA'))
        self.assertTrue(self.endpoint.sent)
        self.assertEqual(self.calls, [])

    async def test_ha_sized_browse_answers_known_service_and_batches_misses(self):
        request = query()
        request.question.extend(query(f'_missing{i}._tcp.local.').question[0] for i in range(60))
        request.answer.append(dns.rrset.from_text('private-pod.local.', 120, 'IN', 'AAAA', 'fd00::2'))
        await self.session._answer(self.endpoint, parse_pod_query(request.to_wire()), ('fd00::2', 5353))
        self.assertTrue(self.endpoint.sent)
        self.assertEqual(sum(len(c['questions']) for c in self.calls), 61)
        self.assertTrue(all(len(c['questions']) <= 16 for c in self.calls))
        self.assertNotIn('private-pod', str(self.calls))

    async def test_expired_session_never_sends_or_looks_up(self):
        self.session.deadline = time.monotonic() - 1
        await self.answer()
        await self.answer(query('missing.local.', 'AAAA'))
        self.assertEqual(self.endpoint.sent, [])
        self.assertEqual(self.calls, [])
        for deadline in (float('nan'), time.monotonic() - 1, time.monotonic() + 31):
            with self.assertRaises(ValueError):
                self.session.renew(deadline)

    async def test_duplicate_queries_and_pending_work_are_bounded(self):
        self.endpoint.incoming = [query().to_wire()] * 40
        for _ in range(3):
            self.session._receive(self.endpoint)
        self.assertEqual(len(self.session.tasks), 1)
        await asyncio.gather(*self.session.tasks)
        self.assertEqual(len(self.endpoint.sent), 1)
        self.endpoint.incoming = [query(f'unknown{i}.local.', 'AAAA').to_wire() for i in range(40)]
        for _ in range(3):
            self.session._receive(self.endpoint)
        self.assertLessEqual(len(self.session.tasks), 17)

    async def test_close_cancels_pending_replies(self):
        self.session._task(self.session._answer(self.endpoint, parse_pod_query(query().to_wire()), ('fd00::2', 5353)))
        await self.session.aclose()
        self.assertEqual(self.endpoint.sent, [])
        self.assertFalse(self.session.tasks)


class SocketBoundaryTests(unittest.TestCase):
    def test_questions_and_foreign_peers_are_rejected_before_send(self):
        endpoint = PodSocket.__new__(PodSocket)
        endpoint.closed, endpoint.family = False, 6
        endpoint.addresses = frozenset({ip_address('fd00::2')})
        with self.assertRaises(ValueError):
            endpoint.send(Reply('multicast', 6, query().to_wire(), ()), ('fd00::2', 5353))
        message = dns.message.make_response(query())
        with self.assertRaises(ValueError):
            endpoint.send(Reply('peer', 6, message.to_wire(), ()), ('fd00::3', 5353))

    def test_revoked_receive_is_terminal(self):
        endpoint = PodSocket.__new__(PodSocket)
        endpoint.socket = SimpleNamespace(recvmsg=lambda *args: (b'', [], 0, None))
        with self.assertRaises(OSError):
            endpoint.receive()
