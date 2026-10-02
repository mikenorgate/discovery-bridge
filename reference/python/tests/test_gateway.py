"""Real loopback HTTP, source admission, API isolation and failure limits."""
import asyncio
import json
from pathlib import Path
import socket
import tempfile
import unittest

import dns.message
import dns.rrset

from discovery.catalog import Catalog
from discovery.feed import GatewayFeed, NodeFeed, encode
from discovery.gateway import GatewayAPI, GatewayClient, GatewayServer
from discovery.lookup import Bucket, LookupCoordinator
from discovery.query import parse_pod_query
from discovery.records import PublicationPolicy
from discovery.responder import Responder
from test_catalog import NOW, fixture, policy
from test_lookup import request
from test_query import query


class GatewayHTTPTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = Path(self.temp.name)
        self.calls = []
        async def demand(question, sources):
            self.calls.append((question, sources))
        self.lookups = LookupCoordinator({'vlan22'}, demand, clock=lambda: 100)
        self.source = Catalog(policy())
        data = fixture()
        self.source.install(encode(data), now=NOW, monotonic=100)
        self.feed = GatewayFeed(self.source, PublicationPolicy(frozenset(r['id'] for r in data['records'])), path / 'gateway.db')
        self.node = NodeFeed(policy())
        self.api = GatewayAPI(self.feed, self.lookups, now=lambda: NOW, clock=lambda: 100)
        self.server = GatewayServer(self.api, ['127.0.0.1/32'], timeout=.5, max_connections=2)
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(8)
        self.port = listener.getsockname()[1]
        await self.server.start(listener)

    async def asyncTearDown(self):
        await self.server.close()
        await self.lookups.close()
        self.feed.close()

    def client(self):
        return GatewayClient('127.0.0.1', self.port, timeout=1, now=lambda: NOW, clock=lambda: 100)

    async def test_http_catalog_to_responder_and_question_only_miss(self):
        client = self.client()
        self.assertEqual(await client.refresh(self.node), 1)
        self.assertEqual(len(self.node.catalog.records(now=NOW, monotonic=100)), 6)
        message = query()
        message.answer.append(dns.rrset.from_text('private-pod.local.', 120, 'IN', 'AAAA', '2001:db8:1000:f000::1'))
        parsed = parse_pod_query(message.to_wire())
        await client.lookup(parsed)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][0].name, '_esphomelib._tcp.local.')
        self.assertEqual(self.calls[0][1], {'vlan22'})
        result = Responder(self.node.catalog).build(parsed, policy=self.node.authority, now=NOW,
                    monotonic=100, source_port=5353, family=6)
        reply = dns.message.from_wire(result.replies[0].wire)
        self.assertEqual(reply.question, [])
        self.assertNotIn(b'private-pod', result.replies[0].wire)
        self.assertEqual({r.rdtype for r in reply.additional}, {1, 28, 33, 16})

    async def test_source_not_in_allowlist_is_closed_before_request(self):
        import ipaddress
        self.server.clients = (ipaddress.ip_network('192.0.2.1/32'),)
        with self.assertRaises((ValueError, OSError)):
            await self.client().refresh(self.node)
        self.assertIsNone(self.node.catalog.snapshot)
        self.assertEqual(self.server.events['source_denied'], 1)
        self.assertEqual(self.calls, [])

    async def test_numeric_endpoint_and_explicit_source_allowlist_required(self):
        for host in ('gateway.invalid', '0.0.0.0', 'ff02::1'):
            with self.assertRaises(ValueError):
                GatewayClient(host, self.port)
        for clients in ([], ['0.0.0.0/0'], ['::/0']):
            with self.assertRaises(ValueError):
                GatewayServer(self.api, clients)

    async def test_ipv6_catalog_and_source_denial(self):
        import ipaddress
        listener = socket.socket(socket.AF_INET6)
        listener.bind(('::1', 0))
        listener.listen(8)
        server = GatewayServer(self.api, ['::1/128'])
        await server.start(listener)
        client = GatewayClient('::1', listener.getsockname()[1], timeout=1,
                               now=lambda: NOW, clock=lambda: 100)
        try:
            self.assertEqual(await client.refresh(self.node), 1)
            server.clients = (ipaddress.ip_network('2001:db8::/64'),)
            with self.assertRaises((ValueError, OSError)):
                await client.refresh(self.node)
            self.assertEqual(server.events['source_denied'], 1)
        finally:
            await server.close()

    async def test_nodes_share_catalog_but_cannot_override_sources_or_publish(self):
        other = NodeFeed(policy())
        await self.client().refresh(other)
        await self.client().refresh(self.node)
        self.assertEqual(other.catalog.snapshot.records, self.node.catalog.snapshot.records)
        self.assertEqual(len(other.catalog.snapshot.records), 6)
        for payload in (request(view='all'), request(sources=['vlan55']), request(records=[]), request(pod_uid='other')):
            with self.assertRaisesRegex(ValueError, '400'):
                await self.client().post(b'/v1/lookup', payload, expected=202)
        self.assertEqual(self.calls, [])

    async def test_api_read_quota_and_no_publication_route(self):
        self.api.global_reads = Bucket(1, 8)
        for _ in range(8):
            await self.client().refresh(self.node)
        with self.assertRaisesRegex(ValueError, '429'):
            await self.client().refresh(self.node)
        self.api.global_reads = Bucket(1, 8)
        for method, route, expected in ((b'POST', b'/v1/publish', 404), (b'GET', b'/v1/catalog', 405)):
            code, _ = await self.api.handle(method, route, b'{}')
            self.assertEqual(code, expected)
        self.assertFalse(self.calls)

    async def test_malformed_framing_closes_before_lan_work(self):
        requests = [b'POST /v1/lookup HTTP/1.1\r\nHost: gateway.test\r\nContent-Type: application/json\r\n'
                    + framing + b'\r\n' + body for framing, body in (
                        (b'Transfer-Encoding: chunked\r\n', b'2\r\n{}\r\n0\r\n\r\n'),
                        (b'Content-Length: 20000\r\n', b'{}'),
                        (b'Content-Length: 2\r\nContent-Encoding: gzip\r\n', b'{}'),
                        (b'Content-Length: 2\r\nX-Big: ' + b'x' * 9000 + b'\r\n', b'{}'))]
        for raw in requests:
            reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
            try:
                writer.write(raw)
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
            finally:
                writer.close()
                await writer.wait_closed()
        self.assertEqual(self.calls, [])

    async def test_stalled_connections_are_bounded_before_requests(self):
        clients = []
        try:
            for _ in range(3):
                clients.append(await asyncio.open_connection('127.0.0.1', self.port))
            await asyncio.sleep(.02)
            self.assertEqual(len(self.server.connections), 2)
            self.assertEqual(await asyncio.wait_for(clients[2][0].read(), .2), b'')
            self.assertEqual(self.server.events['connection_limit'], 1)
            await asyncio.sleep(.55)
            self.assertEqual(len(self.server.connections), 0)
            await self.client().refresh(self.node)
        finally:
            for _, writer in clients:
                writer.close()
                await writer.wait_closed()

    async def test_feed_loss_does_not_renew_existing_lease(self):
        await self.client().refresh(self.node)
        await self.server.close()
        with self.assertRaises(OSError):
            await self.client().refresh(self.node)
        from datetime import timedelta
        self.assertEqual(self.node.catalog.records(now=NOW + timedelta(seconds=30), monotonic=130), ())
        self.assertIsNone(self.node._nonce)
