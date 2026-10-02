"""Bounded internal HTTP catalog and question-only lookup API.

No implicit listeners, credentials, discovery publications or NAT allocations.
The owner supplies an operator-approved bind socket, policy and LAN callback.
"""
import asyncio
from collections import Counter
from datetime import datetime, timezone
import json
import ipaddress
import time

import h11

from discovery.catalog import _fields, _object
from discovery.feed import MAX_FEED_BYTES, encode, nonce
from discovery.lookup import Bucket, Busy, MAX_LOOKUP_BYTES, decode_lookup


def utcnow():
    return datetime.now(timezone.utc)


async def receive(connection, reader, *, request, limit):
    """One explicit Content-Length JSON message; no streaming/chunked bodies."""
    start, length, body = None, None, bytearray()
    while True:
        event = connection.next_event()
        if event is h11.NEED_DATA:
            block = await reader.read(8192)
            if not block:
                raise ValueError('incomplete HTTP message')
            connection.receive_data(block)
        elif isinstance(event, h11.Request if request else h11.Response):
            if start is not None or event.http_version != b'1.1':
                raise ValueError('invalid HTTP start')
            start = event
            if sum(len(k) + len(v) + 4 for k, v in event.headers) > 8192:
                raise ValueError('HTTP header limit')
            headers = {}
            for key, value in event.headers:
                if key in headers:
                    raise ValueError('duplicate HTTP header')
                headers[key] = value
            if b'transfer-encoding' in headers or b'content-encoding' in headers or b'expect' in headers:
                raise ValueError('unsupported HTTP framing')
            raw_length = headers.get(b'content-length', b'')
            if not raw_length.isdigit() or len(raw_length) > 8:
                raise ValueError('Content-Length required')
            length = int(raw_length)
            if not 1 <= length <= limit or headers.get(b'content-type') != b'application/json':
                raise ValueError('HTTP body size/type rejected')
        elif isinstance(event, h11.Data):
            body.extend(event.data)
            if start is None or len(body) > limit or len(body) > length:
                raise ValueError('HTTP body exceeds limit')
        elif isinstance(event, h11.EndOfMessage):
            if start is None or len(body) != length or event.headers or connection.trailing_data[0]:
                raise ValueError('incomplete or pipelined HTTP message')
            return start, bytes(body)
        else:
            raise ValueError('unexpected HTTP event')


async def send(connection, writer, start, body):
    writer.write(connection.send(start))
    writer.write(connection.send(h11.Data(data=body)))
    writer.write(connection.send(h11.EndOfMessage()))
    await writer.drain()


def headers(body):
    return [(b'content-type', b'application/json'), (b'content-length', str(len(body)).encode()),
            (b'connection', b'close'), (b'cache-control', b'no-store')]


class GatewayAPI:
    def __init__(self, feed, lookups, *, now=utcnow, clock=time.monotonic):
        self.feed, self.lookups = feed, lookups
        self.now, self.clock = now, clock
        self.global_reads = Bucket(64, 128)

    async def handle(self, method, target, payload):
        try:
            sources = self.feed.source.policy.sources
            tick = self.clock()
            if not self.global_reads.take(tick):
                raise Busy('request rate exceeded')
            if method != b'POST':
                return 405, encode({'error': 'method'})
            if target == b'/v1/catalog':
                value = json.loads(payload.decode('utf-8'), object_pairs_hook=_object)
                _fields(value, {'schema', 'nonce'})
                if type(value['schema']) is not int or value['schema'] != 1:
                    raise ValueError('invalid catalog request')
                challenge = nonce(value['nonce'])
                return 200, self.feed.read(sources=sources, challenge=challenge,
                                           now=self.now(), monotonic=tick)
            if target == b'/v1/lookup':
                count = await self.lookups.submit(payload)
                return 202, encode({'schema': 1, 'accepted': count})
            return 404, encode({'error': 'route'})
        except Busy:
            return 429, encode({'error': 'capacity'})
        except (ValueError, UnicodeError, RecursionError):
            return 400, encode({'error': 'request'})
        except (TimeoutError, OSError):
            return 503, encode({'error': 'unavailable'})


class GatewayServer:
    """Bound connections before reading HTTP; admit only configured source prefixes.

    Single event-loop owner; one request per connection, absolute deadline.
    Socket ownership transfers on start. Shutdown never owns feed persistence.
    """
    def __init__(self, api, clients, *, max_connections=32, timeout=5):
        if not 1 <= max_connections <= 128 or not 0 < timeout <= 10:
            raise ValueError('invalid HTTP service limits')
        if not isinstance(clients, (list, tuple)):
            raise ValueError('explicit client source prefixes required')
        self.clients = tuple(ipaddress.ip_network(value) for value in clients)
        if not self.clients or len(self.clients) > 32 or any(n.prefixlen == 0 or n.is_multicast for n in self.clients):
            raise ValueError('explicit client source prefixes required')
        self.api = api
        self.max_connections, self.timeout = max_connections, timeout
        self.connections, self.listener, self.acceptor = set(), None, None
        self.events = Counter()  # fixed event names; no client names, bodies or keys

    async def start(self, listener):
        if self.acceptor is not None:
            raise RuntimeError('gateway already started')
        listener.setblocking(False)
        self.listener = listener
        self.acceptor = asyncio.create_task(self._accept())

    async def _accept(self):
        loop = asyncio.get_running_loop()
        while True:
            sock, peer = await loop.sock_accept(self.listener)
            address = ipaddress.ip_address(peer[0])
            if not any(address in network for network in self.clients):
                self.events["source_denied"] += 1
                sock.close()
                continue
            if len(self.connections) >= self.max_connections:
                self.events['connection_limit'] += 1
                sock.close()
                continue
            task = asyncio.create_task(self._serve(sock))
            self.connections.add(task)
            task.add_done_callback(self._done)

    def _done(self, task):
        self.connections.discard(task)
        if not task.cancelled():
            if task.exception() is not None:
                self.events['internal_error'] += 1

    async def _serve(self, sock):
        transport = writer = None
        try:
            async with asyncio.timeout(self.timeout):
                loop = asyncio.get_running_loop()
                reader = asyncio.StreamReader(limit=16384)
                protocol = asyncio.StreamReaderProtocol(reader)
                transport, _ = await loop.connect_accepted_socket(lambda: protocol, sock)
                writer = asyncio.StreamWriter(transport, protocol, reader, loop)
                connection = h11.Connection(h11.SERVER, max_incomplete_event_size=8192)
                request, body = await receive(connection, reader, request=True, limit=MAX_LOOKUP_BYTES)
                status, result = await self.api.handle(request.method, request.target, body)
                self.events[f'http_{status}'] += 1
                await send(connection, writer, h11.Response(status_code=status, headers=headers(result)), result)
                writer.close()
                await writer.wait_closed()
        except (TimeoutError, OSError, ValueError, h11.ProtocolError):
            self.events['transport_or_request_rejected'] += 1
        finally:
            if transport is not None:
                transport.abort()
            sock.close()

    async def close(self):
        if self.acceptor is not None:
            self.acceptor.cancel()
            await asyncio.gather(self.acceptor, return_exceptions=True)
        if self.listener is not None:
            self.listener.close()
        tasks = tuple(self.connections)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class GatewayClient:
    """Fixed numeric operator endpoint; no DNS, redirect or proxy fallback."""
    def __init__(self, host, port, *, timeout=5, now=utcnow, clock=time.monotonic):
        address = ipaddress.ip_address(host)
        if address.is_unspecified or address.is_multicast or type(port) is not int or not 1 <= port <= 65535 or not 0 < timeout <= 10:
            raise ValueError('explicit unicast endpoint and bounded deadline required')
        self.host, self.port = str(address), port
        self.authority = f'[{address}]:{port}' if address.version == 6 else f'{address}:{port}'
        self.timeout, self.now, self.clock = timeout, now, clock
        self._refresh_lock = asyncio.Lock()

    async def post(self, target, payload, *, expected):
        if target not in (b'/v1/catalog', b'/v1/lookup', b'/v1/publications') or not 1 <= len(payload) <= MAX_LOOKUP_BYTES:
            raise ValueError('invalid gateway operation')
        writer = None
        try:
            async with asyncio.timeout(self.timeout):
                reader, writer = await asyncio.open_connection(
                    self.host, self.port, limit=16384)
                connection = h11.Connection(h11.CLIENT, max_incomplete_event_size=8192)
                start = h11.Request(method=b'POST', target=target,
                                    headers=headers(payload) + [(b'host', self.authority.encode('ascii'))])
                await send(connection, writer, start, payload)
                response, body = await receive(connection, reader, request=False, limit=MAX_FEED_BYTES)
                if response.status_code != expected:
                    raise ValueError(f'gateway HTTP status {response.status_code}')
                return body
        finally:
            if writer is not None:
                writer.transport.abort()

    async def refresh(self, feed):
        async with self._refresh_lock:
            challenge = feed.begin_request()
            try:
                body = await self.post(b'/v1/catalog', encode({'schema': 1, 'nonce': challenge}), expected=200)
                return feed.accept_catalog(body, now=self.now(), monotonic=self.clock())
            finally:
                feed.abort_request()

    async def lookup(self, query):
        payload = encode(query.lookup_payload())
        decode_lookup(payload)
        return await self.post(b'/v1/lookup', payload, expected=202)
