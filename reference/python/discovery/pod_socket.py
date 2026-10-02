"""Linux multicast-bound pod sockets and a bounded answer-only response loop.

Open sockets in a verified namespace in the single-threaded broker. The socket
keeps that namespace after the broker leaves. No raw socket or port-5353 wildcard
bind is needed. The node runtime supplies verified admission and broker expiry.
"""
import asyncio
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import errno
import hashlib
from ipaddress import ip_address
import math
import random
import socket
import struct
import time

import dns.rdatatype as rt

from discovery.lookup import Bucket
from discovery.local_claims import LocalClaims
from discovery.query import PodQuery, parse_pod_query
from discovery.responder import Responder

IP_PKTINFO, IP_RECVTTL, IP_MULTICAST_ALL = 8, 12, 49


def revoke(sock):
    """Shutdown the shared Linux socket, including descriptors held by a worker.

    Unconnected UDP reports ENOTCONN after setting its shutdown flags. Merely
    closing this descriptor would leave worker copies usable. Keep independent
    broker ownership until shutdown has run; qualify this on deployment kernels.
    """
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError as exc:
        if exc.errno != errno.ENOTCONN:
            raise
    finally:
        sock.close()


class PodSocket:
    def _scope(self, index, family, addresses):
        if type(index) is not int or index <= 0 or type(family) is not int:
            raise ValueError('valid interface index and family required')
        self.index, self.family = index, family
        self.addresses = frozenset(ip_address(a) for a in addresses)
        usable = [ip_address(a) for a in addresses if ip_address(a).version == family]
        if family not in (4, 6) or not usable or any(a.is_multicast or a.is_unspecified or a.is_loopback for a in self.addresses):
            raise ValueError('verified pod interface addresses required')
        self.source = usable[0]
        self.af = socket.AF_INET if family == 4 else socket.AF_INET6
        self.group = '224.0.0.251' if family == 4 else 'ff02::fb'
        self.target = (self.group, 5353) if family == 4 else (self.group, 5353, 0, self.index)
        self.send_info = [(socket.IPPROTO_IP, IP_PKTINFO,
                           struct.pack('@I4s4s', self.index, self.source.packed, bytes(4)))] if family == 4 else [
            (socket.IPPROTO_IPV6, socket.IPV6_PKTINFO, self.source.packed + struct.pack('@I', self.index))]

    def __init__(self, interface, family, addresses):
        self._scope(socket.if_nametoindex(interface), family, addresses)
        self.socket = socket.socket(self.af, socket.SOCK_DGRAM)
        self.closed = False
        try:
            sock = self.socket
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == 4:
                sock.bind(self.target)
                sock.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
                sock.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
                sock.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_ALL, 0)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, self.source.packed)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                    socket.inet_aton(self.group) + self.source.packed + struct.pack('@I', self.index))
            else:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind(self.target)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVHOPLIMIT, 1)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, self.index)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                    socket.inet_pton(self.af, self.group) + struct.pack('@I', self.index))
            sock.setblocking(False)
        except BaseException:
            sock.close()
            raise

    def description(self):
        return {'index': self.index, 'family': self.family,
                'addresses': [str(self.source)] + sorted(str(a) for a in self.addresses if a != self.source)}

    @classmethod
    def adopt(cls, sock, description):
        """Take ownership of a broker descriptor, without namespace entry."""
        try:
            if set(description) != {'index', 'family', 'addresses'}:
                raise ValueError('invalid pod socket description')
            values = description['addresses']
            if not isinstance(values, list) or not 1 <= len(values) <= 16:
                raise ValueError('bounded pod socket addresses required')
            result = cls.__new__(cls)
            result._scope(description['index'], description['family'], values)
            if (sock.family != result.af or sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_DGRAM
                    or sock.getsockopt(socket.SOL_SOCKET, socket.SO_PROTOCOL) != socket.IPPROTO_UDP
                    or sock.getsockname()[:2] != result.target[:2]):
                raise ValueError('descriptor is not the described multicast UDP socket')
            result.socket, result.closed = sock, False
            sock.setblocking(False)
            return result
        except BaseException:
            sock.close()  # Do not shutdown an untrusted/mismatched descriptor.
            raise

    def receive(self):
        wire, control, flags, peer = self.socket.recvmsg(9000, 256)
        if not wire and peer is None:
            raise OSError(errno.ESHUTDOWN, 'broker revoked the pod socket')
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or not 12 <= len(wire) <= 9000:
            raise ValueError('incomplete pod datagram')
        index = destination = hop = None
        for level, kind, data in control:
            if self.family == 4 and level == socket.IPPROTO_IP:
                if kind == IP_PKTINFO:
                    index, _, destination = struct.unpack('@I4s4s', data)
                elif kind == socket.IP_TTL:
                    hop = struct.unpack('@i', data)[0]
            elif self.family == 6 and level == socket.IPPROTO_IPV6:
                if kind == socket.IPV6_PKTINFO:
                    destination, index = struct.unpack('@16sI', data)
                elif kind == socket.IPV6_HOPLIMIT:
                    hop = struct.unpack('@i', data)[0]
        if (index != self.index or hop != 255 or destination != socket.inet_pton(self.af, self.group)
                or ip_address(peer[0].split('%')[0]) not in self.addresses or peer[1] == 0):
            raise ValueError('pod receive scope/hop/source rejected')
        return wire, peer

    def send(self, reply, peer):
        if self.closed or reply.family != self.family or not 12 <= len(reply.wire) <= 8952:
            raise ValueError('invalid or revoked pod reply')
        if not struct.unpack_from('!H', reply.wire, 2)[0] & 0x8000:
            raise ValueError('questions must never be sent into pods')
        if ip_address(peer[0].split('%')[0]) not in self.addresses or not 1 <= peer[1] <= 65535:
            raise ValueError('reply peer is outside this pod')
        target = self.target if reply.destination == 'multicast' else peer
        return self.socket.sendmsg([reply.wire], self.send_info, 0, target)

    def close(self):
        if not self.closed:
            self.closed = True
            revoke(self.socket)


@dataclass
class QueryBatch:
    query: PodQuery
    due: float
    expires: float
    size: int = 0
    packets: int = 0
    task: object = None


class PodSession:
    """One eligible namespace, supplied feed, bounded query work and local expiry.

    A separate broker must also revoke retained socket copies on eligibility
    loss/expiry so a suspended session cannot retain usable descriptors.
    """
    def __init__(self, sockets, feed, *, deadline, on_miss=None):
        self.sockets, self.feed, self.on_miss = tuple(sockets), feed, on_miss
        self.responder = Responder(feed.catalog)
        self.closed, self.started = False, False
        self.tasks, self.recent, self.events = set(), {}, Counter()
        self.pending = {}
        self.claims, self.loopback = LocalClaims(), {}
        self.ingress, self.egress = Bucket(32, 64), Bucket(10, 32)
        self.renew(deadline)

    def renew(self, deadline):
        if self.closed or not math.isfinite(deadline) or not 0 < deadline - time.monotonic() <= 30:
            raise ValueError('fresh eligibility lease of at most 30 seconds required')
        self.deadline = deadline

    def _task(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        def done(task):
            self.tasks.discard(task)
            if not task.cancelled() and task.exception() is not None:
                self.events['task_error'] += 1
                self.close()
        task.add_done_callback(done)
        return task

    def start(self):
        if self.started or self.closed:
            raise RuntimeError('session cannot be restarted')
        self.started = True
        for endpoint in self.sockets:
            asyncio.get_running_loop().add_reader(endpoint.socket.fileno(), self._receive, endpoint)
        self._task(self._expire())

    async def _expire(self):
        next_withdrawal = 0
        while time.monotonic() < self.deadline:
            if time.monotonic() >= next_withdrawal:
                self._withdraw()
                next_withdrawal = time.monotonic() + 1
            await asyncio.sleep(min(.1, self.deadline - time.monotonic()))
        self.close()

    def _withdraw(self):
        if self.closed or time.monotonic() >= self.deadline:
            return
        self.responder.catalog = self.feed.catalog
        for endpoint in self.sockets:
            replies = self.responder.withdrawals(policy=self._policy(),
                now=datetime.now(timezone.utc), monotonic=time.monotonic(), family=endpoint.family)
            for reply in replies:
                if self.egress.take(time.monotonic()):
                    self._send(endpoint, reply, (str(endpoint.source), 5353))
                    self.events['goodbye'] += 1

    def _policy(self):
        return replace(self.feed.authority,
            blocked_names=self.feed.authority.blocked_names | self.claims.active(time.monotonic()))

    def _send(self, endpoint, reply, peer):
        endpoint.send(reply, peer)
        now = time.monotonic()
        self.responder.note_sent(reply, monotonic=now)
        if reply.destination == 'multicast':
            self.loopback = {key: until for key, until in self.loopback.items() if until > now}
            self.loopback[(endpoint.family, hashlib.sha256(reply.wire).digest())] = now + 2
            # Egress rate limiting admits at most 52 packets per two seconds.
            while len(self.loopback) > 128:
                del self.loopback[next(iter(self.loopback))]

    def _receive(self, endpoint):
        if self.closed or time.monotonic() >= self.deadline:
            self.close()
            return
        for _ in range(16):
            try:
                wire, peer = endpoint.receive()
                now = time.monotonic()
                if self.loopback.get((endpoint.family, hashlib.sha256(wire).digest()), 0) > now:
                    continue
                if not self.ingress.take(now):
                    batch = self.pending.pop((endpoint.family, peer), None)
                    if batch is not None:
                        batch.task.cancel()
                    self.events['capacity'] += 1
                    continue
                if peer[1] == 5353 and self.claims.observe(wire, now):
                    self.events['local_claim_packet'] += 1
                    self._withdraw()
                    continue
                query = parse_pod_query(wire, allow_continuation=True)
                batch_key = (endpoint.family, peer)
                batch = self.pending.get(batch_key)
                if (query.truncated or not query.questions
                        or (batch and query.questions == batch.query.questions)):
                    self._assemble(endpoint, query, peer, len(wire), now)
                    continue
                if len(self.tasks) >= 17:
                    self.events['capacity'] += 1
                    continue
                self.recent = {key: until for key, until in self.recent.items() if until > now}
                key = (endpoint.family, peer, wire)
                if key in self.recent:
                    continue
                self.recent[key] = now + 1
                while len(self.recent) > 128:
                    del self.recent[next(iter(self.recent))]
                self._task(self._answer(endpoint, query, peer))
            except BlockingIOError:
                break
            except ValueError:
                self.events['rejected'] += 1
            except OverflowError:
                self.events['local_claim_capacity'] += 1
                self.close()
                break
            except OSError:
                self.close()
                break

    def _assemble(self, endpoint, query, peer, size, now):
        key = (endpoint.family, peer)
        batch = self.pending.get(key)
        if peer[1] != 5353 or (batch is None and not query.questions):
            self.events['continuation_rejected'] += 1
            return
        if batch is None:
            if len(self.pending) >= 16 or len(self.tasks) >= 17:
                self.events['capacity'] += 1
                return
            batch = QueryBatch(replace(query, known_answers=()), now + random.uniform(.4, .5), now + 2)
            self.pending[key] = batch
            batch.task = self._task(self._complete(endpoint, peer, key, batch))
        elif query.questions and (query.questions != batch.query.questions
                                  or query.unicast_requested != batch.query.unicast_requested):
            # Overlapping question sequences from one host are ambiguous. Drop
            # this batch; do not guess which continuation belongs to which query.
            self.pending.pop(key)
            batch.task.cancel()
            self.events['continuation_rejected'] += 1
            return
        batch.size += size
        batch.packets += 1
        known = {(a.name, a.type, a.data): a for a in batch.query.known_answers}
        for answer in query.known_answers:
            record = (answer.name, answer.type, answer.data)
            if record not in known or answer.ttl > known[record].ttl:
                known[record] = answer
        if batch.size > 32768 or batch.packets > 16 or len(known) > 128 or now >= batch.expires:
            self.pending.pop(key)
            batch.task.cancel()
            self.events['continuation_limit'] += 1
            return
        batch.query = replace(batch.query, known_answers=tuple(known.values()))
        if query.truncated:
            batch.due = now + random.uniform(.4, .5)

    async def _complete(self, endpoint, peer, key, batch):
        try:
            while time.monotonic() < min(batch.due, batch.expires):
                await asyncio.sleep(min(batch.due, batch.expires) - time.monotonic())
            if time.monotonic() >= batch.expires:
                self.events['continuation_limit'] += 1
                return
            self.pending.pop(key, None)
            self.events['continuation_complete'] += 1
            await self._answer(endpoint, replace(batch.query, truncated=False), peer, delay=False)
        finally:
            if self.pending.get(key) is batch:
                del self.pending[key]

    async def _answer(self, endpoint, query, peer, *, delay=True):
        if delay and peer[1] == 5353:
            await asyncio.sleep(random.uniform(.02, .12))
        now = time.monotonic()
        ttl_limit = max(0, math.floor(self.deadline - now))
        if self.closed or ttl_limit == 0:
            return
        # Feed replacement keeps the responder's successful-send history intact.
        self.responder.catalog = self.feed.catalog
        policy = self._policy()
        result = self.responder.build(query, policy=policy, now=datetime.now(timezone.utc),
            monotonic=now, source_port=peer[1], family=endpoint.family,
            ttl_limit=ttl_limit)
        for reply in result.replies:
            if self.egress.take(time.monotonic()):
                self._send(endpoint, reply, peer)
                self.events['sent'] += 1
        blocked = {name.lower() for name in policy.blocked_names}
        # Shared PTR answers are not a complete list. Refresh even when a
        # browse has cached answers so other types/instances can be discovered.
        # The existing gateway coordinator coalesces and bounds this demand.
        lookups = tuple(dict.fromkeys(q for q in query.questions
            if (q in result.misses or q.type == rt.PTR) and q.name.lower() not in blocked))
        if lookups and self.on_miss:
            # Known answers, source identity and other pod metadata stay local.
            try:
                async with asyncio.timeout(2):
                    for offset in range(0, len(lookups), 16):
                        questions = lookups[offset:offset + 16]
                        await self.on_miss(PodQuery(0, questions, (False,) * len(questions)))
            except (ValueError, OSError, TimeoutError):
                self.events['lookup_failed'] += 1

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.pending.clear()
        loop = asyncio.get_running_loop()
        for endpoint in self.sockets:
            if self.started:
                loop.remove_reader(endpoint.socket.fileno())
            endpoint.close()
        for task in tuple(self.tasks):
            if task is not asyncio.current_task():
                task.cancel()

    async def aclose(self):
        self.close()
        await asyncio.gather(*self.tasks, return_exceptions=True)
