"""Private inherited SOCK_SEQPACKET handoff of pod sockets and eligibility leases."""
import array
import asyncio
import json
import os
import socket
import time

from discovery.pod_socket import PodSession, PodSocket

MAX_MESSAGE = 8192


def send(channel, value, descriptors=()):
    wire = json.dumps(value, separators=(',', ':'), allow_nan=False).encode()
    if len(wire) > MAX_MESSAGE or len(descriptors) > 2:
        raise ValueError('oversized broker message')
    control = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', descriptors))] if descriptors else []
    if channel.sendmsg([wire], control, socket.MSG_DONTWAIT) != len(wire):
        raise OSError('incomplete broker message')


def receive(channel):
    wire, control, flags, _ = channel.recvmsg(MAX_MESSAGE, socket.CMSG_SPACE(8), socket.MSG_CMSG_CLOEXEC)
    descriptors = []
    try:
        for level, kind, value in control:
            if (level, kind) != (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                raise ValueError('unexpected broker ancillary data')
            values = array.array('i'); values.frombytes(value)
            descriptors.extend(values)
        if not wire:
            raise EOFError('broker disconnected')
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(descriptors) > 2:
            raise ValueError('truncated broker message')
        return json.loads(wire), descriptors
    except BaseException:
        for fd in descriptors: os.close(fd)
        raise


class Publisher:
    """The responder has no namespace request operation; the broker pushes state."""
    def __init__(self, channel):
        self.channel, self.sent = channel, {}
        self.last_ping = float('-inf')

    def sync(self, leases):
        for uid, token in tuple(self.sent.items()):
            if uid not in leases or leases[uid].token != token:
                send(self.channel, {'op': 'remove', 'uid': uid, 'token': token})
                del self.sent[uid]
        for uid, lease in leases.items():
            if self.sent.get(uid) == lease.token:
                continue
            send(self.channel, {'op': 'open', 'uid': uid, 'token': lease.token,
                                'deadline': lease.deadline, 'sockets': [s.description() for s in lease.sockets]},
                 [s.socket.fileno() for s in lease.sockets])
            self.sent[uid] = lease.token
        if time.monotonic() - self.last_ping >= .5:
            # This is a liveness signal only; it never extends eligibility.
            send(self.channel, {'op': 'ping'})
            self.last_ping = time.monotonic()

    def renew(self, leases):
        self.sync(leases)
        for uid, lease in leases.items():
            send(self.channel, {'op': 'renew', 'uid': uid, 'token': lease.token, 'deadline': lease.deadline})


class Sessions:
    def __init__(self, channel, feed, *, on_miss=None):
        self.channel, self.feed, self.on_miss = channel, feed, on_miss
        self.sessions, self.tokens = {}, {}
        self.last_ping, self.closed = time.monotonic(), False

    def apply(self, value, descriptors):
        endpoints = []
        try:
            op = value['op']
            if op == 'ping' and value == {'op': 'ping'} and not descriptors:
                self.last_ping = time.monotonic()
                return
            fields = {'op', 'uid', 'token'} | ({'deadline'} if op in ('open', 'renew') else set())
            if op == 'open': fields.add('sockets')
            if op not in ('open', 'renew', 'remove') or set(value) != fields:
                raise ValueError('unknown broker operation')
            uid, token = value['uid'], value['token']
            if (not isinstance(uid, str) or not 1 <= len(uid) <= 128
                    or not isinstance(token, str) or len(token) != 32):
                raise ValueError('invalid broker identity')
            if op != 'open' and descriptors:
                raise ValueError('unexpected descriptors')
            if op == 'open':
                if uid in self.sessions or len(self.sessions) >= 256:
                    raise ValueError('duplicate or excessive pod session')
                if (not isinstance(value['sockets'], list) or not 1 <= len(descriptors) <= 2
                        or len(value['sockets']) != len(descriptors)):
                    raise ValueError('incomplete socket handoff')
                for description in value['sockets']:
                    sock = socket.socket(fileno=descriptors[0])
                    descriptors.pop(0)
                    endpoints.append(PodSocket.adopt(sock, description))
                if len({s.family for s in endpoints}) != len(endpoints):
                    raise ValueError('duplicate socket family')
                session = PodSession(endpoints, self.feed, deadline=value['deadline'], on_miss=self.on_miss)
                try:
                    session.start()
                except BaseException:
                    session.close()
                    raise
                self.sessions[uid], self.tokens[uid] = session, token
                endpoints = []
            else:
                if self.tokens.get(uid) != token:
                    raise ValueError('stale broker operation')
                if op == 'remove':
                    self.sessions.pop(uid).close()
                    del self.tokens[uid]
                else:
                    self.sessions[uid].renew(value['deadline'])
        finally:
            for fd in descriptors: os.close(fd)
            for endpoint in endpoints: endpoint.close()

    async def run(self):
        loop = asyncio.get_running_loop()
        done = loop.create_future()
        self.channel.setblocking(False)
        def read():
            try:
                for _ in range(32):
                    self.apply(*receive(self.channel))
            except BlockingIOError:
                pass
            except (EOFError, OSError, ValueError, KeyError, TypeError) as exc:
                if not done.done(): done.set_exception(exc)
        loop.add_reader(self.channel.fileno(), read)
        try:
            while not done.done():
                await asyncio.wait((done,), timeout=.1)
                if not done.done() and time.monotonic() - self.last_ping > 5:
                    raise TimeoutError('broker heartbeat expired')
            await done
        finally:
            loop.remove_reader(self.channel.fileno())
            done.cancel()
            await self.close()

    async def close(self):
        if self.closed: return
        self.closed = True
        sessions = tuple(self.sessions.values())
        self.sessions.clear(); self.tokens.clear()
        for session in sessions: session.close()
        await asyncio.gather(*(session.aclose() for session in sessions), return_exceptions=True)
        self.channel.close()
