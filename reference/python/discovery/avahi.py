"""Interface-scoped Avahi record browsing through its local D-Bus API.

Events are hints, never TTL-bearing catalog observations. The adapter has no
publication API. Packet provenance/expiry and production supervision are separate.
"""

import asyncio
from dataclasses import dataclass
from types import MappingProxyType
from uuid import uuid4

from dbus_next import BusType, Message, MessageType
from dbus_next.aio import MessageBus
import dns.exception
import dns.name
import dns.rdata
import dns.rdatatype as rt

SERVICE = 'org.freedesktop.Avahi'
BROWSER = SERVICE + '.RecordBrowser'
SERVER = SERVICE + '.Server'
SERVER2 = SERVICE + '.Server2'
DBUS = 'org.freedesktop.DBus'
DBUS_PATH = '/org/freedesktop/DBus'
ENUMERATION = '_services._dns-sd._udp.local.'
SUPPORTED = frozenset((rt.A, rt.AAAA, rt.PTR, rt.SRV, rt.TXT))


def local_name(value: str) -> dns.name.Name:
    # Avahi's presentation names need not have a trailing dot.
    name = dns.name.from_text(value.encode('utf-8'))
    if not name.is_subdomain(dns.name.from_text('local.')):
        raise ValueError('Avahi discovery must stay within local names')
    return name


def avahi_name(value: str) -> str:
    r"""Use Avahi's decimal escapes, not DNS zone-file escapes such as \@."""
    return '.'.join(''.join(chr(byte) if chr(byte) in
                           'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-'
                           else f'\\{byte:03d}' for byte in label)
                    for label in local_name(value).labels)


@dataclass(frozen=True)
class Link:
    source: str
    generation: str
    families: frozenset[int]

    def __post_init__(self):
        object.__setattr__(self, 'families', frozenset(self.families))
        if not self.source or not self.generation or not self.families or not self.families <= {4, 6}:
            raise ValueError('link requires identity, generation and enabled IP families')


@dataclass(frozen=True)
class RecordQuery:
    interface: int
    family: int
    name: str
    type: int


@dataclass(frozen=True)
class RecordEvent:
    epoch: str
    source: str
    generation: str
    query: RecordQuery
    name: str
    added: bool
    data: bytes
    cached: bool
    received_monotonic: float

    # Deliberately no TTL or expires_at: browser delivery cannot renew a record.


class AvahiBrowser:
    """Single-event-loop owner; D-Bus owner loss invalidates the entire epoch."""

    def __init__(self, links: dict[int, Link], *, queue_limit=512, browser_limit=1024, record_limit=4096):
        if not links or any(type(index) is not int or index <= 0 for index in links):
            raise ValueError('explicit positive interface indices are required')
        for value, maximum in [(queue_limit, 4096), (browser_limit, 1024), (record_limit, 4096)]:
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError('invalid adapter resource limit')
        self.links = MappingProxyType(dict(links))
        self.epoch = str(uuid4())
        self.failure = None
        self.bus = None
        self.owner = None
        self._events = asyncio.Queue(queue_limit)
        self._paths = {}
        self._queries = {}
        self._seen = set()
        self._touched = {}
        self._permanent = set()
        self._browser_limit, self._record_limit = browser_limit, record_limit
        self.deferred = 0
        self._lock = asyncio.Lock()
        self._disconnect_task = None
        self._closed = False

    @property
    def healthy(self):
        return self.bus is not None and self.owner is not None and self.failure is None

    def _fail(self, reason):
        if self.failure is not None:
            return
        self.failure = reason
        self._seen.clear()
        while not self._events.empty():
            self._events.get_nowait()
        self._events.put_nowait(None)
        if self.bus is not None:
            self.bus.disconnect()

    async def _call(self, path, interface, member, signature='', body=None, *, destination=None):
        reply = await asyncio.wait_for(self.bus.call(Message(
            destination=destination or self.owner, path=path, interface=interface,
            member=member, signature=signature, body=[] if body is None else body)), timeout=3)
        if reply.message_type != MessageType.METHOD_RETURN:
            raise RuntimeError(f'{interface}.{member}: {reply.error_name}')
        return reply.body

    async def connect(self, *, bus_address=None):
        if self.bus is not None or self.failure is not None:
            raise RuntimeError('create a new browser for each connection epoch')
        if bus_address is None:
            bus_address = 'unix:path=/run/dbus/system_bus_socket'
        if not bus_address.startswith('unix:') or ';' in bus_address:
            raise ValueError('Avahi requires a local Unix D-Bus connection')
        try:
            self.bus = MessageBus(bus_address=bus_address, bus_type=BusType.SYSTEM)
            await asyncio.wait_for(self.bus.connect(), timeout=3)
            self.bus.add_message_handler(self._signal)
            # Subscribe before resolving ownership, then recheck after installing
            # the owner-scoped match to cover a daemon restart during setup.
            await self._call(DBUS_PATH, DBUS, 'AddMatch', 's', [
                "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',"
                "member='NameOwnerChanged',arg0='org.freedesktop.Avahi'"], destination=DBUS)
            self.owner = (await self._call(DBUS_PATH, DBUS, 'GetNameOwner', 's', [SERVICE], destination=DBUS))[0]
            await self._call(DBUS_PATH, DBUS, 'AddMatch', 's', [
                f"type='signal',sender='{self.owner}'"], destination=DBUS)
            current = (await self._call(DBUS_PATH, DBUS, 'GetNameOwner', 's', [SERVICE], destination=DBUS))[0]
            state = (await self._call('/', SERVER, 'GetState'))[0]
            if current != self.owner or state != 2 or self.failure:
                raise RuntimeError('Avahi is not stable and running')
            self._disconnect_task = asyncio.create_task(self._disconnected())
            return self
        except BaseException:
            await self.close()
            raise

    async def _disconnected(self):
        try:
            await self.bus.wait_for_disconnect()
        finally:
            self._fail('D-Bus disconnected; discard this observation epoch')

    def _signal(self, message):
        if message.message_type != MessageType.SIGNAL or self.failure:
            return
        if message.sender == DBUS and message.interface == DBUS and message.member == 'NameOwnerChanged':
            if message.body[0] == SERVICE and self.owner and message.body[2] != self.owner:
                self._fail('Avahi owner changed; discard this observation epoch')
            return
        if message.sender != self.owner:
            return
        if message.path == '/' and message.interface == SERVER and message.member == 'StateChanged':
            if message.body[0] != 2:
                self._fail('Avahi left running state')
            return
        query = self._paths.get(message.path)
        if query is None or message.interface != BROWSER:
            return
        if message.member == 'Failure':
            self._fail('Avahi record browser failed')
            return
        if message.member not in ('ItemNew', 'ItemRemove'):
            return
        try:
            interface, protocol, name, class_, kind, raw, flags = message.body
            family = {0: 4, 1: 6}[protocol]
            owner = local_name(name)
            if (interface, family, owner, kind, class_) != (
                    query.interface, query.family, local_name(query.name), query.type, 1):
                raise ValueError('browser event scope mismatch')
            # A shared type PTR may also be registered by our publisher, so
            # Avahi marks the remote device's identical type as LOCAL too.
            # Admit that hint only: export still requires non-local wire
            # evidence on this interface, with the remote record's own TTL.
            enumeration = kind == rt.PTR and owner == local_name(ENUMERATION)
            if flags & (2 | 16 | 32) or (flags & 8 and not enumeration) or not flags & 4:
                return
            if len(raw) > 4096:
                raise ValueError('record data exceeds limit')
            data = dns.rdata.from_wire(1, kind, bytes(raw), 0, len(raw))
            if kind in (rt.PTR, rt.SRV):
                local_name(data.target.to_text())
            key = (message.path, data.to_digestable())
            added = message.member == 'ItemNew'
            if added:
                self._seen.add(key)
                if len(self._seen) > self._record_limit:
                    raise ValueError('record hint budget exceeded')
            elif key not in self._seen:
                return
            else:
                self._seen.remove(key)
            link = self.links[interface]
            self._events.put_nowait(RecordEvent(self.epoch, link.source, link.generation, query, owner.to_text(), added,
                                                data.to_wire(), bool(flags & 1),
                                                asyncio.get_running_loop().time()))
        except (ValueError, TypeError, KeyError, dns.exception.DNSException, asyncio.QueueFull):
            self._fail('invalid or overflowing Avahi event stream')

    async def watch(self, query: RecordQuery):
        name = local_name(query.name).canonicalize().to_text()
        query = RecordQuery(query.interface, query.family, name, query.type)
        if query.interface not in self.links or query.family not in self.links[query.interface].families:
            raise ValueError('unapproved interface or family')
        if query.type not in SUPPORTED:
            raise ValueError('unsupported record type')
        async with self._lock:
            if not self.healthy:
                raise RuntimeError(self.failure or 'Avahi is not connected')
            if query in self._queries:
                self._touched[query] = asyncio.get_running_loop().time()
                return self._queries[query]
            if len(self._queries) >= self._browser_limit:
                # Keep admitted observations alive. Reject only the new watch;
                # retirement frees capacity for a later event or client demand.
                self.deferred += 1
                return None
            self._touched[query] = asyncio.get_running_loop().time()
            try:
                path = (await self._call('/', SERVER2, 'RecordBrowserPrepare', 'iisqqu',
                                         [query.interface, 0 if query.family == 4 else 1,
                                          avahi_name(query.name), 1, query.type, 2]))[0]
                self._paths[path] = query
                self._queries[query] = path
                await self._call(path, BROWSER, 'Start')
                if not self.healthy:
                    raise RuntimeError(self.failure)
                return path
            except BaseException:
                self._fail('record browser setup failed; discard this observation epoch')
                raise

    async def seed(self):
        for interface, link in self.links.items():
            for family in sorted(link.families):
                query = RecordQuery(interface, family, ENUMERATION, rt.PTR)
                await self.watch(query)
                self._permanent.add(query)

    async def retire(self, *, now=None, idle=120):
        """Retire empty dependency browsers; active records remain observed."""
        now = asyncio.get_running_loop().time() if now is None else now
        async with self._lock:
            needed = set()
            for path, raw in self._seen:
                parent = self._paths[path]
                needed.update(self._dependencies(parent, raw))
            for query, path in list(self._queries.items()):
                if query in self._permanent or query in needed or now - self._touched[query] < idle:
                    continue
                if any(key[0] == path for key in self._seen):
                    continue
                # Stop routing before Free; queued late signals cannot revive it.
                del self._paths[path]
                del self._queries[query]
                del self._touched[query]
                try:
                    await self._call(path, BROWSER, 'Free')
                except BaseException:
                    self._fail('browser retirement failed')
                    raise

    async def next_event(self):
        if not self.healthy:
            raise RuntimeError(self.failure or 'Avahi is not connected')
        event = await self._events.get()
        if event is None or not self.healthy:
            raise RuntimeError(self.failure or 'Avahi is not connected')
        return event

    @staticmethod
    def _dependencies(query, raw):
        data = dns.rdata.from_wire(1, query.type, raw, 0, len(raw))
        if query.type == rt.PTR:
            kinds = (rt.PTR,) if local_name(query.name) == local_name(ENUMERATION) else (rt.SRV, rt.TXT)
        elif query.type == rt.SRV:
            kinds = (rt.A, rt.AAAA)
        else:
            return ()
        return tuple(RecordQuery(query.interface, query.family, data.target.canonicalize().to_text(), kind)
                     for kind in kinds)

    async def follow(self, event: RecordEvent):
        """Demand-driven dependency browsing; descriptions never act as a filter."""
        if not event.added or event.epoch != self.epoch:
            return
        for query in self._dependencies(event.query, event.data):
            await self.watch(query)

    async def close(self):
        if self._closed:
            return
        self._closed = True
        self._fail('browser closed')
        if self.bus is not None:
            self.bus.remove_message_handler(self._signal)
            self.bus.disconnect()  # Avahi frees all browsers owned by this connection.
            # dbus-next 0.2.3 does not finalize an interrupted authentication,
            # and disconnect() only shuts down its socket. Explicitly release
            # these pinned-version resources, including the pre-Hello path.
            self.bus._finalize()
        if self._disconnect_task is not None:
            await asyncio.gather(self._disconnect_task, return_exceptions=True)
        if self.bus is not None:
            self.bus._stream.close()
            self.bus._sock.close()
