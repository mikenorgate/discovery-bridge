"""Independent local publication owner with bounded producer leases.

The Unix peer's UID is the publication authority. This is not a remote feed API.
The owner holds the Avahi connection and withdraws on timeout/disconnect even
when the collector is SIGSTOP'ed. A systemd watchdog must supervise this owner.
"""
import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import math
import os
from pathlib import Path
import socket
import struct
import time

import dns.name
import dns.rdata
import dns.rdatatype as rt
from dbus_next import MessageType

from discovery.avahi import AvahiBrowser, SERVICE, SERVER, avahi_name
from discovery.catalog import Record
from discovery.records import PublicationPolicy, response_view
from discovery.transport import send_goodbyes

GROUP = SERVICE + '.EntryGroup'
BOOT = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
MAX_FRAME = 1_048_576


@dataclass(frozen=True)
class Intent:
    interface: int
    family: int
    deadline: float
    records: tuple


def frame(groups, *, sequence, now=None):
    now = time.monotonic() if now is None else now
    return json.dumps({'boot': BOOT, 'sequence': sequence, 'issued': now, 'groups': [
        {'interface': i.interface, 'family': i.family, 'deadline': i.deadline,
         'records': [{'name': a.name.to_text(), 'type': int(a.type), 'data': a.data.to_text(),
                      'source': a.source, 'unique': a.unique} for a in i.records]} for i in groups]},
        separators=(',', ':')).encode() + b'\n'


def decode(payload, *, now, previous, links, owns, sources=(), owns_host=lambda source, name: False):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    if len(payload) > MAX_FRAME:
        raise ValueError('publication frame too large')
    value = json.loads(payload.decode('utf-8'), object_pairs_hook=pairs)
    if set(value) != {'boot', 'sequence', 'issued', 'groups'} or value['boot'] != BOOT:
        raise ValueError('invalid local publication envelope')
    sequence, issued = value['sequence'], value['issued']
    if type(sequence) is not int or not previous < sequence < 2**63:
        raise ValueError('publication replay')
    if type(issued) not in (int, float) or not math.isfinite(issued) or not 0 <= now - issued <= 1:
        raise ValueError('stale producer snapshot')
    if not isinstance(value['groups'], list) or len(value['groups']) > 12:
        raise ValueError('publication group limit')
    groups, keys, budget = [], set(), 0
    for group in value['groups']:
        if set(group) != {'interface', 'family', 'deadline', 'records'}:
            raise ValueError('invalid publication group')
        interface, family, deadline = group['interface'], group['family'], group['deadline']
        if type(interface) is not int or type(family) is not int or interface not in links or family not in links[interface].families:
            raise ValueError('unapproved publication link')
        if type(deadline) not in (int, float) or not math.isfinite(deadline) or not now < deadline <= issued + 30:
            raise ValueError('invalid publication deadline')
        if (interface, family) in keys:
            raise ValueError('duplicate publication group')
        keys.add((interface, family))
        if not isinstance(group['records'], list):
            raise ValueError('invalid publication records')
        budget += len(group['records'])
        if budget > 4096:
            raise ValueError('publication record limit')
        records, unique = [], set()
        for i, record in enumerate(group['records']):
            if set(record) != {'name', 'type', 'data', 'source', 'unique'} or type(record['unique']) is not bool:
                raise ValueError('invalid publication record')
            kind = record['type']
            if type(kind) is not int or kind not in (rt.A, rt.AAAA, rt.PTR, rt.SRV, rt.TXT):
                raise ValueError('invalid publication type')
            name = dns.name.from_text(record['name'])
            data = dns.rdata.from_text(1, kind, record['data'], origin=dns.name.root, relativize=False)
            if not name.is_subdomain(dns.name.from_text('local.')):
                raise ValueError('publication outside local')
            if not isinstance(record['source'], str) or record['source'] not in ({link.source for link in links.values()} | set(sources)):
                raise ValueError('unapproved publication source')
            hostname = (kind in (rt.A, rt.AAAA) and record['source'] != links[interface].source
                        and owns_host(record['source'], name))
            if kind != rt.PTR and (not record['unique'] or not (owns(name) or hostname)):
                raise ValueError('unique name has no persistent gateway reservation')
            if kind == rt.PTR and record['unique']:
                raise ValueError('browse PTR must be shared')
            if kind in (rt.PTR, rt.SRV) and not data.target.is_subdomain(dns.name.from_text('local.')):
                raise ValueError('foreign publication dependency')
            if record['unique']:
                unique.add((record['name'], kind))
            records.append(Record(str(i), record['name'], kind, data.to_text(), record['source'],
                                  datetime.now(timezone.utc) + timedelta(seconds=1)))
        # Recompute coherence at the independent owner boundary. TTL=1 keeps
        # receiver caching within one second of an independent withdrawal.
        policy = PublicationPolicy(frozenset(r.id for r in records), frozenset(unique))
        view = response_view(tuple((r, 1) for r in records), policy)
        if len(view) != len(records):
            raise ValueError('incomplete, colliding or duplicate publication graph')
        groups.append(Intent(interface, family, deadline, view))
    return sequence, tuple(groups)


class Publisher(AvahiBrowser):
    """One independent D-Bus connection and at most twelve complete record groups."""
    def __init__(self, links, *, addresses, sources=()):
        super().__init__(links)
        self.sources = tuple(sources)
        self.addresses = {i: tuple(values) for i, values in addresses.items()}
        self.groups = {}
        self.conflicts = set()
        self.conflicting_names = set()
        self._expired_at = None

    def _signal(self, message):
        super()._signal(message)
        if (message.message_type == MessageType.SIGNAL and message.sender == self.owner and
                message.interface == GROUP and message.member == 'StateChanged' and message.body[0] in (3, 4)):
            self.conflicts.add(message.path)
            for path, signature, _ in self.groups.values():
                if path == message.path:
                    for key, unique in signature:
                        if unique:
                            name, _ = dns.name.from_wire(key[0], 0)
                            self.conflicting_names.add(name.to_text())

    async def clear(self):
        if not self.healthy:
            self.groups.clear()
            return
        for key, (path, signature, _) in list(self.groups.items()):
            try:
                await self._call(path, GROUP, 'Reset')
                await self._call(path, GROUP, 'Free')
                send_goodbyes(*key, signature, self.addresses[key[0]])
            except Exception:
                self._fail('cannot withdraw publication')
        self.groups.clear()

    async def reconcile(self, intents):
        desired = {(i.interface, i.family): i for i in intents}
        if not self.healthy or self.conflicts:
            await self.clear()
            raise RuntimeError('publication ownership lost; rotate conflicting aliases before retry')
        # A validated renewal extends unchanged records immediately. Removed
        # records retain their old deadline until Avahi has withdrawn them.
        removed = []
        for key, (path, signature, deadline) in list(self.groups.items()):
            intent = desired.get(key)
            new_signature = tuple((a.key, a.unique) for a in intent.records) if intent else None
            if new_signature != signature:
                removed.append((key, path, signature, deadline))
            else:
                self.groups[key] = (path, signature, intent.deadline)
        try:
            fresh_deadline = min((i.deadline for i in intents), default=time.monotonic() + 3)
            async def remove(key, path, signature):
                await self._call(path, GROUP, 'Reset')
                await self._call(path, GROUP, 'Free')
                send_goodbyes(*key, signature, self.addresses[key[0]])
                del self.groups[key]

            async with asyncio.timeout_at(min([fresh_deadline] + [g[3] for g in removed])):
                async with asyncio.TaskGroup() as tasks:
                    for key, path, signature, _ in removed:
                        tasks.create_task(remove(key, path, signature))
            # Withdrawn records no longer constrain the replacement's lease.
            async def add(key, intent):
                if not intent.records:
                    return
                signature = tuple((a.key, a.unique) for a in intent.records)
                if key in self.groups:
                    path = self.groups[key][0]
                else:
                    path = (await self._call('/', SERVER, 'EntryGroupNew'))[0]
                    # Track immediately so partial setup can always withdraw.
                    self.groups[key] = (path, signature, intent.deadline)
                    for record in intent.records:
                        await self._call(path, GROUP, 'AddRecord', 'iiusqquay', [
                            intent.interface, 0 if intent.family == 4 else 1,
                            9 if record.unique else 0, avahi_name(record.name.to_text()), 1,
                            int(record.type), 1, record.data.to_wire()])
                    await self._call(path, GROUP, 'Commit')
                self.groups[key] = (path, signature, intent.deadline)

            # Each of at most twelve independent groups keeps ordered D-Bus
            # calls. Parallel groups avoid multiplying short leases by 12.
            async with asyncio.timeout_at(fresh_deadline):
                async with asyncio.TaskGroup() as tasks:
                    for key, intent in desired.items():
                        tasks.create_task(add(key, intent))
            await self.expire()
        except BaseException:
            # Disconnect first: cleanup calls must not prolong expired ownership.
            self._fail('publication reconciliation failed or exceeded lease budget')
            await self.clear()
            raise

    async def expire(self, now=None):
        now = time.monotonic() if now is None else now
        if not math.isfinite(now) or (self._expired_at is not None and now < self._expired_at):
            await self.clear()
            raise RuntimeError('publication clock invalid')
        self._expired_at = now
        for key, (path, signature, deadline) in list(self.groups.items()):
            if now >= deadline or path in self.conflicts:
                await self._call(path, GROUP, 'Reset')
                await self._call(path, GROUP, 'Free')
                send_goodbyes(*key, signature, self.addresses[key[0]])
                del self.groups[key]

    async def close(self):
        if self.healthy:
            await self.clear()
        await super().close()


class LeaseServer:
    def __init__(self, publisher, *, producer_uid, owns, owns_host=lambda source, name: False, watchdog=lambda: None):
        self.publisher, self.producer_uid, self.owns = publisher, producer_uid, owns
        self.owns_host = owns_host
        self.watchdog = watchdog
        self.busy = False
        self.lock = asyncio.Lock()

    async def client(self, reader, writer):
        admitted = False
        reconciliation = {}
        try:
            _, uid, _ = struct.unpack('3i', writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != self.producer_uid or self.busy:
                raise ValueError('unauthorized or competing publication producer')
            self.busy = admitted = True
            previous = 0
            while True:
                payload = await reader.readline()
                if not payload:
                    break
                sequence, groups = decode(payload, now=time.monotonic(), previous=previous,
                                          links=self.publisher.links, owns=self.owns,
                                          owns_host=self.owns_host,
                                          sources=getattr(self.publisher, 'sources', ()))
                started = time.monotonic()
                reconciliation = {'started': started, 'records': sum(len(g.records) for g in groups),
                                  'lease_seconds': min((g.deadline - started for g in groups), default=0)}
                try:
                    # Reconcile enforces each old/new lease during its own phase.
                    async with asyncio.timeout(3):
                        async with self.lock:
                            await self.publisher.reconcile(groups)
                except TimeoutError:
                    self.publisher._fail('publication reconciliation exceeded lease budget')
                    raise
                previous = sequence
                reconciliation = {}
                writer.write(b'OK\n')
                await writer.drain()
        except (Exception, asyncio.CancelledError) as exc:
            if admitted:
                if reconciliation:
                    reconciliation['elapsed_seconds'] = time.monotonic() - reconciliation.pop('started')
                print(json.dumps({'event': 'publication_rejected', 'error': type(exc).__name__,
                                  'failure': self.publisher.failure, **reconciliation}), flush=True)
            # Any invalid snapshot revokes this owner's complete publication.
            if self.publisher.conflicting_names:
                writer.write(b'CONFLICT ' + json.dumps(sorted(self.publisher.conflicting_names)).encode() + b'\n')
                with __import__('contextlib').suppress(Exception):
                    await writer.drain()
        finally:
            if admitted:
                async with self.lock:
                    await self.publisher.clear()
                self.publisher.conflicts.clear()
                self.publisher.conflicting_names.clear()
                self.busy = False
            writer.close()
            await writer.wait_closed()

    async def sweep(self):
        while self.publisher.healthy:
            async with self.lock:
                await self.publisher.expire()
            self.watchdog()
            await asyncio.sleep(0.1)
        raise RuntimeError('publication D-Bus owner lost')

    async def serve(self, path):
        server = await asyncio.start_unix_server(self.client, path=path, limit=MAX_FRAME + 1)
        os.chmod(path, 0o660)
        try:
            async with server:
                await self.sweep()
        finally:
            await self.publisher.close()
            Path(path).unlink(missing_ok=True)
