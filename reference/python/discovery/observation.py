"""Correlate authenticated local Avahi hints with admitted LAN wire evidence.

mDNS itself does not authenticate devices. Provenance here means the kernel
receive interface/source plus operator scope and an Avahi observation on that
same link. Nothing in this module confers application access.
"""

from dataclasses import dataclass, replace
from datetime import timedelta
import hashlib
from ipaddress import ip_address
import math
import struct

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdatatype as rt

from discovery.catalog import Record, SourcePolicy

KINDS = frozenset((rt.PTR, rt.SRV, rt.TXT, rt.A, rt.AAAA))
LOCAL = dns.name.from_text('local.')


@dataclass(frozen=True)
class Packet:
    interface: int
    generation: str
    family: int
    source: str
    destination: str
    hop_limit: int
    source_port: int
    destination_port: int
    wire: bytes


@dataclass(frozen=True)
class WireRecord:
    source: str
    generation: str
    family: int
    name: str
    type: int
    data: bytes
    ttl: int
    flush: bool

    @property
    def key(self):
        name = dns.name.from_text(self.name).canonicalize().to_wire()
        data = dns.rdata.from_wire(1, self.type, self.data, 0, len(self.data)).to_digestable()
        return (self.source, self.generation, self.family, name, self.type, data)


def parse_response(packet: Packet, *, links, policy: SourcePolicy, local_addresses,
                   owns_name=lambda name: False) -> tuple[WireRecord, ...]:
    """Validate the entire response before returning any usable records.

    local_addresses maps interface indices to its assigned addresses. The
    caller must derive Packet metadata from receive ancillary data, not JSON.
    """
    link = links.get(packet.interface)
    if link is None or packet.generation != link.generation or packet.family not in link.families:
        raise ValueError('unapproved receive interface generation/family')
    src, dst = ip_address(packet.source), ip_address(packet.destination)
    if src.version != packet.family or dst.version != packet.family:
        raise ValueError('address family mismatch')
    if src.is_unspecified or src.is_multicast or src.is_loopback:
        raise ValueError('invalid LAN sender')
    own = {ip_address(a) for values in local_addresses.values() for a in values}
    if src in own:
        return ()
    # IPv6 link-local is valid packet provenance, but never an exported target.
    if not (packet.family == 6 and src.is_link_local):
        policy.check_address(link.source, str(src))
    group = ip_address('224.0.0.251' if packet.family == 4 else 'ff02::fb')
    if dst != group and str(dst) not in local_addresses.get(packet.interface, ()):
        raise ValueError('response is not addressed to discovery on this link')
    if packet.hop_limit != 255 or packet.source_port != 5353 or packet.destination_port != 5353:
        raise ValueError('invalid mDNS hop limit or UDP ports')
    if not 12 <= len(packet.wire) <= 8952:
        raise ValueError('response size outside budget')
    _, flags, questions, answers, authority, additional = struct.unpack('!6H', packet.wire[:12])
    if not flags & dns.flags.QR or not flags & dns.flags.AA or flags & (0x7800 | dns.flags.TC | 0xF):
        raise ValueError('not a complete authoritative mDNS response')
    if questions > 16 or answers + authority + additional > 256:
        raise ValueError('response record budget exceeded')
    try:
        # mDNS's cache-flush bit is in CLASS. Clear only RR class bits before
        # decoding so compressed RDATA remains attached to its original packet.
        normalized = bytearray(packet.wire)
        offset = 12
        for _ in range(questions):
            _, used = dns.name.from_wire(packet.wire, offset)
            offset += used + 4
        flushes = []
        for _ in range(answers + authority + additional):
            _, used = dns.name.from_wire(packet.wire, offset)
            offset += used
            _, class_, _, size = struct.unpack_from('!HHIH', packet.wire, offset)
            flushes.append(bool(class_ & 0x8000))
            struct.pack_into('!H', normalized, offset + 2, class_ & 0x7FFF)
            offset += 10 + size
        if offset != len(packet.wire):
            raise ValueError('invalid record lengths or trailing bytes')
        message = dns.message.from_wire(bytes(normalized), one_rr_per_rrset=True)
        result = []
        sections = message.answer + message.authority + message.additional
        for rrset, flush in zip(sections, flushes, strict=True):
            if rrset.rdclass != 1 or rrset.rdtype not in KINDS:
                continue
            if not rrset.name.is_subdomain(LOCAL) or owns_name(rrset.name):
                continue
            data = rrset[0]
            if rrset.rdtype in (rt.A, rt.AAAA):
                try:
                    policy.check_address(link.source, data.address)
                except ValueError:
                    continue
            if rrset.rdtype in (rt.PTR, rt.SRV):
                if not data.target.is_subdomain(LOCAL) or owns_name(data.target):
                    continue
            result.append(WireRecord(link.source, link.generation, packet.family,
                                     rrset.name.to_text(), int(rrset.rdtype), data.to_wire(),
                                     rrset.ttl, flush and rrset.rdtype != rt.PTR))
        return tuple(result)
    except (dns.exception.DNSException, IndexError, struct.error) as exc:
        raise ValueError('malformed mDNS response') from exc


@dataclass(frozen=True)
class Evidence:
    record: WireRecord
    received: float
    deadline: float


class Observations:
    """Bounded cache with wire TTLs, one-second grace and no restart revival."""

    def __init__(self, *, limit=4096):
        if type(limit) is not int or not 1 <= limit <= 65536:
            raise ValueError('invalid cache limit')
        self.limit = limit
        self._wire = {}
        self._hints = {}
        self._last = None
        self.failed = False

    def _clock(self, now):
        if not math.isfinite(now) or (self._last is not None and now < self._last):
            self.failed = True
            self._wire.clear()
            self._hints.clear()
        if self.failed:
            raise ValueError('observation cache requires fresh bootstrap')
        self._last = now
        self._wire = {key: value for key, value in self._wire.items() if value.deadline > now}

    def ingest(self, records: tuple[WireRecord, ...], *, now: float):
        self._clock(now)
        candidate = dict(self._wire)
        # Process the complete packet's RRsets before individual additions.
        flushing = {r.key[:2] + r.key[3:5] for r in records if r.flush and r.ttl > 0}
        present = {r.key[:2] + r.key[3:] for r in records if r.ttl > 0}
        for key, evidence in candidate.items():
            if key[:2] + key[3:5] in flushing and key[:2] + key[3:] not in present and now - evidence.received >= 1:
                candidate[key] = replace(evidence, deadline=min(evidence.deadline, now + 1))
        for record in records:
            if record.ttl == 0:
                for key, old in list(candidate.items()):
                    if key[:2] + key[3:] == record.key[:2] + record.key[3:]:
                        candidate[key] = replace(old, deadline=min(old.deadline, now + 1))
            else:
                candidate[record.key] = Evidence(record, now, now + min(record.ttl, 86400))
        if len(candidate) > self.limit:
            self.failed = True
            self._wire.clear()
            self._hints.clear()
            raise ValueError('observation capacity exceeded; discard epoch')
        self._wire = candidate

    def hint(self, event):
        record = WireRecord(event.source, event.generation, event.query.family, event.name,
                            event.query.type, event.data, 0, False)
        if event.added:
            if len(self._hints) >= self.limit and record.key not in self._hints:
                self.failed = True
                self._wire.clear()
                self._hints.clear()
                raise ValueError('hint capacity exceeded; discard epoch')
            self._hints.setdefault(record.key, set()).add(event.epoch)
        else:
            epochs = self._hints.get(record.key, set())
            epochs.discard(event.epoch)
            if not epochs:
                self._hints.pop(record.key, None)

    def forget_epoch(self, epoch):
        for key, epochs in list(self._hints.items()):
            epochs.discard(epoch)
            if not epochs:
                del self._hints[key]

    def forget_link(self, source, generation):
        self._wire = {k: v for k, v in self._wire.items() if k[:2] != (source, generation)}
        self._hints = {k: v for k, v in self._hints.items() if k[:2] != (source, generation)}

    def records(self, *, now, wall):
        self._clock(now)
        result = {}
        for key, evidence in self._wire.items():
            if key not in self._hints:
                continue
            ttl = math.floor(min(30, evidence.deadline - now))
            if ttl < 1:
                continue
            record = evidence.record
            data = dns.rdata.from_wire(1, record.type, record.data, 0, len(record.data))
            # Transport family is evidence, not part of device record identity.
            identity = hashlib.sha256(repr((key[0], key[3:])).encode()).hexdigest()
            value = Record(identity, record.name, record.type, data.to_text(), record.source,
                           wall + timedelta(seconds=ttl))
            if identity not in result or value.expires_at < result[identity].expires_at:
                result[identity] = value
        return tuple(result.values())
