"""Construct answer-only native DNS packets; no sockets or gateway writes.

Call one instance per pod namespace after receive admission and scheduling.
Build again at send time so catalog, authorization and TTLs are current.
"""

from dataclasses import dataclass, replace
from datetime import datetime
import math
import struct

import dns.flags
import dns.name
import dns.rdatatype as rt

from discovery.catalog import Catalog, MAX_RECORDS
from discovery.query import PodQuery, Question
from discovery.records import Answer, PublicationPolicy, RecordKey, additionals, response_view


@dataclass(frozen=True)
class Reply:
    destination: str  # "multicast" or "peer"; the socket adapter owns addresses.
    family: int
    wire: bytes
    records: tuple[Answer, ...]


@dataclass(frozen=True)
class Result:
    replies: tuple[Reply, ...]
    misses: tuple[Question, ...]
    oversized: bool = False


def _rr_wire(answer: Answer, legacy: bool) -> bytes:
    data = answer.data.to_wire()  # No compression, including legacy SRV targets.
    class_ = 1 | (0x8000 if answer.unique and not legacy else 0)
    ttl = min(answer.ttl, 10) if legacy else answer.ttl
    return answer.name.to_wire() + struct.pack('!HHIH', answer.type, class_, ttl, len(data)) + data


def _packet(query: PodQuery, answers: list[Answer], extra: list[Answer], *, legacy: bool,
            truncated: bool = False) -> bytes:
    flags = dns.flags.QR | dns.flags.AA
    questions = b''
    if legacy:
        flags |= dns.flags.RD if query.recursion_desired else 0
        for question, qu in zip(query.questions, query.unicast_requested, strict=True):
            questions += dns.name.from_text(question.name).to_wire()
            questions += struct.pack('!HH', question.type, question.class_ | (0x8000 if qu else 0))
    flags |= dns.flags.TC if truncated else 0
    header = struct.pack('!6H', query.transaction_id if legacy else 0, flags,
                         len(query.questions) if legacy else 0, len(answers), 0, len(extra))
    return header + questions + b''.join(_rr_wire(a, legacy) for a in answers + extra)


def _units(records: list[Answer]) -> list[list[Answer]]:
    """Keep unique RRsets together; shared PTR records can cross packet boundaries."""
    units = []
    unique = {}
    for record in records:
        if record.unique:
            if record.rrset not in unique:
                unique[record.rrset] = []
                units.append(unique[record.rrset])
            unique[record.rrset].append(record)
        else:
            units.append([record])
    return units


def _pack(query: PodQuery, answers: list[Answer], extra: list[Answer], *, destination: str,
          family: int, legacy: bool, budget: int) -> tuple[Reply, ...]:
    if not answers:
        return ()
    limit = min(budget, 512) if legacy else budget
    replies = []
    packed_answers, packed_extra = [], []
    if len(_packet(query, [], [], legacy=legacy)) > limit:
        raise ValueError('question section exceeds packet budget')
    for section, units in [('answer', _units(answers)), ('additional', _units(extra))]:
        for unit in units:
            next_answers = packed_answers + unit if section == 'answer' else packed_answers
            next_extra = packed_extra + unit if section == 'additional' else packed_extra
            wire = _packet(query, next_answers, next_extra, legacy=legacy)
            if len(wire) > limit:
                if legacy:
                    # Missing optional additionals do not imply a truncated answer.
                    wire = _packet(query, packed_answers, packed_extra, legacy=True,
                                   truncated=section == 'answer')
                    return (Reply(destination, family, wire, tuple(packed_answers + packed_extra)),)
                if packed_answers or packed_extra:
                    replies.append(Reply(destination, family,
                                         _packet(query, packed_answers, packed_extra, legacy=False),
                                         tuple(packed_answers + packed_extra)))
                    if len(replies) >= 16:
                        raise ValueError('response packet count exceeds budget')
                packed_answers, packed_extra = [], []
                next_answers = unit if section == 'answer' else []
                next_extra = unit if section == 'additional' else []
                wire = _packet(query, next_answers, next_extra, legacy=False)
                if len(wire) > limit:
                    raise ValueError('record or unique RRset exceeds packet budget')
            packed_answers, packed_extra = next_answers, next_extra
    replies.append(Reply(destination, family,
                         _packet(query, packed_answers, packed_extra, legacy=legacy),
                         tuple(packed_answers + packed_extra)))
    if len(replies) > 16:
        raise ValueError('response packet count exceeds budget')
    return tuple(replies)


class Responder:
    """A per-namespace response builder with bounded successful-multicast history."""

    def __init__(self, catalog: Catalog):
        self.catalog = catalog
        self._multicast: dict[tuple[int, RecordKey], tuple[float, int]] = {}
        self._advertised: dict[tuple[int, RecordKey], Answer] = {}

    def note_sent(self, reply: Reply, *, monotonic: float) -> None:
        """Call only after a successful send; plans and failed sends do not count."""
        if not math.isfinite(monotonic):
            raise ValueError('invalid send clock')
        self._multicast = {key: value for key, value in self._multicast.items()
                           if 0 <= monotonic - value[0] < value[1]}
        for record in reply.records:
            key = (reply.family, record.key)
            if record.ttl == 0:
                self._multicast.pop(key, None)
                self._advertised.pop(key, None)
            else:
                if reply.destination == 'multicast':
                    self._multicast[key] = (monotonic, record.ttl)
                if struct.unpack_from('!H', reply.wire, 4)[0] == 0:
                    self._advertised[key] = record
        # Omitted history causes a conservative multicast response to QU.
        while len(self._multicast) > MAX_RECORDS * 2:
            del self._multicast[next(iter(self._multicast))]
        while len(self._advertised) > MAX_RECORDS * 2:
            del self._advertised[next(iter(self._advertised))]

    def withdrawals(self, *, policy, now, monotonic, family):
        """Withdraw only previously sent mDNS records absent from current authority.

        Some clients extend short PTR TTLs, so positive wire TTL expiry alone
        cannot remove their browse entries. Retain bounded sent evidence until
        a successful goodbye; rate-limited sends retry on the next sweep.
        """
        live = {a.key for a in response_view(self.catalog.records(now=now, monotonic=monotonic), policy)}
        removed = [replace(answer, ttl=0, unique=False)
                   for (sent_family, key), answer in self._advertised.items()
                   if sent_family == family and key not in live][:16]
        return _pack(PodQuery(0, (), ()), removed, [], destination='multicast',
                     family=family, legacy=False, budget=1232)

    def build(self, query: PodQuery, *, policy: PublicationPolicy, now: datetime,
              monotonic: float, source_port: int, family: int,
          direct_unicast: bool = False, budget: int = 1232, ttl_limit: int = 30) -> Result:
        """Build positive responses from fresh authorized state, never from pod RRs."""
        if query.truncated or not query.questions:
            raise ValueError("query assembly must finish before building replies")
        if type(source_port) is not int or not 1 <= source_port <= 65535:
            raise ValueError('invalid source port')
        if family not in (4, 6) or type(budget) is not int or not 512 <= budget <= 8952:
            raise ValueError('invalid family or packet budget')
        if type(ttl_limit) is not int or not 0 <= ttl_limit <= 30:
            raise ValueError('invalid local eligibility TTL limit')
        view = response_view(self.catalog.records(now=now, monotonic=monotonic), policy)
        view = tuple(replace(a, ttl=min(a.ttl, ttl_limit)) for a in view) if ttl_limit else ()
        legacy = source_port != 5353
        known = {}
        if not legacy:
            for item in query.known_answers:
                key = (item.name, item.type, item.data)
                known[key] = max(known.get(key, 0), item.ttl)
        suppressed = {a.key for a in view if known.get(a.key, 0) * 2 >= a.ttl}
        # If any member of a unique RRset needs updating, transmit the full set.
        incomplete = {a.rrset for a in view if a.unique and a.key not in suppressed}
        suppressed -= {a.key for a in view if a.unique and a.rrset in incomplete}
        destinations = {'multicast': {}, 'peer': {}}
        misses = []
        for question, qu in zip(query.questions, query.unicast_requested, strict=True):
            name = dns.name.from_text(question.name)
            matches = [a for a in view if a.name == name and
                       (question.type == rt.ANY or question.type == a.type)]
            if not matches:
                misses.append(question)
            for answer in matches:
                if answer.key in suppressed:
                    continue
                sent = self._multicast.get((family, answer.key))
                recent = sent is not None and 0 <= monotonic - sent[0] < min(sent[1], answer.ttl) / 4
                destination = 'peer' if legacy or ((qu or direct_unicast) and recent) else 'multicast'
                destinations[destination][answer.key] = answer
        multicast_sets = {a.rrset for a in destinations['multicast'].values() if a.unique}
        for answer in view:
            if answer.unique and answer.rrset in multicast_sets:
                destinations['multicast'][answer.key] = answer
        # RFC 6762 section 6: different questions/transaction IDs must not
        # cause the same record to be multicast twice within one second.
        held = {a.key for a in view if (family, a.key) in self._multicast
                and 0 <= monotonic - self._multicast[(family, a.key)][0] < 1}
        held_sets = {a.rrset for a in view if a.unique and a.key in held}
        held.update(a.key for a in view if a.unique and a.rrset in held_sets)
        for key in destinations['multicast']:
            destinations['peer'].pop(key, None)
        destinations['multicast'] = {key: answer for key, answer in destinations['multicast'].items()
                                     if key not in held}
        replies = []
        try:
            for destination, selected in destinations.items():
                extra = {}
                for answer in selected.values():
                    for dependency in additionals(answer, view):
                        if (dependency.key not in selected and dependency.key not in suppressed
                                and (destination != 'multicast' or dependency.key not in held)):
                            extra[dependency.key] = dependency
                replies.extend(_pack(query, list(selected.values()), list(extra.values()),
                                     destination=destination, family=family, legacy=legacy, budget=budget))
            if len(replies) > 16:
                raise ValueError('response packet count exceeds budget')
        except ValueError:
            return Result((), tuple(misses), oversized=True)
        return Result(tuple(replies), tuple(misses))
