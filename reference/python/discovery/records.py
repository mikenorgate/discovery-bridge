"""Build a coherent native response view from explicitly authorized records."""

from collections import defaultdict
from dataclasses import dataclass, replace

import dns.name
import dns.rdata
import dns.rdatatype as rt

from discovery.catalog import Record

RecordKey = tuple[bytes, int, bytes]
RRSetKey = tuple[bytes, int]
ENUMERATION = dns.name.from_text('_services._dns-sd._udp.local.')


@dataclass(frozen=True)
class Answer:
    name: dns.name.Name
    type: int
    data: dns.rdata.Rdata
    ttl: int
    source: str
    unique: bool

    @property
    def key(self) -> RecordKey:
        return (self.name.canonicalize().to_wire(), self.type, self.data.to_digestable())

    @property
    def rrset(self) -> RRSetKey:
        return self.key[:2]


@dataclass(frozen=True)
class PublicationPolicy:
    """Caller-owned export authorization; observation alone is insufficient.

    Unique RRsets must have established gateway ownership before use. Local
    conflict detection can block names without ever publishing the pod's claim.
    Production authorization and conflict observation are not supplied here.
    """

    record_ids: frozenset[str]
    unique_rrsets: frozenset[tuple[str, int]] = frozenset()
    blocked_names: frozenset[str] = frozenset()

    def __post_init__(self):
        for field in ('record_ids', 'unique_rrsets', 'blocked_names'):
            object.__setattr__(self, field, frozenset(getattr(self, field)))


def response_view(records: tuple[tuple[Record, int], ...], policy: PublicationPolicy) -> tuple[Answer, ...]:
    """Withhold collisions and service chains missing a same-source dependency."""
    unique = {(dns.name.from_text(name).canonicalize().to_wire(), kind)
              for name, kind in policy.unique_rrsets}
    blocked = {dns.name.from_text(name) for name in policy.blocked_names}
    candidates = []
    owners = defaultdict(set)
    for record, ttl in records:
        if record.id not in policy.record_ids:
            continue
        name = dns.name.from_text(record.name)
        data = dns.rdata.from_text(1, record.type, record.data, origin=dns.name.root, relativize=False)
        answer = Answer(name, record.type, data, ttl, record.source_link, False)
        answer = replace(answer, unique=record.type != rt.PTR and answer.rrset in unique)
        candidates.append(answer)
        # Shared PTR owners may occur on many VLANs; their target instances may not.
        if record.type != rt.PTR:
            owners[name].add(record.source_link)
    blocked.update(name for name, sources in owners.items() if len(sources) > 1)
    evidence = {}
    for answer in candidates:
        if answer.name in blocked:
            continue
        key = (answer.source, answer.key)
        if key not in evidence or answer.ttl < evidence[key].ttl:
            evidence[key] = answer
    candidates = list(evidence.values())

    by_name = defaultdict(list)
    for answer in candidates:
        by_name[(answer.source, answer.name)].append(answer)
    hosts = {}
    for key, values in by_name.items():
        addresses = [a for a in values if a.type in (rt.A, rt.AAAA)]
        if addresses:
            hosts[key] = addresses

    services = {}
    for key, values in by_name.items():
        srvs = {a.key: a for a in values if a.type == rt.SRV}
        txts = {a.key: a for a in values if a.type == rt.TXT}
        # DNS-SD has one SRV and one TXT per instance. Ambiguity is withheld
        # until gateway collision/alias reconciliation has resolved it.
        if len(srvs) != 1 or len(txts) != 1:
            continue
        srv, txt = next(iter(srvs.values())), next(iter(txts.values()))
        addresses = hosts.get((srv.source, srv.data.target), [])
        if srv.data.port == 0 or not addresses:
            continue
        ttl = min(srv.ttl, txt.ttl, *(a.ttl for a in addresses))
        services[key] = (replace(srv, ttl=ttl), replace(txt, ttl=ttl))

    view = [a for addresses in hosts.values() for a in addresses]
    view.extend(a for service in services.values() for a in service)
    browses = []
    for answer in candidates:
        if answer.type != rt.PTR or answer.name == ENUMERATION:
            continue
        service = services.get((answer.source, answer.data.target))
        if service:
            browses.append(replace(answer, ttl=min(answer.ttl, *(a.ttl for a in service))))
    view.extend(browses)
    for answer in candidates:
        if answer.type == rt.PTR and answer.name == ENUMERATION:
            # Type discovery precedes instance resolution (RFC 6763 section 9).
            # Requiring a complete instance here hides the type that a browser
            # needs to query to obtain those missing records in the first place.
            labels = answer.data.target.canonicalize().labels
            if (len(labels) == 4 and labels[0].startswith(b'_') and len(labels[0]) > 1
                    and labels[1] in (b'_tcp', b'_udp') and labels[2] == b'local'):
                view.append(answer)

    # Duplicate evidence must not extend a record. RRset TTLs share the shortest
    # member validity; this also makes partial cache-flush updates unnecessary.
    deduplicated = {}
    for answer in view:
        previous = deduplicated.get(answer.key)
        if previous is None or answer.ttl < previous.ttl:
            deduplicated[answer.key] = answer
    ttls = {}
    for answer in deduplicated.values():
        ttls[answer.rrset] = min(ttls.get(answer.rrset, answer.ttl), answer.ttl)
    return tuple(replace(a, ttl=ttls[a.rrset]) for a in deduplicated.values())


def additionals(answer: Answer, view: tuple[Answer, ...]) -> tuple[Answer, ...]:
    """Return only same-source dependencies; enumeration does not recurse."""
    if answer.type == rt.PTR and answer.name != ENUMERATION:
        service = [a for a in view if a.source == answer.source and a.name == answer.data.target
                   and a.type in (rt.SRV, rt.TXT)]
        addresses = [a for srv in service if srv.type == rt.SRV for a in view
                     if a.source == srv.source and a.name == srv.data.target and a.type in (rt.A, rt.AAAA)]
        return tuple(service + addresses)
    if answer.type == rt.SRV:
        return tuple(a for a in view if a.source == answer.source and a.name == answer.data.target
                     and a.type in (rt.A, rt.AAAA))
    return ()
