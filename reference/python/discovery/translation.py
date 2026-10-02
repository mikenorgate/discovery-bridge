"""Read-only translated views. Mapping acquisition/authentication belongs to G3."""
from dataclasses import replace
from datetime import timedelta
from ipaddress import IPv4Address, IPv4Network, IPv6Address

import dns.name
import dns.rdata
import dns.rdatatype as rt

from discovery.policy import nat46_record
from discovery.catalog import MAX_RECORDS
from discovery.records import PublicationPolicy, response_view

NAT64 = IPv6Address('2001:db8:1000:fd65::')
POOL = IPv4Network('198.19.200.0/24')
RESERVED = frozenset({IPv4Address('198.19.200.1')})


def translated_records(records, *, now, catalog_until, mappings, nat64=False, nat46=False):
    """Input native records must already pass SourcePolicy, mappings must be trusted.

    Mapping dictionary keys are native address record IDs, never query names.
    There is deliberately no allocation callback.
    """
    records = tuple(r for r in records if r.expires_at > now)
    result = list(records)
    hosts = {}
    for record in records:
        hosts.setdefault((record.source_link, dns.name.from_text(record.name)), set()).add(record.type)
    for record in records:
        if len(result) >= MAX_RECORDS:
            break  # Keep native discovery usable when the export budget is full.
        if record.native_id is not None:
            continue
        types = hosts[(record.source_link, dns.name.from_text(record.name))]
        if (nat64 and catalog_until > now and record.type == rt.A and rt.AAAA not in types
                and IPv4Address(record.data) not in POOL):
            address = str(IPv6Address(int(NAT64) + int(IPv4Address(record.data))))
            result.append(replace(record, id=record.id + ':nat64', type=rt.AAAA, data=address,
                                  expires_at=min(record.expires_at, catalog_until), native_id=record.id))
        if nat46 and record.type == rt.AAAA and rt.A not in types:
            eligible = nat46_record(mappings.get(record.id), endpoint_id=record.id,
                                   target=IPv6Address(record.data), now=now,
                                   source_until=record.expires_at, catalog_until=catalog_until,
                                   pool=POOL, reserved=RESERVED)
            if eligible:
                result.append(replace(record, id=record.id + ':nat46', type=rt.A, data=str(eligible.address),
                                      expires_at=now + timedelta(seconds=eligible.ttl), native_id=record.id))
    return tuple(result)


def coherent_translated_view(records, *, now, catalog_until, mappings, nat64=False, nat46=False):
    values = translated_records(records, now=now, catalog_until=catalog_until, mappings=mappings,
                                nat64=nat64, nat46=nat46)
    policy = PublicationPolicy(frozenset(r.id for r in values),
                               frozenset((r.name, r.type) for r in values if r.type != rt.PTR))
    return response_view(tuple((r, min(30, int((min(r.expires_at, catalog_until) - now).total_seconds())))
                               for r in values if min(r.expires_at, catalog_until) >= now + timedelta(seconds=1)), policy)


def validate_derived(records, *, now, until):
    """Validate gateway-derived addresses without relaxing native source admission.

    NAT46 readiness remains gateway authority, carried by the derived record's
    expiry. Nodes verify its native target, pool and lease; they cannot allocate.
    """
    by_id = {r.id: r for r in records}
    native_rrsets = {(r.source_link, dns.name.from_text(r.name), r.type)
                     for r in records if r.native_id is None and r.expires_at > now}
    seen = set()
    aliases = {}
    for record in records:
        if record.native_id is None:
            continue
        native = by_id.get(record.native_id)
        if (native is None or native.native_id is not None or record.source_link != native.source_link
                or dns.name.from_text(record.name) != dns.name.from_text(native.name)
                or record.expires_at > min(native.expires_at, until)
                or (record.native_id, record.type) in seen):
            raise ValueError('invalid translated record provenance or expiry')
        seen.add((record.native_id, record.type))
        if record.type == rt.AAAA and native.type == rt.A:
            if IPv4Address(native.data) in POOL or IPv6Address(record.data) != IPv6Address(int(NAT64) + int(IPv4Address(native.data))):
                raise ValueError('invalid NAT64 derivation')
        elif record.type == rt.A and native.type == rt.AAAA:
            alias = IPv4Address(record.data)
            if alias not in POOL or alias in RESERVED or alias in (POOL.network_address, POOL.broadcast_address):
                raise ValueError('invalid NAT46 alias')
            target = IPv6Address(native.data)
            if alias in aliases and aliases[alias] != target:
                raise ValueError('NAT46 alias has conflicting targets')
            aliases[alias] = target
        else:
            raise ValueError('invalid translated record type')
        if (native.source_link, dns.name.from_text(native.name), record.type) in native_rrsets:
            raise ValueError('native address takes precedence over translation')
