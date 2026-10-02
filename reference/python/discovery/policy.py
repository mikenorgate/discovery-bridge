"""Side-effect-free publication rules; no network, allocator or runtime access.

Mapping inputs must come from a validated router readiness adapter. This module
checks consistency and expiry; it does not authenticate router acknowledgements.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Network, IPv6Address
import re


def remaining_ttl(now: datetime, *deadlines: datetime, maximum: int = 30) -> int:
    """Floor the shortest validity to seconds; never turn expiry into freshness."""
    if type(maximum) is not int or maximum < 1:
        raise ValueError("maximum TTL must be a positive integer")
    if not deadlines:
        raise ValueError("at least one validity deadline is required")
    if any(value.tzinfo is None or value.utcoffset() is None for value in (now, *deadlines)):
        raise ValueError("validity timestamps must have a timezone")
    seconds = min((deadline - now) // timedelta(seconds=1) for deadline in deadlines)
    return max(0, min(maximum, seconds))


def service_identifier(value: str) -> str:
    """Validate a generated RFC6335 identifier, without its DNS-SD underscore."""
    if not 1 <= len(value) <= 15:
        raise ValueError("service identifier must contain 1 to 15 ASCII characters")
    if not re.fullmatch(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*", value):
        raise ValueError("invalid service identifier syntax")
    if not re.search(r"[A-Za-z]", value):
        raise ValueError("service identifier must contain a letter")
    return value.lower()


@dataclass(frozen=True)
class MappingReadiness:
    """A router-adapter observation; construction alone does not prove trust."""

    endpoint_id: str
    target: IPv6Address
    alias: IPv4Address
    desired_generation: int
    installed_generation: int
    acknowledged_generation: int
    state: str
    valid_until: datetime


@dataclass(frozen=True)
class SyntheticA:
    """Eligible synthetic IPv4 data, not a DNS publication or allocation."""

    address: IPv4Address
    ttl: int
    generation: int


def nat46_record(
    mapping: MappingReadiness | None,
    *,
    endpoint_id: str,
    target: IPv6Address,
    now: datetime,
    source_until: datetime,
    catalog_until: datetime,
    pool: IPv4Network,
    reserved: frozenset[IPv4Address],
    maximum_ttl: int = 30,
) -> SyntheticA | None:
    """Return A data only for this target's current installed/acknowledged map.

    The caller owns native A handling and target/link admission. This function
    has no allocator callback and does not modify mapping state. Pool network,
    broadcast and explicitly reserved addresses cannot be published.
    """
    if mapping is None or not endpoint_id or mapping.endpoint_id != endpoint_id:
        return None
    if not isinstance(target, IPv6Address) or target.ipv4_mapped is not None:
        return None
    if target.is_unspecified or target.is_multicast or target.is_loopback or target.is_link_local:
        return None
    if target.scope_id is not None or mapping.target != target or mapping.state != "ready":
        return None
    generations = (
        mapping.desired_generation,
        mapping.installed_generation,
        mapping.acknowledged_generation,
    )
    if any(type(value) is not int or value < 1 for value in generations):
        return None
    if len(set(generations)) != 1:
        return None
    if not isinstance(mapping.alias, IPv4Address) or mapping.alias not in pool:
        return None
    if mapping.alias in reserved or mapping.alias in (pool.network_address, pool.broadcast_address):
        return None
    ttl = remaining_ttl(
        now, source_until, catalog_until, mapping.valid_until, maximum=maximum_ttl
    )
    if ttl == 0:
        return None
    return SyntheticA(mapping.alias, ttl, mapping.acknowledged_generation)
