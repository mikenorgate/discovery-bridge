"""Bounded native-record snapshots and a leased, replay-resistant in-memory view.

Transport authentication, persistent replay state and translated records are
not supplied here. The caller supplies operator-owned source/address policy.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
import json
import math
from types import MappingProxyType

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype

MAX_BYTES = 1_048_576
MAX_RECORDS = 4096
MAX_LEASE_SECONDS = 30
CLOCK_SKEW_SECONDS = 5
MAX_TTL = 30


@dataclass(frozen=True)
class Record:
    """Immutable, canonical DNS text with independently expiring provenance."""

    id: str
    name: str
    type: int
    data: str
    source_link: str
    expires_at: datetime
    native_id: str | None = None

    def identity(self) -> tuple:
        return (self.id, self.name, self.type, self.data, self.source_link,
                self.expires_at.isoformat(), self.native_id)


@dataclass(frozen=True)
class Snapshot:
    """A full v1 native catalog; omission withdraws a prior record."""

    epoch: str
    revision: int
    issued_at: datetime
    valid_until: datetime
    records: tuple[Record, ...]
    digest: str


@dataclass(frozen=True, init=False)
class SourcePolicy:
    """Operator-owned source scopes; callers cannot mutate them after creation."""

    sources: Mapping[str, tuple[IPv4Network | IPv6Network, ...]]
    forbidden: tuple[IPv4Network | IPv6Network, ...]

    def __init__(self, sources: dict[str, tuple[str, ...]], forbidden: tuple[str, ...]):
        if not sources or any(not key or not prefixes for key, prefixes in sources.items()):
            raise ValueError("every source needs an address scope")
        object.__setattr__(self, "sources", MappingProxyType({
            key: tuple(ip_network(p) for p in prefixes) for key, prefixes in sources.items()
        }))
        # Synthetic spaces cannot enter this native-only schema, even when an
        # operator allows a larger enclosing ULA prefix. NAT rendering is G3.
        object.__setattr__(self, "forbidden", tuple(ip_network(p) for p in forbidden) + tuple(map(ip_network, (
            "198.19.200.0/24", "2001:db8:1000:fd46::/96",
            "2001:db8:1000:fd65::/96", "64:ff9b::/96",
            "2001:db8:1000:f000::/56",
        ))))

    def check_address(self, source: str, address: str) -> None:
        value = ip_address(address)
        if value.is_loopback or value.is_link_local or value.is_multicast or value.is_unspecified:
            raise ValueError("unusable discovery address")
        if getattr(value, "ipv4_mapped", None) or getattr(value, "scope_id", None):
            raise ValueError("mapped or scoped address is not a native catalog address")
        if any(value in prefix for prefix in self.forbidden):
            raise ValueError("address belongs to a forbidden or synthetic scope")
        scopes = [prefix for prefix in self.sources[source] if value in prefix]
        if not scopes:
            raise ValueError("address is outside its source scope")
        if value.version == 4 and any(prefix.prefixlen < 31 and
                                     value in (prefix.network_address, prefix.broadcast_address)
                                     for prefix in scopes):
            raise ValueError("network or broadcast address is not an endpoint")


def _object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _fields(value: object, required: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("unexpected or missing object fields")
    return value


def _text(value: object, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ValueError("invalid text field")
    return value


def _time(value: object) -> datetime:
    text = _text(value, 40)
    try:
        result = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("timestamp must have a timezone")
    return result.astimezone(timezone.utc)


def _name(value: object) -> str:
    name = dns.name.from_text(_text(value, 1024), origin=None)
    if not name.is_absolute() or not name.is_subdomain(dns.name.from_text("local.")):
        raise ValueError("native discovery names must be absolute local names")
    return name.to_text()


def decode_snapshot(payload: bytes, *, now: datetime, policy: SourcePolicy, allow_translated=False) -> Snapshot:
    """Reject a malformed full snapshot atomically; stale individual records expire later."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("current time must have a timezone")
    if not 1 <= len(payload) <= MAX_BYTES:
        raise ValueError("catalog byte limit exceeded")
    try:
        data = json.loads(payload.decode("utf-8"), object_pairs_hook=_object)
        _fields(data, {"schema", "epoch", "revision", "issued_at", "valid_until", "records"})
        if type(data['schema']) is not int or data['schema'] not in ((1, 2) if allow_translated else (1,)):
            raise ValueError("unsupported catalog schema")
        if type(data['revision']) is not int or not 1 <= data['revision'] <= 2**63 - 1:
            raise ValueError("invalid catalog revision")
        epoch = _text(data['epoch'], 128)
        issued, until = _time(data['issued_at']), _time(data['valid_until'])
        if not 0 < (until - issued).total_seconds() <= MAX_LEASE_SECONDS:
            raise ValueError("invalid catalog lease")
        if (issued - now).total_seconds() > CLOCK_SKEW_SECONDS or until <= now:
            raise ValueError("future or expired catalog")
        raw = data['records']
        if not isinstance(raw, list) or len(raw) > MAX_RECORDS:
            raise ValueError("catalog record limit exceeded")
        records = []
        ids = set()
        types = {"A", "AAAA", "PTR", "SRV", "TXT"}
        for item in raw:
            derived = data["schema"] == 2 and isinstance(item, dict) and "native_id" in item
            _fields(item, {"id", "name", "type", "data", "source_link", "expires_at"} | ({"native_id"} if derived else set()))
            identifier = _text(item['id'], 128)
            if identifier in ids:
                raise ValueError("duplicate record identity")
            ids.add(identifier)
            source = _text(item['source_link'], 128)
            if source not in policy.sources:
                raise ValueError("unapproved catalog source")
            kind = _text(item['type'], 8)
            if kind not in types:
                raise ValueError("unsupported catalog record type")
            name = _name(item['name'])
            rtype = dns.rdatatype.from_text(kind)
            parsed = dns.rdata.from_text(dns.rdataclass.IN, rtype, _text(item['data'], 4096),
                                        origin=dns.name.root, relativize=False)
            if kind in {'A', 'AAAA'} and not derived:
                policy.check_address(source, parsed.address)
            if kind in {'PTR', 'SRV'}:
                _name(parsed.target.to_text())
            records.append(Record(identifier, name, int(rtype), parsed.to_text(), source,
                                  _time(item['expires_at']), _text(item['native_id'], 128) if derived else None))
        if data["schema"] == 2:
            from discovery.translation import validate_derived
            validate_derived(records, now=now, until=until)
        immutable = tuple(sorted(records, key=lambda record: record.id))
        digest = hashlib.sha256(json.dumps([r.identity() for r in immutable]).encode()).hexdigest()
        return Snapshot(epoch, data['revision'], issued, until, immutable, digest)
    except (dns.exception.DNSException, UnicodeError, RecursionError, TypeError, OverflowError) as exc:
        raise ValueError("invalid catalog encoding or record") from exc


class Catalog:
    """Single-owner in-memory view; accepted watermarks survive expiry/withdrawal.

    Access from one event-loop thread. Epoch changes require a new gateway
    bootstrap; persistent restart/replay protection is still a separate gate.
    """

    def __init__(self, policy: SourcePolicy, *, allow_translated=False):
        self.policy = policy
        self.allow_translated = allow_translated
        self.snapshot = None
        self._wall = None
        self._mono = None
        self._last_mono = None
        self._feed_deadline = 0.0
        self._record_deadlines = {}
        self._clock_failed = False

    def _check_clock(self, now: datetime, monotonic: float) -> None:
        if now.tzinfo is None or now.utcoffset() is None or not math.isfinite(monotonic):
            raise ValueError("invalid clock input")
        if self._clock_failed:
            raise ValueError("clock discontinuity requires a fresh gateway bootstrap")
        if self._last_mono is not None and monotonic < self._last_mono:
            self._clock_failed = True
            raise ValueError("monotonic clock moved backwards")
        if self._mono is not None:
            elapsed = monotonic - self._mono
            if elapsed < 0 or abs((now - self._wall).total_seconds() - elapsed) > CLOCK_SKEW_SECONDS:
                self._clock_failed = True
                raise ValueError("clock discontinuity")
        self._last_mono = monotonic

    def install(self, payload: bytes, *, now: datetime, monotonic: float) -> bool:
        """Install a complete valid replacement; replay cannot renew its lease."""
        self._check_clock(now, monotonic)
        candidate = decode_snapshot(payload, now=now, policy=self.policy, allow_translated=self.allow_translated)
        current = self.snapshot
        if current is not None:
            if candidate.epoch != current.epoch or candidate.revision < current.revision:
                raise ValueError("epoch change or catalog rollback requires gateway resync")
            if candidate.revision == current.revision and candidate.digest != current.digest:
                raise ValueError("record changes require a new revision")
            if candidate.issued_at < current.issued_at:
                raise ValueError("catalog issue time moved backwards")
            if candidate.revision == current.revision and candidate.issued_at == current.issued_at:
                if candidate.valid_until != current.valid_until:
                    raise ValueError("lease change requires a newer issue time")
                return False
        deadline = monotonic + min(MAX_LEASE_SECONDS, (candidate.valid_until - now).total_seconds())
        record_deadlines = {}
        previous = {record.id: record for record in current.records} if current else {}
        for record in candidate.records:
            expiry = monotonic + (record.expires_at - now).total_seconds()
            old = previous.get(record.id)
            if old is not None and old.expires_at == record.expires_at:
                expiry = min(expiry, self._record_deadlines[record.id])
            record_deadlines[record.id] = expiry
        self.snapshot = candidate
        self._wall, self._mono = now, monotonic
        self._feed_deadline, self._record_deadlines = deadline, record_deadlines
        return True

    def records(self, *, now: datetime, monotonic: float) -> tuple[tuple[Record, int], ...]:
        """Return fresh records and floored TTLs, or nothing on loss of clock trust."""
        try:
            self._check_clock(now, monotonic)
        except ValueError:
            return ()
        if self.snapshot is None:
            return ()
        answer = []
        for record in self.snapshot.records:
            ttl = math.floor(min(MAX_TTL, self._feed_deadline - monotonic,
                                 self._record_deadlines[record.id] - monotonic,
                                 self._record_deadlines[record.native_id] - monotonic if record.native_id else MAX_TTL,
                                 (record.expires_at - now).total_seconds(),
                                 (self.snapshot.valid_until - now).total_seconds()))
            if ttl >= 1:
                answer.append((record, ttl))
        return tuple(answer)
