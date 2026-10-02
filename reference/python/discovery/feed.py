"""Leased full native catalogs; node state lives only in memory.

The fixed internal HTTP endpoint relies on router/Cilium network restrictions.
Nonces correlate replies with live requests; digests detect corruption, not a
forged sender. Nodes bootstrap from a fresh read after every restart.
"""
import copy
from datetime import timedelta
import fcntl
import hashlib
import json
import re
import secrets
import sqlite3
from uuid import uuid4

import dns.name
import dns.exception
import dns.rdatatype as rt

from discovery.catalog import Catalog, MAX_BYTES, _fields, _object, decode_snapshot
from discovery.records import PublicationPolicy, response_view

MAX_FEED_BYTES = 2_097_152


def encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def nonce(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('invalid catalog challenge')
    return value


def integer(value):
    if type(value) is not int or not 1 <= value < 2**63:
        raise ValueError('invalid generation/revision')
    return value


def export_records(answers, now):
    """Encode already-authorized native answers without extending their TTLs."""
    records, unique = [], set()
    for answer in answers:
        identifier = hashlib.sha256(encode([answer.source, answer.name.to_text(), answer.type, answer.data.to_text()])).hexdigest()
        records.append({'id': identifier, 'name': answer.name.to_text(), 'type': rt.to_text(answer.type),
                        'data': answer.data.to_text(), 'source_link': answer.source,
                        'expires_at': (now + timedelta(seconds=answer.ttl)).isoformat()})
        if answer.unique:
            unique.add((answer.name.canonicalize().to_text(), int(answer.type)))
    return sorted(records, key=lambda r: r['id']), sorted(unique)


class GatewayFeed:
    """One local gateway owner, fed by a trusted expiring native Catalog."""
    def __init__(self, source, authority, database, *, policy_revision=1, translation=None):
        self.source, self.authority = source, authority
        self.translation = translation
        self.policy_revision = integer(policy_revision)
        self._lock = open(str(database) + '.lock', 'a+b')
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect(database)
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('CREATE TABLE IF NOT EXISTS gateway_generation (id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL)')
            with self.db:
                self.db.execute('BEGIN IMMEDIATE')
                row = self.db.execute('SELECT generation FROM gateway_generation WHERE id=1').fetchone()
                self.generation = integer(row[0] + 1 if row else 1)
                self.db.execute('INSERT INTO gateway_generation VALUES (1,?) ON CONFLICT(id) DO UPDATE SET generation=excluded.generation', (self.generation,))
        except BaseException:
            if hasattr(self, 'db'): self.db.close()
            self._lock.close()
            raise
        self.epoch = str(uuid4())
        self._revision, self._signature = 0, None

    def read(self, *, sources, challenge, now, monotonic):
        nonce(challenge)
        native = tuple((r, ttl) for r, ttl in self.source.records(now=now, monotonic=monotonic) if r.source_link in sources)
        answers = response_view(native, self.authority)
        records, unique = export_records(answers, now)
        snapshot = {'schema': 1, 'epoch': self.epoch, 'revision': 1,
                    'issued_at': now.isoformat(), 'valid_until': (now + timedelta(seconds=30)).isoformat(),
                    'records': records}
        if self.translation is not None:
            admitted = decode_snapshot(encode(snapshot), now=now, policy=self.source.policy)
            rendered = self.translation.render(admitted.records, now=now, monotonic=monotonic)
            by_id = {r.id: r for r in admitted.records}
            for record in rendered:
                if record.native_id is None:
                    continue
                records.append({'id': record.id, 'name': record.name, 'type': rt.to_text(record.type),
                                'data': record.data, 'source_link': record.source_link,
                                'expires_at': record.expires_at.isoformat(), 'native_id': record.native_id})
                native_record = by_id[record.native_id]
                if (dns.name.from_text(native_record.name).canonicalize().to_text(), native_record.type) in unique:
                    unique.append((dns.name.from_text(record.name).canonicalize().to_text(), record.type))
            if any(r.get('native_id') for r in records):
                snapshot['schema'] = 2
            unique = sorted(set(unique))
        signature = hashlib.sha256(encode([records, unique, self.policy_revision])).hexdigest()
        revision = integer(self._revision + (signature != self._signature))
        snapshot['revision'] = revision
        value = {'schema': 1, 'generation': self.generation,
                 'policy_revision': self.policy_revision, 'nonce': challenge,
                 'unique_rrsets': unique,
                 'snapshot': snapshot}
        payload = encode(value)
        if len(payload) > MAX_FEED_BYTES or len(encode(value['snapshot'])) > MAX_BYTES:
            raise ValueError('catalog envelope exceeds byte limit')
        self._revision, self._signature = revision, signature
        return payload

    def close(self):
        self.db.close()
        self._lock.close()


class NodeFeed:
    """One gateway per process; fresh HTTP bootstrap, no node database or disk cache."""
    def __init__(self, policy):
        self.catalog = Catalog(policy, allow_translated=True)
        self.authority = PublicationPolicy(frozenset())
        self.generation = None
        self._watermark = None
        self._nonce = None

    def begin_request(self):
        if self._nonce is not None:
            raise RuntimeError('only one catalog read may be outstanding')
        self._nonce = secrets.token_hex(32)
        return self._nonce

    def abort_request(self):
        self._nonce = None

    def accept_catalog(self, payload, *, now, monotonic):
        expected, self._nonce = self._nonce, None
        if expected is None or not 1 <= len(payload) <= MAX_FEED_BYTES:
            raise ValueError('catalog has no pending catalog read or exceeds budget')
        try:
            value = json.loads(payload.decode('utf-8'), object_pairs_hook=_object)
            _fields(value, {'schema', 'generation', 'policy_revision', 'nonce', 'snapshot', 'unique_rrsets'})
            if type(value['schema']) is not int or value['schema'] != 1:
                raise ValueError('invalid catalog envelope')
            if nonce(value['nonce']) != expected:
                raise ValueError('catalog response does not match this read')
            generation, policy_revision = integer(value['generation']), integer(value['policy_revision'])
            snapshot_payload = encode(value['snapshot'])
            snapshot = decode_snapshot(snapshot_payload, now=now, policy=self.catalog.policy, allow_translated=True)
            raw_unique = value['unique_rrsets']
            if not isinstance(raw_unique, list) or len(raw_unique) > 4096:
                raise ValueError('ownership metadata limit')
            present = {(dns.name.from_text(r.name).canonicalize().to_text(), r.type) for r in snapshot.records if r.type != rt.PTR}
            unique = set()
            for pair in raw_unique:
                if not isinstance(pair, list) or len(pair) != 2 or not isinstance(pair[0], str) or type(pair[1]) is not int:
                    raise ValueError('invalid unique RRset claim')
                name = dns.name.from_text(pair[0]).canonicalize().to_text()
                key = (name, pair[1])
                if key not in present or key in unique:
                    raise ValueError('unknown or duplicate unique RRset claim')
                unique.add(key)
            signature = hashlib.sha256(encode([snapshot.digest, sorted(unique), policy_revision])).hexdigest()
            issued, until = snapshot.issued_at, snapshot.valid_until
            if self._watermark:
                old_generation, epoch, revision, digest, old_issued, old_until, old_policy = self._watermark
                if generation < old_generation or policy_revision < old_policy:
                    raise ValueError('catalog generation or policy rollback')
                if generation == old_generation:
                    if snapshot.epoch != epoch or snapshot.revision < revision or issued < old_issued:
                        raise ValueError('catalog epoch/revision/time rollback')
                    if snapshot.revision == revision and signature != digest:
                        raise ValueError('changed catalog requires a newer revision')
                    if issued == old_issued and until != old_until:
                        raise ValueError('replayed lease cannot be extended')
            # Validate the whole candidate before replacing any live state.
            same_epoch = self.generation == generation and not self.catalog._clock_failed
            candidate = copy.copy(self.catalog) if same_epoch else Catalog(self.catalog.policy, allow_translated=True)
            try:
                candidate.install(snapshot_payload, now=now, monotonic=monotonic)
            except ValueError:
                if candidate._clock_failed:
                    self.catalog._clock_failed = True
                raise
            self.catalog = candidate
            self.authority = PublicationPolicy(frozenset(r.id for r in snapshot.records), frozenset(unique))
            self.generation = generation
            self._watermark = (generation, snapshot.epoch, snapshot.revision, signature, issued, until, policy_revision)
            return snapshot.revision
        except (UnicodeError, RecursionError, TypeError, OverflowError, dns.exception.DNSException) as exc:
            raise ValueError('invalid catalog envelope') from exc
