"""Offline descriptive metadata; observed names never depend on registry approval."""

import csv
import hashlib
import io
import json
from pathlib import Path
import re
import sqlite3

import dns.name

from discovery.policy import service_identifier


def observed_type(value):
    name = dns.name.from_text(value).canonicalize()
    labels = name.labels
    if labels[-2:] == (b'local', b''):
        labels = labels[:-2]
    elif labels[-1:] == (b'',):
        labels = labels[:-1]
    if len(labels) != 2 or not labels[0].startswith(b'_') or len(labels[0]) < 2 or labels[1] not in (b'_tcp', b'_udp'):
        raise ValueError('expected a DNS-SD service type')
    return dns.name.Name(labels + (b'',)).to_text().rstrip('.')


def generated_type(identifier, transport):
    if transport not in ('tcp', 'udp'):
        raise ValueError('DNS-SD requires tcp or udp')
    return '_' + service_identifier(identifier) + '._' + transport


class Registry:
    def __init__(self, directory):
        path = Path(directory)
        manifest = json.loads((path / 'manifest.json').read_text())
        raw = {}
        for name in ('service-types', 'iana.csv'):
            data = (path / name).read_bytes()
            if len(data) > 4_000_000 or hashlib.sha256(data).hexdigest() != manifest['files'][name]['sha256']:
                raise ValueError('registry hash/size mismatch')
            raw[name] = data
        self.digest = hashlib.sha256(raw['service-types'] + b'\0' + raw['iana.csv']).hexdigest()
        descriptions = {}
        for line in raw['service-types'].decode('utf-8').splitlines():
            if not line.strip() or line.startswith('#'):
                continue
            key, text = line.split(':', 1)
            match = re.fullmatch(r'([^\[]+)(?:\[([^\]]+)\])?', key)
            if match is None:
                raise ValueError('malformed Avahi metadata')
            kind, locale = match.groups()
            kind = observed_type(kind)
            descriptions.setdefault(kind, {})[locale or ''] = text.strip()
        self.descriptions = descriptions
        reader = csv.DictReader(io.StringIO(raw['iana.csv'].decode('utf-8-sig')))
        if not {'Service Name', 'Port Number', 'Transport Protocol', 'Description'} <= set(reader.fieldnames or ()):
            raise ValueError('invalid IANA fields')
        self.rows = tuple(dict(row) for row in reader)
        self.by_service = {}
        for row in self.rows:
            if None in row:
                raise ValueError('malformed IANA row')
            key = (row['Service Name'].lower(), row['Transport Protocol'].lower())
            self.by_service.setdefault(key, []).append(row)

    def describe(self, kind, locale=''):
        key = observed_type(kind)
        choices = self.descriptions.get(key, {})
        return choices.get(locale, choices.get(locale.split('_')[0], choices.get('', key)))

    def metadata(self, identifier, transport):
        # Return copies: caller edits must not change the active registry.
        return tuple(dict(row) for row in self.by_service.get((identifier.lower(), transport.lower()), ()))


class RegistryStore:
    """Atomic activation history. Rollback is an explicit new monotonic revision."""
    def __init__(self, database):
        self.db = sqlite3.connect(database)
        self.db.execute('CREATE TABLE IF NOT EXISTS registry_history (revision INTEGER PRIMARY KEY, digest TEXT NOT NULL)')
        self.active = None

    def activate(self, directory, *, revision, rollback=False):
        candidate = Registry(directory)
        if type(revision) is not int or not 1 <= revision < 2**63:
            raise ValueError('invalid registry revision')
        with self.db:
            latest = self.db.execute('SELECT revision,digest FROM registry_history ORDER BY revision DESC LIMIT 1').fetchone()
            previous = self.db.execute('SELECT 1 FROM registry_history WHERE digest=?', (candidate.digest,)).fetchone()
            if latest and (revision <= latest[0] or (previous and candidate.digest != latest[1] and not rollback)):
                raise ValueError('replayed revision or implicit registry rollback')
            self.db.execute('INSERT INTO registry_history VALUES (?,?)', (revision, candidate.digest))
        self.active = candidate
        return candidate

    def close(self):
        self.db.close()
