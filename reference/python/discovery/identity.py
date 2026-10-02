"""Persistent source identities, gateway aliases and permanent name reservations."""

from dataclasses import replace
import hashlib
import sqlite3

import dns.name
import dns.rdata
import dns.rdatatype as rt

from discovery.records import PublicationPolicy, response_view


class Identities:
    def __init__(self, path):
        self.suppressed_hosts = set()
        self.db = sqlite3.connect(path)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS identities (
            identity TEXT PRIMARY KEY, source TEXT NOT NULL, original BLOB NOT NULL,
            alias TEXT NOT NULL UNIQUE, collision INTEGER NOT NULL DEFAULT 0,
            UNIQUE(source, original));
          CREATE TABLE IF NOT EXISTS reservations (name BLOB PRIMARY KEY, identity TEXT NOT NULL);
        ''')

    def close(self):
        self.db.close()

    def owns(self, name):
        key = name.canonicalize().to_wire()
        return self.db.execute('SELECT 1 FROM reservations WHERE name=?', (key,)).fetchone() is not None

    def owns_host(self, source, name):
        """An observed original hostname, distinct from our export aliases."""
        return (len(name.labels) == 3 and not self.owns(name) and
                self.db.execute('SELECT 1 FROM identities WHERE source=? AND original=?',
                                (source, name.canonicalize().to_wire())).fetchone() is not None)

    def resolve_conflicts(self, names):
        # Avahi reports an entire entry-group collision, not the offending RR.
        # Withdraw original names first; never rename the device or rotate all
        # stable service aliases because one added hostname is already in use.
        originals = {dns.name.from_text(n).canonicalize() for n in names
                     if not self.owns(dns.name.from_text(n))}
        if originals:
            self.suppressed_hosts.update(originals)
        else:
            for name in names:
                self.rotate_alias(name)

    def alias(self, source, name, *, collision=False):
        original = name.canonicalize().to_wire()
        identity = hashlib.sha256(source.encode() + b'\x00' + original).hexdigest()
        with self.db:
            row = self.db.execute('SELECT alias,collision FROM identities WHERE identity=?', (identity,)).fetchone()
            if row and not collision:
                return identity, dns.name.from_text(row[0])
            count = (row[1] + 1) if row else 0
            while True:
                suffix = hashlib.sha256((identity + ':' + str(count)).encode()).hexdigest()[:20]
                if len(name.labels) == 3:
                    alias = dns.name.from_text('db-' + suffix + '.local.')
                else:
                    label = name.labels[0].decode('utf-8', errors='replace')
                    while len(label.encode()) > 41:
                        label = label[:-1]
                    alias = dns.name.Name(((label + '-' + suffix).encode(),) + name.labels[1:])
                reserved = self.db.execute('SELECT identity FROM reservations WHERE name=?',
                                           (alias.canonicalize().to_wire(),)).fetchone()
                if reserved is None:
                    break
                count += 1
            self.db.execute('INSERT INTO reservations VALUES (?,?)', (alias.canonicalize().to_wire(), identity))
            self.db.execute('INSERT INTO identities VALUES (?,?,?,?,?) ON CONFLICT(identity) DO UPDATE SET alias=excluded.alias, collision=excluded.collision',
                            (identity, source, original, alias.to_text(), count))
        return identity, alias

    def rotate_alias(self, alias):
        """Persist a remote collision decision before the next publication."""
        row = self.db.execute('SELECT source,original FROM identities WHERE alias=?',
                              (dns.name.from_text(alias).to_text(),)).fetchone()
        if row is not None:
            name, _ = dns.name.from_wire(bytes(row[1]), 0)
            return self.alias(row[0], name, collision=True)[1]
        return None

    def original(self, alias):
        """Resolve a current export alias back to its scoped LAN query name."""
        queried = dns.name.from_text(alias)
        row = self.db.execute('SELECT source,original,alias FROM identities JOIN reservations USING(identity) WHERE name=?',
                              (queried.canonicalize().to_wire(),)).fetchone()
        if row is None or dns.name.from_text(row[2]) != queried:
            return None
        name, _ = dns.name.from_wire(bytes(row[1]), 0)
        return row[0], name.to_text()

    def compile(self, records, *, now):
        """Rename before combining links; coherent views never join foreign targets."""
        aliases = {}
        for record in records:
            if record.type in (rt.A, rt.AAAA, rt.SRV, rt.TXT):
                name = dns.name.from_text(record.name)
                aliases[(record.source_link, name)] = self.alias(record.source_link, name)[1]
        renamed = []
        for record in records:
            name = dns.name.from_text(record.name)
            data = dns.rdata.from_text(1, record.type, record.data, origin=dns.name.root, relativize=False)
            if record.type in (rt.PTR, rt.SRV):
                target = aliases.get((record.source_link, data.target), data.target)
                data = data.replace(target=target)
            name = aliases.get((record.source_link, name), name)
            renamed.append(replace(record, name=name.to_text(), data=data.to_text()))
        policy = PublicationPolicy(frozenset(r.id for r in renamed),
                                   frozenset((r.name, r.type) for r in renamed if r.type != rt.PTR))
        values = tuple((r, min(30, int((r.expires_at - now).total_seconds()))) for r in renamed if r.expires_at > now)
        return tuple(a for a in response_view(values, policy) if a.ttl > 0)
