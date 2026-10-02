"""Compare persistent Go identities with the maintained Python implementation."""
import json
import sqlite3
import sys

import dns.name

from discovery.identity import Identities


def dump(path):
    with sqlite3.connect(path) as db:
        identities = [
            (identity, source, bytes(original).hex(), dns.name.from_text(alias).to_wire().hex(), collision)
            for identity, source, original, alias, collision in db.execute(
                "SELECT identity,source,original,alias,collision FROM identities ORDER BY identity")
        ]
        reservations = [(bytes(name).hex(), identity) for name, identity in db.execute(
            "SELECT name,identity FROM reservations ORDER BY name")]
    return identities, reservations


if sys.argv[1] == "compare":
    assert dump(sys.argv[2]) == dump(sys.argv[3]), "SQLite identities or reservations differ"
else:
    store = Identities(sys.argv[2])
    operations = []
    names = [dns.name.from_text("sensor.local."), dns.name.from_text("Sensor.LOCAL.")]
    for label in [b"Demo", "Café.with dot".encode(), b"\xff\xfe", b"\xe1\x80",
                  b"\xf0\x90\x80X", ("😀" * 15 + "ABC").encode()]:
        names.append(dns.name.Name((label, b"_presence_olpc", b"_tcp", b"local", b"")))
    for name in names:
        identity, alias = store.alias("lan-a", name)
        operations.append(dict(op="alias", source="lan-a", name=name.to_text(),
                               identity=identity, alias_wire=alias.to_wire().hex()))
    rotated = store.rotate_alias(alias.to_text())
    operations.append(dict(op="rotate", source="lan-a", name=alias.to_text(),
                           alias_wire=rotated.to_wire().hex()))
    store.close()
    print(json.dumps(operations))
