"""Regenerate synthetic DNS views with the verified Python reference."""
from dataclasses import replace
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference/python"))
from discovery.catalog import Record
from discovery.records import PublicationPolicy, response_view

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def record(identifier, name, kind, data, source="lab-a", seconds=20):
    return Record(identifier, name, kind, data, source, NOW + timedelta(seconds=seconds))


BASE = [
    record("host4", "sensor.local.", 1, "192.0.2.42"),
    record("host6", "sensor.local.", 28, "2001:db8:1::42"),
    record("srv", "Sensor._example._tcp.local.", 33, "0 0 6053 sensor.local."),
    record("txt", "Sensor._example._tcp.local.", 16, '"version=1"'),
    record("ptr", "_example._tcp.local.", 12, "Sensor._example._tcp.local."),
    record("sub", "_test._sub._example._tcp.local.", 12, "Sensor._example._tcp.local."),
    record("enum", "_services._dns-sd._udp.local.", 12, "_example._tcp.local."),
]
CASES = {
    "complete": BASE,
    "missing_txt": [r for r in BASE if r.id != "txt"],
    "missing_address": [r for r in BASE if r.id not in ("host4", "host6")],
    "standalone_enumeration": [BASE[-1]],
    "unknown_observed_type": [record("unknown", "_services._dns-sd._udp.local.", 12, "_vendor_weird._udp.local.")],
    "ambiguous_host": BASE + [record("foreign", "sensor.local.", 1, "198.51.100.42", "lab-b")],
    "foreign_dependency": [replace(r, source_link="lab-b", data="198.51.100.42" if r.id == "host4" else "2001:db8:2::42") if r.id in ("host4", "host6") else r for r in BASE],
    "duplicate_evidence": BASE + [replace(BASE[0], id="duplicate", expires_at=NOW+timedelta(seconds=3))],
    "rrset_shortest_ttl": BASE + [record("second", "sensor.local.", 1, "192.0.2.43", seconds=7)],
    "ambiguous_srv": BASE + [record("srv2", "Sensor._example._tcp.local.", 33, "0 0 6054 sensor.local.")],
    "expired_host": [replace(r, expires_at=NOW) if r.id in ("host4", "host6") else r for r in BASE],
    "zero_port": [replace(r, data="0 0 0 sensor.local.") if r.id == "srv" else r for r in BASE],
}


def fixture():
    result = []
    for name, records in CASES.items():
        selected = tuple((r, int((r.expires_at-NOW).total_seconds())) for r in records if r.expires_at > NOW)
        unique = {(r.name, r.type) for r in records if r.type != 12}
        authority = PublicationPolicy(frozenset(r.id for r in records), frozenset(unique))
        answers = response_view(selected, authority)
        expected = []
        for answer in answers:
            owner, kind, data = answer.key
            wire = owner + struct.pack("!HHIH", kind, 1, 0, len(data)) + data
            expected.append({"key": wire.hex(), "ttl": answer.ttl, "source": answer.source, "unique": answer.unique})
        result.append({
            "case": name,
            "snapshot": {"schema": 1, "epoch": "synthetic-reference", "revision": 1,
                         "issued_at": NOW.isoformat(), "valid_until": (NOW+timedelta(seconds=30)).isoformat(),
                         "records": [{"id": r.id, "name": r.name, "type": {1:"A",28:"AAAA",33:"SRV",16:"TXT",12:"PTR"}[r.type],
                                      "data": r.data, "source_link": r.source_link, "expires_at": r.expires_at.isoformat()} for r in records]},
            "expected": sorted(expected, key=lambda a: a["key"]),
        })
    return json.dumps(result, indent=2, sort_keys=True)+"\n"


if __name__ == "__main__":
    target = ROOT / "tests/fixtures/views.json"
    text = fixture()
    if "--check" in sys.argv:
        if target.read_text() != text:
            raise SystemExit("Reference views differ; regenerate and review the change.")
    else:
        target.parent.mkdir(exist_ok=True)
        target.write_text(text)
