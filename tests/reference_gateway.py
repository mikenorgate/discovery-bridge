"""Run the maintained Python gateway with synthetic data for Go interoperability."""
import asyncio
from datetime import datetime, timedelta, timezone
import json
import socket
import sys
import time

from discovery.catalog import Catalog, SourcePolicy
from discovery.feed import GatewayFeed, encode
from discovery.gateway import GatewayAPI, GatewayServer
from discovery.lookup import LookupCoordinator
from discovery.records import PublicationPolicy


async def main():
    policy = SourcePolicy({"lan-a": ("192.0.2.0/24", "2001:db8:1::/64")}, ())
    source = Catalog(policy)
    now = datetime.now(timezone.utc)
    values = [
        ("enum", "_services._dns-sd._udp.local.", "PTR", "_http._tcp.local."),
        ("browse", "_http._tcp.local.", "PTR", "Demo._http._tcp.local."),
        ("srv", "Demo._http._tcp.local.", "SRV", "0 0 8080 sensor.local."),
        ("txt", "Demo._http._tcp.local.", "TXT", r'"opaque=\255\000"'),
        ("v4", "sensor.local.", "A", "192.0.2.42"),
        ("v6", "sensor.local.", "AAAA", "2001:db8:1::42"),
    ]
    snapshot = {
        "schema": 1, "epoch": "reference-test", "revision": 1,
        "issued_at": now.isoformat(),
        "valid_until": (now + timedelta(seconds=30)).isoformat(),
        "records": [dict(id=identifier, name=name, type=kind, data=data,
                         source_link="lan-a", expires_at=(now + timedelta(seconds=20)).isoformat())
                    for identifier, name, kind, data in values],
    }
    source.install(encode(snapshot), now=now, monotonic=time.monotonic())
    authority = PublicationPolicy(frozenset(r[0] for r in values),
                                  frozenset({("Demo._http._tcp.local.", 33),
                                             ("Demo._http._tcp.local.", 16)}))
    feed = GatewayFeed(source, authority, sys.argv[1])
    calls = []

    async def demand(question, sources):
        assert sources == frozenset({"lan-a"})
        calls.append(question.as_dict())

    lookups = LookupCoordinator(policy.sources, demand)
    server = GatewayServer(GatewayAPI(feed, lookups), ["127.0.0.1/32"])
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    await server.start(listener)
    print(json.dumps({"port": listener.getsockname()[1]}), flush=True)
    try:
        while command := await asyncio.to_thread(sys.stdin.readline):
            command = command.strip()
            if command == "withdraw":
                now = datetime.now(timezone.utc)
                snapshot.update(revision=2, records=[], issued_at=now.isoformat(),
                                valid_until=(now + timedelta(seconds=30)).isoformat())
                source.install(encode(snapshot), now=now, monotonic=time.monotonic())
                print(json.dumps({"withdrawn": True}), flush=True)
            elif command == "lookups":
                print(json.dumps({"questions": calls}), flush=True)
            else:
                raise ValueError("unsupported test control command")
    finally:
        await server.close()
        await lookups.close()
        feed.close()


asyncio.run(main())
