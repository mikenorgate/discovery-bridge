"""Real UDP TC continuation, record timing and query-only export boundaries."""
import asyncio
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
import os
import socket
import time
from types import SimpleNamespace

import dns.flags
import dns.message
import dns.rdatatype as rt

from discovery.catalog import Catalog
from discovery.feed import encode
from discovery.pod_socket import PodSession, PodSocket
from discovery.records import PublicationPolicy
from packet_lab import ip, namespace, udp
from test_catalog import fixture, policy
from test_continuation import first, continuation
from test_query import query


def report(case, family):
    print(json.dumps({'case': case, 'family': family, 'status': 'pass'}), flush=True)


async def check(family):
    with namespace():
        index = socket.if_nametoindex('eth0')
        endpoint = PodSocket('eth0', family, ['192.0.2.2', 'fd00:5353::2'])
        client = udp(family, index)
    data = fixture(); now = datetime.now(timezone.utc)
    data.update(issued_at=now.isoformat(), valid_until=(now + timedelta(seconds=30)).isoformat())
    for record in data['records']: record['expires_at'] = (now + timedelta(seconds=30)).isoformat()
    feed = SimpleNamespace(catalog=Catalog(policy()), authority=PublicationPolicy(
        frozenset(r['id'] for r in data['records']),
        frozenset((r['name'], rt.from_text(r['type'])) for r in data['records'] if r['type'] != 'PTR')))
    feed.catalog.install(encode(data), now=now, monotonic=time.monotonic())
    snapshot = feed.catalog.snapshot
    calls, queries, observed = [], Counter(), Counter()
    async def miss(value): calls.append(value.lookup_payload())
    session = PodSession([endpoint], feed, deadline=time.monotonic() + 30, on_miss=miss)
    session.start()
    target = ('224.0.0.251', 5353) if family == 4 else ('ff02::fb', 5353, 0, index)
    def send(message):
        wire = message.to_wire()
        queries[wire] += 1  # Includes fixture announcements; never agent traffic.
        client.sendto(wire, target)
    async def collect(seconds):
        end = time.monotonic() + seconds
        replies = []
        while time.monotonic() < end:
            try:
                wire = await asyncio.wait_for(asyncio.get_running_loop().sock_recv(client, 9000), end - time.monotonic())
            except TimeoutError: break
            if wire in queries:
                observed[wire] += 1
                assert observed[wire] <= queries[wire], 'agent repeated a fixture packet'
                continue
            message = dns.message.from_wire(wire)
            assert message.flags & dns.flags.QR, 'agent emitted a question into the pod'
            assert not message.question and not message.authority
            assert b'private-pod' not in wire
            replies.append((time.monotonic(), message))
        return replies
    try:
        send(first()); send(continuation())
        assert not await collect(.7)
        assert not calls
        report('tc_later_known_answer_suppresses_reply', family)

        start = time.monotonic()
        send(first('sensor.local.', 'AAAA'))
        assert not await collect(.2)
        send(continuation(truncated=True, private=True))
        send(continuation(private=True))
        replies = await collect(.65)
        assert len(replies) == 1 and replies[0][0] - start >= .59
        assert replies[0][1].answer[0].rdtype == rt.AAAA
        report('tc_last_fragment_extends_delay_and_answers', family)

        # The prior AAAA answer still counts when a different transaction asks
        # for the same record; no second multicast is allowed before one second.
        request = query('sensor.local.', 'AAAA'); request.id = 9876
        send(request)
        assert not await collect(.3)
        await asyncio.sleep(max(0, replies[0][0] + 1.05 - time.monotonic()))
        request.id = 9877; send(request)
        assert await collect(.25)
        report('different_query_obeys_per_record_multicast_interval', family)

        send(first('missing.local.', 'AAAA')); send(continuation(private=True))
        assert not await collect(.65)
        assert calls == [{'schema': 1, 'questions': [{'name': 'missing.local.', 'type': 28, 'class': 1}]}]
        assert feed.catalog.snapshot is snapshot
        report('tc_miss_exports_only_original_question', family)

        announcement = continuation(private=True); announcement.flags = dns.flags.QR | dns.flags.AA
        probe = query('private-pod.local.', 'ANY'); probe.authority.extend(announcement.answer)
        send(announcement); send(probe)
        assert not await collect(.25)
        assert len(calls) == 1 and feed.catalog.snapshot is snapshot
        report('pod_announcement_and_probe_do_not_enter_feed_or_lookups', family)
        assert observed == queries, 'fixture capture did not see every injected packet'
        report('observed_agent_packets_are_answers_only', family)
    finally:
        await session.aclose(); client.close()


def main():
    if os.environ.get('MDNS_ISOLATED_LAB') != '1' or socket.if_nameindex() != [(1, 'lo')]:
        raise SystemExit('requires a fresh network-isolated container')
    ip('link', 'set', 'lo', 'up'); ip('netns', 'add', 'discovery-pod')
    ip('link', 'add', 'pod-link', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', 'discovery-pod')
    ip('link', 'set', 'pod-link', 'up')
    with namespace():
        ip('link', 'set', 'lo', 'up'); ip('link', 'set', 'eth0', 'up')
        ip('address', 'add', '192.0.2.2/24', 'dev', 'eth0')
        ip('-6', 'address', 'add', 'fd00:5353::2/64', 'dev', 'eth0', 'nodad')
        # Use the explicitly supplied global source for fixture IPv6 queries.
        ip('-6', 'address', 'flush', 'dev', 'eth0', 'scope', 'link')
    async def run():
        for family in (4, 6): await check(family)
    asyncio.run(run())


if __name__ == '__main__': main()
