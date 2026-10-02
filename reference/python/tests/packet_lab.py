"""Isolated UDP qualification of the response core, not the production broker.

Run only through run_packet_lab.sh. All interfaces/namespaces are disposable
inside its rootless container. The fixture opens sockets via Python 3.13 setns.
"""

from contextlib import contextmanager
from datetime import timedelta
import json
import os
import select
import socket
import struct
import subprocess
import time
import tempfile
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

import dns.flags
import dns.message
import dns.rdatatype as rt
import dns.rrset

from discovery.catalog import Catalog
from discovery.query import parse_pod_query
from discovery.records import PublicationPolicy
from discovery.responder import Responder
from discovery.feed import GatewayFeed, NodeFeed
from discovery.router_translation import Readiness, RouterTranslation
from test_catalog import NOW, encode, fixture, policy
from test_query import query


def ip(*args):
    result = subprocess.run(['ip', *args], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f'ip {args}: {result.stderr.strip()}')


@contextmanager
def namespace():
    with open('/proc/self/ns/net', 'rb') as current, open('/run/netns/discovery-pod', 'rb') as target:
        os.setns(target.fileno(), os.CLONE_NEWNET)
        try:
            yield
        finally:
            os.setns(current.fileno(), os.CLONE_NEWNET)


def udp(family, index, port=5353):
    sock = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == 4:
        sock.bind(('', port))
        address = socket.inet_aton('192.0.2.2')
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, address)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                        socket.inet_aton('224.0.0.251') + address)
    else:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(('::', port))
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                        socket.inet_pton(socket.AF_INET6, 'ff02::fb') + struct.pack('@I', index))
    sock.setblocking(False)
    return sock


def drain(*sockets):
    for sock in sockets:
        while select.select([sock], [], [], 0)[0]:
            sock.recvfrom(65535)


def check_family(family):
    with namespace():
        index = socket.if_nametoindex('eth0')
        server = udp(family, index)
        client = udp(family, index)
        legacy = udp(family, index, 0)
    group = ('224.0.0.251', 5353) if family == 4 else ('ff02::fb', 5353, 0, index)
    data = fixture()
    catalog = Catalog(policy())
    start = time.monotonic()
    catalog.install(encode(data), now=NOW, monotonic=start)
    responder = Responder(catalog)
    publication = PublicationPolicy(frozenset(r['id'] for r in data['records']),
                                     frozenset((r['name'], rt.from_text(r['type']))
                                               for r in data['records'] if r['type'] != 'PTR'))

    def report(case):
        print(json.dumps({'family': family, 'case': case, 'status': 'pass'}), flush=True)

    def exchange(request, *, sock=client, expect=True, destination='multicast'):
        drain(server, client, legacy)
        wire = request.to_wire()
        sock.sendto(wire, group)
        deadline = time.monotonic() + 2
        source = None
        while time.monotonic() < deadline:
            ready = select.select([server], [], [], max(0, deadline - time.monotonic()))[0]
            if not ready:
                break
            received, peer = server.recvfrom(9000)
            if received == wire:
                source = peer
                break
        assert source is not None, 'server did not receive query'
        parsed = parse_pod_query(wire)
        assert 'private-pod' not in json.dumps(parsed.lookup_payload())
        current = time.monotonic()
        result = responder.build(parsed, policy=publication, now=NOW + timedelta(seconds=current - start),
                                 monotonic=current, source_port=source[1], family=family)
        assert bool(result.replies) == expect, result
        for reply in result.replies:
            assert reply.destination == destination, reply.destination
            message = dns.message.from_wire(reply.wire)
            assert message.flags & dns.flags.QR
            assert b'private-pod' not in reply.wire and b'secret-identity' not in reply.wire
            target = group if reply.destination == 'multicast' else source
            server.sendto(reply.wire, target)
            responder.note_sent(reply, monotonic=time.monotonic())
        responses = []
        deadline = time.monotonic() + (1 if expect else 0.1)
        while time.monotonic() < deadline:
            ready = select.select([sock], [], [], max(0, deadline - time.monotonic()))[0]
            if not ready:
                break
            received, _ = sock.recvfrom(9000)
            if not dns.message.from_wire(received).flags & dns.flags.QR:
                assert received == wire, 'unexpected agent-generated query'
                continue
            responses.append(dns.message.from_wire(received))
            if len(responses) == len(result.replies):
                break
        assert len(responses) == len(result.replies), 'reply was not delivered to client socket'
        return responses

    try:
        assert not select.select([client], [], [], 0.1)[0], 'idle agent emitted a packet'
        report('idle_no_queries')
        response = exchange(query())[0]
        assert {r.rdtype for r in response.additional} == {rt.SRV, rt.TXT, rt.A, rt.AAAA}
        report('qm_service_dependencies')
        request = query('sensor.local.', 'AAAA')
        request.question[0].rdclass = 0x8001
        exchange(request, destination='peer')
        report('qu_after_multicast')
        request = query('sensor.local.', 'AAAA')
        request.id = 4242
        request.flags = dns.flags.RD
        response = exchange(request, sock=legacy, destination='peer')[0]
        assert response.id == 4242 and response.question == request.question
        assert all(r.ttl <= 10 and r.rdclass == 1 for r in response.answer)
        report('legacy_ephemeral_port')
        request = query()
        request.answer.append(dns.rrset.from_text('_esphomelib._tcp.local.', 120, 'IN', 'PTR',
                                                  'Sensor._esphomelib._tcp.local.'))
        exchange(request, expect=False)
        report('known_answer_suppression')
        # This case tests pod-record exclusion independently of the previous
        # multicast's one-second repeat-suppression window.
        responder = Responder(catalog)
        request = query()
        request.answer.append(dns.rrset.from_text('private-pod.local.', 120, 'IN', 'AAAA',
                                                  '2001:db8:1000:f000::42'))
        request.additional.append(dns.rrset.from_text('private-pod.local.', 120, 'IN', 'TXT',
                                                      '"secret-identity"'))
        exchange(request)
        report('pod_records_not_exported_or_answered')
        exchange(query('missing.local.', 'AAAA'), expect=False)
        report('miss_silent_no_negative_or_query')
        for target_family in (4, 6):
            native = fixture()
            native['records'] = [r for r in native['records'] if r['type'] != ('AAAA' if target_family == 4 else 'A')]
            source = Catalog(policy())
            source.install(encode(native), now=NOW, monotonic=start)
            translation = RouterTranslation()
            translation.state = Readiness(NOW, start, True,
                {IPv6Address('2001:db8:1000:22::42'): IPv4Address('198.19.200.42')})
            authority = PublicationPolicy(frozenset(r['id'] for r in native['records']))
            with tempfile.TemporaryDirectory() as directory:
                gateway = GatewayFeed(source, authority, Path(directory) / 'gateway', translation=translation)
                try:
                    node = NodeFeed(policy())
                    def refresh():
                        current = time.monotonic()
                        wall = NOW + timedelta(seconds=current - start)
                        payload = gateway.read(sources={'vlan22'}, challenge=node.begin_request(), now=wall, monotonic=current)
                        node.accept_catalog(payload, now=wall, monotonic=current)
                        return Responder(node.catalog), node.authority
                    responder, publication = refresh()
                    kind = rt.AAAA if target_family == 4 else rt.A
                    expected = '2001:db8:1000:fd65::a16:2a' if target_family == 4 else '198.19.200.42'
                    response = exchange(query())[0]
                    assert any(rr.rdtype == kind and rr[0].address == expected for rr in response.additional)
                    responder = Responder(node.catalog)
                    response = exchange(query('sensor.local.', rt.to_text(kind)))[0]
                    assert any(rr.rdtype == kind and rr[0].address == expected for rr in response.answer)
                    report('nat64_browse_and_direct' if target_family == 4 else 'nat46_browse_and_direct')
                    translation.state = None
                    responder, publication = refresh()
                    exchange(query('sensor.local.', rt.to_text(kind)), expect=False)
                    response = exchange(query())[0]
                    assert all(rr.rdtype != kind for rr in response.answer + response.additional)
                    assert any(rr.rdtype == rt.SRV for rr in response.additional)
                    report('nat64_loss_preserves_service' if target_family == 4 else 'nat46_loss_preserves_service')
                finally:
                    gateway.close()
    finally:
        server.close()
        client.close()
        legacy.close()


def main():
    if os.environ.get('MDNS_ISOLATED_LAB') != '1' or socket.if_nameindex() != [(1, 'lo')]:
        raise SystemExit('requires a fresh network-isolated container')
    ip('netns', 'add', 'discovery-pod')
    try:
        ip('link', 'add', 'pod-link', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', 'discovery-pod')
        ip('link', 'set', 'pod-link', 'up')
        # ip -n also remounts /sys; use setns directly with the read-only lab root.
        with namespace():
            ip('link', 'set', 'lo', 'up')
            ip('link', 'set', 'eth0', 'up')
            ip('address', 'add', '192.0.2.2/24', 'dev', 'eth0')
            ip('-6', 'address', 'add', 'fd00:5353::2/64', 'dev', 'eth0', 'nodad')
        check_family(4)
        check_family(6)
    finally:
        ip('netns', 'delete', 'discovery-pod')


if __name__ == '__main__':
    main()
