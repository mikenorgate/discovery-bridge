"""Real zeroconf clients, TLS-fed replies and independent UDP FD revocation."""
import array
import asyncio
from datetime import datetime, timedelta, timezone
import errno
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

import dns.flags
import dns.message
import dns.rdatatype as rt
import dns.rrset
from zeroconf import AddressResolver, IPVersion, ServiceStateChange
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

from discovery.catalog import Catalog
from discovery.feed import GatewayFeed, NodeFeed, encode
from discovery.gateway import GatewayAPI, GatewayClient, GatewayServer
from discovery.lookup import LookupCoordinator
from discovery.pod_socket import PodSession, PodSocket
from discovery.records import PublicationPolicy
from discovery.responder import Reply
from packet_lab import ip, namespace, udp
from test_catalog import fixture, policy
from test_query import query


def report(case, **fields):
    print(json.dumps({'case': case, 'status': 'pass', **fields}), flush=True)


def worker(control_fd, family, index):
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    assert next(line for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:')).split()[1] == '0000000000000000'
    channel = socket.socket(fileno=control_fd)
    _, control, _, _ = channel.recvmsg(1, socket.CMSG_SPACE(4))
    descriptors = array.array('i'); descriptors.frombytes(control[0][2])
    sock = socket.socket(fileno=descriptors[0])
    source = '192.0.2.2' if family == 4 else 'fd00:5353::2'
    info = [(socket.IPPROTO_IP, 8, struct.pack('@I4s4s', index, socket.inet_aton(source), bytes(4)))] if family == 4 else [
        (socket.IPPROTO_IPV6, socket.IPV6_PKTINFO, socket.inet_pton(socket.AF_INET6, source) + struct.pack('@I', index))]
    target = ('224.0.0.251', 5353) if family == 4 else ('ff02::fb', 5353, 0, index)
    message = dns.message.Message(); message.flags = dns.flags.QR | dns.flags.AA
    channel.send(b'ready')
    while channel.recv(10):
        try:
            sock.sendmsg([message.to_wire()], info, 0, target)
            channel.send(b'sent')
        except OSError as exc:
            channel.send(str(exc.errno).encode())


async def revoke_check(family):
    with namespace():
        endpoint = PodSocket('eth0', family, ['192.0.2.2', 'fd00:5353::2'])
    owner, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    process = subprocess.Popen([sys.executable, __file__, 'worker', str(child.fileno()), str(family), str(endpoint.index)],
                               pass_fds=(child.fileno(),))
    child.close()
    owner.setblocking(False)
    loop = asyncio.get_running_loop()
    async def read():
        return await asyncio.wait_for(loop.sock_recv(owner, 100), 2)
    try:
        owner.sendmsg([b's'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [endpoint.socket.fileno()]))])
        assert await read() == b'ready'
        owner.send(b'send'); assert await read() == b'sent'
        process.send_signal(signal.SIGSTOP)
        _, status = os.waitpid(process.pid, os.WUNTRACED)
        assert os.WIFSTOPPED(status)
        endpoint.close()  # kernel shutdown reaches the paused receiver's SCM_RIGHTS copy
        owner.send(b'send')
        process.send_signal(signal.SIGCONT)
        assert await read() == str(errno.EPIPE).encode(), 'passed descriptor remained writable'
        report('broker_shutdown_revokes_paused_worker_descriptor', family=family, kernel=os.uname().release, worker_uid=65534)
    finally:
        owner.close()
        endpoint.close()
        if process.poll() is None:
            process.send_signal(signal.SIGCONT)
            process.terminate()
        process.wait(timeout=3)


async def check_client(family, agent_first, feed, gateway_client, demand_calls):
    now, tick = datetime.now(timezone.utc), time.monotonic()
    data = fixture()
    data.update(issued_at=now.isoformat(), valid_until=(now + timedelta(seconds=30)).isoformat())
    for record in data['records']:
        record['expires_at'] = (now + timedelta(seconds=30)).isoformat()
    feed.source = Catalog(policy())
    feed.source.install(encode(data), now=now, monotonic=tick)
    node = NodeFeed(policy())
    await gateway_client.refresh(node)
    with namespace():
        index = socket.if_nametoindex('eth0')
        values = json.loads(subprocess.check_output(['ip', '-j', 'address', 'show', 'dev', 'eth0']))
        addresses = [v['local'] for v in values[0]['addr_info']]
        endpoint = PodSocket('eth0', family, addresses) if agent_first else None
        zc = AsyncZeroconf(interfaces=['192.0.2.2'] if family == 4 else [index],
                          ip_version=IPVersion.V4Only if family == 4 else IPVersion.V6Only)
        if endpoint is None:
            endpoint = PodSocket('eth0', family, addresses)
        legacy = udp(family, index, 0)
    source = '192.0.2.2' if family == 4 else 'fd00:5353::2'
    session = PodSession([endpoint], node, deadline=time.monotonic() + 29, on_miss=gateway_client.lookup)
    session.start()
    browser = None
    try:
        await asyncio.sleep(.15)
        assert session.events['sent'] == 0, 'idle session sent a packet'
        resolver = AddressResolver('sensor.local.')
        assert await resolver.async_request(zc.zeroconf, 3000), dict(session.events)
        assert set(resolver.parsed_addresses(IPVersion.All)) == {'198.18.22.42', '2001:db8:1000:22::42'}
        found = asyncio.Event()
        def discovered(zeroconf, service_type, name, state_change):
            if name == 'Sensor._esphomelib._tcp.local.' and state_change == ServiceStateChange.Added:
                found.set()
        browser = AsyncServiceBrowser(zc.zeroconf, '_esphomelib._tcp.local.', handlers=[discovered])
        await asyncio.wait_for(found.wait(), 3)
        info = AsyncServiceInfo('_esphomelib._tcp.local.', 'Sensor._esphomelib._tcp.local.')
        assert await info.async_request(zc.zeroconf, 3000)
        assert info.port == 6053 and info.server == 'sensor.local.'
        assert info.properties[b'opaque'] == b'\xff\x00'
        assert set(info.parsed_addresses(IPVersion.All)) == {'198.18.22.42', '2001:db8:1000:22::42'}
        report('zeroconf_hostname_and_service_browse_over_tls_feed', family=family, agent_first=agent_first)

        # A fresh unicast answer must reach zeroconf, regardless of bind order.
        message = dns.message.Message(); message.flags = dns.flags.QR | dns.flags.AA
        message.answer.append(dns.rrset.from_text('unicast.local.', 5, 'IN', 'A', '198.18.22.99'))
        endpoint.send(Reply('peer', family, message.to_wire(), ()), (source, 5353))
        unicast = AddressResolver('unicast.local.')
        async with asyncio.timeout(2):
            while not unicast.load_from_cache(zc.zeroconf):
                await asyncio.sleep(.01)
        assert unicast.parsed_addresses() == ['198.18.22.99']
        report('shared_5353_unicast_reaches_zeroconf', family=family, agent_first=agent_first)

        request = query(); request.id = 4242
        legacy.sendto(request.to_wire(), endpoint.target)
        wire, _ = await asyncio.wait_for(asyncio.get_running_loop().sock_recvfrom(legacy, 9000), 2)
        response = dns.message.from_wire(wire)
        assert response.id == 4242 and response.flags & dns.flags.QR
        assert response.question == request.question and all(rr.ttl <= 10 for rr in response.answer + response.additional)
        report('legacy_reply_with_real_zeroconf_sharing_port', family=family, agent_first=agent_first)

        rejected = session.events['rejected']
        level, option = (socket.IPPROTO_IP, socket.IP_MULTICAST_TTL) if family == 4 else (socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS)
        legacy.setsockopt(level, option, 2)
        legacy.sendto(query('bad-hop.local.', 'AAAA').to_wire(), endpoint.target)
        await asyncio.sleep(.1)
        legacy.setsockopt(level, option, 255)
        assert session.events['rejected'] > rejected
        assert all(q.name != 'bad-hop.local.' for q in demand_calls)
        report('short_hop_query_rejected_before_gateway_lookup', family=family, agent_first=agent_first)

        calls_before = len(demand_calls)
        request = query('missing.local.', 'AAAA')
        request.answer.append(dns.rrset.from_text('private-pod.local.', 120, 'IN', 'AAAA', '2001:db8:1000:f000::1'))
        legacy.sendto(request.to_wire(), endpoint.target)
        async with asyncio.timeout(3):
            while len(demand_calls) == calls_before:
                await asyncio.sleep(.02)
        assert demand_calls[-1].name == 'missing.local.'
        assert 'private-pod' not in str(demand_calls)
        sent_before = session.events['sent']
        try:
            endpoint.send(Reply('multicast', family, request.to_wire(), ()), (source, 5353))
        except ValueError:
            pass
        else:
            raise AssertionError('transport admitted an outbound question')
        assert session.events['sent'] == sent_before
        report('pod_miss_exports_questions_only_and_outbound_questions_are_denied', family=family, agent_first=agent_first)

        session.renew(time.monotonic() + .3)
        await asyncio.sleep(.4)
        assert session.closed
        report('eligibility_expiry_closes_session_sockets', family=family, agent_first=agent_first)
    finally:
        await session.aclose()
        legacy.close()
        if browser:
            await browser.async_cancel()
        await zc.async_close()


async def run():
    data = fixture()
    authority = PublicationPolicy(frozenset(r['id'] for r in data['records']),
        frozenset((r['name'], rt.from_text(r['type'])) for r in data['records'] if r['type'] != 'PTR'))
    feed = GatewayFeed(Catalog(policy()), authority, '/tmp/feed.db')
    calls = []
    async def demand(question, sources):
        calls.append(question)
    coordinator = LookupCoordinator({'vlan22'}, demand)
    server = GatewayServer(GatewayAPI(feed, coordinator), ['127.0.0.1/32'])
    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(32)
    port = listener.getsockname()[1]
    await server.start(listener)
    client = GatewayClient('127.0.0.1', port)
    try:
        for family in (4, 6):
            if family == 6:
                with namespace():
                    ip('address', 'delete', '192.0.2.2/24', 'dev', 'eth0')
            for agent_first in (True, False):
                await check_client(family, agent_first, feed, client, calls)
                await asyncio.sleep(1)  # separate lookup cooldowns between fixtures
            await revoke_check(family)
    finally:
        await server.close()
        await coordinator.close()
        feed.close()


def main():
    if os.environ.get('MDNS_ISOLATED_LAB') != '1' or socket.if_nameindex() != [(1, 'lo')]:
        raise SystemExit('requires a fresh network-isolated container')
    ip('link', 'set', 'lo', 'up')
    ip('netns', 'add', 'discovery-pod')
    ip('link', 'add', 'pod-link', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', 'discovery-pod')
    ip('link', 'set', 'pod-link', 'up')
    with namespace():
        ip('link', 'set', 'lo', 'up'); ip('link', 'set', 'eth0', 'up')
        ip('address', 'add', '192.0.2.2/24', 'dev', 'eth0')
        ip('-6', 'address', 'add', 'fd00:5353::2/64', 'dev', 'eth0', 'nodad')
    asyncio.run(run())


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'worker':
        worker(*map(int, sys.argv[2:]))
    else:
        main()
