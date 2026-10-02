"""Isolated six-LAN qualification of the actual G1 components and nft candidate."""
import asyncio
import ctypes
import fcntl
import struct
from contextlib import suppress
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import time

import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdatatype as rt
import dns.rrset

from avahi_lab import namespace, endpoint, packets, report, send, next_matching
from packet_lab import ip
from discovery.avahi import AvahiBrowser, Link, RecordQuery
from discovery.catalog import Record, SourcePolicy
from discovery.identity import Identities
from discovery.feed import NodeFeed
from discovery.gateway import GatewayClient
from discovery.observation import parse_response
from discovery.publication import Intent, Publisher
from discovery.query import parse_pod_query
from discovery.responder import Responder
from discovery.router_candidate import VLANS, avahi_config, transaction
from discovery.transport import Receiver, LinkMonitor


def nft(text):
    subprocess.run(['nft', '-f', '-'], input=text, text=True, check=True, capture_output=True)


def native(ttl=20):
    now = datetime.now(timezone.utc)
    values = [('_services._dns-sd._udp.local.', rt.PTR, '_presence_olpc._tcp.local.'),
              ('_presence_olpc._tcp.local.', rt.PTR, r'Caf\195\169\.Lab._presence_olpc._tcp.local.'),
              ('_private._sub._presence_olpc._tcp.local.', rt.PTR, r'Caf\195\169\.Lab._presence_olpc._tcp.local.'),
              (r'Caf\195\169\.Lab._presence_olpc._tcp.local.', rt.SRV, '0 0 6053 sensor.local.'),
              (r'Caf\195\169\.Lab._presence_olpc._tcp.local.', rt.TXT, r'"opaque=\255\000"'),
              ('sensor.local.', rt.A, '10.22.0.2'), ('sensor.local.', rt.A, '10.22.0.3'),
              ('sensor.local.', rt.AAAA, 'fd00:22::2')]
    return tuple(Record(str(i), n, int(k), d, 'lan-vlan22', now + timedelta(seconds=ttl)) for i, (n, k, d) in enumerate(values))


async def query(ep, name, kind, *, duration=0.7):
    await packets(ep[0], 0.03)
    request = dns.message.make_query(name, kind); request.flags = 0
    result = []
    for _ in range(3):
        ep[0].sendto(request.to_wire(), ep[1])
        result.extend(rr for m in await packets(ep[0], duration / 3) if m.flags & dns.flags.QR for rr in m.answer + m.additional)
    return result


async def checks(processes, endpoints, config, start):
    for value in json.loads(subprocess.check_output(['ip', '-j', 'address', 'show'])):
        if value['ifname'] in config['router']:
            config['router'][value['ifname']]['addresses'] = [a['local'] for a in value['addr_info']]
    links = {socket.if_nametoindex(name): Link(name, 'lab', frozenset({4, 6})) for name in config['interfaces']}
    addresses = {i: tuple(config['router'][link.source]['addresses']) for i, link in links.items()}
    policy = SourcePolicy(config['prefixes'], ())
    index22 = socket.if_nametoindex('lan-vlan22')
    receivers = [Receiver('lan-vlan22', index22, 'lab', family, '10.22.0.1') for family in (4, 6)]
    try:
        # The same local-services jumps as the factory; explicit default deny.
        nft('''table inet example_router_factory {
          chain input_local_services { }
          chain output_local_services { }
          chain input { type filter hook input priority filter; policy drop;
            iifname "lo" accept
            ct state invalid drop
            icmpv6 type { 135, 136 } ip6 hoplimit 255 accept
            jump input_local_services
          }
          chain output { type filter hook output priority filter; policy drop;
            oifname "lo" accept
            ct state invalid drop
            icmpv6 type { 135, 136 } ip6 hoplimit 255 accept
            jump output_local_services
          }
          chain forward { type filter hook forward priority filter; policy drop; counter drop; }
        }''')
        send(endpoints[(22, 4)], [('blocked.local.', 'A', '10.22.0.2')])
        await asyncio.sleep(0.1)
        assert not select.select([receivers[0].socket], [], [], 0)[0]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'lan-vlan22\0')
            try:
                sock.sendto(b'default deny', ('224.0.0.251', 5353))
            except PermissionError:
                pass
            else:
                raise AssertionError('default-deny output did not block discovery')
        report('router_default_deny_blocks_input_and_output')
        nft(transaction(config['router']))
        for receiver in receivers:
            # DNS payload exceeds link MTU and uses multiple TXT RRs.
            message = dns.message.Message(id=0); message.flags = dns.flags.QR | dns.flags.AA
            for n in range(3):
                message.additional.append(dns.rrset.from_text(f'large{n}.local.', 20, 'IN', 'TXT', ' '.join(['"' + 'x' * 240 + '"'] * 9)))
            raw = message.to_wire(max_size=8952)
            assert len(raw) > 6000
            endpoints[(22, receiver.family)][0].sendto(raw, endpoints[(22, receiver.family)][1])
            received = None
            async with asyncio.timeout(3):
                while received is None:
                    if select.select([receiver.socket], [], [], 0)[0]:
                        value = receiver.receive()
                        if value.wire == raw:
                            received = value
                    await asyncio.sleep(0.01)
            assert len(parse_response(received, links=links, policy=policy, local_addresses=addresses)) == 3
            report('full_fragmented_mdns_with_kernel_reassembly', family=receiver.family, bytes=len(raw))
    finally:
        for receiver in receivers: receiver.close()

    # Denial remains independent: packets addressed to a router application fail.
    listener = socket.socket(); listener.setblocking(False); listener.bind(('10.22.0.1', 6053)); listener.listen()
    with namespace('lan-vlan22'):
        client = socket.socket(); client.setblocking(False); client.connect_ex(('10.22.0.1', 6053))
    await asyncio.sleep(0.15)
    assert not select.select([listener], [], [], 0)[0]
    client.close(); listener.close()
    rules = subprocess.check_output(['nft', 'list', 'chain', 'inet', 'example_router_factory', 'forward'], text=True)
    assert 'policy drop' in rules and 'accept' not in rules
    report('discovery_permits_preserve_application_and_forward_deny')

    # Start real Avahi only after membership/input/output policy is ready.
    Path('/run/dbus').mkdir(exist_ok=True)
    start('dbus', ['dbus-daemon', '--system', '--nofork', '--nopidfile']); await asyncio.sleep(0.4)
    Path('/tmp/avahi.conf').write_text(avahi_config())
    avahi = start('avahi', ['avahi-daemon', '--no-chroot', '--no-drop-root', '--debug', '-f', '/tmp/avahi.conf'])
    await asyncio.sleep(1)
    store = Identities('/tmp/identities.db')
    publisher = await Publisher(links, addresses=addresses).connect()
    try:
        # Exercise the short lease and full twelve-group fanout seen on the
        # router, including a complete graph replacement while still leased.
        from discovery.kubernetes import records as service_records
        selected = [{'namespace': 'services', 'name': f'web-{i}', 'port': 'http',
                     'type': '_http._tcp', 'instance': f'Web {i}', 'txt': {'path': '/'},
                     'subtypes': [], 'uid': f'uid-{i}', 'addresses': ['2001:db8:1000:ff00::22'],
                     'service_port': 80} for i in range(16)]
        began = time.monotonic()
        for port in (80, 8080):
            for item in selected:
                item['service_port'] = port
            now = datetime.now(timezone.utc)
            bulk = store.compile(service_records(selected, now + timedelta(seconds=15)), now=now)
            await publisher.reconcile(tuple(Intent(i, f, time.monotonic() + 1, bulk)
                                            for i in links for f in (4, 6)))
        assert len(publisher.groups) == 12 and publisher.healthy
        await publisher.clear()
        report('short_lease_bulk_publication_and_replacement', services=16, groups=12,
               elapsed_seconds=round(time.monotonic() - began, 3))
        view = store.compile(native(), now=datetime.now(timezone.utc))
        host = next(a.name.to_text() for a in view if a.type == rt.A)
        await publisher.reconcile(tuple(Intent(i, f, time.monotonic() + 20, view) for i in links for f in (4, 6)))
        await asyncio.sleep(1.5)
        for vlan in VLANS:
            for family in (4, 6):
                rrsets = await query(endpoints[(vlan, family)], host, 'A', duration=1.2)
                # dnspython preserves the cache-flush bit as an unknown class;
                # address records therefore appear as opaque wire data here.
                values = [rr[0].to_wire() for rr in rrsets if rr.name.to_text() == host and rr.rdtype == rt.A and rr.ttl]
                assert set(values) == {socket.inet_aton('10.22.0.2'), socket.inet_aton('10.22.0.3')}, (vlan, family, values, [(rr.to_text()) for rr in rrsets], [(await publisher._call(g[0], 'org.freedesktop.Avahi.EntryGroup', 'GetState'))[0] for g in publisher.groups.values()])
        report('six_link_ipv4_ipv6_publication_complete_unique_rrsets', links=6, transports=12)
        # Browser ignores own publications; wire importer also excludes persistent aliases.
        browser = await AvahiBrowser(links).connect()
        try:
            for i in links:
                for family in (4, 6): await browser.watch(RecordQuery(i, family, host, rt.A))
            await asyncio.sleep(0.5)
            assert browser._events.empty()
            report('six_link_no_gateway_self_import')
            # Avahi flags a shared type as LOCAL when our publisher registers
            # the same PTR. Its hint alone must not create a native observation.
            from discovery.observation import Observations
            enumeration = '_services._dns-sd._udp.local.'
            await browser.watch(RecordQuery(index22, 4, enumeration, rt.PTR))
            event = await next_matching(browser, lambda e: e.name == enumeration and e.added)
            cache = Observations()
            cache.hint(event)
            assert not cache.records(now=time.monotonic(), wall=datetime.now(timezone.utc))
            receiver = Receiver('lan-vlan22', index22, 'lab', 4, '10.22.0.1')
            try:
                send(endpoints[(22, 4)], [(enumeration, 'PTR', '_presence_olpc._tcp.local.')], ttl=120)
                async with asyncio.timeout(3):
                    while not cache.records(now=time.monotonic(), wall=datetime.now(timezone.utc)):
                        try:
                            packet = receiver.receive()
                            cache.ingest(parse_response(packet, links=links, policy=policy,
                                local_addresses=addresses, owns_name=store.owns), now=time.monotonic())
                        except BlockingIOError:
                            pass
                        await asyncio.sleep(.01)
                assert all(r.name == enumeration for r in cache.records(
                    now=time.monotonic(), wall=datetime.now(timezone.utc)))
                report('shared_local_type_requires_remote_wire_evidence')
            finally:
                receiver.close()
            idle = RecordQuery(index22, 4, 'absent.local.', rt.A)
            await browser.watch(idle)
            await browser.retire(now=asyncio.get_running_loop().time() + 121)
            assert idle not in browser._queries
            report('dynamic_empty_browser_retirement')
        finally:
            await browser.close()
        changed = tuple(r for r in native() if r.data != '10.22.0.3')
        new_view = store.compile(changed, now=datetime.now(timezone.utc))
        await publisher.reconcile(tuple(Intent(i, f, time.monotonic() + 20, new_view) for i in links for f in (4, 6)))
        await asyncio.sleep(1.3)
        rrsets = await query(endpoints[(55, 6)], host, 'A')
        assert {rr[0].to_wire() for rr in rrsets if rr.name.to_text() == host and rr.rdtype == rt.A and rr.ttl} == {socket.inet_aton('10.22.0.2')}
        report('full_rrset_replacement_removes_old_member')
        # A remote contradictory assertion triggers Avahi's defense, then collision.
        for _ in range(5):
            send(endpoints[(22, 4)], [(host, 'A', '10.22.0.99')])
            await asyncio.sleep(0.15)
        assert publisher.conflicts, 'remote conflict did not reach ownership boundary'
        original = dns.name.from_text(host)
        changed_alias = store.rotate_alias(host)
        assert changed_alias != original and store.owns(original) and store.owns(changed_alias)
        report('remote_conflict_detected_and_alias_rotation_persisted')
    finally:
        await publisher.close(); store.close()

    # Raw receive copies must coexist with Avahi's actual unicast UDP listener.
    browser = await AvahiBrowser(links).connect()
    try:
        for family in (4, 6):
            receiver = Receiver('lan-vlan22', index22, 'lab', family, '10.22.0.1')
            try:
                name = f'unicast{family}.local.'
                await browser.watch(RecordQuery(index22, family, name, rt.A))
                sock = endpoints[(22, family)][0]
                if family == 4:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
                    target = ('10.22.0.1', 5353)
                else:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)
                    target = ('fd00:22::1', 5353)
                send((sock, target), [(name, 'A', '10.22.0.2')])
                event = await next_matching(browser, lambda e: e.name == name and e.added)
                observed = None
                async with asyncio.timeout(3):
                    while observed is None:
                        try:
                            packet = receiver.receive()
                            records = parse_response(packet, links=links, policy=policy, local_addresses=addresses)
                            observed = next((r for r in records if r.name == name), None)
                        except (BlockingIOError, ValueError):
                            pass
                        await asyncio.sleep(0.01)
                assert observed.data == event.data and observed.ttl == 37
                report('unicast_reply_delivered_to_avahi_and_raw_observer', family=family)
            finally:
                receiver.close()
    finally:
        await browser.close()

    # Independent process owns leases; collector uses production wiring and TTL evidence.
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        gateway_port = reservation.getsockname()[1]
    config['gateway'] = {'enabled': True, 'listen_address': '127.0.0.1', 'port': gateway_port,
                         'clients': ['127.0.0.1/32']}
    # Avahi can retain an answer from before the collector's receive epoch.
    # A new record browser must not strand a pod behind known-answer suppression.
    warm = await AvahiBrowser(links).connect()
    await warm.watch(RecordQuery(index22, 4, 'cold-start.local.', rt.A))
    send(endpoints[(22, 4)], [('cold-start.local.', 'A', '10.22.0.2')], ttl=120)
    await next_matching(warm, lambda e: e.name == 'cold-start.local.' and e.added)
    await warm.close()
    Path('/tmp/config.json').write_text(json.dumps(config))
    common = ['--config', '/tmp/config.json', '--state', '/tmp/identities.db', '--socket', '/tmp/publisher.sock']
    owner = start('owner', [sys.executable, '-m', 'discovery.runtime', 'publisher', *common])
    async with asyncio.timeout(5):
        while not Path('/tmp/publisher.sock').exists():
            assert owner.poll() is None
            await asyncio.sleep(0.05)
    collector = start('collector', [sys.executable, '-m', 'discovery.runtime', 'collector', *common])
    client = GatewayClient('127.0.0.1', gateway_port, timeout=1)
    node = NodeFeed(policy)
    async with asyncio.timeout(8):
        while True:
            try:
                await client.refresh(node)
                break
            except (OSError, ValueError):
                await asyncio.sleep(.1)
    cold = dns.message.make_query('cold-start.local.', 'A'); cold.flags = 0
    await packets(endpoints[(22, 4)][0], .02)
    recovered = False
    for _ in range(4):
        try:
            await client.lookup(parse_pod_query(cold.to_wire()))
        except ValueError as exc:
            # HTTP starts before the collector finishes opening its browsers.
            if str(exc) != 'gateway HTTP status 503':
                raise
            await asyncio.sleep(.75)
            continue
        observed = await packets(endpoints[(22, 4)][0], .35)
        for message in observed:
            if message.flags & dns.flags.QR:
                continue
            if any(q.name.to_text() == 'cold-start.local.' for q in message.question):
                if not any(r.name.to_text() == 'cold-start.local.' and r.ttl >= 60
                           for r in message.answer):
                    send(endpoints[(22, 4)], [('cold-start.local.', 'A', '10.22.0.2')], ttl=120)
        await asyncio.sleep(.75)
        await client.refresh(node)
        recovered = any(r.name == 'cold-start.local.' for r, _ in node.catalog.records(
            now=datetime.now(timezone.utc), monotonic=time.monotonic()))
        if recovered:
            break
    assert recovered, 'warm Avahi cache prevented fresh wire evidence after collector startup'
    report('warm_avahi_cache_recovers_fresh_wire_evidence_on_pod_demand')
    send(endpoints[(22, 4)], [('cold-start.local.', 'A', '10.22.0.2')], ttl=0)
    # A generic browser needs the type before it can ask for any instances.
    enumeration = '_services._dns-sd._udp.local.'
    for _ in range(4):
        send(endpoints[(22, 4)], [(enumeration, 'PTR', '_enumeration-test._tcp.local.')], ttl=8)
        await asyncio.sleep(.3)
    await client.refresh(node)
    request = dns.message.make_query(enumeration, 'PTR'); request.flags = 0
    result = Responder(node.catalog).build(parse_pod_query(request.to_wire()), policy=node.authority,
        now=datetime.now(timezone.utc), monotonic=time.monotonic(), source_port=5353, family=6)
    assert any(a.name.to_text() == enumeration and a.data.to_text() == '_enumeration-test._tcp.local.'
               for reply in result.replies for a in reply.records)
    report('native_type_enumeration_reaches_node_before_instance_resolution')
    send(endpoints[(22, 4)], [(enumeration, 'PTR', '_enumeration-test._tcp.local.')], ttl=0)
    records = native(ttl=8)
    # Native packets are repeated to satisfy browsers created after PTR/SRV arrival.
    for _ in range(8):
        send(endpoints[(22, 4)], [(r.name, rt.to_text(r.type), r.data) for r in records], ttl=8)
        await asyncio.sleep(0.35)
    store = Identities('/tmp/identities.db')
    host = store.alias('lan-vlan22', dns.name.from_text('sensor.local.'))[1].to_text()
    store.close()
    rrsets = await query(endpoints[(55, 6)], '_presence_olpc._tcp.local.', 'PTR', duration=1)
    assert any(rr.ttl > 0 and rr.rdtype == rt.PTR for rr in rrsets), 'end-to-end catalog did not publish service'
    report('wire_avahi_identity_lease_pipeline_publishes_cross_vlan_service')
    for family, kind, expected in ((4, 'A', socket.inet_aton('10.22.0.2')),
                                   (6, 'AAAA', socket.inet_pton(socket.AF_INET6, 'fd00:22::2'))):
        # Keep the short-lived source alive while checking both families;
        # LAN publication reserves five seconds for reconcile/withdrawal.
        send(endpoints[(22, 4)], [(r.name, rt.to_text(r.type), r.data) for r in records], ttl=8)
        await asyncio.sleep(.35)
        rrsets = await query(endpoints[(55, family)], 'sensor.local.', kind, duration=.7)
        assert any(rr.ttl > 0 and rr.name.to_text() == 'sensor.local.'
                   and any(r.to_wire() == expected for r in rr) for rr in rrsets), (family, rrsets)
    report('original_hostname_resolves_across_vlans_over_both_mdns_families')
    node = NodeFeed(policy)
    client = GatewayClient('127.0.0.1', gateway_port, timeout=1)
    await client.refresh(node)
    question = dns.message.make_query('_presence_olpc._tcp.local.', 'PTR'); question.flags = 0
    answer = Responder(node.catalog).build(parse_pod_query(question.to_wire()), policy=node.authority,
        now=datetime.now(timezone.utc), monotonic=time.monotonic(), source_port=5353, family=6)
    assert answer.replies, 'real collector did not feed authenticated node'
    decoded = dns.message.from_wire(answer.replies[0].wire)
    assert not decoded.question and {rr.rdtype for rr in decoded.additional} == {rt.SRV, rt.TXT, rt.A, rt.AAAA}
    assert any(rr.name.to_text() == 'sensor.local.' for rr in decoded.additional)
    report('real_collector_tls_catalog_builds_complete_node_service_reply')

    question = dns.message.make_query('on-demand.local.', 'A'); question.flags = 0
    question.answer.append(dns.rrset.from_text('private-pod.local.', 120, 'IN', 'AAAA', '2001:db8:1000:f000::1'))
    await packets(endpoints[(22, 4)][0], .02)
    await client.lookup(parse_pod_query(question.to_wire()))
    observed = await packets(endpoints[(22, 4)][0], .6)
    assert any(q.name.to_text() == 'on-demand.local.' for m in observed for q in m.question)
    assert not any(rr.name.to_text() == 'private-pod.local.' for m in observed
                   for rr in m.question + m.answer + m.authority + m.additional)
    for _ in range(3):
        send(endpoints[(22, 4)], [('on-demand.local.', 'A', '10.22.0.2')], ttl=8)
        await asyncio.sleep(.3)
    await client.refresh(node)
    store = Identities('/tmp/identities.db')
    demand_host = store.alias('lan-vlan22', dns.name.from_text('on-demand.local.'))[1].to_text()
    store.close()
    assert any(r.name == 'on-demand.local.' and r.type == rt.A for r, _ in node.catalog.records(
        now=datetime.now(timezone.utc), monotonic=time.monotonic()))
    report('tls_miss_queries_real_avahi_without_exporting_pod_known_answers')
    # Earlier checks can consume the LAN publication margin. Refresh the
    # fixture before pausing so this tests independent expiry of live groups,
    # rather than draining goodbyes from an already-withdrawn registration.
    for _ in range(3):
        send(endpoints[(22, 4)], [(r.name, rt.to_text(r.type), r.data) for r in records], ttl=8)
        await asyncio.sleep(.3)
    await client.refresh(node)
    rrsets = await query(endpoints[(55, 6)], host, 'A', duration=.3)
    assert any(rr.ttl > 0 and rr.name.to_text() == host for rr in rrsets)
    for ep in endpoints.values():
        await packets(ep[0], 0.01)
    collector.send_signal(signal.SIGSTOP)
    withdrawn = await packets(endpoints[(55, 6)][0], 9)
    assert owner.poll() is None
    assert any(rr.ttl == 0 and rr.name.to_text() == host for m in withdrawn for rr in m.answer), (host, [(rr.name.to_text(), rr.ttl) for m in withdrawn for rr in m.answer])
    assert any(rr.ttl == 0 and rr.name.to_text() == 'sensor.local.'
               for m in withdrawn for rr in m.answer), 'original hostname outlived its publication lease'
    for key, ep in endpoints.items():
        messages = withdrawn if key == (55, 6) else await packets(ep[0], 0.02)
        assert any(rr.ttl == 0 and rr.name.to_text() == host for m in messages for rr in m.answer), key
    rrsets = await query(endpoints[(55, 6)], host, 'A', duration=0.7)
    assert not any(rr.ttl and rr.name.to_text() == host for rr in rrsets)
    report('paused_producer_cannot_renew_independent_registration_lease')
    assert not node.catalog.records(now=datetime.now(timezone.utc), monotonic=time.monotonic())
    try:
        await client.refresh(node)
    except (TimeoutError, OSError, ValueError):
        pass
    else:
        raise AssertionError('stopped collector unexpectedly answered HTTPS')
    assert not node.catalog.records(now=datetime.now(timezone.utc), monotonic=time.monotonic())
    report('paused_collector_expires_node_catalog_without_lease_renewal')
    collector.send_signal(signal.SIGCONT)
    collector.terminate(); collector.wait(timeout=5)
    owner.terminate(); owner.wait(timeout=5)
    monitor = LinkMonitor()
    try:
        ip('address', 'add', '10.22.0.9/24', 'dev', 'lan-vlan22')
        await asyncio.sleep(0.05)
        assert monitor.changed()
        report('live_address_change_invalidates_interface_generation')
    finally:
        monitor.close()
    avahi.terminate(); avahi.wait(timeout=5)


def main():
    if os.environ.get('MDNS_ISOLATED_LAB') != '1' or socket.if_nameindex() != [(1, 'lo')]:
        raise SystemExit('requires a fresh network-isolated container')
    processes, logs, endpoints = [], {}, {}
    config = {'enabled': True, 'interfaces': [], 'prefixes': {}, 'router': {},
              'bootstrap': [['_presence_olpc._tcp.local.', 12], ['_private._sub._presence_olpc._tcp.local.', 12]]}
    def start(name, command):
        log = open('/tmp/' + name + '.log', 'w+'); logs[name] = log
        process = subprocess.Popen(command, stdout=log, stderr=log); processes.append(process)
        return process
    try:
        ip('link', 'set', 'lo', 'up')
        for vlan in VLANS:
            name = f'lan-vlan{vlan}'; config['interfaces'].append(name)
            config['prefixes'][name] = [f'10.{vlan}.0.0/24', f'fd00:{vlan}::/64']
            config['router'][name] = {'addresses': [f'10.{vlan}.0.1', f'fd00:{vlan}::1'], 'prefixes': config['prefixes'][name]}
            ip('netns', 'add', name)
            ip('link', 'add', name, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', name)
            ip('link', 'set', name, 'up'); ip('address', 'add', f'10.{vlan}.0.1/24', 'dev', name)
            ip('-6', 'address', 'add', f'fd00:{vlan}::1/64', 'dev', name, 'nodad')
            with namespace(name):
                ip('link', 'set', 'lo', 'up'); ip('link', 'set', 'eth0', 'up')
                # Model packets arriving from a physical LAN: complete checksums
                # before veth transfer, rather than retaining CHECKSUM_PARTIAL.
                command = ctypes.create_string_buffer(struct.pack('II', 0x17, 0))
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
                    fcntl.ioctl(control.fileno(), 0x8946, struct.pack('16sP', b'eth0', ctypes.addressof(command)))
                ip('address', 'add', f'10.{vlan}.0.2/24', 'dev', 'eth0')
                ip('-6', 'address', 'add', f'fd00:{vlan}::2/64', 'dev', 'eth0', 'nodad')
            for family in (4, 6): endpoints[(vlan, family)] = endpoint(name, family, f'10.{vlan}.0.2')
        asyncio.run(checks(processes, endpoints, config, start))
    except BaseException:
        print(config['router']['lan-vlan1'], file=sys.stderr)
        print(subprocess.check_output(['nft', 'list', 'ruleset'], text=True), file=sys.stderr)
        for name, log in logs.items():
            log.seek(0); data = log.read(); print(name, '\n'.join(line for line in data.splitlines() if any(s in line.lower() for s in ('fail', 'error', 'sendmsg', 'joining', 'leaving', 'collision'))) + data[-1500:], file=sys.stderr)
        raise
    finally:
        for sock, _ in endpoints.values(): sock.close()
        for process in reversed(processes):
            if process.poll() is None:
                with suppress(ProcessLookupError): process.send_signal(signal.SIGCONT); process.terminate()
            process.wait(timeout=5)
        for log in logs.values(): log.close()


if __name__ == '__main__': main()
