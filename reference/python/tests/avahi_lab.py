"""Real Avahi 0.8 D-Bus and UDP API qualification in a disposable container."""

import asyncio
from contextlib import contextmanager
from dataclasses import asdict
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import time

from dbus_next import Message, MessageType
from dbus_next.aio import MessageBus
import dns.flags
import dns.message
import dns.rdata
import dns.rdatatype as rt
import dns.rrset

from discovery.avahi import AvahiBrowser, Link, RecordQuery, SERVER, SERVICE, avahi_name
from discovery.router_candidate import avahi_config
from packet_lab import ip

BUS_ADDRESS = 'unix:path=/run/dbus/system_bus_socket'


def report(case, **details):
    print(json.dumps({'case': case, 'status': 'pass', **details}), flush=True)


@contextmanager
def namespace(name):
    with open('/proc/self/ns/net', 'rb') as current, open('/run/netns/' + name, 'rb') as target:
        os.setns(target.fileno(), os.CLONE_NEWNET)
        try:
            yield
        finally:
            os.setns(current.fileno(), os.CLONE_NEWNET)


def endpoint(name, family, address):
    with namespace(name):
        index = socket.if_nametoindex('eth0')
        sock = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == 4:
            sock.bind(('', 5353))
            addr = socket.inet_aton(address)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, addr)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton('224.0.0.251') + addr)
            destination = ('224.0.0.251', 5353)
        else:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind(('::', 5353))
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                            socket.inet_pton(socket.AF_INET6, 'ff02::fb') + struct.pack('@I', index))
            destination = ('ff02::fb', 5353, 0, index)
        sock.setblocking(False)
        return sock, destination


def send(endpoint, records, ttl=37):
    message = dns.message.Message(id=0)
    message.flags = dns.flags.QR | dns.flags.AA
    for name, kind, data in records:
        message.answer.append(dns.rrset.from_text(name, ttl, 'IN', kind, data))
    endpoint[0].sendto(message.to_wire(), endpoint[1])


async def next_matching(browser, predicate, timeout=3):
    async with asyncio.timeout(timeout):
        while True:
            event = await browser.next_event()
            if predicate(event):
                return event


async def packets(sock, seconds=0.2):
    result = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        while select.select([sock], [], [], 0)[0]:
            wire, _ = sock.recvfrom(9000)
            result.append(dns.message.from_wire(wire, one_rr_per_rrset=True))
        await asyncio.sleep(0.01)
    return result


async def run_checks(avahi, endpoints):
    links = {socket.if_nametoindex('vlan22'): Link('vlan22', 'generation22', frozenset({4, 6})),
             socket.if_nametoindex('vlan55'): Link('vlan55', 'generation55', frozenset({4, 6}))}
    index22, index55 = links
    browser = AvahiBrowser(links)
    cached = None
    publisher = None
    try:
        capacity = await AvahiBrowser(links).connect(bus_address=BUS_ADDRESS)
        try:
            for n in range(1024):
                await capacity.watch(RecordQuery(index22, 4, f'capacity-{n}.local.', rt.A))
            assert await capacity.watch(RecordQuery(index22, 4, 'over-limit.local.', rt.A)) is None
            assert capacity.healthy and len(capacity._queries) == 1024
            await capacity.retire(now=asyncio.get_running_loop().time() + 121)
            assert not capacity._queries
            assert await capacity.watch(RecordQuery(index22, 4, 'after-retirement.local.', rt.A))
            report('1024_browsers_saturation_and_retirement_preserve_connection')
        finally:
            await capacity.close()
        await browser.connect(bus_address=BUS_ADDRESS)
        # A real LAN RAOP instance exposed DNS zone-file escapes that Avahi
        # rejects. Exercise punctuation, spaces and UTF-8 against the daemon.
        escaped = r'000678de48f1\@mike\226\128\153s\032avr._raop._tcp.local.'
        await browser.watch(RecordQuery(index22, 4, escaped, rt.TXT))
        send(endpoints[(22, 4)], [(escaped, 'TXT', '"canary=escaped"')])
        special = await next_matching(browser, lambda e: e.query.type == rt.TXT)
        assert dns.name.from_text(special.name) == dns.name.from_text(escaped)
        assert browser.healthy
        report('escaped_service_instance_roundtrips_through_real_avahi')
        for index in links:
            await browser.watch(RecordQuery(index, 4, '_presence_olpc._tcp.local.', rt.PTR))
            await browser.watch(RecordQuery(index, 6, '_ipv6._tcp.local.', rt.PTR))
        record = ('_presence_olpc._tcp.local.', 'PTR', 'Device._presence_olpc._tcp.local.')
        send(endpoints[(22, 4)], [record])
        event = await next_matching(browser, lambda e: e.query.type == rt.PTR)
        assert event.source == 'vlan22' and event.query.family == 4
        await asyncio.sleep(0.1)
        assert browser._events.empty(), 'record appeared on a second interface'
        report('ipv4_scoped_legacy_type_browse')
        assert not {'ttl', 'expires_at'} & asdict(event).keys()
        report('browser_hint_has_no_invented_ttl')

        cached = await AvahiBrowser(links).connect(bus_address=BUS_ADDRESS)
        await cached.watch(event.query)
        replay = await next_matching(cached, lambda e: e.added)
        assert replay.cached and replay.data == event.data
        report('prepare_start_receives_cached_record_without_race')
        await cached.close()
        cached = None

        await browser.follow(event)
        service = [
            ('Device._presence_olpc._tcp.local.', 'SRV', '0 0 6053 sensor.local.'),
            ('Device._presence_olpc._tcp.local.', 'TXT', r'"opaque=\255\000"'),
        ]
        send(endpoints[(22, 4)], service)
        found = {}
        while len(found) < 2:
            result = await next_matching(browser, lambda e: e.query.type in (rt.SRV, rt.TXT))
            found[result.query.type] = result
            await browser.follow(result)
        send(endpoints[(22, 4)], [('sensor.local.', 'A', '192.0.2.2'),
                                  ('sensor.local.', 'AAAA', 'fd00:22::2')])
        addresses = set()
        while len(addresses) < 2:
            result = await next_matching(browser, lambda e: e.query.type in (rt.A, rt.AAAA))
            assert result.source == 'vlan22' and result.query.family == 4
            addresses.add(result.query.type)
        txt = dns.rdata.from_wire(1, rt.TXT, found[rt.TXT].data, 0, len(found[rt.TXT].data))
        assert txt.strings == (b'opaque=\xff\x00',)
        report('service_to_srv_txt_and_both_address_families')

        send(endpoints[(22, 6)], [('_ipv6._tcp.local.', 'PTR', 'IPv6._ipv6._tcp.local.')])
        event6 = await next_matching(browser, lambda e: e.query.family == 6)
        assert event6.source == 'vlan22'
        report('ipv6_scoped_browse')

        send(endpoints[(22, 4)], [record], ttl=0)
        removed = await next_matching(browser, lambda e: not e.added and e.query.type == rt.PTR)
        assert removed.source == 'vlan22'
        report('wire_goodbye_produces_scoped_remove')

        # Publication API qualification uses a separate fixture connection. The
        # production AvahiBrowser exposes no AddRecord or publication method.
        publisher = await MessageBus(bus_address=BUS_ADDRESS).connect()

        async def call(path, interface, member, signature='', body=None):
            reply = await publisher.call(Message(destination=SERVICE, path=path, interface=interface,
                                                 member=member, signature=signature, body=body or []))
            assert reply.message_type == MessageType.METHOD_RETURN, (reply.error_name, reply.body)
            return reply.body

        group_interface = SERVICE + '.EntryGroup'
        bulk = (await call('/', SERVER, 'EntryGroupNew'))[0]
        for n in range(300):
            raw = dns.rdata.from_text(1, rt.TXT, '"scale=test"').to_wire()
            await call(bulk, group_interface, 'AddRecord', 'iiusqquay',
                       [index22, 0, 0, f'bulk-{n}.local.', 1, int(rt.TXT), 7, raw])
        await call(bulk, group_interface, 'Free')
        report('300_records_in_one_real_avahi_entry_group')
        group = (await call('/', SERVER, 'EntryGroupNew'))[0]
        publication = [
            ('db-lab.local.', rt.A, '192.0.2.123', True),
            (r'Lab\@receiver._raop._tcp.local.', rt.TXT, '"canary=escaped"', True),
            ('Lab._http._tcp.local.', rt.SRV, '0 0 8123 db-lab.local.', True),
            ('Lab._http._tcp.local.', rt.TXT, '"path=/"', True),
            ('_http._tcp.local.', rt.PTR, 'Lab._http._tcp.local.', False),
            ('_dashboard._sub._http._tcp.local.', rt.PTR, 'Lab._http._tcp.local.', False),
        ]
        await browser.watch(RecordQuery(index22, 4, 'db-lab.local.', rt.A))
        for ep in endpoints.values():
            await packets(ep[0], 0.02)
        for name, kind, data, unique in publication:
            raw = dns.rdata.from_text(1, kind, data, origin=dns.name.root, relativize=False).to_wire()
            await call(group, group_interface, 'AddRecord', 'iiusqquay',
                       [index22, 0, 1 if unique else 0, avahi_name(name), 1, int(kind), 7, raw])
        await call(group, group_interface, 'Commit')
        async with asyncio.timeout(4):
            while (await call(group, group_interface, 'GetState'))[0] != 2:
                await asyncio.sleep(0.05)
        observed = await packets(endpoints[(22, 4)][0], 0.3)
        records = [rr for message in observed if message.flags & dns.flags.QR
                   for rr in message.answer + message.additional if rr.name.to_text() in {p[0] for p in publication}]
        assert {rr.name.to_text() for rr in records} == {p[0] for p in publication}
        assert all(rr.ttl == 7 for rr in records), [rr.ttl for rr in records]
        report('generic_add_record_service_subtype_and_explicit_ttl')
        assert any(not m.flags & dns.flags.QR and any(q.name.to_text() == 'db-lab.local.' and
                                                     q.rdtype == rt.ANY for q in m.question) for m in observed)
        report('unique_record_probing_on_lan')
        other = await packets(endpoints[(55, 4)][0])
        assert not any(rr.name.to_text() == 'db-lab.local.' for m in other for rr in m.answer + m.additional)
        report('publication_stays_on_selected_interface')
        assert browser._events.empty(), 'locally published record was imported'
        report('local_publication_not_imported')

        conflict = (await call('/', SERVER, 'EntryGroupNew'))[0]
        raw = dns.rdata.from_text(1, rt.A, '192.0.2.124').to_wire()
        collision = await publisher.call(Message(destination=SERVICE, path=conflict, interface=group_interface,
                                                  member='AddRecord', signature='iiusqquay',
                                                  body=[index22, 0, 1, 'db-lab.local.', 1, int(rt.A), 7, raw]))
        assert collision.message_type == MessageType.ERROR and collision.error_name == SERVICE + '.CollisionError', (
            collision.error_name, collision.body)
        await call(conflict, group_interface, 'Free')
        report('local_unique_collision_rejected')

        # TTL controls receiver caching, not Avahi's ownership lifetime.
        await asyncio.sleep(7.2)
        await packets(endpoints[(22, 4)][0], 0.02)
        request = dns.message.make_query('db-lab.local.', 'A')
        request.flags = 0
        endpoints[(22, 4)][0].sendto(request.to_wire(), endpoints[(22, 4)][1])
        still = await packets(endpoints[(22, 4)][0], 1)
        assert any(rr.name.to_text() == 'db-lab.local.' and rr.ttl == 7
                   for m in still if m.flags & dns.flags.QR for rr in m.answer)
        report('ttl_is_not_publication_lease_independent_expiry_required')

        await call(group, group_interface, 'Reset')
        goodbye = await packets(endpoints[(22, 4)][0], 1)
        assert any(rr.name.to_text() == 'db-lab.local.' and rr.ttl == 0
                   for m in goodbye for rr in m.answer)
        report('entry_group_reset_sends_goodbye')
        raw = dns.rdata.from_text(1, rt.A, '192.0.2.123').to_wire()
        await call(group, group_interface, 'AddRecord', 'iiusqquay',
                   [index22, 0, 1, 'db-lab.local.', 1, int(rt.A), 7, raw])
        await call(group, group_interface, 'Commit')
        async with asyncio.timeout(4):
            while (await call(group, group_interface, 'GetState'))[0] != 2:
                await asyncio.sleep(0.05)
        await packets(endpoints[(22, 4)][0], 0.1)
        publisher.disconnect()
        await publisher.wait_for_disconnect()
        publisher = None
        goodbye = await packets(endpoints[(22, 4)][0], 1)
        assert any(rr.name.to_text() == 'db-lab.local.' and rr.ttl == 0
                   for m in goodbye for rr in m.answer)
        report('publisher_disconnect_withdraws_registration')

        waiter = asyncio.create_task(browser.next_event())
        avahi.terminate()
        with_expectation = False
        try:
            await asyncio.wait_for(waiter, 3)
        except RuntimeError:
            with_expectation = True
        assert with_expectation and not browser.healthy
        report('daemon_loss_invalidates_epoch_and_wakes_consumer')
    finally:
        if cached is not None:
            await cached.close()
        await browser.close()
        if publisher is not None:
            publisher.disconnect()
            await publisher.wait_for_disconnect()


def main():
    if os.environ.get('MDNS_ISOLATED_LAB') != '1' or socket.if_nameindex() != [(1, 'lo')]:
        raise SystemExit('requires a fresh network-isolated container')
    processes, endpoints, logs = [], {}, []
    try:
        ip('link', 'set', 'lo', 'up')
        for vlan, network in [(22, '192.0.2'), (55, '198.51.100')]:
            name = f'vlan{vlan}'
            ip('netns', 'add', name)
            ip('link', 'add', name, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', name)
            ip('link', 'set', name, 'up')
            ip('address', 'add', network + '.1/24', 'dev', name)
            ip('-6', 'address', 'add', f'fd00:{vlan}::1/64', 'dev', name, 'nodad')
            with namespace(name):
                ip('link', 'set', 'lo', 'up')
                ip('link', 'set', 'eth0', 'up')
                ip('address', 'add', network + '.2/24', 'dev', 'eth0')
                ip('-6', 'address', 'add', f'fd00:{vlan}::2/64', 'dev', 'eth0', 'nodad')
            for family in (4, 6):
                endpoints[(vlan, family)] = endpoint(name, family, network + '.2')
        Path('/run/dbus').mkdir(exist_ok=True)
        config = Path('/tmp/avahi.conf')
        config.write_text(avahi_config().replace(
            'lan-vlan1,lan-vlan11,lan-vlan22,lan-vlan23,lan-vlan55,lan-vlan98', 'vlan22,vlan55'))
        for name, command in [('dbus', ['dbus-daemon', '--system', '--nofork', '--nopidfile']),
                              ('avahi', ['avahi-daemon', '--no-chroot', '--no-drop-root', '--debug', '-f', str(config)])]:
            log = open(f'/tmp/{name}.log', 'w+')
            logs.append(log)
            processes.append(subprocess.Popen(command, stdout=log, stderr=log))
            time.sleep(0.5 if name == 'dbus' else 1.5)
            assert processes[-1].poll() is None, f'{name} did not start'
        asyncio.run(run_checks(processes[-1], endpoints))
    except BaseException:
        for log in logs:
            log.seek(0)
            print(log.read()[-6000:], file=sys.stderr, flush=True)
        raise
    finally:
        for sock, _ in endpoints.values():
            sock.close()
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
        for log in logs:
            log.close()


if __name__ == '__main__':
    main()
