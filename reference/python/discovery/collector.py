"""Supervised LAN epoch: kernel evidence + Avahi hints -> leased alias graph."""
import asyncio
from contextlib import suppress
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import socket
import subprocess
import time
from uuid import uuid4

import dns.rdatatype as rt
import dns.name

from discovery.avahi import AvahiBrowser, Link, RecordQuery, SUPPORTED
from discovery.catalog import Catalog, SourcePolicy
from discovery.feed import encode, export_records
from discovery.observation import Observations, parse_response
from discovery.publication import Intent, frame
from discovery.records import PublicationPolicy, response_view
from discovery.transport import LinkMonitor, Receiver, send_questions


class CollectorFeed:
    """Share one collector's validated output and browsers with its HTTP API."""
    def __init__(self, feed, identities):
        self.feed, self.identities = feed, identities
        self.browser = None
        self.addresses = {}
        self.revision = 0

    def clear(self):
        self.browser = None
        self.addresses = {}
        self.feed.source = Catalog(self.feed.source.policy)
        self.feed.authority = PublicationPolicy(frozenset())

    def publish(self, answers, *, now, monotonic, observed_at=None):
        if self.browser is None or not self.browser.healthy:
            raise RuntimeError('collector is not ready')
        records, unique = export_records(answers, observed_at or now)
        self.revision += 1
        payload = encode({'schema': 1, 'epoch': self.feed.epoch, 'revision': self.revision,
                          'issued_at': now.isoformat(),
                          'valid_until': (now + timedelta(seconds=30)).isoformat(),
                          'records': records})
        self.feed.source.install(payload, now=now, monotonic=monotonic)
        self.feed.authority = PublicationPolicy(frozenset(r['id'] for r in records), frozenset(unique))

    async def demand(self, question, sources):
        browser = self.browser
        if browser is None or not browser.healthy:
            raise OSError('LAN collector unavailable')
        original = self.identities.original(question.name)
        if original:
            source, name = original
            sources = sources & {source}
        elif self.identities.owns(dns.name.from_text(question.name)):
            return  # retired aliases must never trigger queries for our own names
        else:
            name = question.name
        kinds = sorted(SUPPORTED) if question.type == rt.ANY else (question.type,)
        if self.feed.translation is not None and question.type in (rt.A, rt.AAAA):
            kinds = (rt.A, rt.AAAA)  # Fetch the native family for an uncached translated answer.
        try:
            for interface, link in browser.links.items():
                if link.source in sources:
                    for family in sorted(link.families):
                        for kind in kinds:
                            await browser.watch(RecordQuery(interface, family, name, kind))
                        if self.browser is not browser or not browser.healthy:
                            raise OSError('LAN observation epoch changed')
                        # Avahi may already know the answer from an older
                        # collector epoch. Its cache cannot supply wire TTLs;
                        # request fresh responses without known-answer suppression.
                        send_questions(interface, family, name, kinds, self.addresses[interface])
            if self.browser is not browser or not browser.healthy:
                raise OSError('LAN observation epoch changed')
        except RuntimeError as exc:
            raise OSError('LAN collector unavailable') from exc


def pod_view(records, *, now):
    """Preserve unambiguous device names for application consumers.

    Native names are shared answers: the gateway has not probed for exclusive
    ownership inside pods. Existing coherence checks withhold cross-LAN name
    conflicts and incomplete dependencies. LAN publication retains its aliases.
    """
    policy = PublicationPolicy(frozenset(r.id for r in records))
    values = tuple((r, min(30, int((r.expires_at - now).total_seconds())))
                   for r in records if r.expires_at > now)
    return tuple(a for a in response_view(values, policy) if a.ttl > 0)


def lan_view(records, identities, *, now):
    # Reserve the three-second reconciliation budget and one-second snapshot
    # age allowance. Filter before compiling so dependencies remain coherent.
    # Pod answers retain their original expiry; LAN records withdraw early.
    return identities.compile(tuple(r for r in records
                                    if (r.expires_at - now).total_seconds() >= 5), now=now)


def lan_hostnames(records, identities, *, now):
    """Offer observed, unambiguous hostnames alongside the stable service aliases.

    The caller excludes each hostname's origin link. Avahi probes these unique
    address sets; a conflict suppresses the original name for this collector
    process. Source expiry and translation readiness still bound the records.
    """
    return tuple(replace(a, unique=True) for a in pod_view(records, now=now)
                 if a.type in (rt.A, rt.AAAA) and a.ttl >= 5
                 and identities.owns_host(a.source, a.name)
                 and a.name.canonicalize() not in identities.suppressed_hosts)


def lan_groups(view, hostnames, links, *, now):
    records = {i: view + tuple(a for a in hostnames if a.source != link.source)
               for i, link in links.items()}
    if sum(len(records[i]) * len(link.families) for i, link in links.items()) > 4096:
        records = {i: view for i in links}  # Preserve the existing publication budget.
    return tuple(Intent(i, family, now + min(a.ttl for a in values), values)
                 for i, link in links.items() if (values := records[i])
                 for family in sorted(link.families))


def topology(config, *, receive=True):
    """Resolve live indices/addresses afresh after every netlink/daemon epoch."""
    names = config['interfaces']
    if not names or len(names) > 6 or any(not name.startswith('lan-vlan') for name in names):
        raise ValueError('explicit LAN interface allowlist required')
    if set(names) - {f'lan-vlan{vlan}' for vlan in (1, 11, 22, 23, 55, 98)}:
        raise ValueError('interface is outside production discovery VLANs')
    values = json.loads(subprocess.check_output(['ip', '-j', 'address', 'show'], timeout=3))
    links, addresses, receivers = {}, {}, []
    generation = str(uuid4())
    policy = SourcePolicy({name: tuple(config['prefixes'][name]) for name in names}, tuple(config.get('forbidden', ())))
    try:
        for value in values:
            name = value['ifname']
            if name not in names or 'UP' not in value['flags']:
                continue
            index = socket.if_nametoindex(name)
            assigned = tuple(a['local'] for a in value['addr_info'] if not a.get('tentative', False))
            families = frozenset(f for f in (4, 6) if any((':' in a) == (f == 6) for a in assigned))
            if not families:
                continue
            links[index] = Link(name, generation, families)
            addresses[index] = assigned
            for family in families:
                v4 = next((a for a in assigned if ':' not in a), None)
                if receive:
                    receivers.append(Receiver(name, index, generation, family, v4))
        if len(links) != len(names):
            raise RuntimeError('approved LAN interfaces are not all ready')
        return links, addresses, receivers, policy
    except BaseException:
        for receiver in receivers:
            receiver.close()
        raise


async def collect_epoch(*, links, addresses, receivers, policy, identities, publisher_socket,
                        monitor=None, bootstrap=(), browser=None, watchdog=lambda: None, gateway=None, translation=None,
                        publications=None):
    """Run one epoch. Any loss withdraws; a new epoch cannot reuse old TTLs."""
    cache = Observations()
    browser = browser or AvahiBrowser(links)
    reader = writer = None
    workers = []
    try:
        await browser.connect()
        reader, writer = await asyncio.open_unix_connection(publisher_socket)
        await browser.seed()
        for interface, link in links.items():
            for family in link.families:
                for name, kind in bootstrap:
                    await browser.watch(RecordQuery(interface, family, name, kind))
        if gateway:
            gateway.addresses = addresses
            gateway.browser = browser
        async def hints():
            while True:
                event = await browser.next_event()
                cache.hint(event)
                await browser.follow(event)

        async def packets(receiver):
            rejected = set()
            loop = asyncio.get_running_loop()
            while True:
                ready = loop.create_future()
                def wake():
                    if not ready.done():
                        ready.set_result(None)
                loop.add_reader(receiver.socket.fileno(), wake)
                try:
                    await ready
                finally:
                    loop.remove_reader(receiver.socket.fileno())
                for _ in range(64):
                    try:
                        packet = receiver.receive()
                        records = parse_response(packet, links=links, policy=policy,
                                                 local_addresses=addresses, owns_name=identities.owns)
                    except BlockingIOError:
                        break
                    except ValueError as exc:
                        reason = str(exc)
                        if reason not in rejected and len(rejected) < 16:
                            print(json.dumps({'event': 'packet_rejected', 'family': receiver.family,
                                              'interface': receiver.interface, 'reason': reason}), flush=True)
                            rejected.add(reason)
                        continue
                    cache.ingest(records, now=time.monotonic())
                await asyncio.sleep(0)

        workers = [asyncio.create_task(hints())] + [asyncio.create_task(packets(r)) for r in receivers]
        sequence = 0
        last_counts = None
        while True:
            for worker in workers:
                if worker.done():
                    worker.result()
                    raise RuntimeError('observation worker stopped')
            if monitor and monitor.changed():
                raise RuntimeError('link/address generation changed')
            now, wall = time.monotonic(), datetime.now(timezone.utc)
            native_records = records = cache.records(now=now, wall=wall)
            if publications is not None:
                records += publications.records(now=wall, monotonic=now)
            published = translation.render(records, now=wall, monotonic=now) if translation else records
            view = lan_view(published, identities, now=wall)
            if records != native_records and len(view) * sum(len(link.families) for link in links.values()) > 4096:
                # Optional publication must not exhaust the existing LAN owner's
                # whole-frame budget and interrupt native device discovery.
                records = native_records
                published = translation.render(records, now=wall, monotonic=now) if translation else records
                view = lan_view(published, identities, now=wall)
            counts = (len(cache._wire), len(cache._hints), len(records), len(view),
                      len(browser._queries), browser.deferred)
            if counts != last_counts:
                print(json.dumps({'event': 'catalog_counts', 'wire': counts[0], 'hints': counts[1],
                                  'correlated': counts[2], 'published': counts[3],
                                  'browsers': counts[4], 'deferred': counts[5]}), flush=True)
                last_counts = counts
            groups = lan_groups(view, lan_hostnames(published, identities, now=wall), links, now=now)
            sequence += 1
            writer.write(frame(groups, sequence=sequence, now=now))
            await writer.drain()
            reply = await asyncio.wait_for(reader.readline(), 3)
            if reply != b'OK\n':
                if reply.startswith(b'CONFLICT '):
                    identities.resolve_conflicts(json.loads(reply[9:]))
                raise RuntimeError('independent publisher rejected snapshot')
            if gateway:
                # LAN publication ownership remains independently admitted.
                # Pod applications need original device names, with ambiguity
                # withheld rather than silently renaming configured devices.
                gateway.publish(pod_view(records, now=wall), observed_at=wall,
                                now=datetime.now(timezone.utc), monotonic=time.monotonic())
            await browser.retire()
            watchdog()
            await asyncio.sleep(0.25)
    finally:
        if gateway:
            gateway.clear()
        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        if writer:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
        await browser.close()
        for receiver in receivers:
            receiver.close()


async def supervise(config, identities, publisher_socket, *, stop=None, watchdog=lambda: None, gateway=None, translation=None,
                    publications=None):
    """Bounded retry; reconnect reopens sockets and revalidates all generations."""
    delay = 0.5
    while stop is None or not stop.is_set():
        monitor = LinkMonitor()
        began = time.monotonic()
        try:
            links, addresses, receivers, policy = topology(config)
            await collect_epoch(links=links, addresses=addresses, receivers=receivers, policy=policy,
                                identities=identities, publisher_socket=publisher_socket, monitor=monitor,
                                bootstrap=config.get('bootstrap', ()), watchdog=watchdog, gateway=gateway,
                                translation=translation, publications=publications)
        except (OSError, ValueError, RuntimeError, TimeoutError) as exc:
            print(json.dumps({'event': 'discovery_epoch_lost', 'reason': str(exc)}), flush=True)
        finally:
            monitor.close()
        if time.monotonic() - began > 30:
            delay = 0.5
        await asyncio.sleep(delay)
        delay = min(30, delay * 2)
