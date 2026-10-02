"""D-Bus admission/lifecycle tests; real-daemon checks live in avahi_lab.py."""

import asyncio
from dataclasses import asdict, replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock

from dbus_next import Message, MessageType
import dns.rdata
import dns.rdatatype as rt

from discovery.avahi import AvahiBrowser, BROWSER, DBUS, ENUMERATION, Link, RecordQuery, SERVICE


class Bus:
    disconnected = False

    def disconnect(self):
        self.disconnected = True


class AvahiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.browser = AvahiBrowser({2: Link('vlan22', 'link-generation-1', frozenset({4, 6}))})
        self.browser.bus = Bus()
        self.browser.owner = ':1.42'
        self.query = RecordQuery(2, 4, '_private._tcp.local.', rt.PTR)
        self.browser._paths['/browser/1'] = self.query
        self.browser._queries[self.query] = '/browser/1'

    def signal(self, *, member='ItemNew', owner=':1.42', flags=4, interface=2, protocol=0,
               name='_private._tcp.local.', kind=rt.PTR, data='Device._private._tcp.local.', path='/browser/1'):
        raw = dns.rdata.from_text(1, kind, data, origin=dns.name.root, relativize=False).to_wire()
        return Message(message_type=MessageType.SIGNAL, sender=owner, path=path, interface=BROWSER,
                       member=member, signature='iisqqayu', body=[interface, protocol, name, 1, kind, raw, flags])

    async def test_native_hint_keeps_scope_bytes_but_has_no_expiry(self):
        self.browser._signal(self.signal(flags=5))
        event = await self.browser.next_event()
        self.assertEqual((event.source, event.generation, event.query.interface, event.query.family),
                         ('vlan22', 'link-generation-1', 2, 4))
        self.assertTrue(event.cached)
        self.assertNotIn('ttl', asdict(event))
        self.assertNotIn('expires_at', asdict(event))
        self.assertEqual(dns.rdata.from_wire(1, rt.PTR, event.data, 0, len(event.data)).target.to_text(),
                         'Device._private._tcp.local.')

    async def test_foreign_sender_unknown_browser_and_local_records_ignored(self):
        for change in [{'owner': ':1.99'}, {'path': '/browser/other'}, {'flags': 12},
                       {'flags': 20}, {'flags': 36}, {'flags': 2}, {'flags': 0}]:
            with self.subTest(change=change):
                self.browser._signal(self.signal(**change))
                self.assertTrue(self.browser.healthy)
                self.assertTrue(self.browser._events.empty())

    async def test_cross_interface_or_family_invalidates_epoch(self):
        for change in [{'interface': 3}, {'protocol': 1}, {'name': 'wrong.local.'}]:
            with self.subTest(change=change):
                browser = AvahiBrowser(dict(self.browser.links))
                browser.bus, browser.owner = Bus(), ':1.42'
                browser._paths['/browser/1'] = self.query
                browser._signal(self.signal(**change))
                self.assertFalse(browser.healthy)
                self.assertTrue(browser.bus.disconnected)
                with self.assertRaises(RuntimeError):
                    await browser.next_event()

    async def test_shared_local_type_is_only_a_hint_until_remote_wire_evidence(self):
        from datetime import datetime, timezone
        from discovery.observation import Observations, WireRecord
        query = RecordQuery(2, 4, ENUMERATION, rt.PTR)
        self.browser._paths['/browser/1'] = query
        self.browser._signal(self.signal(name=ENUMERATION, data='_private._tcp.local.', flags=13))
        event = await self.browser.next_event()
        cache = Observations()
        cache.hint(event)
        now = datetime.now(timezone.utc)
        self.assertEqual(cache.records(now=100, wall=now), ())
        wire = WireRecord(event.source, event.generation, 4, event.name, rt.PTR, event.data, 2, False)
        cache.ingest((wire,), now=100)
        self.assertEqual(len(cache.records(now=100, wall=now)), 1)
        self.assertEqual(cache.records(now=102, wall=now), ())

    async def test_type_hint_still_rejects_static_wide_area_and_own_client_records(self):
        self.browser._paths['/browser/1'] = RecordQuery(2, 4, ENUMERATION, rt.PTR)
        for flags in (2, 20, 36, 0):
            self.browser._signal(self.signal(name=ENUMERATION, data='_private._tcp.local.', flags=flags))
            self.assertTrue(self.browser._events.empty())

    async def test_remove_only_applies_to_admitted_hint(self):
        self.browser._signal(self.signal(member='ItemRemove'))
        self.assertTrue(self.browser._events.empty())
        self.browser._signal(self.signal())
        self.browser._signal(self.signal(member='ItemRemove'))
        self.assertTrue((await self.browser.next_event()).added)
        self.assertFalse((await self.browser.next_event()).added)

    async def test_queue_overflow_discards_pending_events(self):
        self.browser._events = asyncio.Queue(1)
        self.browser._signal(self.signal())
        self.browser._signal(self.signal(data='Second._private._tcp.local.'))
        self.assertFalse(self.browser.healthy)
        with self.assertRaises(RuntimeError):
            await self.browser.next_event()

    async def test_record_budget_invalidates_epoch(self):
        self.browser._record_limit = 1
        self.browser._signal(self.signal())
        self.browser._signal(self.signal(data='Second._private._tcp.local.'))
        self.assertFalse(self.browser.healthy)

    async def test_owner_loss_wakes_waiting_consumer(self):
        waiting = asyncio.create_task(self.browser.next_event())
        await asyncio.sleep(0)
        self.browser._signal(Message(message_type=MessageType.SIGNAL, sender=DBUS,
                                     path='/org/freedesktop/DBus', interface=DBUS, member='NameOwnerChanged',
                                     signature='sss', body=[SERVICE, ':1.42', ':1.43']))
        with self.assertRaises(RuntimeError):
            await asyncio.wait_for(waiting, 1)

    async def test_prepare_installs_handler_before_start_and_coalesces(self):
        calls = []

        async def call(path, interface, member, signature='', body=None):
            calls.append(member)
            if member == 'RecordBrowserPrepare':
                self.assertEqual(body, [2, 0, 'host.local.', 1, rt.AAAA, 2])
                return ['/browser/2']
            self.assertIn('/browser/2', self.browser._paths)
            return []

        self.browser._call = call
        query = RecordQuery(2, 4, 'HOST.local', rt.AAAA)
        await self.browser.watch(query)
        await self.browser.watch(replace(query, name='host.local.'))
        self.assertEqual(calls, ['RecordBrowserPrepare', 'Start'])

    async def test_type_and_service_following_stays_on_original_link(self):
        self.browser.watch = AsyncMock()
        self.browser._signal(self.signal())
        event = await self.browser.next_event()
        await self.browser.follow(event)
        self.assertEqual([call.args[0].type for call in self.browser.watch.call_args_list], [rt.SRV, rt.TXT])
        self.assertTrue(all(call.args[0].interface == 2 and call.args[0].family == 4
                            for call in self.browser.watch.call_args_list))
        self.browser.watch.reset_mock()
        await self.browser.follow(replace(event, epoch='stale'))
        await self.browser.follow(replace(event, added=False))
        self.browser.watch.assert_not_called()

    async def test_seed_only_uses_operator_approved_families(self):
        browser = AvahiBrowser({2: Link('vlan1', 'generation', frozenset({6})),
                                3: Link('vlan22', 'generation', frozenset({4, 6}))})
        browser.watch = AsyncMock()
        await browser.seed()
        self.assertEqual({(c.args[0].interface, c.args[0].family) for c in browser.watch.call_args_list},
                         {(2, 6), (3, 4), (3, 6)})
        self.assertTrue(all(c.args[0].name == ENUMERATION for c in browser.watch.call_args_list))

    async def test_unapproved_watch_and_browser_limit(self):
        self.browser._call = AsyncMock()
        for query in [RecordQuery(99, 4, 'host.local.', rt.A), RecordQuery(2, 5, 'host.local.', rt.A),
                      RecordQuery(2, 4, 'example.org.', rt.A), RecordQuery(2, 4, 'host.local.', rt.CNAME)]:
            with self.subTest(query=query), self.assertRaises(ValueError):
                await self.browser.watch(query)
        self.browser._call.assert_not_called()
        self.browser._browser_limit = 1
        for index in range(100):
            self.assertIsNone(await self.browser.watch(RecordQuery(2, 4, f'host-{index}.local.', rt.A)))
        self.assertTrue(self.browser.healthy)
        self.assertEqual(self.browser.deferred, 100)
        self.assertEqual(len(self.browser._queries), 1)
        self.assertFalse(self.browser._touched)
        self.browser._call.assert_not_called()
        self.browser._signal(self.signal())
        self.assertTrue((await self.browser.next_event()).added)
        self.assertEqual(await self.browser.watch(self.query), '/browser/1')

    async def test_stalled_authentication_times_out_and_releases_connection(self):
        closed = asyncio.Event()

        async def blackhole(reader, writer):
            await reader.read()
            writer.close()
            await writer.wait_closed()
            closed.set()

        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'bus')
            server = await asyncio.start_unix_server(blackhole, path=path)
            async with server:
                browser = AvahiBrowser(dict(self.browser.links))
                with self.assertRaises(TimeoutError):
                    await browser.connect(bus_address='unix:path=' + path)
                await asyncio.wait_for(closed.wait(), 1)
                self.assertFalse(browser.healthy)
                self.assertEqual(browser.bus._sock.fileno(), -1)

    async def test_nonlocal_bus_transports_rejected(self):
        for address in ['tcp:host=example.org,port=1234', 'unix:path=/tmp/bus;tcp:host=example.org,port=1234']:
            with self.subTest(address=address), self.assertRaises(ValueError):
                await AvahiBrowser(dict(self.browser.links)).connect(bus_address=address)


if __name__ == '__main__':
    unittest.main()
