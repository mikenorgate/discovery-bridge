"""Bounded delivery checks on the existing joined application fixture."""
import asyncio
from collections import Counter
import os
import signal
import time

import dns.message
import dns.rrset
from zeroconf import IPVersion
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

from application_lab import HOST, INSTANCE, SERVICE
from avahi_lab import endpoint, namespace, report
from node_lab import child_of, exited, wait_until
from test_local_claims import claim
from test_query import query


async def exercise(collector, broker, broker_command, processes, start):
    pod = endpoint('discovery-pod', 6, 'fd00:5353::2')
    lan = endpoint('device', 4, '10.22.0.2')
    observed, transmitted, exported = Counter(), Counter(), []
    positive, goodbyes = [], []
    running = True

    async def capture():
        while running:
            for sock, is_pod in ((pod[0], True), (lan[0], False)):
                for _ in range(128):
                    try:
                        wire = sock.recv(9000)
                    except BlockingIOError:
                        break
                    message = dns.message.from_wire(wire)
                    if is_pod:
                        if not message.flags & 0x8000:
                            observed[wire] += 1
                        for rr in message.answer + message.additional:
                            if rr.name.to_text() == HOST and rr.rdtype == 28:
                                (positive if rr.ttl else goodbyes).append((time.monotonic(), rr))
                    else:
                        exported.append(message)
            await asyncio.sleep(.01)

    def send_query(message=None):
        wire = (message or query(HOST, 'AAAA')).to_wire()
        transmitted[wire] += 1
        pod[0].sendto(wire, pod[1])

    async def answer(expected=True, seconds=12):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            before = len(positive)
            send_query()
            await asyncio.sleep(1.2)
            found = len(positive) > before
            if expected and found:
                return
            if not expected:
                assert not found, 'stale/conflicting answer delivered'
        assert not expected, 'answer did not recover'

    task = asyncio.create_task(capture())
    try:
        await answer()
        report('joined_native_answer_available')
        # Device-side questions must not be forwarded into an idle pod.
        lan[0].sendto(query('lan-only.local.', 'AAAA').to_wire(), lan[1])
        await asyncio.sleep(2)
        assert observed == transmitted
        report('joined_no_agent_or_lan_questions_into_pod')

        # A normal miss creates a LAN question; resource sections remain private.
        request = query('lookup-only.local.', 'AAAA')
        request.answer.append(dns.rrset.from_text('pod-private.local.', 120, 'IN', 'AAAA', 'fd00:5353::2'))
        send_query(request)
        private = claim('pod-private.local.', ttl=2)
        pod[0].sendto(private.to_wire(), pod[1])
        probe = claim('pod-probe.local.', ttl=2, probe=True)
        transmitted[probe.to_wire()] += 1
        pod[0].sendto(probe.to_wire(), pod[1])
        await asyncio.sleep(3)
        assert any(q.name.to_text() == 'lookup-only.local.' for m in exported for q in m.question)
        report('joined_question_only_miss_reaches_lan')

        # Local host ownership suppresses both addresses and dependent DNS-SD.
        local = claim(HOST, ttl=4)
        pod[0].sendto(local.to_wire(), pod[1])
        await asyncio.sleep(.3)
        positive.clear()  # Exclude the fixture's own local announcement.
        await answer(False, seconds=2.4)
        assert goodbyes, 'previous remote answer was not withdrawn'
        await answer()
        report('joined_local_claim_withdraws_and_expiry_recovers')

        # Stop the whole gateway process: no refresh may extend its last lease.
        os.kill(collector.pid, signal.SIGSTOP)
        await asyncio.sleep(12)
        await answer(False, seconds=2.4)
        os.kill(collector.pid, signal.SIGCONT)
        await answer(seconds=20)
        report('joined_gateway_loss_expires_answers_and_reconnect_recovers')

        worker = child_of(broker.pid)
        processes.remove(broker)
        os.kill(worker, signal.SIGKILL)
        await wait_until(lambda: broker.poll() is not None)
        broker.wait(timeout=3)
        await answer(False, seconds=2.4)
        broker = start('broker-after-worker-failure', broker_command)
        await answer()
        send_query(request)
        await asyncio.sleep(2)
        report('joined_worker_loss_stops_broker_and_restart_recovers')
        assert observed == transmitted, 'unexpected question entered the pod'
        for message in exported:
            assert 'pod-private' not in message.to_text() and 'pod-probe' not in message.to_text()
            assert 'fd00:5353::2' not in message.to_text()
        report('joined_zero_pod_record_export_including_reconnect',
               pod_queries=sum(observed.values()), lan_packets=len(exported))

        # This separate client phase generates its own queries. The direction
        # assertion above covers precisely attributed fixture traffic only.
        running = False
        await task
        with namespace('discovery-pod'):
            zc = AsyncZeroconf(interfaces=['fd00:5353::2'], ip_version=IPVersion.V6Only)
        browser = AsyncServiceBrowser(zc.zeroconf, SERVICE, handlers=[lambda **kwargs: None])
        try:
            info = AsyncServiceInfo(SERVICE, INSTANCE)
            assert await info.async_request(zc.zeroconf, 5000)
            await wait_until(lambda: any(r.type == 12 and r.ttl == 1125
                for r in zc.zeroconf.cache.entries_with_name(SERVICE)))
            cached = [r for r in zc.zeroconf.cache.entries_with_name(SERVICE) if r.type == 12]
            assert cached and max(r.ttl for r in cached) == 1125, [str(r) for r in cached]
            worker = child_of(broker.pid)
            processes.remove(broker)
            broker.kill(); broker.wait(timeout=3)
            await wait_until(lambda: exited(worker))
            await asyncio.sleep(3)
            assert zc.zeroconf.cache.entries_with_name(SERVICE), 'expected retained client PTR cache'
            report('joined_broker_death_kills_worker_but_client_ptr_cache_persists', ptr_ttl=1125)
            broker = start('broker-after-abrupt-loss', broker_command)
            # A fresh client request proves recovery independently of cached info.
            await asyncio.sleep(6)
            resolver = AsyncServiceInfo(SERVICE, INSTANCE)
            assert await resolver.async_request(zc.zeroconf, 5000)
        finally:
            await browser.async_cancel()
            await zc.async_close()
        running = True
        task = asyncio.create_task(capture())
        await answer()
        report('joined_broker_restart_restores_fresh_wire_answers')
    finally:
        running = False
        await task
        pod[0].close(); lan[0].close()
        if collector.poll() is None:
            os.kill(collector.pid, signal.SIGCONT)
