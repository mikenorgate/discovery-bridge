"""Production broker/worker wiring, fixture CLIs, real HTTP and zeroconf clients."""
import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

import dns.message
import dns.rdatatype as rt
from zeroconf import AddressResolver, IPVersion
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf

from discovery.catalog import Catalog
from discovery.feed import GatewayFeed, encode
from discovery.gateway import GatewayAPI, GatewayServer
from discovery.lookup import LookupCoordinator
from discovery.records import PublicationPolicy
from broker_lab import pause_process, report
from packet_lab import ip, namespace, udp
from test_broker import pod_item, runtime_status
from test_catalog import fixture, policy
from test_query import query


def state_file(value):
    temporary = Path('/tmp/node-state.tmp')
    temporary.write_text(json.dumps(value))
    temporary.replace('/tmp/node-state.json')


def child_of(pid):
    return int(Path(f'/proc/{pid}/task/{pid}/children').read_text().strip())


def exited(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0] == 'Z'
    except FileNotFoundError:
        return True


async def wait_until(check, timeout=12):
    deadline = time.monotonic() + timeout
    while not check():
        assert time.monotonic() < deadline, 'condition timed out'
        await asyncio.sleep(.05)


async def check_discovery(family):
    with namespace():
        index = socket.if_nametoindex('eth0')
        zc = AsyncZeroconf(interfaces=['192.0.2.2'] if family == 4 else [index],
                          ip_version=IPVersion.V4Only if family == 4 else IPVersion.V6Only)
    try:
        resolver = AddressResolver('sensor.local.')
        assert await resolver.async_request(zc.zeroconf, 5000)
        info = AsyncServiceInfo('_esphomelib._tcp.local.', 'Sensor._esphomelib._tcp.local.')
        assert await info.async_request(zc.zeroconf, 5000)
        assert info.port == 6053 and info.properties[b'opaque'] == b'\xff\x00'
        assert {'198.18.22.42', '2001:db8:1000:22::42'} <= set(info.parsed_addresses())
        report('broker_to_worker_http_zeroconf_hostname_service', family=family)
    finally:
        await zc.async_close()


async def answer_present():
    with namespace():
        index = socket.if_nametoindex('eth0')
        sock = udp(6, index, 0)
    try:
        sock.setblocking(False)
        message = query('sensor.local.', 'AAAA')
        sock.sendto(message.to_wire(), ('ff02::fb', 5353, 0, index))
        try:
            wire = await asyncio.wait_for(asyncio.get_running_loop().sock_recv(sock, 9000), .4)
            return bool(dns.message.from_wire(wire).answer)
        except TimeoutError:
            return False
    finally:
        sock.close()


async def run_lab(sandbox):
    data = fixture()
    authority = PublicationPolicy(frozenset(r['id'] for r in data['records']),
        frozenset((r['name'], rt.from_text(r['type'])) for r in data['records'] if r['type'] != 'PTR'))
    feed = GatewayFeed(Catalog(policy()), authority, '/tmp/feed.db')
    calls = []
    async def demand(question, sources): calls.append(question)
    coordinator = LookupCoordinator({'vlan22'}, demand)
    server = GatewayServer(GatewayAPI(feed, coordinator), ['127.0.0.1/32'])
    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(32)
    port = listener.getsockname()[1]
    await server.start(listener)
    async def publish():
        while True:
            now = datetime.now(timezone.utc)
            data.update(issued_at=now.isoformat(), valid_until=(now + timedelta(seconds=30)).isoformat())
            data['revision'] += 1
            for record in data['records']: record['expires_at'] = (now + timedelta(seconds=30)).isoformat()
            feed.source.install(encode(data), now=now, monotonic=time.monotonic())
            await asyncio.sleep(5)
    refresh = asyncio.create_task(publish())
    item = pod_item(); item['status']['podIPs'] = [{'ip': 'fd00:5353::2'}, {'ip': '192.0.2.2'}]
    runtime = runtime_status(sandbox.pid)
    runtime['status']['network'] = {'ip': 'fd00:5353::2', 'additionalIps': [{'ip': '192.0.2.2'}]}
    state = {'pods': [item], 'runtime': runtime}
    state_file(state)
    config = {'enabled': True, 'node': 'node-1', 'kubectl': ['/app/tests/node_commands.py'],
        'kubeconfig': '/tmp/fixture-kubeconfig', 'crictl': ['/app/tests/node_commands.py'],
        'runtime_endpoint': 'unix:///tmp/fixture-containerd.sock', 'host_proc': '/proc',
        'worker_uid': 65534, 'worker_gid': 65534,
        'rules': [{'namespace': 'default', 'service_account': 'home-assistant',
                   'match_labels': {'app.kubernetes.io/name': 'home-assistant'}}],
        'gateway': {'host': '127.0.0.1', 'port': port},
        'sources': {'vlan22': ['198.18.22.0/24', '2001:db8:1000:22::/64']}, 'forbidden': ['198.19.0.0/16']}
    Path('/tmp/node-config.json').write_text(json.dumps(config))
    process = None
    def start():
        return subprocess.Popen([sys.executable, '-m', 'discovery.node_runtime', 'broker', '--config', '/tmp/node-config.json'])
    async def ready():
        deadline = time.monotonic() + 8
        while not await answer_present():
            assert process.poll() is None, 'broker exited'
            assert time.monotonic() < deadline, 'broker did not deliver answers'
            await asyncio.sleep(.1)
    try:
        process = start()
        await ready()
        worker = child_of(process.pid)
        status = Path(f'/proc/{worker}/status').read_text()
        assert 'Uid:\t65534\t65534\t65534\t65534' in status
        assert 'CapEff:\t0000000000000000' in status
        assert 'NoNewPrivs:\t1' in status
        report('worker_credentials_dropped_and_no_new_privileges')
        await check_discovery(4)
        await check_discovery(6)
        assert process.poll() is None

        # A successful full relist observes deletion; no worker-controlled renew.
        state['pods'] = []; state_file(state)
        await asyncio.sleep(10.5)
        assert not await answer_present()
        report('automatic_pod_deletion_removes_delivery')
        state['pods'] = [item]; state_file(state)
        await asyncio.sleep(10.5)
        await ready()
        report('automatic_relist_restores_eligible_pod')

        state['api_failure'] = True; state_file(state)
        await asyncio.sleep(31)
        assert not await answer_present()
        assert process.poll() is None
        report('api_loss_expires_original_eligibility_without_renewal')
        state['api_failure'] = False; state_file(state)
        await asyncio.sleep(10.5)
        await ready()
        report('fresh_api_relist_recovers_after_lease_expiry')

        # Stopping the broker leaves the unprivileged worker running. Its private
        # heartbeat timeout must close the sockets rather than renew them.
        process.send_signal(signal.SIGSTOP)
        await wait_until(lambda: exited(worker), timeout=7)
        assert not await answer_present()
        process.send_signal(signal.SIGCONT)
        await wait_until(lambda: process.poll() is not None)
        report('stopped_broker_causes_worker_to_close_delivery')

        process = start(); await ready()
        worker = child_of(process.pid)
        os.kill(worker, signal.SIGSTOP)
        process.kill(); process.wait(timeout=3)
        await wait_until(lambda: exited(worker), timeout=3)
        assert not await answer_present()
        report('broker_death_kills_stopped_worker')
    finally:
        if process and process.poll() is None:
            process.send_signal(signal.SIGCONT); process.terminate()
            await wait_until(lambda: process.poll() is not None)
        refresh.cancel(); await asyncio.gather(refresh, return_exceptions=True)
        await server.close(); await coordinator.close(); feed.close()


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
        deadline = time.monotonic() + 3
        while any(a.get('tentative') for link in json.loads(subprocess.check_output(
                ['ip', '-j', 'address', 'show', 'dev', 'eth0'])) for a in link['addr_info']):
            assert time.monotonic() < deadline, 'interface DAD did not finish'
            time.sleep(.05)
    sandbox = pause_process()
    try:
        asyncio.run(run_lab(sandbox))
    finally:
        sandbox.terminate(); sandbox.wait(timeout=3)


if __name__ == '__main__': main()
