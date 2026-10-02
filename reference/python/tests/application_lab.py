"""Joined collector/gateway/broker fixture for released application consumers.

The container's initial network namespace is the application pod (IPv6-only by
default, with a separately labelled dual-stack comparison).
Router and device namespaces are separate. Only the device and API/CRI metadata
are fixtures; discovery records travel through the production entry points.
"""
import asyncio
from contextlib import suppress
import ctypes
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

import dns.name
import dns.message
from avahi_lab import endpoint, namespace, send
from discovery.identity import Identities
from discovery.router_candidate import avahi_config
from packet_lab import ip
from test_broker import pod_item, runtime_status

ROOT = Path('/lab')
SERVICE = '_esphomelib._tcp.local.'
HOST = 'mdns-canary.local.'
INSTANCE = 'mdns-canary.' + SERVICE
DUAL_STACK = os.environ.get('MDNS_APP_NETWORK', 'ipv6') == 'dual'


def setup_network():
    ip('netns', 'attach', 'discovery-pod', str(os.getpid()))
    ip('link', 'set', 'lo', 'up')
    for name in ('router', 'device'):
        ip('netns', 'add', name)
        with namespace(name):
            ip('link', 'set', 'lo', 'up')
    ip('link', 'add', 'eth0', 'type', 'veth', 'peer', 'name', 'pod-link', 'netns', 'router')
    ip('link', 'set', 'eth0', 'up')
    ip('-6', 'address', 'add', 'fd00:5353::2/64', 'dev', 'eth0', 'nodad')
    ip('-6', 'route', 'add', 'default', 'via', 'fd00:5353::1')
    if DUAL_STACK:
        ip('address', 'add', '192.0.2.2/24', 'dev', 'eth0')
        ip('route', 'add', 'default', 'via', '192.0.2.1')
    with namespace('router'):
        ip('link', 'set', 'pod-link', 'up')
        ip('-6', 'address', 'add', 'fd00:5353::1/64', 'dev', 'pod-link', 'nodad')
        if DUAL_STACK:
            ip('address', 'add', '192.0.2.1/24', 'dev', 'pod-link')
        ip('link', 'add', 'lan-vlan22', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', 'device')
        ip('link', 'set', 'lan-vlan22', 'up')
        ip('address', 'add', '198.18.22.1/24', 'dev', 'lan-vlan22')
        ip('-6', 'address', 'add', 'fd00:22::1/64', 'dev', 'lan-vlan22', 'nodad')
    with namespace('device'):
        ip('link', 'set', 'eth0', 'up')
        # Match physical LAN receive checksums, as in the existing G1 lab.
        command = ctypes.create_string_buffer(struct.pack('II', 0x17, 0))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
            fcntl.ioctl(control.fileno(), 0x8946, struct.pack('16sP', b'eth0', ctypes.addressof(command)))
        ip('address', 'add', '198.18.22.2/24', 'dev', 'eth0')
        ip('-6', 'address', 'add', 'fd00:22::2/64', 'dev', 'eth0', 'nodad')
    time.sleep(1.2)  # Finish link-local DAD before the collector pins its epoch.


async def run():
    processes, logs = [], []
    def start(name, command, *, router=True):
        log = (ROOT / (name + '.log')).open('w')
        logs.append(log)
        # setns without ip-netns-exec's unrelated /sys mount operations.
        with namespace('router' if router else 'discovery-pod'):
            process = subprocess.Popen(command, stdout=log, stderr=log)
        processes.append(process)
        return process
    ep = endpoint('device', 4, '198.18.22.2')
    capture = endpoint('discovery-pod', 6, 'fd00:5353::2')[0]
    query_shapes = set()
    records = [('_services._dns-sd._udp.local.', 'PTR', SERVICE),
               (SERVICE, 'PTR', INSTANCE), (INSTANCE, 'SRV', '0 0 6053 ' + HOST),
               (INSTANCE, 'TXT', '"version=2026.9.0" "mac=020000000042" "platform=ESP32" "board=esp32dev" "friendly_name=mDNS Canary"'),
               (HOST, 'A', '198.18.22.2'), (HOST, 'AAAA', 'fd00:22::2')]
    try:
        gateway = {'enabled': True, 'listen_address': '127.0.0.1', 'port': 18443,
                   'clients': ['127.0.0.1/32']}
        config = {'enabled': True, 'interfaces': ['lan-vlan22'],
                  'prefixes': {'lan-vlan22': ['198.18.22.0/24', 'fd00:22::/64']},
                  'bootstrap': [[SERVICE, 12]], 'gateway': gateway}
        Path('/tmp/router-config.json').write_text(json.dumps(config))
        Path('/tmp/avahi.conf').write_text(avahi_config())
        Path('/run/dbus').mkdir(exist_ok=True)
        start('dbus', ['dbus-daemon', '--system', '--nofork', '--nopidfile'])
        await asyncio.sleep(.4)
        start('avahi', ['avahi-daemon', '--no-chroot', '--no-drop-root', '-f', '/tmp/avahi.conf'])
        await asyncio.sleep(1)
        common = ['--config', '/tmp/router-config.json', '--state', '/tmp/identities.db', '--socket', '/tmp/publisher.sock']
        start('owner', [sys.executable, '-m', 'discovery.runtime', 'publisher', *common])
        async with asyncio.timeout(8):
            while not Path('/tmp/publisher.sock').exists():
                await asyncio.sleep(.1)
        collector = start('collector', [sys.executable, '-m', 'discovery.runtime', 'collector', *common])

        sandbox = start('sandbox', ['sleep', '600'], router=False)
        item = pod_item(); item['status']['podIPs'] = [{'ip': 'fd00:5353::2'}]
        runtime = runtime_status(sandbox.pid); runtime['status']['network']['ip'] = 'fd00:5353::2'
        if DUAL_STACK:
            item['status']['podIPs'].append({'ip': '192.0.2.2'})
            runtime['status']['network']['additionalIps'] = [{'ip': '192.0.2.2'}]
        Path('/tmp/node-state.json').write_text(json.dumps({'pods': [item], 'runtime': runtime}))
        node = {'enabled': True, 'node': 'node-1', 'kubectl': ['/app/tests/node_commands.py'],
                'kubeconfig': '/tmp/fixture-kubeconfig', 'crictl': ['/app/tests/node_commands.py'],
                'runtime_endpoint': 'unix:///tmp/fixture-containerd.sock', 'host_proc': '/proc',
                'worker_uid': 65534, 'worker_gid': 65534,
                'rules': [{'namespace': 'default', 'service_account': 'home-assistant',
                           'match_labels': {'app.kubernetes.io/name': 'home-assistant'}}],
                'gateway': {'host': '127.0.0.1', 'port': 18443},
                'sources': config['prefixes'], 'forbidden': ['fd00:5353::/64']}
        Path('/tmp/node-config.json').write_text(json.dumps(node))
        broker_command = [sys.executable, '-m', 'discovery.node_runtime', 'broker', '--config', '/tmp/node-config.json']
        broker = start('broker', broker_command)
        for _ in range(16):
            send(ep, records, ttl=8)
            await asyncio.sleep(.5)
        store = Identities('/tmp/identities.db')
        host_alias = store.alias('lan-vlan22', dns.name.from_text(HOST))[1].to_text()
        instance_alias = store.alias('lan-vlan22', dns.name.from_text(INSTANCE))[1].to_text()
        store.close()
        (ROOT / 'ready.json').write_text(json.dumps({'host': HOST, 'instance': INSTANCE,
            'host_alias': host_alias, 'instance_alias': instance_alias, 'pod_ipv6': 'fd00:5353::2',
            'network': 'dual' if DUAL_STACK else 'ipv6'}))
        previous = 'up'
        boundary = None
        if os.environ.get('MDNS_BOUNDARY_LAB') == '1':
            from g2_delivery_lab import exercise
            boundary = asyncio.create_task(exercise(collector, broker, broker_command, processes, start))
        until = time.monotonic() + 300
        while not (ROOT / 'stop').exists():
            if boundary and boundary.done():
                boundary.result()
                break
            assert time.monotonic() < until, 'application lab deadline exceeded'
            assert all(p.poll() is None for p in processes), 'lab component exited; inspect logs'
            phase = (ROOT / 'phase').read_text().strip() if (ROOT / 'phase').exists() else 'up'
            if phase == 'up':
                send(ep, records, ttl=8)
            elif previous != 'down':
                send(ep, records, ttl=0)
            previous = phase
            for _ in range(64):
                try:
                    wire = capture.recv(9000)
                except BlockingIOError:
                    break
                message = dns.message.from_wire(wire)
                if not message.flags & 0x8000:
                    query_shapes.add((len(message.question), len(wire),
                                      any(q.name.to_text() == SERVICE for q in message.question)))
            await asyncio.sleep(.5)
    finally:
        if 'boundary' in locals() and boundary:
            boundary.cancel()
            await asyncio.gather(boundary, return_exceptions=True)
        ep[0].close()
        capture.close()
        (ROOT / 'query-shapes.json').write_text(json.dumps(sorted(query_shapes)))
        for process in reversed(processes):
            if process.poll() is None:
                with suppress(ProcessLookupError):
                    process.send_signal(signal.SIGCONT); process.terminate()
            process.wait(timeout=5)
        for log in logs:
            log.close()


if __name__ == '__main__':
    if os.environ.get('MDNS_ISOLATED_LAB') != '1' or socket.if_nameindex() != [(1, 'lo')]:
        raise SystemExit('requires a fresh network-isolated lab container')
    setup_network()
    # PID 1 represents the host/router, distinct from the fixture pod sandbox.
    with namespace('router'):
        asyncio.run(run())
