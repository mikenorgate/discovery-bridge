"""Compare released Go and reference Python workers on an isolated pod network.

Run in the Debian 13 integration fixture with verified reference dependencies.
Only the workers are measured; the same Python gateway supplies both catalogs.
The namespace, gateway and client are fixture processes, outside the samples.
"""
import argparse
import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import time

import dns.message
import dns.name
import dns.rdatatype as rt

from discovery.catalog import Catalog, SourcePolicy
from discovery.feed import GatewayFeed, encode
from discovery.gateway import GatewayAPI, GatewayServer
from discovery.lookup import LookupCoordinator
from discovery.node_ipc import send
from discovery.node_runtime import confine_worker
from discovery.pod_socket import PodSocket
from discovery.records import PublicationPolicy


def decode(wire):
    # Clear mDNS cache-flush bits before dnspython selects its RDATA parser;
    # preserve offsets so compressed names still refer to the original packet.
    _, _, questions, answers, authority, additional = struct.unpack_from('!6H', wire)
    normalized, offset = bytearray(wire), 12
    for _ in range(questions):
        _, used = dns.name.from_wire(wire, offset)
        offset += used + 4
    for _ in range(answers + authority + additional):
        _, used = dns.name.from_wire(wire, offset)
        offset += used
        _, class_, _, size = struct.unpack_from('!HHIH', wire, offset)
        struct.pack_into('!H', normalized, offset + 2, class_ & 0x7fff)
        offset += 10 + size
    if offset != len(wire):
        raise RuntimeError('Measured reply has invalid record lengths')
    return dns.message.from_wire(bytes(normalized), one_rr_per_rrset=True)


@contextmanager
def enter(pid):
    if len(os.listdir('/proc/self/task')) != 1:
        raise RuntimeError('The fixture must enter namespaces before starting threads')
    home = os.open('/proc/self/ns/net', os.O_RDONLY | os.O_CLOEXEC)
    target = os.open(f'/proc/{pid}/ns/net', os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.setns(target, os.CLONE_NEWNET)
        try:
            yield
        finally:
            os.setns(home, os.CLONE_NEWNET)
    finally:
        os.close(target)
        os.close(home)


def sample(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    status = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines())
    if status['CapEff'].strip() != '0000000000000000' or status['NoNewPrivs'].strip() != '1':
        raise RuntimeError('Measured worker lost its unprivileged boundary')
    rss = int(status['VmRSS'].split()[0])
    threads = int(status['Threads'].strip())
    if rss > 128 * 1024 or threads > 32:
        raise RuntimeError('Measured worker exceeds the existing resource budget')
    return {'cpu_seconds': (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK'),
            'rss_kib': rss, 'threads': threads}


def install(source, count, revision):
    now = datetime.now(timezone.utc)
    records = [('enum', '_services._dns-sd._udp.local.', 'PTR', '_http._tcp.local.')]
    unique = []
    for index in range(count):
        host, instance = f'sensor-{index}.local.', f'Example-{index}._http._tcp.local.'
        records.extend([
            (f'browse-{index}', '_http._tcp.local.', 'PTR', instance),
            (f'srv-{index}', instance, 'SRV', f'0 0 8080 {host}'),
            (f'txt-{index}', instance, 'TXT', '"path=/"'),
            (f'v4-{index}', host, 'A', f'192.0.2.{index + 42}'),
            (f'v6-{index}', host, 'AAAA', f'2001:db8:1::{index + 42:x}'),
        ])
        unique.extend([(instance, 33), (instance, 16)])
    snapshot = {'schema': 1, 'epoch': 'comparison', 'revision': revision,
                'issued_at': now.isoformat(), 'valid_until': (now + timedelta(seconds=30)).isoformat(),
                'records': [dict(id=identifier, name=name, type=kind, data=data, source_link='lan-a',
                                 expires_at=(now + timedelta(seconds=20)).isoformat())
                            for identifier, name, kind, data in records]}
    source.install(encode(snapshot), now=now, monotonic=time.monotonic())
    return PublicationPolicy(frozenset(r[0] for r in records), frozenset(unique))


async def trial(language, args, pod, settings):
    owner, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    control = child.fileno()
    command = [args.go_binary, 'worker', '--control-fd', str(control), '--parent', str(os.getpid())]
    options = {}
    if language == 'python':
        command = [sys.executable, '-m', 'discovery.node_runtime', *command[1:], '--uid', '65532', '--gid', '65532']
    else:
        # The reference drops inside its worker entry point; Go inherits the
        # same credentials and no-new-privileges boundary before its runtime starts.
        parent = os.getpid()
        options['preexec_fn'] = lambda: confine_worker(65532, 65532, parent)
    process = subprocess.Popen(command, pass_fds=(control,), env=dict(os.environ, GOMAXPROCS='2'), **options)
    child.close()
    with enter(pod.pid):
        worker_socket = PodSocket('eth0', 6, ['198.51.100.42', '2001:db8:2::42'])
        client = PodSocket('eth0', 6, ['198.51.100.42', '2001:db8:2::42'])
    stopped = False

    async def heartbeat():
        while not stopped:
            send(owner, {'op': 'ping'})
            await asyncio.sleep(.5)

    async def request(index):
        host = index % args.devices
        kind = (rt.AAAA, rt.SRV, rt.TXT)[(index // args.devices) % 3]
        name = f'sensor-{host}.local.' if kind == rt.AAAA else f'Example-{host}._http._tcp.local.'
        message = dns.message.make_query(name, kind)
        message.flags = 0
        wire = message.to_wire()
        while True:
            try:
                client.socket.recv(9000)
            except BlockingIOError:
                break
        start = time.perf_counter()
        client.socket.sendmsg([wire], client.send_info, 0, client.target)
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            process.poll()
            if process.returncode is not None:
                raise RuntimeError(f'{language} worker exited with {process.returncode}')
            try:
                incoming, _, _, _ = client.socket.recvmsg(9000, 256)
            except BlockingIOError:
                await asyncio.sleep(.001)
                continue
            answer = decode(incoming)
            if not answer.flags & 0x8000:
                if incoming != wire:
                    raise RuntimeError('An unexpected question entered the pod')
                continue
            matches = [rr for rr in answer.answer if rr.name.to_text().lower() == name.lower() and rr.rdtype == kind and rr.ttl > 0]
            if matches:
                expected = {rt.AAAA: f'2001:db8:1::{host + 42:x}', rt.SRV: f'0 0 8080 sensor-{host}.local.', rt.TXT: '"path=/"'}[kind]
                if len(matches) != 1 or len(matches[0]) != 1 or matches[0][0].to_text() != expected:
                    raise RuntimeError(f'{language} reply for {name} {rt.to_text(kind)}: '
                                       f'expected {expected!r}, received {[rr.to_text() for rr in matches]!r}')
                return (time.perf_counter() - start) * 1000
        raise RuntimeError(f'{language} worker did not answer {name} {rt.to_text(kind)}')

    ping = None
    try:
        send(owner, settings)
        send(owner, {'op': 'open', 'uid': 'comparison-pod', 'token': '0123456789abcdef0123456789abcdef',
                     'deadline': time.monotonic() + 20, 'sockets': [worker_socket.description()]}, [worker_socket.socket.fileno()])
        ping = asyncio.create_task(heartbeat())
        await asyncio.sleep(.5)
        await request(args.devices - 1)
        await asyncio.sleep(1)
        initial = sample(process.pid)
        latencies = []
        peak_rss, peak_threads = initial['rss_kib'], initial['threads']
        started = time.monotonic()
        for index in range(args.queries):
            latencies.append(await request(index))
            current = sample(process.pid)
            peak_rss, peak_threads = max(peak_rss, current['rss_kib']), max(peak_threads, current['threads'])
            # Stay below the existing ten-response-per-second egress budget.
            await asyncio.sleep(max(0, started + (index + 1) / 8 - time.monotonic()))
        final = sample(process.pid)
        return {'language': language, 'queries': args.queries, 'devices': args.devices,
                'elapsed_seconds': time.monotonic() - started,
                'cpu_seconds': final['cpu_seconds'] - initial['cpu_seconds'],
                'peak_rss_kib': peak_rss, 'peak_threads': peak_threads,
                'latency_mean_ms': statistics.mean(latencies),
                'latency_p95_ms': sorted(latencies)[int(len(latencies) * .95) - 1]}
    finally:
        stopped = True
        if ping:
            ping.cancel()
            await asyncio.gather(ping, return_exceptions=True)
        owner.close()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        worker_socket.close()
        client.close()


async def main(args):
    if os.geteuid() != 0 or not os.path.isabs(args.go_binary):
        raise RuntimeError('Run the isolated fixture as root with an absolute Go executable')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    pod = subprocess.Popen(['unshare', '--net', 'sleep', '600'])
    try:
        for _ in range(100):
            home = os.stat('/proc/self/ns/net')
            peer = os.stat(f'/proc/{pod.pid}/ns/net')
            if (home.st_dev, home.st_ino) != (peer.st_dev, peer.st_ino):
                break
            await asyncio.sleep(.01)
        else:
            raise RuntimeError('Fixture namespace did not start')
        prefix = ['nsenter', '--target', str(pod.pid), '--net', 'ip']
        for command in (['link', 'add', 'eth0', 'type', 'dummy'],
                        ['address', 'add', '198.51.100.42/24', 'dev', 'eth0'],
                        ['address', 'add', '2001:db8:2::42/64', 'dev', 'eth0', 'nodad'],
                        ['link', 'set', 'eth0', 'multicast', 'on', 'up']):
            subprocess.run(prefix + command, check=True)
        with tempfile.TemporaryDirectory(prefix='bridge-comparison-') as directory:
            policy = SourcePolicy({'lan-a': ('192.0.2.0/24', '2001:db8:1::/64')}, ())
            source = Catalog(policy)
            feed = GatewayFeed(source, install(source, args.devices, 1), Path(directory) / 'generation.sqlite')

            async def demand(*_):
                pass

            lookups = LookupCoordinator(policy.sources, demand)
            server = GatewayServer(GatewayAPI(feed, lookups), ['127.0.0.1/32'])
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            endpoint = {'host': '127.0.0.1', 'port': listener.getsockname()[1]}
            settings = {'gateway': endpoint, 'sources': {'lan-a': ['192.0.2.0/24', '2001:db8:1::/64']}, 'forbidden': []}
            await server.start(listener)
            values, revision = [], 1
            try:
                for repeat in range(args.repeat):
                    for language in (('go', 'python') if repeat % 2 == 0 else ('python', 'go')):
                        revision += 1
                        feed.authority = install(source, args.devices, revision)
                        result = await trial(language, args, pod, settings)
                        result['repeat'] = repeat + 1
                        values.append(result)
                        print(json.dumps(result, sort_keys=True), flush=True)
            finally:
                await server.close()
                await lookups.close()
                feed.close()
            args.output.write_text(json.dumps({'schema': 1, 'scope': 'unprivileged_worker_native_ipv6_mdns',
                'go_version': subprocess.check_output([args.go_binary, 'version'], text=True).strip(),
                'python_version': sys.version.split()[0], 'samples': values}, sort_keys=True, indent=2) + '\n')
    finally:
        pod.kill()
        pod.wait(timeout=2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-binary', required=True)
    parser.add_argument('--repeat', type=int, default=10, choices=range(1, 21))
    parser.add_argument('--devices', type=int, default=16, choices=range(1, 65))
    parser.add_argument('--queries', type=int, default=48, choices=range(3, 97))
    parser.add_argument('--output', type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
