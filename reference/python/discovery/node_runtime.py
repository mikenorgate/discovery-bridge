"""One container, a single-threaded broker and an unprivileged responder process.

Source candidate only. Host proc/runtime mounts, credentials, confinement and
actual Cilium/runtime qualification remain deployment gates.
"""
import argparse
import asyncio
import ctypes
from functools import partial
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

from discovery.broker import Broker
from discovery.catalog import SourcePolicy
from discovery.feed import NodeFeed
from discovery.gateway import GatewayClient
from discovery.namespace import Namespace
from discovery.node_inputs import Containerd, KubernetesPods, read_json
from discovery.node_ipc import Publisher, Sessions, receive, send
from discovery.pod_policy import PodPolicy, Rule


def load(path):
    payload = Path(path).read_bytes()
    if len(payload) > 65536:
        raise ValueError('node configuration too large')
    value = json.loads(payload)
    fields = {'enabled', 'node', 'kubectl', 'kubeconfig', 'crictl', 'runtime_endpoint',
              'host_proc', 'worker_uid', 'worker_gid', 'rules', 'gateway', 'sources', 'forbidden'}
    if set(value) != fields or value['enabled'] is not True:
        raise ValueError('explicit enabled node configuration required')
    if any(type(value[k]) is not int or value[k] <= 0 for k in ('worker_uid', 'worker_gid')):
        raise ValueError('non-root worker UID and GID required')
    if not isinstance(value['rules'], list) or len(value['rules']) > 64 or not os.path.isabs(value['host_proc']):
        raise ValueError('bounded operator rules and absolute host proc path required')
    for rule in value['rules']:
        if set(rule) != {'namespace', 'service_account', 'match_labels'} or not isinstance(rule['match_labels'], dict):
            raise ValueError('invalid operator rule')
        Rule(rule['namespace'], rule['service_account'], tuple(rule['match_labels'].items()))
    if set(value['gateway']) != {'host', 'port'}:
        raise ValueError('fixed gateway HTTP endpoint required')
    SourcePolicy(value['sources'], tuple(value['forbidden']))
    return value


def confine_worker(uid, gid, parent):
    """Drop credentials and make broker death fatal, including while stopped."""
    if uid <= 0 or gid <= 0:
        raise ValueError('non-root worker credentials required')
    libc = ctypes.CDLL(None, use_errno=True)
    os.setgroups([]); os.setgid(gid); os.setuid(uid)
    # Credential changes clear PDEATHSIG, so set it after dropping privileges.
    for option, argument in ((38, 1), (1, signal.SIGKILL)):  # NO_NEW_PRIVS, PDEATHSIG
        if libc.prctl(option, argument, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'worker process confinement failed')
    if os.getppid() != parent:
        raise RuntimeError('broker exited during worker startup')
    caps = next(line for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:'))
    if int(caps.split()[1], 16):
        raise RuntimeError('worker retained effective capabilities')


async def respond(channel, config):
    settings = config['gateway']
    feed = NodeFeed(SourcePolicy(config['sources'], tuple(config['forbidden'])))
    gateway = GatewayClient(settings['host'], settings['port'])
    sessions = Sessions(channel, feed, on_miss=gateway.lookup)
    async def refresh():
        while True:
            try:
                await gateway.refresh(feed)
            except (OSError, ValueError, TimeoutError):
                pass  # Existing feed expires independently; never extend it.
            await asyncio.sleep(5)
    refresh_task = asyncio.create_task(refresh())
    try:
        await sessions.run()
    finally:
        refresh_task.cancel()
        await asyncio.gather(refresh_task, return_exceptions=True)
        await sessions.close()


class Owner:
    """A broker loop that never accepts worker input or worker lease renewals."""
    def __init__(self, config, channel, process):
        self.channel, self.process = channel, process
        self.publisher = Publisher(channel)
        policy = PodPolicy(config['node'], [Rule(r['namespace'], r['service_account'],
                          tuple(r['match_labels'].items())) for r in config['rules']])
        run = partial(read_json, tick=self.tick)
        runtime = Containerd(config['crictl'], config['runtime_endpoint'], run=run)
        self.broker = Broker(policy, runtime.inspect, pin=partial(Namespace, proc=config['host_proc']))
        self.pods = KubernetesPods(config['node'], config['kubectl'], config['kubeconfig'], run=run)

    def tick(self):
        if self.process.poll() is not None:
            raise RuntimeError('responder exited')
        self.broker.expire()
        self.publisher.sync(self.broker.leases)

    def refresh(self):
        try:
            items, observed_at = self.pods.snapshot()
        except (OSError, ValueError):
            self.broker.events['api_failed'] += 1
            self.tick()  # API failures retain only the original, expiring leases.
            return
        self.broker.reconcile(items, observed_at=observed_at)
        self.publisher.renew(self.broker.leases)

    def run(self):
        next_refresh = 0
        while True:
            self.tick()
            if time.monotonic() >= next_refresh:
                next_refresh = time.monotonic() + 10
                self.refresh()
            time.sleep(.05)


def run(config):
    owner, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    process = None
    broker = None
    try:
        process = subprocess.Popen([sys.executable, '-m', 'discovery.node_runtime', 'worker',
            '--control-fd', str(child.fileno()), '--parent', str(os.getpid()),
            '--uid', str(config['worker_uid']), '--gid', str(config['worker_gid'])],
            pass_fds=(child.fileno(),), stdin=subprocess.DEVNULL, close_fds=True,
            # API credentials/configuration remain in the broker's environment.
            env={k: v for k, v in os.environ.items() if k in ('PATH', 'PYTHONPATH', 'PYTHONDONTWRITEBYTECODE', 'LANG')})
        child.close()
        send(owner, {k: config[k] for k in ('gateway', 'sources', 'forbidden')})
        broker = Owner(config, owner, process)
        broker.run()
    finally:
        try:
            if broker: broker.broker.close()
        finally:
            owner.close(); child.close()
            if process:
                if process.poll() is None: process.kill()
                process.wait(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    broker = sub.add_parser('broker')
    broker.add_argument('--config', required=True)
    broker.add_argument('--node', help='override with the Kubernetes downward API node name')
    worker = sub.add_parser('worker')
    for argument in ('control-fd', 'parent', 'uid', 'gid'):
        worker.add_argument('--' + argument, type=int, required=True)
    args = parser.parse_args()
    if args.mode == 'worker':
        confine_worker(args.uid, args.gid, args.parent)
        channel = socket.socket(fileno=args.control_fd)
        channel.settimeout(5)
        config, descriptors = receive(channel)
        for fd in descriptors: os.close(fd)
        if descriptors or set(config) != {'gateway', 'sources', 'forbidden'}:
            raise ValueError('invalid worker configuration')
        asyncio.run(respond(channel, config))
    else:
        def stop(*_): raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, stop)
        try:
            config = load(args.config)
            if args.node is not None:
                config['node'] = args.node
            run(config)
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    try:
        main()
    except (EOFError, OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print('node discovery stopped: ' + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
