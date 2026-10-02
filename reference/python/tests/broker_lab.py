"""Real process/netns pinning with fixture API/CRI data, isolated from the host."""
import array
import errno
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time

from discovery.broker import Broker
from discovery.namespace import Namespace
from discovery.pod_policy import Sandbox
from packet_lab import ip, namespace
from pod_socket_lab import worker
from test_broker import pod_item, policy, runtime_status


def report(case, **fields):
    print(json.dumps({'case': case, 'status': 'pass', **fields}), flush=True)


def pause_process():
    process = subprocess.Popen([sys.executable, __file__, 'sandbox'])
    target = os.stat('/run/netns/discovery-pod').st_ino
    deadline = time.monotonic() + 2
    while os.stat(f'/proc/{process.pid}/ns/net').st_ino != target:
        if time.monotonic() >= deadline:
            process.kill(); process.wait()
            raise AssertionError('sandbox process did not enter namespace')
        time.sleep(.01)
    return process


def revoke_worker(broker, endpoint, case):
    owner, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    owner.settimeout(3)
    process = subprocess.Popen([sys.executable, __file__, 'worker', str(child.fileno()),
                                str(endpoint.family), str(endpoint.index)], pass_fds=(child.fileno(),))
    child.close()
    try:
        owner.sendmsg([b's'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [endpoint.socket.fileno()]))])
        assert owner.recv(100) == b'ready'
        owner.send(b'send'); assert owner.recv(100) == b'sent'
        process.send_signal(signal.SIGSTOP)
        assert os.WIFSTOPPED(os.waitpid(process.pid, os.WUNTRACED)[1])
        if case == 'expiry':
            deadline = min(lease.deadline for lease in broker.leases.values())
            while time.monotonic() < deadline + .01:
                broker.expire()
                time.sleep(.02)
            broker.expire()
        else:
            broker.reconcile([], observed_at=time.monotonic())
        assert not broker.leases
        process.send_signal(signal.SIGCONT)
        owner.send(b'send')
        assert owner.recv(100) == str(errno.EPIPE).encode()
        report('broker_' + case + '_revokes_paused_unprivileged_worker', family=endpoint.family,
               worker_uid=65534, kernel=os.uname().release)
    finally:
        owner.close()
        if process.poll() is None:
            process.send_signal(signal.SIGCONT); process.terminate()
        process.wait(timeout=3)


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
    process = pause_process()
    item = pod_item()
    item['status']['podIPs'] = [{'ip': 'fd00:5353::2'}, {'ip': '192.0.2.2'}]
    pod = policy().select(item)
    def inspect(pod):
        data = runtime_status(process.pid)
        data['status']['network'] = {'ip': 'fd00:5353::2', 'additionalIps': [{'ip': '192.0.2.2'}]}
        return Sandbox.from_status(data, pod)
    broker = Broker(policy(), inspect)
    original = os.stat('/proc/self/ns/net').st_ino
    try:
        broker.reconcile([item], observed_at=time.monotonic())
        lease = broker.leases[pod.uid]
        assert {e.family for e in lease.sockets} == {4, 6}
        assert lease.namespace.start > 0
        assert os.stat('/proc/self/ns/net').st_ino == original
        report('verified_real_process_namespace_and_dual_stack_interface')

        with lease.namespace.enter():
            assert os.stat('/proc/self/ns/net').st_ino != original
        try:
            with lease.namespace.enter(): raise ValueError('injected failure')
        except ValueError: pass
        assert os.stat('/proc/self/ns/net').st_ino == original
        report('namespace_restored_after_failure')

        stop = threading.Event()
        thread = threading.Thread(target=stop.wait); thread.start()
        try:
            try:
                with lease.namespace.enter(): raise AssertionError('entered with extra thread')
            except RuntimeError: pass
        finally:
            stop.set(); thread.join()
        report('namespace_entry_rejects_multithreaded_process')

        # A fixture cannot direct the opener into the node or broker namespace.
        try:
            Namespace(Sandbox('a' * 64, os.getpid(), pod))
            raise AssertionError('broker namespace admitted')
        except ValueError: pass
        report('host_or_broker_namespace_rejected')

        for family, address in (('-6', 'fd00:5353::3/64'), ('-4', '169.254.1.2/16')):
            broker.reconcile([item], observed_at=time.monotonic())
            lease = broker.leases[pod.uid]
            with namespace():
                extra = ['nodad'] if family == '-6' else []
                ip(family, 'address', 'add', address, 'dev', 'eth0', *extra)
            broker.reconcile([item], observed_at=time.monotonic())
            assert not broker.leases and all(e.closed for e in lease.sockets)
            with namespace(): ip(family, 'address', 'delete', address, 'dev', 'eth0')
        report('interface_address_change_revokes_existing_sockets',
               addresses=['fd00:5353::3', '169.254.1.2'])

        broker.close(); broker = Broker(policy(), inspect)
        for family in (4, 6):
            for case in ('expiry', 'deletion'):
                # Model an API observation whose original 30-second lease has
                # two seconds left. No shortened production TTL is introduced.
                broker.reconcile([item], observed_at=time.monotonic() - (28 if case == 'expiry' else 0))
                endpoint = next(e for e in broker.leases[pod.uid].sockets if e.family == family)
                revoke_worker(broker, endpoint, case)
                # A new broker represents a new authenticated API baseline.
                broker.close(); broker = Broker(policy(), inspect)

        broker.reconcile([item], observed_at=time.monotonic())
        lease = broker.leases[pod.uid]
        process.terminate(); process.wait(timeout=3)
        broker.reconcile([item], observed_at=time.monotonic())
        assert not broker.leases and all(e.closed for e in lease.sockets)
        report('exited_sandbox_revoked_despite_stale_runtime_fixture')
    finally:
        broker.close()
        if process.poll() is None: process.terminate()
        process.wait(timeout=3)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'worker': worker(*map(int, sys.argv[2:]))
    elif len(sys.argv) > 1 and sys.argv[1] == 'sandbox':
        with namespace(): signal.pause()
    else: main()
