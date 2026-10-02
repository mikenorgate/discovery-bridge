"""Pin and verify a containerd sandbox namespace in a single-threaded broker.

No paths, interfaces, PIDs or runtime commands are accepted from the responder.
The trusted runtime adapter supplies Sandbox; operator configuration fixes eth0.
"""
from contextlib import contextmanager
from ipaddress import ip_address
import json
import os
from pathlib import Path
import socket
import subprocess

from discovery.pod_socket import PodSocket


def identity(fd):
    stat = os.fstat(fd)
    return stat.st_dev, stat.st_ino


def process_start(proc_fd):
    fd = os.open('stat', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=proc_fd)
    try:
        # comm can contain spaces and parentheses; starttime is field 22.
        fields = os.read(fd, 8192).rsplit(b')', 1)[1].split()
        if fields[0] in (b'Z', b'X', b'x'):
            raise ValueError('sandbox process exited')
        return int(fields[19])
    finally:
        os.close(fd)


class Namespace:
    def __init__(self, sandbox, *, proc='/proc', interface='eth0'):
        if interface != 'eth0':
            raise ValueError('only the qualified ordinary pod interface is supported')
        if type(sandbox.pid) is not int or sandbox.pid <= 1:
            raise ValueError('invalid sandbox PID')
        self.sandbox, self.proc, self.interface = sandbox, Path(proc), interface
        self.process = self.net = self.home = None
        try:
            self.home = os.open('/proc/self/ns/net', os.O_RDONLY | os.O_CLOEXEC)
            self.process = os.open(self.proc / str(sandbox.pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.start = process_start(self.process)
            self.net = os.open('ns/net', os.O_RDONLY | os.O_CLOEXEC, dir_fd=self.process)
            host = os.open(self.proc / '1/ns/net', os.O_RDONLY | os.O_CLOEXEC)
            try:
                if identity(self.net) in (identity(self.home), identity(host)):
                    raise ValueError('host/agent network namespace rejected')
            finally:
                os.close(host)
            self.verify()
            with self.enter():
                self.index, self.addresses = self.inspect_interface()
            self.key = (sandbox, self.start, identity(self.net), self.index, self.addresses)
        except BaseException:
            self.close()
            raise

    def verify(self):
        # Reopening the numeric PID detects PID reuse; anchored proc reads retain
        # the original process identity even if the numeric path is replaced.
        current = os.open(self.proc / str(self.sandbox.pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if identity(current) != identity(self.process) or process_start(current) != self.start:
                raise ValueError('sandbox process identity changed')
            net = os.open('ns/net', os.O_RDONLY | os.O_CLOEXEC, dir_fd=current)
            try:
                if identity(net) != identity(self.net):
                    raise ValueError('sandbox network namespace changed')
            finally:
                os.close(net)
        finally:
            os.close(current)

    @contextmanager
    def enter(self):
        if len(os.listdir('/proc/self/task')) != 1:
            raise RuntimeError('namespace entry requires a single-threaded broker process')
        self.verify()
        os.setns(self.net, os.CLONE_NEWNET)
        try:
            yield
        finally:
            try:
                os.setns(self.home, os.CLONE_NEWNET)
            except OSError:
                # Continuing in a pod namespace is unsafe. The supervisor must
                # stop the responder too; runtime supervision remains a gate.
                os._exit(70)
        self.verify()

    def inspect_interface(self):
        result = subprocess.run(['ip', '-j', 'address', 'show', 'dev', self.interface],
                                check=True, capture_output=True, timeout=1)
        if len(result.stdout) > 65536:
            raise ValueError('oversized interface description')
        links = json.loads(result.stdout)
        if len(links) != 1:
            raise ValueError('pod interface missing or ambiguous')
        link = links[0]
        if not {'UP', 'MULTICAST'} <= set(link['flags']) or link['ifindex'] != socket.if_nametoindex(self.interface):
            raise ValueError('pod interface is not usable')
        values = []
        for item in link['addr_info']:
            if item['family'] not in ('inet', 'inet6'):
                continue
            value = ip_address(item['local'])
            if (item.get('tentative') or item.get('dadfailed') or item.get('deprecated')
                    or {'tentative', 'dadfailed', 'deprecated'} & set(item.get('flags', []))):
                raise ValueError('pod interface address not ready')
            if value.is_loopback or value.is_unspecified or value.is_multicast:
                raise ValueError('invalid pod interface address')
            values.append(value)
        actual = frozenset(values)
        if frozenset(a for a in actual if not (a.version == 6 and a.is_link_local)) != self.sandbox.pod.addresses:
            raise ValueError('API/CRI/interface addresses differ')
        return link['ifindex'], actual

    def open_sockets(self):
        sockets = []
        try:
            with self.enter():
                if self.inspect_interface() != (self.index, self.addresses):
                    raise ValueError('interface changed before socket creation')
                values = tuple(str(a) for a in sorted(self.addresses, key=lambda a: (a.version, int(a))))
                for family in sorted({a.version for a in self.addresses}):
                    sockets.append(PodSocket(self.interface, family, values))
                if self.inspect_interface() != (self.index, self.addresses):
                    raise ValueError('interface changed during socket creation')
            return tuple(sockets)
        except BaseException:
            for endpoint in sockets:
                endpoint.close()
            raise

    def close(self):
        for name in ('net', 'process', 'home'):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)
