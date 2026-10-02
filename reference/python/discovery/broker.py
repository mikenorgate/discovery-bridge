"""Broker-owned eligibility and sockets; no worker-controlled namespace entry.

Call reconcile only with a complete, authenticated own-node Pod list and the
monotonic time at which that API request began. The broker process must call
expire independently of the responder. Production API/CRI transport and process
supervision are separate integration work.
"""
from collections import Counter
from dataclasses import dataclass, field
import math
import subprocess
import time
from uuid import uuid4

from discovery.namespace import Namespace


@dataclass
class Lease:
    pod: object
    namespace: object
    sockets: tuple
    deadline: float
    token: str = field(default_factory=lambda: uuid4().hex)

    def close(self):
        errors = []
        for resource in (*self.sockets, self.namespace):
            try:
                resource.close()
            except OSError as exc:
                errors.append(exc)
        if errors:
            raise ExceptionGroup('broker resource revocation failed', errors)


class Broker:
    def __init__(self, policy, inspect, *, pin=Namespace, clock=time.monotonic, capacity=64):
        if type(capacity) is not int or not 1 <= capacity <= 256:
            raise ValueError('broker capacity must be 1..256 pods')
        self.policy, self.inspect, self.pin = policy, inspect, pin
        self.clock, self.capacity = clock, capacity
        self.leases, self.events = {}, Counter()
        self.observed_at = float('-inf')

    def remove(self, uid):
        lease = self.leases.pop(uid, None)
        if lease:
            lease.close()
            self.events['revoked'] += 1

    def expire(self):
        now = self.clock()
        for uid, lease in tuple(self.leases.items()):
            if now >= lease.deadline:
                self.remove(uid)
                self.events['expired'] += 1

    def close(self):
        errors = []
        for uid in tuple(self.leases):
            try:
                self.remove(uid)
            except (OSError, ExceptionGroup) as exc:
                errors.append(exc)
        if errors:
            raise ExceptionGroup('broker shutdown failed', errors)

    def reconcile(self, items, *, observed_at):
        """Replace eligibility from a fresh full list. Failed requests never renew.

        Runtime calls and namespace inspection must be bounded by the production
        adapter. Call expire on API errors; do not replay a cached list with a new
        observation time. Responder activity never renews broker leases.
        """
        self.expire()
        now = self.clock()
        if (type(observed_at) not in (int, float) or not math.isfinite(observed_at)
                or not 0 <= now - observed_at < 30 or observed_at < self.observed_at):
            raise ValueError('fresh monotonically ordered API observation required')
        if not isinstance(items, (tuple, list)) or len(items) > 4096:
            self.close()
            raise ValueError('complete bounded Pod list required')
        selected = {}
        seen = set()
        for item in items:
            meta = item.get('metadata') if isinstance(item, dict) else None
            uid = meta.get('uid') if isinstance(meta, dict) else None
            if not isinstance(uid, str) or not uid or uid in seen:
                self.close()
                raise ValueError('malformed or duplicate Pod identity in list')
            seen.add(uid)
            pod = self.policy.select(item)
            if pod:
                selected[pod.uid] = pod
        if len(selected) > self.capacity:
            self.close()
            raise ValueError('eligible Pod capacity exceeded')
        self.observed_at = observed_at
        for uid in set(self.leases) - selected.keys():
            self.remove(uid)
        for uid, pod in selected.items():
            if self.clock() >= observed_at + 30:
                break
            namespace, endpoints = None, ()
            try:
                sandbox = self.inspect(pod)
                if sandbox.pod != pod:
                    raise ValueError('runtime adapter returned a different Pod')
                namespace = self.pin(sandbox)
                current = self.leases.get(uid)
                if current and current.namespace.key != namespace.key:
                    self.remove(uid)
                    current = None
                if current is None:
                    endpoints = namespace.open_sockets()
                # A second runtime read detects sandbox stop/replacement during
                # namespace inspection/open. Never install stale descriptors.
                if self.inspect(pod) != sandbox:
                    raise ValueError('sandbox changed during verification')
                namespace.verify()
                self.expire()
                deadline = observed_at + 30
                if self.clock() >= deadline:
                    raise ValueError('eligibility expired during verification')
                if current:
                    if self.leases.get(uid) is not current:
                        raise ValueError('previous lease expired during verification')
                    current.deadline = deadline
                else:
                    self.leases[uid] = Lease(pod, namespace, endpoints, deadline)
                    namespace, endpoints = None, ()
                    self.events['opened'] += 1
            except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError):
                self.remove(uid)
                # Do not log runtime payloads or Pod labels.
                self.events['rejected'] += 1
            finally:
                if namespace is not None:
                    Lease(pod, namespace, endpoints, 0).close()
        self.expire()
