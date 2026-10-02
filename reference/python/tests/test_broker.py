"""Trusted API/CRI selection, identity replacement and broker-owned lease tests."""
from copy import deepcopy
from dataclasses import replace
import os
import tempfile
from types import SimpleNamespace
import unittest

from discovery.broker import Broker, Lease
from discovery.namespace import process_start
from discovery.pod_policy import OPT_IN, PodPolicy, Rule, Sandbox


def pod_item():
    return {'metadata': {'uid': 'pod-uid', 'name': 'home-assistant-0', 'namespace': 'default',
                         'labels': {OPT_IN: 'true', 'app.kubernetes.io/name': 'home-assistant'}},
            'spec': {'nodeName': 'node-1', 'serviceAccountName': 'home-assistant'},
            'status': {'phase': 'Running', 'podIPs': [{'ip': 'fd00::2'}]}}


def policy():
    return PodPolicy('node-1', [Rule('default', 'home-assistant',
                                   (('app.kubernetes.io/name', 'home-assistant'),))])


def runtime_status(pid=100):
    return {'status': {'id': 'a' * 64, 'state': 'SANDBOX_READY',
                       'metadata': {'uid': 'pod-uid', 'name': 'home-assistant-0', 'namespace': 'default'},
                       'network': {'ip': 'fd00::2'},
                       'linux': {'namespaces': {'options': {'network': 'POD'}}}},
            'info': {'pid': pid, 'processStatus': 'running', 'netNamespaceClosed': False}}


class PolicyTests(unittest.TestCase):
    def test_opt_in_requires_every_operator_dimension(self):
        self.assertIsNotNone(policy().select(pod_item()))
        self.assertIsNone(PodPolicy('node-1', []).select(pod_item()))
        changes = [('metadata', 'namespace', 'other'), ('spec', 'serviceAccountName', 'other'),
                   ('spec', 'nodeName', 'node-2'), ('spec', 'hostNetwork', True),
                   ('metadata', 'deletionTimestamp', '2026-09-28T12:00:00Z'),
                   ('status', 'phase', 'Succeeded')]
        for section, field, value in changes:
            with self.subTest(field=field):
                item = pod_item(); item[section][field] = value
                self.assertIsNone(policy().select(item))
        for labels in ({}, {OPT_IN: 'true'}, {OPT_IN: 'True', 'app.kubernetes.io/name': 'home-assistant'}):
            item = pod_item(); item['metadata']['labels'] = labels
            self.assertIsNone(policy().select(item))

    def test_rules_require_a_workload_selector(self):
        for labels in ((), ((OPT_IN, 'true'),), (('app', 'ha'), ('app', 'ha'))):
            with self.assertRaises(ValueError):
                Rule('default', 'ha', labels)

    def test_bad_or_ipv4_only_api_addresses_are_denied(self):
        for values in ([], ['192.0.2.2'], ['::1'], ['fe80::2'], ['ff02::fb'], ['::'], ['bad'],
                       ['fd00::2', 'fd00::3']):
            item = pod_item(); item['status']['podIPs'] = [{'ip': a} for a in values]
            self.assertIsNone(policy().select(item))
        item['status']['podIPs'] = [{'ip': a} for a in ('fd00::2', '192.0.2.2')]
        self.assertEqual(len(policy().select(item).addresses), 2)

    def test_malformed_api_objects_fail_closed(self):
        for item in (None, [], {}, {'metadata': None}, {'metadata': {'uid': []}}):
            self.assertIsNone(policy().select(item))

    def test_containerd_admission_checks_identity_state_and_addresses(self):
        pod = policy().select(pod_item())
        valid = runtime_status()
        self.assertEqual(Sandbox.from_status(valid, pod), Sandbox('a' * 64, 100, pod))
        changes = [('status.state', 'SANDBOX_NOTREADY'), ('status.metadata.uid', 'other'),
                   ('status.metadata.name', 'other'), ('status.metadata.namespace', 'other'),
                   ('status.network.ip', 'fd00::3'), ('status.id', '../anything'),
                   ('status.linux.namespaces.options.network', 'NODE'),
                   ('info.processStatus', 'stopped'), ('info.netNamespaceClosed', True),
                   ('info.pid', 1), ('info.pid', True), ('info.pid', '100')]
        for path, value in changes:
            with self.subTest(path=path, value=value):
                data = deepcopy(valid); target = data
                for part in path.split('.')[:-1]: target = target[part]
                target[path.split('.')[-1]] = value
                with self.assertRaises(ValueError): Sandbox.from_status(data, pod)

    def test_unknown_runtime_shape_rejected(self):
        for data in ({}, {'status': {}, 'info': {}}, {'status': None, 'info': None}):
            with self.assertRaises(ValueError):
                Sandbox.from_status(data, policy().select(pod_item()))

    def test_process_start_parses_parentheses_in_comm_and_rejects_zombies(self):
        with tempfile.TemporaryDirectory() as path:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for state in ('S', 'Z'):
                    with open(path + '/stat', 'w') as stream:
                        stream.write('100 (odd ) process) ' + state + ' ' + ' '.join(['0'] * 18) + ' 12345')
                    if state == 'S': self.assertEqual(process_start(fd), 12345)
                    else:
                        with self.assertRaises(ValueError): process_start(fd)
            finally: os.close(fd)


class FakeNamespace:
    def __init__(self, sandbox, generation):
        self.key = (sandbox, generation)
        self.closed = False
        self.opened = []
        self.fail = False

    def verify(self):
        if self.fail: raise ValueError('reused process')

    def open_sockets(self):
        self.opened = [SimpleNamespace(closed=False)]
        def close(): self.opened[0].closed = True
        self.opened[0].close = close
        return tuple(self.opened)

    def close(self): self.closed = True


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.now, self.generation = 100., 1
        self.pod = policy().select(pod_item())
        self.sandbox = Sandbox('a' * 64, 100, self.pod)
        self.pins = []
        self.broker = Broker(policy(), lambda pod: self.sandbox, pin=self.pin, clock=lambda: self.now)
        self.addCleanup(self.broker.close)

    def pin(self, sandbox):
        value = FakeNamespace(sandbox, self.generation)
        self.pins.append(value)
        return value

    def install(self, observed_at=None):
        self.broker.reconcile([pod_item()], observed_at=self.now if observed_at is None else observed_at)
        return self.broker.leases.get(self.pod.uid)

    def test_fresh_observation_renews_without_reopening(self):
        first = self.install()
        self.now += 10
        self.assertIs(self.install(), first)
        self.assertEqual(first.deadline, 140)
        self.assertEqual(self.broker.events['opened'], 1)
        self.assertTrue(self.pins[-1].closed)

    def test_cached_observation_cannot_extend_lease(self):
        first = self.install()
        self.now += 10
        self.install(observed_at=100)
        self.assertEqual(first.deadline, 130)
        self.now = 130
        self.broker.expire()
        self.assertEqual(self.broker.leases, {})
        self.assertTrue(first.sockets[0].closed)

    def test_invalid_observation_does_not_renew(self):
        first = self.install()
        for observed in (99, 101, float('nan'), float('inf'), True):
            with self.assertRaises(ValueError): self.install(observed)
        self.now = 130
        with self.assertRaises(ValueError): self.install(100)
        self.assertTrue(first.sockets[0].closed)

    def test_deletion_opt_out_and_policy_removal_revoke(self):
        for mode in ('deleted', 'opt-out', 'policy'):
            with self.subTest(mode=mode):
                self.broker.policy = policy()
                first = self.install()
                items = [pod_item()]
                if mode == 'deleted': items = []
                elif mode == 'opt-out': items[0]['metadata']['labels'][OPT_IN] = 'false'
                else: self.broker.policy = PodPolicy('node-1', [])
                self.broker.reconcile(items, observed_at=self.now)
                self.assertTrue(first.sockets[0].closed)
                self.assertEqual(self.broker.leases, {})

    def test_runtime_process_namespace_or_interface_change_replaces(self):
        first = self.install()
        self.generation += 1
        second = self.install()
        self.assertIsNot(first, second)
        self.assertTrue(first.sockets[0].closed)
        self.sandbox = replace(self.sandbox, id='b' * 64, pid=200)
        third = self.install()
        self.assertIsNot(second, third)
        self.assertTrue(second.sockets[0].closed)

    def test_runtime_loss_rejects_existing_lease(self):
        first = self.install()
        def unavailable(pod): raise OSError('runtime unavailable')
        self.broker.inspect = unavailable
        self.assertIsNone(self.install())
        self.assertTrue(first.sockets[0].closed)

    def test_sandbox_replacement_during_open_never_installs(self):
        calls = iter([self.sandbox, replace(self.sandbox, id='b' * 64)])
        self.broker.inspect = lambda pod: next(calls)
        self.assertIsNone(self.install())
        self.assertTrue(self.pins[-1].opened[0].closed)
        self.assertTrue(self.pins[-1].closed)

    def test_slow_verification_cannot_extend_deadline(self):
        def slow(pod):
            self.now += 16
            return self.sandbox
        self.broker.inspect = slow
        self.assertIsNone(self.install(100))
        self.assertTrue(self.pins[-1].opened[0].closed)

    def test_duplicate_incomplete_or_over_capacity_snapshot_fails_closed(self):
        for items in ([pod_item(), pod_item()], [None], {'items': [pod_item()]}):
            first = self.install()
            with self.assertRaises(ValueError): self.broker.reconcile(items, observed_at=self.now)
            self.assertTrue(first.sockets[0].closed)
        first = self.install()
        self.broker.capacity = 1
        second = pod_item(); second['metadata']['uid'] = 'another'
        with self.assertRaises(ValueError):
            self.broker.reconcile([pod_item(), second], observed_at=self.now)
        self.assertTrue(first.sockets[0].closed)

    def test_proc_recheck_failure_cleans_new_sockets(self):
        original = self.pin
        def failed(sandbox):
            value = original(sandbox); value.fail = True
            return value
        self.broker.pin = failed
        self.assertIsNone(self.install())
        self.assertTrue(self.pins[-1].opened[0].closed)

    def test_shutdown_error_still_revokes_other_sockets_and_leases(self):
        closed = []
        def fail(): raise OSError('shutdown failed')
        def resource(name): return SimpleNamespace(close=lambda: closed.append(name))
        self.broker.leases = {
            'one': Lease(None, resource('ns-one'), (SimpleNamespace(close=fail), resource('ipv6')), 130),
            'two': Lease(None, resource('ns-two'), (resource('second-pod'),), 130),
        }
        with self.assertRaises(ExceptionGroup): self.broker.close()
        self.assertEqual(closed, ['ipv6', 'ns-one', 'second-pod', 'ns-two'])
        self.assertEqual(self.broker.leases, {})
