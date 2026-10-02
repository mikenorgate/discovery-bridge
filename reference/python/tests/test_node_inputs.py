"""Read-only CLI contracts, bounded subprocesses and complete fresh Pod lists."""
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

from discovery.node_inputs import CommandError, Containerd, KubernetesPods, read_json
from discovery.node_runtime import load
from test_broker import pod_item, policy, runtime_status

CONFIG = {'clusters': [{'cluster': {'server': 'https://kubernetes.test'}}]}


class InputTests(unittest.TestCase):
    def test_kubernetes_uses_verified_https_and_node_selector(self):
        calls = []
        def run(argv):
            calls.append(argv)
            return CONFIG if 'config' in argv else {'kind': 'PodList', 'apiVersion': 'v1', 'items': [pod_item()]}
        client = KubernetesPods('node-1', ['/usr/bin/kubectl'], '/config/kubeconfig', run=run)
        start = time.monotonic()
        items, observed_at = client.snapshot()
        self.assertEqual(items, [pod_item()])
        self.assertGreaterEqual(observed_at, start)
        self.assertIn('--raw=/api/v1/pods?fieldSelector=spec.nodeName%3Dnode-1', calls[-1])
        self.assertIn('--insecure-skip-tls-verify=false', calls[-1])
        self.assertNotIn('--raw', calls[0])

    def test_plaintext_or_insecure_kubernetes_config_is_rejected(self):
        for cluster in ({'server': 'http://kubernetes.test'}, {'server': 'https://kubernetes.test', 'insecure-skip-tls-verify': True}):
            client = KubernetesPods('node-1', ['/usr/bin/kubectl'], '/config', run=lambda argv: {'clusters': [{'cluster': cluster}]})
            with self.assertRaises(ValueError): client.snapshot()

    def test_partial_malformed_and_foreign_node_snapshots_rejected(self):
        foreign = pod_item(); foreign['spec']['nodeName'] = 'node-2'
        for change in ({'metadata': {'continue': 'next'}}, {'items': [foreign]}, {'items': [None]},
                       {'items': {}}, {'items': [pod_item()] * 4097}, {'kind': 'SecretList'}):
            def run(argv):
                return CONFIG if 'config' in argv else {'kind': 'PodList', 'apiVersion': 'v1', 'items': []} | change
            with self.assertRaises(ValueError):
                KubernetesPods('node-1', ['/usr/bin/kubectl'], '/config', run=run).snapshot()

    def test_runtime_only_lists_and_inspects_exact_ready_sandbox(self):
        calls = []
        def run(argv):
            calls.append(argv)
            return {'items': [runtime_status()['status']]} if 'pods' in argv else runtime_status()
        result = Containerd(['/usr/bin/k3s', 'crictl'], 'unix:///run/containerd.sock', run=run).inspect(policy().select(pod_item()))
        self.assertEqual(result.pid, 100)
        self.assertIn('--state=ready', calls[0])
        self.assertEqual(calls[1][-3:], ('inspectp', '--output=json', 'a' * 64))

    def test_runtime_missing_ambiguous_and_replaced_sandbox_rejected(self):
        for items in ([], [runtime_status()['status']] * 2, [{'id': '../x', 'metadata': {'uid': 'pod-uid'}}]):
            with self.assertRaises(ValueError):
                Containerd(['/usr/bin/crictl'], 'unix:///run/c.sock', run=lambda argv: {'items': items}).inspect(policy().select(pod_item()))
        def replaced(argv):
            value = runtime_status()
            if 'pods' in argv: return {'items': [value['status']]}
            value['status']['id'] = 'b' * 64
            return value
        with self.assertRaises(ValueError):
            Containerd(['/usr/bin/crictl'], 'unix:///run/c.sock', run=replaced).inspect(policy().select(pod_item()))

    def test_operator_endpoints_must_be_explicit(self):
        with self.assertRaises(ValueError): KubernetesPods('bad,node=x', ['/usr/bin/kubectl'], '/config')
        with self.assertRaises(ValueError): KubernetesPods('node-1', ['kubectl'], '/config')
        with self.assertRaises(ValueError): Containerd(['/usr/bin/crictl'], 'tcp://localhost:1234')

    def test_command_timeout_keeps_expiry_running(self):
        calls = []
        with self.assertRaises(CommandError):
            read_json([sys.executable, '-c', 'import time; time.sleep(5)'], timeout=.2, tick=lambda: calls.append(time.monotonic()))
        self.assertGreaterEqual(len(calls), 3)

    def test_command_output_and_failures_do_not_expose_payloads(self):
        for source in ('print("private" * 100)', 'import sys; print("private"); sys.exit(1)'):
            with self.assertRaises(CommandError) as caught:
                read_json([sys.executable, '-c', source], limit=100)
            self.assertNotIn('private', str(caught.exception))
        self.assertEqual(read_json([sys.executable, '-c', 'print("{}")']), {})

    def test_disabled_config_and_root_worker_rejected(self):
        with tempfile.TemporaryDirectory() as path:
            file = path + '/config.json'
            candidate = json.loads((Path(__file__).parents[1] / 'node_candidate/config.disabled.json').read_text())
            for value in (candidate, candidate | {'enabled': True, 'worker_uid': 0}, {'enabled': True}):
                with open(file, 'w') as stream: json.dump(value, stream)
                with self.assertRaises(ValueError): load(file)
