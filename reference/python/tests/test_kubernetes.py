"""Service exposure, source ownership and independent publication lease regressions."""
import copy
from datetime import datetime, timedelta, timezone
import unittest

import dns.rdatatype as rt

from discovery.catalog import SourcePolicy
from discovery.feed import encode
from discovery.kubernetes import ServiceIntent, PublicationAPI, records, service_intent, SOURCE, VIP_POOL
from discovery.kubernetes_publisher import KubernetesServices

NOW = datetime(2026, 9, 30, tzinfo=timezone.utc)
SELECTED = {'namespace': 'services', 'name': 'example', 'port': 'http', 'type': '_http._tcp',
            'instance': 'Example web', 'txt': {'path': '/'}, 'subtypes': ['test']}
SERVICE = {'apiVersion': 'v1', 'kind': 'Service',
           'metadata': {'namespace': 'services', 'name': 'example', 'uid': 'service-uid', 'resourceVersion': '10'},
           'spec': {'type': 'LoadBalancer', 'ports': [{'name': 'http', 'protocol': 'TCP', 'port': 80, 'targetPort': 3000}],
                    'clusterIP': '2001:db8:1000:e000::10'},
           'status': {'loadBalancer': {'ingress': [{'ip': '2001:db8:1000:ff00::22', 'ipMode': 'VIP'}]}}}
SLICE = {'metadata': {'namespace': 'services', 'name': 'slice',
                     'labels': {'kubernetes.io/service-name': 'example'},
                     'ownerReferences': [{'kind': 'Service', 'uid': 'service-uid', 'controller': True}]},
         'addressType': 'IPv6', 'ports': [{'name': 'http', 'port': 3000, 'protocol': 'TCP'}],
         'endpoints': [{'addresses': ['2001:db8:1000:f004::123'],
                        'conditions': {'ready': True, 'serving': True, 'terminating': False}}]}


def intent():
    return service_intent(copy.deepcopy(SERVICE), [copy.deepcopy(SLICE)], copy.deepcopy(SELECTED))


def payload(services=None, issued=NOW):
    return encode({'schema': 1, 'issued_at': issued.isoformat(),
                   'valid_until': (issued + timedelta(seconds=15)).isoformat(),
                   'services': [intent()] if services is None else services})


class ExposureTests(unittest.TestCase):
    def test_only_vip_and_service_port_are_exposed(self):
        value = intent()
        self.assertEqual(value['addresses'], ['2001:db8:1000:ff00::22'])
        self.assertEqual(value['service_port'], 80)
        text = encode(value).decode()
        self.assertNotIn(SLICE['endpoints'][0]['addresses'][0], text)
        self.assertNotIn(SERVICE['spec']['clusterIP'], text)

    def test_readiness_terminating_missing_and_wrong_slice_owner(self):
        for conditions in ({}, {'ready': False}, {'ready': True, 'serving': False}, {'ready': True, 'terminating': True}):
            value = copy.deepcopy(SLICE);value['endpoints'][0]['conditions'] = conditions
            self.assertIsNone(service_intent(SERVICE, [value], SELECTED))
        for change in ('owner', 'namespace', 'port', 'family', 'deleted'):
            value = copy.deepcopy(SLICE)
            if change == 'owner':value['metadata']['ownerReferences'][0]['uid'] = 'old-uid'
            if change == 'namespace':value['metadata']['namespace'] = 'foreign'
            if change == 'port':value['ports'][0]['name'] = 'other'
            if change == 'family':value['addressType'] = 'IPv4'
            if change == 'deleted':value['metadata']['deletionTimestamp'] = NOW.isoformat()
            self.assertIsNone(service_intent(SERVICE, [value], SELECTED), change)

    def test_unexposed_unready_and_hostname_or_backend_targets_are_not_published(self):
        for change in ('type', 'deleted', 'port', 'unready', 'proxy', 'hostname', 'pod', 'cluster'):
            value = copy.deepcopy(SERVICE)
            if change == 'type':value['spec']['type'] = 'ClusterIP'
            if change == 'deleted':value['metadata']['deletionTimestamp'] = NOW.isoformat()
            if change == 'port':value['spec']['ports'][0]['protocol'] = 'UDP'
            if change == 'unready':value['spec']['publishNotReadyAddresses'] = True
            if change == 'proxy':value['status']['loadBalancer']['ingress'][0]['ipMode'] = 'Proxy'
            if change == 'hostname':value['status']['loadBalancer']['ingress'] = [{'hostname': 'node.local'}]
            if change in ('pod', 'cluster'):
                value['status']['loadBalancer']['ingress'][0]['ip'] = ('2001:db8:1000:f004::123' if change == 'pod' else value['spec']['clusterIP'])
            self.assertIsNone(service_intent(value, [SLICE], SELECTED), change)

    def test_complete_chain_unicode_subtype_and_stable_uid_names(self):
        value = intent();value['instance'] = 'Web café . test'
        first = records([value], NOW + timedelta(seconds=15))
        self.assertEqual({r.type for r in first}, {rt.PTR, rt.SRV, rt.TXT, rt.AAAA})
        self.assertTrue(any(r.name == '_test._sub._http._tcp.local.' for r in first))
        self.assertTrue(any(r.name == '_services._dns-sd._udp.local.' for r in first))
        self.assertEqual(first, records([value], NOW + timedelta(seconds=15)))
        value['uid'] = 'recreated-uid'
        self.assertNotEqual({r.name for r in first if r.type == rt.SRV}, {r.name for r in records([value], NOW) if r.type == rt.SRV})

    def test_gateway_rejects_invalid_metadata_or_addresses(self):
        for change in ({'type': '_123._tcp'}, {'addresses': ['2001:db8:1000:f004::10']},
                       {'addresses': ['198.19.200.8']}, {'service_port': True}, {'uid': ''},
                       {'txt': {'bad=key': 'x'}}, {'txt': {'key': 'x' * 256}},
                       {'subtypes': ['foo', 'foo']}, {'instance': 'x' * 64}):
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                records([intent() | change], NOW)
        with self.assertRaises(ValueError):records([intent(), intent()], NOW)

    def test_shared_root_records_are_deduplicated(self):
        other = intent();other['name'] = 'another';other['uid'] = 'another-uid'
        result = records([intent(), other], NOW)
        self.assertEqual(sum(r.name == '_services._dns-sd._udp.local.' for r in result), 1)


class LeaseTests(unittest.TestCase):
    def test_expiry_replay_renewal_and_empty_withdrawal(self):
        state = ServiceIntent();state.install(payload(), now=NOW, monotonic=0)
        self.assertTrue(state.records(now=NOW, monotonic=0))
        state.install(payload(), now=NOW + timedelta(seconds=10), monotonic=10)
        self.assertFalse(state.records(now=NOW + timedelta(seconds=15), monotonic=15))
        state.install(payload(issued=NOW + timedelta(seconds=15)), now=NOW + timedelta(seconds=15), monotonic=15)
        self.assertTrue(state.records(now=NOW + timedelta(seconds=16), monotonic=16))
        state.install(payload([], issued=NOW + timedelta(seconds=17)), now=NOW + timedelta(seconds=17), monotonic=17)
        self.assertFalse(state.records(now=NOW + timedelta(seconds=17), monotonic=17))

    def test_stale_changed_replay_and_bad_snapshot_preserve_existing_deadline(self):
        state = ServiceIntent();state.install(payload(), now=NOW, monotonic=0)
        for body in (payload(issued=NOW-timedelta(seconds=1)), payload([]), b'{}', payload().replace(b'"schema":1', b'"schema":true')):
            with self.assertRaises(ValueError):state.install(body, now=NOW, monotonic=1)
        self.assertTrue(state.records(now=NOW+timedelta(seconds=14), monotonic=14))
        self.assertFalse(state.records(now=NOW+timedelta(seconds=15), monotonic=15))

    def test_wall_and_monotonic_clock_discontinuity_withholds(self):
        state = ServiceIntent();state.install(payload(), now=NOW, monotonic=10)
        self.assertFalse(state.records(now=NOW, monotonic=9))
        self.assertFalse(state.records(now=NOW+timedelta(seconds=5), monotonic=11))

    def test_new_source_does_not_admit_lan_vip_or_pod_addresses(self):
        policy = SourcePolicy({'lan': ('2001:db8:1000:1001::/64',), SOURCE: (VIP_POOL,)}, ())
        policy.check_address(SOURCE, '2001:db8:1000:ff00::22')
        with self.assertRaises(ValueError):policy.check_address('lan', '2001:db8:1000:ff00::22')
        with self.assertRaises(ValueError):policy.check_address(SOURCE, '2001:db8:1000:f004::22')


class InputTests(unittest.TestCase):
    def source(self, *, slices=None, changed=False):
        calls = []
        def run(argv):
            calls.append(argv)
            if 'config' in argv:return {'clusters': [{'cluster': {'server': 'https://fixture'}}]}
            if 'endpointslices' in argv[-1]:return slices if slices is not None else {'kind': 'EndpointSliceList', 'apiVersion': 'discovery.k8s.io/v1', 'items': [SLICE]}
            value = copy.deepcopy(SERVICE)
            if changed and len(calls) == 4:value['metadata']['resourceVersion'] = '11'
            return value
        result = KubernetesServices({'services': [SELECTED], 'kubectl': ['/usr/bin/kubectl'], 'kubeconfig': '/config'}, run=run)
        return result, calls

    def test_verified_read_only_service_and_slice_queries(self):
        source, calls = self.source();self.assertEqual(len(source.snapshot()['services']), 1)
        self.assertEqual(len(calls), 4)
        self.assertTrue(all('--insecure-skip-tls-verify=false' in c for c in calls))
        self.assertTrue(all('get' in c for c in calls[1:]))

    def test_paginated_or_racing_api_reads_fail_closed(self):
        for options in ({'changed': True}, {'slices': {'kind': 'EndpointSliceList', 'apiVersion': 'discovery.k8s.io/v1', 'items': [], 'metadata': {'continue': 'more'}}}):
            source, _ = self.source(**options)
            with self.assertRaises(ValueError):source.snapshot()

    def test_no_ready_endpoint_produces_empty_replacement(self):
        source, _ = self.source(slices={'kind': 'EndpointSliceList', 'apiVersion': 'discovery.k8s.io/v1', 'items': []})
        self.assertEqual(source.snapshot()['services'], [])


class APITests(unittest.IsolatedAsyncioTestCase):
    async def test_http_intent_to_translated_pod_answer_and_withdrawal(self):
        import socket
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from ipaddress import ip_address
        import dns.message
        from discovery.catalog import Catalog
        from discovery.collector import CollectorFeed, pod_view
        from discovery.feed import GatewayFeed, NodeFeed
        from discovery.gateway import GatewayAPI, GatewayClient, GatewayServer
        from discovery.lookup import LookupCoordinator
        from discovery.query import parse_pod_query
        from discovery.records import PublicationPolicy
        from discovery.responder import Responder
        from discovery.router_translation import Readiness

        with tempfile.TemporaryDirectory() as directory:
            policy = SourcePolicy({SOURCE: (VIP_POOL,)}, ())
            translation = Readiness(NOW, 0, maps={ip_address('2001:db8:1000:ff00::22'): ip_address('198.19.200.8')})
            feed = GatewayFeed(Catalog(policy), PublicationPolicy(frozenset()), Path(directory) / 'feed', translation=translation)
            self.addCleanup(feed.close)
            bridge = CollectorFeed(feed, None)
            bridge.browser = SimpleNamespace(healthy=True)
            state = ServiceIntent()
            lookups = LookupCoordinator({'lan-vlan1'}, bridge.demand)
            self.addAsyncCleanup(lookups.close)
            clients = []
            for api in (PublicationAPI(state, now=lambda: NOW, clock=lambda: 0),
                        GatewayAPI(feed, lookups, now=lambda: NOW, clock=lambda: 0)):
                server = GatewayServer(api, ['127.0.0.1/32'])
                listener = socket.socket()
                listener.bind(('127.0.0.1', 0)); listener.listen(8)
                await server.start(listener)
                self.addAsyncCleanup(server.close)
                clients.append(GatewayClient('127.0.0.1', listener.getsockname()[1], now=lambda: NOW, clock=lambda: 0))
            writer, reader = clients
            with self.assertRaisesRegex(ValueError, '404'):
                await reader.post(b'/v1/publications', payload(), expected=200)
            await writer.post(b'/v1/publications', payload(), expected=200)
            bridge.publish(pod_view(state.records(now=NOW, monotonic=0), now=NOW), now=NOW, monotonic=0)
            node = NodeFeed(policy)
            await reader.refresh(node)
            query = parse_pod_query(dns.message.make_query('_http._tcp.local.', 'PTR').to_wire())
            reply = Responder(node.catalog).build(query, policy=node.authority, now=NOW, monotonic=0, source_port=5353, family=6)
            message = dns.message.from_wire(reply.replies[0].wire)
            answers = [data for rrset in message.answer + message.additional for data in rrset]
            self.assertTrue(any(data.rdtype == rt.SRV and data.port == 80 for data in answers))
            self.assertTrue(any(data.rdtype == rt.TXT and b'path=/' in data.strings for data in answers))
            self.assertEqual({data.address for data in answers if data.rdtype in (rt.A, rt.AAAA)},
                             {'2001:db8:1000:ff00::22', '198.19.200.8'})
            feed.translation = Readiness(NOW, 0)
            await reader.refresh(node)
            self.assertFalse(any(r.type == rt.A for r, _ in node.catalog.records(now=NOW, monotonic=0)))
            expired = NOW + timedelta(seconds=16)
            expiry_node = NodeFeed(policy)
            await reader.refresh(expiry_node)
            self.assertFalse(expiry_node.catalog.records(now=expired, monotonic=16))
            bridge.publish(pod_view(state.records(now=expired, monotonic=16), now=expired), now=NOW, monotonic=0)
            await reader.refresh(node)
            self.assertFalse(node.catalog.records(now=NOW, monotonic=0))

    async def test_publication_listener_accepts_only_bounded_intent_route(self):
        state = ServiceIntent();api = PublicationAPI(state, now=lambda:NOW, clock=lambda:0)
        self.assertEqual((await api.handle(b'POST', b'/v1/publications', payload()))[0], 200)
        self.assertTrue(state.records(now=NOW, monotonic=0))
        self.assertEqual((await api.handle(b'POST', b'/v1/catalog', b'{}'))[0], 404)
        self.assertEqual((await api.handle(b'GET', b'/v1/publications', payload()))[0], 404)
        self.assertEqual((await api.handle(b'POST', b'/v1/publications', b'{}'))[0], 400)
        for _ in range(4):await api.handle(b'POST', b'/v1/publications', payload())
        self.assertEqual((await api.handle(b'POST', b'/v1/publications', payload()))[0], 429)
