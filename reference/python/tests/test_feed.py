"""Memory-only node feed, authenticated restart, atomic replacement and expiry."""
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest

import dns.rdatatype as rt

from discovery.catalog import Catalog
from discovery.feed import GatewayFeed, NodeFeed, encode
from discovery.records import PublicationPolicy
from test_catalog import NOW, fixture, policy, stamp


class FeedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.source = Catalog(policy())
        self.data = fixture()
        self.source.install(encode(self.data), now=NOW, monotonic=100)
        self.authority = PublicationPolicy(frozenset(r['id'] for r in self.data['records']),
            frozenset((r['name'], rt.from_text(r['type'])) for r in self.data['records'] if r['type'] != 'PTR'))
        self.gateway = GatewayFeed(self.source, self.authority, self.path / 'gateway.db')
        self.node = self.new_node()

    def tearDown(self):
        self.gateway.close()

    def new_node(self):
        return NodeFeed(policy())

    def envelope(self, offset=0, sources=frozenset({'vlan22'})):
        return json.loads(self.gateway.read(sources=sources,
            challenge=self.node.begin_request(), now=NOW + timedelta(seconds=offset), monotonic=100 + offset))

    def accept(self, value, offset=0, mono=None):
        return self.node.accept_catalog(encode(value), now=NOW + timedelta(seconds=offset),
                                             monotonic=100 + offset if mono is None else mono)

    def records(self, offset=0):
        return self.node.catalog.records(now=NOW + timedelta(seconds=offset), monotonic=100 + offset)

    def test_scoped_full_catalog_preserves_unique_service_chain(self):
        self.accept(self.envelope())
        self.assertEqual(len(self.records()), 6)
        self.assertEqual(len(self.node.authority.unique_rrsets), 4)
        self.accept(self.envelope(1, frozenset({'vlan55'})), 1)
        self.assertEqual(self.records(1), ())

    def test_gateway_heartbeats_cannot_renew_source_records(self):
        self.accept(self.envelope())
        self.accept(self.envelope(20), 20)
        self.assertEqual({ttl for _, ttl in self.records(29)}, {1})
        self.assertEqual(self.records(30), ())
        self.accept(self.envelope(31), 31)
        self.assertEqual(self.records(31), ())

    def test_invalid_snapshot_and_nonce_are_atomic(self):
        self.accept(self.envelope())
        previous = self.node.catalog
        for edit in (lambda v: v.update(nonce='0' * 64), lambda v: v.update(view='other'),
                     lambda v: v['snapshot']['records'][0].update(source_link='forbidden'),
                     lambda v: v.update(unique_rrsets=[['missing.local.', 1]]),
                     lambda v: v.update(unique_rrsets=[['a' * 64 + '.local.', 1]])):
            value = self.envelope(1)
            edit(value)
            with self.assertRaises(ValueError):
                self.accept(value, 1)
            self.assertIs(self.node.catalog, previous)

    def test_restart_is_empty_and_needs_fresh_authenticated_snapshot(self):
        previous = self.envelope()
        self.accept(previous)
        self.node = self.new_node()
        self.assertIsNone(self.node.catalog.snapshot)
        self.assertEqual(self.records(), ())
        self.node.begin_request()
        with self.assertRaises(ValueError):
            self.accept(previous, 1)  # last process's response has the wrong challenge
        self.accept(self.envelope(1), 1)
        self.assertEqual(len(self.records(1)), 6)
        self.assertFalse((self.path / 'node.db').exists())

    def test_generation_advances_durably_and_old_generation_is_denied(self):
        self.accept(self.envelope())
        old = self.gateway.generation
        self.gateway.close()
        self.gateway = GatewayFeed(self.source, self.authority, self.path / 'gateway.db')
        self.assertEqual(self.gateway.generation, old + 1)
        self.accept(self.envelope(1), 1)
        value = self.envelope(2)
        value['generation'] = old
        with self.assertRaises(ValueError):
            self.accept(value, 2)

    def test_only_one_gateway_owner(self):
        with self.assertRaises(BlockingIOError):
            GatewayFeed(self.source, self.authority, self.path / 'gateway.db')

    def test_revision_policy_and_ownership_rollback(self):
        self.gateway.policy_revision = 2
        self.accept(self.envelope())
        self.gateway.authority = PublicationPolicy(self.authority.record_ids - {'v6'}, self.authority.unique_rrsets)
        self.accept(self.envelope(1), 1)
        for edit in (lambda v: v['snapshot'].update(revision=1), lambda v: v.update(policy_revision=1),
                     lambda v: v['snapshot'].update(epoch='unexpected-boot'),
                     lambda v: v.update(unique_rrsets=[]),
                     lambda v: v['snapshot'].update(issued_at=stamp(0), valid_until=stamp(30))):
            value = self.envelope(1)
            edit(value)
            with self.assertRaises(ValueError):
                self.accept(value, 1)

    def test_replay_has_no_pending_challenge(self):
        value = self.envelope()
        self.accept(value)
        with self.assertRaises(ValueError):
            self.accept(value)
        self.node.begin_request()
        with self.assertRaises(ValueError):
            self.accept(value)

    def test_restart_does_not_remember_prior_authenticated_generation(self):
        self.gateway.generation = 2
        self.accept(self.envelope())
        self.gateway.generation = 1
        with self.assertRaises(ValueError):
            self.accept(self.envelope())
        self.node = self.new_node()
        # Deliberate tradeoff: the trusted gateway defines a new process's baseline.
        self.accept(self.envelope())
        self.assertEqual(self.node.generation, 1)
        self.assertEqual(len(self.records()), 6)

    def test_clock_discontinuity_fails_closed_until_fresh_bootstrap(self):
        self.accept(self.envelope())
        value = self.envelope(1)
        with self.assertRaises(ValueError):
            self.accept(value, 1, mono=120)
        self.assertEqual(self.records(1), ())
        self.accept(self.envelope(2), 2, mono=121)
        self.assertEqual(len(self.node.catalog.records(now=NOW + timedelta(seconds=2), monotonic=121)), 6)
