"""Response wire semantics, dependency expiry and the pod identity boundary."""

from copy import deepcopy
from datetime import timedelta
import unittest

import dns.flags
import dns.message
import dns.rdata
import dns.rdatatype as rt
import dns.rrset

from discovery.catalog import Catalog, SourcePolicy
from discovery.query import parse_pod_query
from discovery.records import PublicationPolicy
from discovery.responder import Responder
from test_catalog import NOW, encode, fixture, policy, stamp
from test_query import query


def read(reply):
    return dns.message.from_wire(reply.wire, one_rr_per_rrset=True)


def contents(message):
    return message.answer + message.additional


def typed_data(rrset):
    data = rrset[0].to_wire()
    return dns.rdata.from_wire(1, rrset.rdtype, data, 0, len(data))


class ResponderTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()
        self.catalog = Catalog(policy())
        self.responder = Responder(self.catalog)
        self.install()

    def install(self):
        self.catalog.install(encode(self.data), now=NOW, monotonic=100)
        self.publication = PublicationPolicy(
            frozenset(r['id'] for r in self.data['records']),
            frozenset((r['name'], rt.from_text(r['type'])) for r in self.data['records']
                      if r['type'] != 'PTR'))

    def build(self, message=None, offset=0, **kwargs):
        return self.responder.build(parse_pod_query((query() if message is None else message).to_wire()),
                                    policy=kwargs.pop('policy', self.publication),
                                    now=NOW + timedelta(seconds=offset), monotonic=100 + offset,
                                    source_port=kwargs.pop('source_port', 5353),
                                    family=kwargs.pop('family', 6), **kwargs)

    def test_multicast_service_answer_has_dependencies_and_no_questions(self):
        result = self.build()
        self.assertEqual(result.misses, ())
        self.assertEqual(len(result.replies), 1)
        reply = result.replies[0]
        message = read(reply)
        self.assertEqual(reply.destination, 'multicast')
        self.assertEqual(message.id, 0)
        self.assertEqual(message.flags, dns.flags.QR | dns.flags.AA)
        self.assertEqual(message.question, [])
        self.assertEqual([r.rdtype for r in message.answer], [rt.PTR])
        self.assertEqual({r.rdtype for r in message.additional}, {rt.SRV, rt.TXT, rt.A, rt.AAAA})
        for record in contents(message):
            self.assertEqual(record.rdclass, 1 if record.rdtype == rt.PTR else 0x8001)
            self.assertEqual(record.ttl, 30)
        srv = typed_data(next(r for r in message.additional if r.rdtype == rt.SRV))
        self.assertEqual((srv.port, srv.target.to_text()), (6053, 'sensor.local.'))

    def test_only_explicit_export_authority_can_answer(self):
        self.assertEqual(self.build(policy=PublicationPolicy(frozenset())).replies, ())
        shared = self.build(policy=PublicationPolicy(self.publication.record_ids))
        self.assertTrue(shared.replies)
        self.assertTrue(all(r.rdclass == 1 for r in contents(read(shared.replies[0]))))

    def test_native_addresses_and_any_matching_are_case_insensitive(self):
        for kind, expected in [('A', {rt.A}), ('AAAA', {rt.AAAA}), ('ANY', {rt.A, rt.AAAA})]:
            with self.subTest(kind=kind):
                result = self.build(query('SeNsOr.LoCaL.', kind))
                self.assertEqual({r.rdtype for r in read(result.replies[0]).answer}, expected)
                self.assertEqual(read(result.replies[0]).additional, [])

    def test_service_enumeration_and_subtype(self):
        result = self.build(query('_services._dns-sd._udp.local.'))
        self.assertEqual(len(read(result.replies[0]).answer), 1)
        self.assertEqual(read(result.replies[0]).additional, [])
        subtype = deepcopy(self.data['records'][1])
        subtype.update(id='subtype', name='_sensor._sub._esphomelib._tcp.local.')
        self.data['records'].append(subtype)
        self.data['revision'] += 1
        self.install()
        result = self.build(query(subtype['name']))
        self.assertEqual(len(read(result.replies[0]).additional), 4)

    def test_enumeration_survives_unresolved_instances_without_inventing_types(self):
        self.data['records'] = self.data['records'][:1]
        self.data['records'][0]['expires_at'] = stamp(5)
        self.data['revision'] += 1
        self.install()
        request = query('_services._dns-sd._udp.local.')
        result = self.build(request, offset=1)
        message = read(result.replies[0])
        self.assertEqual(typed_data(message.answer[0]).target.to_text(), '_esphomelib._tcp.local.')
        self.assertEqual(message.answer[0].ttl, 4)
        self.assertEqual(message.additional, [])
        self.assertEqual(self.build().replies, ())
        self.assertEqual(self.build(request, offset=5).replies, ())

    def test_enumeration_rejects_targets_that_are_not_service_types(self):
        for target in ['sensor.local.', '_x._sub._http._tcp.local.', '_x._sctp.local.']:
            with self.subTest(target=target):
                self.data['records'] = [fixture()['records'][0] | {'data': target}]
                self.data['revision'] += 1
                self.install()
                self.assertEqual(self.build(query('_services._dns-sd._udp.local.')).replies, ())

    def test_legacy_types_escaped_instances_and_opaque_txt_roundtrip(self):
        for revision, (kind, instance) in enumerate([
                ('_presence_olpc', r'Living\032Room'), ('_private-service', r'Caf\195\169')], start=2):
            with self.subTest(kind=kind, instance=instance):
                self.data = fixture()
                self.data['revision'] = revision
                for record in self.data['records']:
                    for field in ('name', 'data'):
                        record[field] = record[field].replace('_esphomelib', kind).replace('Sensor.', instance + '.')
                self.install()
                message = read(self.build(query(f'{kind}._tcp.local.')).replies[0])
                self.assertEqual(typed_data(message.answer[0]).target.to_text(), f'{instance}.{kind}._tcp.local.')
                txt = typed_data(next(r for r in message.additional if r.rdtype == rt.TXT))
                self.assertEqual(txt.strings, (b'name=Sensor', b'opaque=\xff\x00'))

    def test_legacy_reply_uses_transaction_questions_ttl_and_no_flush(self):
        request = query('Sensor._esphomelib._tcp.local.', 'SRV')
        request.id = 4321
        request.flags = dns.flags.RD
        result = self.build(request, source_port=45000)
        reply = result.replies[0]
        message = read(reply)
        self.assertEqual(reply.destination, 'peer')
        self.assertEqual(message.id, 4321)
        self.assertEqual(message.question, request.question)
        self.assertEqual(message.flags, dns.flags.QR | dns.flags.AA | dns.flags.RD)
        self.assertTrue(all(r.ttl == 10 and r.rdclass == 1 for r in contents(message)))
        # SRV target is uncompressed, including in the legacy reply.
        srv_wire = typed_data(message.answer[0]).to_wire()
        self.assertIn(srv_wire, reply.wire)

    def test_qu_requires_actual_recent_multicast_per_family(self):
        request = query('sensor.local.', 'AAAA')
        request.question[0].rdclass = 0x8001
        first = self.build(request)
        self.assertEqual(first.replies[0].destination, 'multicast')
        # Building a response, or a failed send, must not update history.
        self.assertEqual(self.build(request, offset=1).replies[0].destination, 'multicast')
        self.responder.note_sent(first.replies[0], monotonic=100)
        self.assertEqual(self.build(request, offset=2).replies[0].destination, 'peer')
        self.assertEqual(self.build(request, offset=2, family=4).replies[0].destination, 'multicast')
        self.assertEqual(self.build(request, offset=8).replies[0].destination, 'multicast')

    def test_mixed_qm_qu_only_sends_the_answer_once(self):
        request = query('sensor.local.', 'AAAA')
        self.responder.note_sent(self.build(request).replies[0], monotonic=100)
        qu = query('sensor.local.', 'AAAA').question[0]
        qu.rdclass = 0x8001
        request.question.append(qu)
        result = self.build(request, offset=1)
        self.assertEqual(len(result.replies), 1)
        self.assertEqual(result.replies[0].destination, 'multicast')

    def test_direct_unicast_uses_qu_rules(self):
        request = query('sensor.local.', 'AAAA')
        first = self.build(request, direct_unicast=True)
        self.responder.note_sent(first.replies[0], monotonic=100)
        self.assertEqual(self.build(request, offset=1, direct_unicast=True).replies[0].destination, 'peer')

    def test_known_answer_half_ttl_threshold_and_case_canonicalization(self):
        for ttl, suppressed in [(14, False), (15, True), (30, True)]:
            with self.subTest(ttl=ttl):
                request = query()
                request.answer.append(dns.rrset.from_text('_ESPHOMELIB._tcp.local.', ttl, 'IN', 'PTR',
                                                          'SENSOR._esphomelib._tcp.local.'))
                result = self.build(request)
                self.assertEqual(result.replies == (), suppressed)
                self.assertEqual(result.misses, ())

    def test_pod_records_never_become_answers_or_catalog_updates(self):
        request = query()
        request.answer.append(dns.rrset.from_text('private-pod.local.', 120, 'IN', 'AAAA',
                                                  '2001:db8:1000:f000::42'))
        request.additional.append(dns.rrset.from_text('private-pod.local.', 120, 'IN', 'TXT',
                                                      '"secret=identity"'))
        original = self.catalog.snapshot
        result = self.build(request)
        for reply in result.replies:
            self.assertNotIn(b'private-pod', reply.wire)
            self.assertNotIn(b'secret', reply.wire)
        self.assertIs(self.catalog.snapshot, original)
        self.assertEqual(self.build(query('private-pod.local.', 'AAAA')).replies, ())

    def test_legacy_does_not_use_known_answer_suppression(self):
        request = query('sensor.local.', 'AAAA')
        request.answer.append(dns.rrset.from_text('sensor.local.', 120, 'IN', 'AAAA',
                                                  '2001:db8:1000:22::42'))
        self.assertTrue(self.build(request, source_port=45000).replies)

    def test_missing_records_produce_misses_without_negative_answers(self):
        for request in [query('missing.local.', 'A'), query('sensor.local.', 'NSEC')]:
            result = self.build(request)
            self.assertEqual(result.replies, ())
            self.assertEqual(len(result.misses), 1)

    def test_expiry_is_rechecked_at_send_time(self):
        self.assertTrue(self.build().replies)
        self.assertEqual(self.build(offset=30).replies, ())

    def test_missing_or_expired_dependencies_withhold_instances_but_not_types(self):
        self.data['records'][2]['expires_at'] = stamp(5)
        self.data['revision'] += 1
        self.install()
        result = self.build(offset=1)
        self.assertTrue(all(r.ttl <= 4 for r in read(result.replies[0]).answer))
        for request in [query(),
                        query('Sensor._esphomelib._tcp.local.', 'TXT')]:
            self.assertEqual(self.build(request, offset=5).replies, ())
        self.assertTrue(self.build(query('_services._dns-sd._udp.local.'), offset=5).replies)
        self.assertTrue(self.build(query('sensor.local.', 'AAAA'), offset=5).replies)

    def test_local_conflict_blocks_dependent_service_without_claim_export(self):
        denied = PublicationPolicy(self.publication.record_ids, self.publication.unique_rrsets,
                                   frozenset({'sensor.local.'}))
        self.assertEqual(self.build(policy=denied).replies, ())
        self.assertEqual(self.build(query('sensor.local.', 'AAAA'), policy=denied).replies, ())

    def test_cross_link_host_collision_withholds_service_chain(self):
        other = deepcopy(self.data['records'][-1])
        other.update(id='other-host', source_link='vlan55', data='2001:db8:1000:55::42')
        self.data['records'].append(other)
        scopes = SourcePolicy({'vlan22': ('10.22.0.0/24', '2001:db8:1000:22::/64'),
                               'vlan55': ('2001:db8:1000:55::/64',)}, ())
        self.catalog = Catalog(scopes)
        self.responder = Responder(self.catalog)
        self.install()
        self.assertEqual(self.build().replies, ())
        self.assertEqual(self.build(query('sensor.local.', 'AAAA')).replies, ())

    def test_duplicate_evidence_uses_shortest_validity(self):
        duplicate = deepcopy(self.data['records'][2])
        duplicate.update(id='srv-short', expires_at=stamp(3))
        self.data['records'].append(duplicate)
        self.data['revision'] += 1
        self.install()
        self.assertTrue(all(r.ttl <= 3 for r in read(self.build().replies[0]).answer))

    def test_unique_rrset_known_answer_does_not_create_partial_flush(self):
        extra = deepcopy(self.data['records'][-1])
        extra.update(id='v6-extra', data='2001:db8:1000:22::43')
        self.data['records'].append(extra)
        self.data['revision'] += 1
        self.install()
        request = query('sensor.local.', 'AAAA')
        request.answer.append(dns.rrset.from_text('sensor.local.', 120, 'IN', 'AAAA',
                                                  '2001:db8:1000:22::42'))
        result = self.build(request)
        self.assertEqual(len(read(result.replies[0]).answer), 2)

    def test_oversized_record_is_withheld_without_partial_multicast(self):
        self.data['records'][3]['data'] = ' '.join('"' + 'x' * 200 + '"' for _ in range(10))
        self.data['revision'] += 1
        self.install()
        result = self.build(budget=512)
        self.assertTrue(result.oversized)
        self.assertEqual(result.replies, ())

    def test_legacy_answer_overflow_sets_tc_within_512_bytes(self):
        self.data['records'][3]['data'] = ' '.join('"' + 'x' * 200 + '"' for _ in range(4))
        self.data['revision'] += 1
        self.install()
        result = self.build(query('Sensor._esphomelib._tcp.local.', 'TXT'), source_port=45000)
        self.assertLessEqual(len(result.replies[0].wire), 512)
        self.assertTrue(read(result.replies[0]).flags & dns.flags.TC)

    def test_invalid_socket_metadata_and_budget_rejected(self):
        for kwargs in [{'source_port': 0}, {'source_port': True}, {'family': 7},
                       {'budget': 511}, {'budget': 9000}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.build(**kwargs)

    def add_services(self, count):
        for number in range(count):
            instance = f'Sensor-{number}-with-a-long-instance-name._esphomelib._tcp.local.'
            for index in (1, 2, 3):
                record = deepcopy(self.data['records'][index])
                record['id'] = f'extra-{number}-{index}'
                if index == 1:
                    record['data'] = instance
                else:
                    record['name'] = instance
                self.data['records'].append(record)
        self.data['revision'] += 1
        self.install()

    def test_multicast_packet_splitting_keeps_qr_and_clears_tc(self):
        self.add_services(5)
        result = self.build(budget=512)
        self.assertFalse(result.oversized)
        self.assertGreater(len(result.replies), 1)
        ptrs = []
        for reply in result.replies:
            self.assertLessEqual(len(reply.wire), 512)
            message = read(reply)
            self.assertEqual(message.flags, dns.flags.QR | dns.flags.AA)
            self.assertEqual(message.question, [])
            ptrs.extend(r for r in message.answer if r.rdtype == rt.PTR)
        self.assertEqual(len(ptrs), 6)

    def test_packet_count_budget_withholds_entire_plan(self):
        self.add_services(80)
        result = self.build(budget=512)
        self.assertTrue(result.oversized)
        self.assertEqual(result.replies, ())

    def test_unique_rrset_does_not_split_between_multicast_and_unicast(self):
        request = query('sensor.local.', 'AAAA')
        self.responder.note_sent(self.build(request).replies[0], monotonic=100)
        extra = deepcopy(self.data['records'][-1])
        extra.update(id='v6-extra', data='2001:db8:1000:22::43')
        self.data['records'].append(extra)
        self.data['revision'] += 1
        self.install()
        request.question[0].rdclass = 0x8001
        result = self.build(request, offset=1)
        self.assertEqual(len(result.replies), 1)
        self.assertEqual(result.replies[0].destination, 'multicast')
        self.assertEqual(len(read(result.replies[0]).answer), 2)

    def test_oversized_unique_rrset_is_not_partially_flushed(self):
        for number in range(20):
            record = deepcopy(self.data['records'][-1])
            record.update(id=f'address-{number}', data=f'2001:db8:1000:22::{number + 100:x}')
            self.data['records'].append(record)
        self.data['revision'] += 1
        self.install()
        result = self.build(query('sensor.local.', 'AAAA'), budget=512)
        self.assertTrue(result.oversized)
        self.assertEqual(result.replies, ())

    def test_multicast_record_throttle_survives_different_questions(self):
        first = self.build()
        self.responder.note_sent(first.replies[0], monotonic=100)
        for request in (query(), query('sensor.local.', 'AAAA'), query('Sensor._esphomelib._tcp.local.', 'SRV')):
            request.id = 999
            self.assertEqual(self.build(request, offset=.5).replies, ())
            self.assertEqual(self.build(request, offset=.5).misses, ())
        self.assertTrue(self.build(offset=.5, family=4).replies)
        self.assertTrue(self.build(offset=1).replies)

    def test_throttle_does_not_block_legacy_or_recent_qu_unicast(self):
        request = query('sensor.local.', 'AAAA')
        self.responder.note_sent(self.build(request).replies[0], monotonic=100)
        self.assertEqual(self.build(request, offset=.2, source_port=40000).replies[0].destination, 'peer')
        request.question[0].rdclass = 0x8001
        self.assertEqual(self.build(request, offset=.2).replies[0].destination, 'peer')

    def test_recent_unique_member_withholds_whole_rrset(self):
        first = self.build(query('sensor.local.', 'AAAA'))
        self.responder.note_sent(first.replies[0], monotonic=100)
        record = deepcopy(self.data['records'][-1])
        record.update(id='second-address', data='2001:db8:1000:22::43')
        self.data['records'].append(record); self.data['revision'] += 1
        self.install()
        self.assertEqual(self.build(query('sensor.local.', 'AAAA'), offset=.5).replies, ())
        result = self.build(query('sensor.local.', 'AAAA'), offset=1)
        self.assertEqual(len(read(result.replies[0]).answer), 2)

    def test_recent_optional_additional_is_omitted_without_partial_flush(self):
        self.responder.note_sent(self.build(query('sensor.local.', 'AAAA')).replies[0], monotonic=100)
        result = self.build(offset=.5)
        self.assertTrue(result.replies)
        self.assertNotIn(rt.AAAA, {r.rdtype for r in read(result.replies[0]).additional})

    def test_unfinished_query_cannot_be_answered(self):
        request = query(); request.flags |= dns.flags.TC
        parsed = parse_pod_query(request.to_wire(), allow_continuation=True)
        with self.assertRaises(ValueError):
            self.responder.build(parsed, policy=self.publication, now=NOW, monotonic=100, source_port=5353, family=6)


if __name__ == '__main__':
    unittest.main()
