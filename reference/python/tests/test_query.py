"""Exercise the pod export boundary using actual DNS wire packets."""

import json
import struct
import unittest

import dns.flags
import dns.message
import dns.rrset

from discovery.query import parse_pod_query


def query(name='_esphomelib._tcp.local.', kind='PTR'):
    message = dns.message.make_query(name, kind)
    message.flags = 0
    return message


class PodQueryTests(unittest.TestCase):
    def test_questions_only_export_with_local_reply_metadata(self):
        message = query()
        message.id = 1234
        message.question[0].rdclass = 0x8001
        message.question.append(query('device.local.', 'AAAA').question[0])
        parsed = parse_pod_query(message.to_wire())
        self.assertEqual(parsed.transaction_id, 1234)
        self.assertEqual(parsed.unicast_requested, (True, False))
        self.assertEqual(parsed.lookup_payload(), {'schema': 1, 'questions': [
            {'name': '_esphomelib._tcp.local.', 'type': 12, 'class': 1},
            {'name': 'device.local.', 'type': 28, 'class': 1},
        ]})

    def test_known_answers_and_additional_pod_identity_never_export(self):
        message = query()
        message.answer.append(dns.rrset.from_text(
            'private-pod.local.', 120, 'IN', 'AAAA', '2001:db8:1000:f000::42'))
        message.additional.append(dns.rrset.from_text(
            'private-pod.local.', 120, 'IN', 'TXT', '"pod_uid=secret-identity"'))
        payload = parse_pod_query(message.to_wire()).lookup_payload()
        self.assertEqual(payload, parse_pod_query(query().to_wire()).lookup_payload())
        serialized = json.dumps(payload)
        for fragment in ['private-pod', 'f000', 'secret-identity', 'answer', 'additional']:
            self.assertNotIn(fragment, serialized)

    def test_legacy_types_subtypes_and_escaped_instances_remain_valid(self):
        for name in ['_presence_olpc._tcp.local.', '_printer._sub._http._tcp.local.',
                     r'Living\032Room._private._udp.local.',
                     r'Caf\195\169._http._tcp.local.', '_services._dns-sd._udp.local.']:
            with self.subTest(name=name):
                message = query(name)
                self.assertEqual(parse_pod_query(message.to_wire()).questions[0].name,
                                 message.question[0].name.to_text())

    def test_announcements_probes_and_incomplete_queries_rejected(self):
        for flag in [dns.flags.QR, dns.flags.TC, 0x0800, 1]:
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                message = query()
                message.flags = flag
                parse_pod_query(message.to_wire())
        message = query('private-pod.local.', 'ANY')
        message.authority.append(dns.rrset.from_text(
            'private-pod.local.', 120, 'IN', 'AAAA', '2001:db8:1000:f000::42'))
        with self.assertRaises(ValueError):
            parse_pod_query(message.to_wire())

    def test_ignored_flags_do_not_change_exported_lookup(self):
        baseline = parse_pod_query(query().to_wire()).lookup_payload()
        for flag in [dns.flags.AA, dns.flags.RD, dns.flags.RA, 0x0040, dns.flags.AD, dns.flags.CD]:
            with self.subTest(flag=flag):
                message = query()
                message.flags = flag
                parsed = parse_pod_query(message.to_wire())
                self.assertEqual(parsed.lookup_payload(), baseline)
                self.assertEqual(parsed.recursion_desired, bool(flag & dns.flags.RD))

    def test_outside_scope_class_and_transfer_questions_rejected(self):
        for name, kind, class_ in [('example.org.', 'A', 1), ('local.evil.', 'A', 1),
                                   ('host.local.', 'AXFR', 1), ('host.local.', 'IXFR', 1),
                                   ('host.local.', 'A', 3), ('host.local.', 'ANY', 255)]:
            with self.subTest(name=name, kind=kind, class_=class_), self.assertRaises(ValueError):
                message = query(name, kind)
                message.question[0].rdclass = class_
                parse_pod_query(message.to_wire())

    def test_size_counts_corruption_and_trailing_bytes_rejected(self):
        packets = [b'', b'\x00' * 11, b'\x00' * 9001, query().to_wire() + b'trailing',
                   struct.pack('!6H', 0, 0, 0, 0, 0, 0),
                   struct.pack('!6H', 0, 0, 129, 0, 0, 0),
                   struct.pack('!6H', 0, 0, 1, 129, 0, 0),
                   struct.pack('!6H', 0, 0, 1, 0, 0, 0) + b'\xc0\x0c\x00\x01\x00\x01']
        for packet in packets:
            with self.subTest(packet=packet[:20]), self.assertRaises(ValueError):
                parse_pod_query(packet)

    def test_large_browse_packet_requires_bounded_lookup_batches(self):
        message = query()
        message.question.extend(query(f'_type{i}._tcp.local.').question[0] for i in range(127))
        parsed = parse_pod_query(message.to_wire())
        self.assertEqual(len(parsed.questions), 128)
        with self.assertRaises(ValueError):
            parsed.lookup_payload()
        message.question.append(query('_overflow._tcp.local.').question[0])
        with self.assertRaises(ValueError):
            parse_pod_query(message.to_wire())


if __name__ == '__main__':
    unittest.main()
