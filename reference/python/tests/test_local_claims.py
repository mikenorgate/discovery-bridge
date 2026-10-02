import unittest

import dns.message
import dns.rrset

from discovery.local_claims import LocalClaims


def claim(name='sensor.local.', ttl=120, *, probe=False):
    message = dns.message.make_query(name, 'ANY')
    message.flags = 0 if probe else 0x8400
    section = message.authority if probe else message.answer
    section.append(dns.rrset.from_text(name, ttl, 'IN', 'AAAA', 'fd00::2'))
    return message


class LocalClaimsTests(unittest.TestCase):
    def test_response_and_probe_reserve_name_without_retaining_data(self):
        for probe in (True, False):
            claims = LocalClaims()
            self.assertTrue(claims.observe(claim(probe=probe).to_wire(), 10))
            self.assertEqual(claims.names, {'sensor.local.': 130})

    def test_known_answers_and_query_additionals_never_reserve(self):
        message = claim(); message.flags = 0
        message.additional.extend(message.answer)
        claims = LocalClaims()
        self.assertFalse(claims.observe(message.to_wire(), 0))
        self.assertFalse(claims.names)

    def test_expiry_refresh_and_goodbye_do_not_release_another_owner(self):
        claims = LocalClaims()
        claims.observe(claim(ttl=2).to_wire(), 0)
        claims.observe(claim(ttl=0).to_wire(), 1)
        self.assertTrue(claims.active(1.5))
        self.assertFalse(claims.active(2))
        claims.observe(claim(ttl=2).to_wire(), 3)
        claims.observe(claim(ttl=2).to_wire(), 4)
        self.assertTrue(claims.active(5))
        self.assertFalse(claims.active(6))

    def test_ptr_and_foreign_names_do_not_reserve(self):
        message = claim('example.org.')
        message.answer.append(dns.rrset.from_text('_test._tcp.local.', 120, 'IN', 'PTR', 'pod._test._tcp.local.'))
        claims = LocalClaims(); claims.observe(message.to_wire(), 0)
        self.assertFalse(claims.names)

    def test_overflow_is_terminal_instead_of_forgetting_claims(self):
        claims = LocalClaims()
        for index in range(256):
            claims.observe(claim(f'pod{index}.local.').to_wire(), 0)
        with self.assertRaises(OverflowError):
            claims.observe(claim('overflow.local.').to_wire(), 0)
        self.assertEqual(len(claims.names), 256)

    def test_malformed_response_rejected(self):
        with self.assertRaises(ValueError):
            LocalClaims().observe(claim().to_wire()[:-2], 0)
