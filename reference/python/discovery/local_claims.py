"""Passive pod name reservations; no records or registrations leave this object."""
import struct

import dns.exception
import dns.message
import dns.name


class LocalClaims:
    """Withhold locally claimed names until their observed TTL expires.

    Reserve the whole name, even when its data matches the gateway. This avoids
    asserting ownership on behalf of a pod. Goodbyes do not shorten a reservation:
    another local responder may still own it. Only names and expiry times persist.
    Observation is best effort; lost packets and claims before attachment cannot
    be detected without probing, which is prohibited on this boundary.
    """
    def __init__(self):
        self.names = {}

    def active(self, now):
        self.names = {name: until for name, until in self.names.items() if until > now}
        return frozenset(self.names)

    def observe(self, wire, now):
        """Consume responses/probes; ordinary query hints never reserve names."""
        if not 12 <= len(wire) <= 9000:
            raise ValueError('invalid local claim packet size')
        _, flags, questions, answers, authority, additional = struct.unpack('!6H', wire[:12])
        response = bool(flags & 0x8000)
        if not response and not authority:
            return False
        if flags & 0x780F or questions > 128 or answers + authority + additional > 128:
            raise ValueError('invalid local claim packet header')
        try:
            message = dns.message.from_wire(wire, ignore_trailing=False)
        except (dns.exception.DNSException, ValueError, IndexError) as exc:
            raise ValueError('invalid local claim packet') from exc
        self.active(now)
        sections = message.answer + message.additional if response else message.authority
        for rr in sections:
            # PTR browse hints and NSEC/OPT metadata do not establish ownership.
            if (rr.rdclass & 0x7FFF != 1 or rr.rdtype not in (1, 28, 33, 16)
                    or rr.ttl == 0 or not rr.name.is_subdomain(dns.name.from_text('local.'))):
                continue
            name = rr.name.canonicalize().to_text()
            if name not in self.names and len(self.names) >= 256:
                # Losing an observed claim could permit a conflicting answer.
                raise OverflowError('local name reservation capacity exceeded')
            self.names[name] = max(self.names.get(name, now), now + rr.ttl)
        return True
