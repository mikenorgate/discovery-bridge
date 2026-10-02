"""Reduce untrusted pod mDNS packets to bounded question-only lookup requests."""

from dataclasses import dataclass
import struct

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype


@dataclass(frozen=True)
class Question:
    """Only these fields may cross the gateway lookup boundary."""

    name: str
    type: int
    class_: int = dns.rdataclass.IN

    def as_dict(self) -> dict:
        return {"name": self.name, "type": self.type, "class": self.class_}


@dataclass(frozen=True)
class KnownAnswer:
    """Untrusted local suppression hint; never a source for catalog records."""

    name: bytes
    type: int
    data: bytes
    ttl: int


@dataclass(frozen=True)
class PodQuery:
    """Local response metadata is kept separate from exported questions."""

    transaction_id: int
    questions: tuple[Question, ...]
    unicast_requested: tuple[bool, ...]
    known_answers: tuple[KnownAnswer, ...] = ()
    recursion_desired: bool = False
    truncated: bool = False

    def lookup_payload(self) -> dict:
        """Never export resource sections, packet bytes, peer identity or QU flags."""
        if self.truncated or not self.questions:
            raise ValueError("unfinished known-answer sequences cannot become lookups")
        if len(self.questions) > 16:
            raise ValueError("gateway lookups require batches of at most 16 questions")
        return {"schema": 1, "questions": [question.as_dict() for question in self.questions]}


def parse_pod_query(wire: bytes, *, allow_continuation: bool = False) -> PodQuery:
    """Parse bounded questions and local suppression hints, never pod authority.

    Only the socket assembler opts into TC/zero-question continuation packets.
    Their lookup export remains disabled until assembly completes.
    """
    if not 12 <= len(wire) <= 9000:
        raise ValueError("query packet size exceeds bounds")
    _, flags, questions, answers, authority, additional = struct.unpack("!6H", wire[:12])
    # RFC 6762 section 18: ignore AA/RD/RA/Z/AD/CD on receipt. QR, opcode,
    # TC requires an explicitly enabled local assembler; responses never enter.
    ignored = dns.flags.AA | dns.flags.RD | dns.flags.RA | 0x0040 | dns.flags.AD | dns.flags.CD
    if allow_continuation:
        ignored |= dns.flags.TC
    if flags & ~ignored:
        raise ValueError("only complete standard queries are accepted")
    minimum = 0 if allow_continuation and answers else 1
    if not minimum <= questions <= 128 or answers + authority + additional > 128:
        raise ValueError("query record count exceeds bounds")
    if authority:
        raise ValueError("registration probes cannot become gateway lookups")
    try:
        message = dns.message.from_wire(wire, ignore_trailing=False)
    except (dns.exception.DNSException, ValueError, IndexError) as exc:
        raise ValueError("invalid DNS wire query") from exc
    exported = []
    unicast = []
    local = dns.name.from_text("local.")
    excluded = {dns.rdatatype.AXFR, dns.rdatatype.IXFR, dns.rdatatype.OPT,
                dns.rdatatype.TKEY, dns.rdatatype.TSIG}
    for question in message.question:
        class_ = question.rdclass & 0x7FFF
        if class_ != dns.rdataclass.IN or question.rdtype in excluded:
            raise ValueError("unsupported mDNS question class or type")
        if not question.name.is_subdomain(local):
            raise ValueError("gateway lookups must stay within local discovery")
        exported.append(Question(question.name.to_text(), int(question.rdtype), int(class_)))
        unicast.append(bool(question.rdclass & 0x8000))
    known = []
    for rrset in message.answer:
        if rrset.rdclass != dns.rdataclass.IN:
            continue
        for rdata in rrset:
            known.append(KnownAnswer(rrset.name.canonicalize().to_wire(), int(rrset.rdtype),
                                     rdata.to_digestable(), rrset.ttl))
    return PodQuery(message.id, tuple(exported), tuple(unicast), tuple(known),
                    bool(flags & dns.flags.RD), bool(flags & dns.flags.TC))
