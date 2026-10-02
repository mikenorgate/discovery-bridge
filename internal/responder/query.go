// Package responder builds answer-only mDNS responses for admitted pod queries.
package responder

import (
	"encoding/binary"
	"errors"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/dnswire"
)

// Question is the only pod information exported to the LAN lookup boundary.
type Question struct {
	Name  string `json:"name"`
	Type  uint16 `json:"type"`
	Class uint16 `json:"class"`
}

// Query retains untrusted known-answer hints for local suppression only.
type Query struct {
	ID        uint16
	Questions []Question
	Unicast   []bool
	Known     []dns.RR
	Recursion bool
	Truncated bool
}

// Message rejects trailing DNS bytes as well as malformed compression.
func Message(wire []byte) (*dns.Msg, error) {
	return dnswire.Decode(wire, 9000, 128, 128)
}

// Parse accepts questions and suppression hints, never pod publication authority.
func Parse(wire []byte, continuation bool) (Query, error) {
	var q Query
	message, err := Message(wire)
	if err != nil {
		return q, err
	}
	flags := binary.BigEndian.Uint16(wire[2:4])
	ignored := uint16(0x0400 | 0x0100 | 0x0080 | 0x0040 | 0x0020 | 0x0010)
	if continuation {
		ignored |= 0x0200
	}
	minimum := 1
	if continuation && len(message.Answer) > 0 {
		minimum = 0
	}
	if flags & ^ignored != 0 || len(message.Question) < minimum || len(message.Ns) != 0 {
		return q, errors.New("only ordinary local queries are accepted")
	}
	q.ID, q.Recursion, q.Truncated = message.Id, message.RecursionDesired, message.Truncated
	for _, question := range message.Question {
		kind := question.Qtype
		class := question.Qclass & 0x7fff
		if class != dns.ClassINET || kind == dns.TypeAXFR || kind == dns.TypeIXFR || kind == dns.TypeOPT || kind == dns.TypeTKEY || kind == dns.TypeTSIG || !catalog.LocalName(question.Name) {
			return Query{}, errors.New("unsupported local discovery question")
		}
		q.Questions = append(q.Questions, Question{question.Name, kind, class})
		q.Unicast = append(q.Unicast, question.Qclass&0x8000 != 0)
	}
	for _, rr := range message.Answer {
		if rr.Header().Class == dns.ClassINET {
			q.Known = append(q.Known, dns.Copy(rr))
		}
	}
	return q, nil
}

// Lookup removes resources, source identity and QU flags from the gateway request.
func (q Query) Lookup() (any, error) {
	if q.Truncated || len(q.Questions) < 1 || len(q.Questions) > 16 {
		return nil, errors.New("complete bounded lookup questions required")
	}
	return struct {
		Schema    int        `json:"schema"`
		Questions []Question `json:"questions"`
	}{1, q.Questions}, nil
}
