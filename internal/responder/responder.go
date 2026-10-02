package responder

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
)

// Reply contains positive or goodbye answers, never a LAN question.
type Reply struct {
	Peer    bool
	Family  int
	Wire    []byte
	Records []catalog.Answer
}

// Result holds local replies and question-only cache misses.
type Result struct {
	Replies   []Reply
	Misses    []Question
	Oversized bool
}

type historyKey struct {
	family int
	record string
}
type sent struct {
	at  time.Duration
	ttl uint32
}

// Responder retains bounded successful-send history for QU and withdrawals.
type Responder struct {
	multicast  map[historyKey]sent
	advertised map[historyKey]catalog.Answer
}

// New creates a responder for one eligible pod namespace.
func New() *Responder {
	return &Responder{multicast: make(map[historyKey]sent), advertised: make(map[historyKey]catalog.Answer)}
}

// NoteSent must be called only after a successful socket send.
func (r *Responder) NoteSent(reply Reply, now time.Duration) {
	for key, value := range r.multicast {
		if now < value.at || now-value.at >= time.Duration(value.ttl)*time.Second {
			delete(r.multicast, key)
		}
	}
	for _, a := range reply.Records {
		key := historyKey{reply.Family, a.Key()}
		if a.RR.Header().Ttl == 0 {
			delete(r.multicast, key)
			delete(r.advertised, key)
			continue
		}
		if !reply.Peer {
			r.multicast[key] = sent{now, a.RR.Header().Ttl}
		}
		if len(reply.Wire) >= 12 && reply.Wire[4] == 0 && reply.Wire[5] == 0 {
			r.advertised[key] = a
		}
	}
	for len(r.multicast) > catalog.MaxRecords*2 {
		for key := range r.multicast {
			delete(r.multicast, key)
			break
		}
	}
	for len(r.advertised) > catalog.MaxRecords*2 {
		for key := range r.advertised {
			delete(r.advertised, key)
			break
		}
	}
}

// Withdrawals removes previously sent records missing from the current view.
func (r *Responder) Withdrawals(view []catalog.Answer, family int) ([]Reply, error) {
	live := make(map[string]bool)
	for _, a := range view {
		live[a.Key()] = true
	}
	var removed []catalog.Answer
	for key, a := range r.advertised {
		if key.family != family || live[key.record] {
			continue
		}
		a.RR = dns.Copy(a.RR)
		a.RR.Header().Ttl = 0
		a.Unique = false
		removed = append(removed, a)
		if len(removed) == 16 {
			break
		}
	}
	return pack(Query{}, removed, nil, false, family, false, 1232)
}

// Build computes fresh replies under the current lease and catalog authority.
func (r *Responder) Build(q Query, view []catalog.Answer, now time.Duration, port, family, budget int, directUnicast bool) (Result, error) {
	var result Result
	if q.Truncated || len(q.Questions) == 0 || len(q.Questions) != len(q.Unicast) || port < 1 || port > 65535 || (family != 4 && family != 6) || budget < 512 || budget > 8952 {
		return result, errors.New("invalid response inputs")
	}
	legacy := port != 5353
	known := make(map[string]uint32)
	if !legacy {
		for _, rr := range q.Known {
			key := (catalog.Answer{RR: rr}).Key()
			known[key] = max(known[key], rr.Header().Ttl)
		}
	}
	suppressed := make(map[string]bool)
	incomplete := make(map[catalog.RRSet]bool)
	for _, a := range view {
		key := a.Key()
		suppressed[key] = uint64(known[key])*2 >= uint64(a.RR.Header().Ttl)
		if a.Unique && !suppressed[key] {
			incomplete[a.Set()] = true
		}
	}
	for _, a := range view {
		if a.Unique && incomplete[a.Set()] {
			delete(suppressed, a.Key())
		}
	}
	selected := []map[string]catalog.Answer{make(map[string]catalog.Answer), make(map[string]catalog.Answer)}
	for index, question := range q.Questions {
		matched := false
		for _, a := range view {
			if catalog.NameKey(question.Name) != catalog.NameKey(a.RR.Header().Name) || (question.Type != dns.TypeANY && question.Type != a.RR.Header().Rrtype) {
				continue
			}
			matched = true
			if suppressed[a.Key()] {
				continue
			}
			history, exists := r.multicast[historyKey{family, a.Key()}]
			recent := exists && now >= history.at && now-history.at < time.Duration(min(history.ttl, a.RR.Header().Ttl))*time.Second/4
			destination := 0
			if legacy || ((q.Unicast[index] || directUnicast) && recent) {
				destination = 1
			}
			selected[destination][a.Key()] = a
		}
		if !matched {
			result.Misses = append(result.Misses, question)
		}
	}
	sets := make(map[catalog.RRSet]bool)
	for _, a := range selected[0] {
		if a.Unique {
			sets[a.Set()] = true
		}
	}
	for _, a := range view {
		if a.Unique && sets[a.Set()] {
			selected[0][a.Key()] = a
		}
	}
	held, heldSets := make(map[string]bool), make(map[catalog.RRSet]bool)
	for _, a := range view {
		s, ok := r.multicast[historyKey{family, a.Key()}]
		if ok && now >= s.at && now-s.at < time.Second {
			held[a.Key()] = true
			if a.Unique {
				heldSets[a.Set()] = true
			}
		}
	}
	for _, a := range view {
		if a.Unique && heldSets[a.Set()] {
			held[a.Key()] = true
		}
	}
	for key := range selected[0] {
		delete(selected[1], key)
		if held[key] {
			delete(selected[0], key)
		}
	}
	for destination, values := range selected {
		extra := make(map[string]catalog.Answer)
		for _, a := range values {
			for _, dependency := range catalog.Additionals(a, view) {
				key := dependency.Key()
				if _, ok := values[key]; !ok && !suppressed[key] && (destination != 0 || !held[key]) {
					extra[key] = dependency
				}
			}
		}
		replies, err := pack(q, sorted(values), sorted(extra), destination == 1, family, legacy, budget)
		if err != nil {
			result.Oversized = true
			result.Replies = nil
			return result, nil
		}
		result.Replies = append(result.Replies, replies...)
	}
	if len(result.Replies) > 16 {
		result.Oversized = true
		result.Replies = nil
	}
	return result, nil
}

func sorted(values map[string]catalog.Answer) []catalog.Answer {
	result := make([]catalog.Answer, 0, len(values))
	for _, a := range values {
		result = append(result, a)
	}
	slices.SortFunc(result, func(a, b catalog.Answer) int { return strings.Compare(a.Key(), b.Key()) })
	return result
}

func packet(q Query, answers, extra []catalog.Answer, legacy, truncated bool) ([]byte, error) {
	m := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Authoritative: true, Truncated: truncated}}
	if legacy {
		m.Id, m.RecursionDesired = q.ID, q.Recursion
		for index, question := range q.Questions {
			class := question.Class
			if q.Unicast[index] {
				class |= 0x8000
			}
			m.Question = append(m.Question, dns.Question{Name: question.Name, Qtype: question.Type, Qclass: class})
		}
	}
	for section, values := range [][]catalog.Answer{answers, extra} {
		for _, a := range values {
			rr := dns.Copy(a.RR)
			rr.Header().Class = dns.ClassINET
			if a.Unique && !legacy {
				rr.Header().Class |= 0x8000
			}
			if legacy {
				rr.Header().Ttl = min(rr.Header().Ttl, 10)
			}
			if section == 0 {
				m.Answer = append(m.Answer, rr)
			} else {
				m.Extra = append(m.Extra, rr)
			}
		}
	}
	return m.Pack()
}

func units(records []catalog.Answer) [][]catalog.Answer {
	var result [][]catalog.Answer
	unique := make(map[catalog.RRSet]int)
	for _, a := range records {
		if !a.Unique {
			result = append(result, []catalog.Answer{a})
			continue
		}
		index, ok := unique[a.Set()]
		if !ok {
			index = len(result)
			unique[a.Set()] = index
			result = append(result, nil)
		}
		result[index] = append(result[index], a)
	}
	return result
}

func pack(q Query, answers, extra []catalog.Answer, peer bool, family int, legacy bool, budget int) ([]Reply, error) {
	if len(answers) == 0 {
		return nil, nil
	}
	if legacy {
		budget = min(budget, 512)
	}
	var replies []Reply
	var packedAnswers, packedExtra []catalog.Answer
	base, err := packet(q, nil, nil, legacy, false)
	if err != nil || len(base) > budget {
		return nil, errors.New("question section exceeds packet budget")
	}
	for section, values := range [][]catalog.Answer{answers, extra} {
		for _, unit := range units(values) {
			nextAnswers, nextExtra := packedAnswers, packedExtra
			if section == 0 {
				nextAnswers = append(slices.Clone(packedAnswers), unit...)
			} else {
				nextExtra = append(slices.Clone(packedExtra), unit...)
			}
			wire, err := packet(q, nextAnswers, nextExtra, legacy, false)
			if err != nil {
				return nil, err
			}
			if len(wire) > budget {
				if legacy {
					wire, err = packet(q, packedAnswers, packedExtra, true, section == 0)
					return []Reply{{peer, family, wire, append(slices.Clone(packedAnswers), packedExtra...)}}, err
				}
				if len(packedAnswers)+len(packedExtra) > 0 {
					wire, err = packet(q, packedAnswers, packedExtra, false, false)
					if err != nil {
						return nil, err
					}
					replies = append(replies, Reply{peer, family, wire, append(slices.Clone(packedAnswers), packedExtra...)})
					if len(replies) >= 16 {
						return nil, errors.New("response packet count limit")
					}
				}
				nextAnswers, nextExtra = nil, nil
				if section == 0 {
					nextAnswers = unit
				} else {
					nextExtra = unit
				}
				wire, err = packet(q, nextAnswers, nextExtra, false, false)
				if err != nil || len(wire) > budget {
					return nil, errors.New("record or unique RRset exceeds packet budget")
				}
			}
			packedAnswers, packedExtra = nextAnswers, nextExtra
		}
	}
	wire, err := packet(q, packedAnswers, packedExtra, legacy, false)
	if err != nil {
		return nil, err
	}
	replies = append(replies, Reply{peer, family, wire, append(slices.Clone(packedAnswers), packedExtra...)})
	return replies, nil
}
