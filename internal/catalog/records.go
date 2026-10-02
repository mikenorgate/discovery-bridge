package catalog

import (
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// RRSet identifies a canonical owner and record type.
type RRSet struct {
	Name string
	Type uint16
}

// Authority contains caller-approved record identities and established ownership.
type Authority struct {
	IDs     map[string]bool
	Unique  map[RRSet]bool
	Blocked map[string]bool
}

// Answer is an admitted DNS record with source and gateway ownership.
type Answer struct {
	RR     dns.RR
	Source string
	Unique bool
}

// Set identifies the answer's canonical RRset.
func (a Answer) Set() RRSet { return RRSet{NameKey(a.RR.Header().Name), a.RR.Header().Rrtype} }

// Key gives a TTL-independent canonical record identity for deduplication.
func (a Answer) Key() string {
	rr := dns.Copy(a.RR)
	rr.Header().Name = NameKey(rr.Header().Name)
	rr.Header().Ttl, rr.Header().Class = 0, dns.ClassINET
	switch value := rr.(type) {
	case *dns.PTR:
		value.Ptr = NameKey(value.Ptr)
	case *dns.SRV:
		value.Target = NameKey(value.Target)
	}
	buffer := make([]byte, dns.Len(rr)+256)
	n, err := dns.PackRR(rr, buffer, 0, nil, false)
	if err != nil {
		return ""
	}
	return string(buffer[:n])
}

func withTTL(a Answer, ttl uint32) Answer { a.RR = dns.Copy(a.RR); a.RR.Header().Ttl = ttl; return a }

// ResponseView withholds ambiguous owners and incomplete same-source chains.
func ResponseView(records []TimedRecord, authority Authority) []Answer {
	owners := make(map[string]map[string]bool)
	candidates := make([]Answer, 0, len(records))
	for _, value := range records {
		r := value.Record
		if !authority.IDs[r.ID] || value.TTL == 0 {
			continue
		}
		rr, err := r.RR(value.TTL)
		if err != nil {
			continue
		}
		a := Answer{RR: rr, Source: r.Source}
		a.Unique = rr.Header().Rrtype != dns.TypePTR && authority.Unique[a.Set()]
		candidates = append(candidates, a)
		if rr.Header().Rrtype != dns.TypePTR {
			name := NameKey(rr.Header().Name)
			if owners[name] == nil {
				owners[name] = make(map[string]bool)
			}
			owners[name][r.Source] = true
		}
	}
	evidence := make(map[string]Answer)
	for _, a := range candidates {
		name := NameKey(a.RR.Header().Name)
		if authority.Blocked[name] || len(owners[name]) > 1 {
			continue
		}
		key := a.Source + "\x00" + a.Key()
		if previous, ok := evidence[key]; !ok || a.RR.Header().Ttl < previous.RR.Header().Ttl {
			evidence[key] = a
		}
	}
	byName := make(map[string][]Answer)
	for _, a := range evidence {
		key := a.Source + "\x00" + NameKey(a.RR.Header().Name)
		byName[key] = append(byName[key], a)
	}
	hosts := make(map[string][]Answer)
	for key, values := range byName {
		for _, a := range values {
			if a.RR.Header().Rrtype == dns.TypeA || a.RR.Header().Rrtype == dns.TypeAAAA {
				hosts[key] = append(hosts[key], a)
			}
		}
	}
	services := make(map[string][]Answer)
	for key, values := range byName {
		var srvs, txts []Answer
		for _, a := range values {
			switch a.RR.Header().Rrtype {
			case dns.TypeSRV:
				srvs = append(srvs, a)
			case dns.TypeTXT:
				txts = append(txts, a)
			}
		}
		if len(srvs) != 1 || len(txts) != 1 {
			continue
		}
		srv := srvs[0].RR.(*dns.SRV)
		addresses := hosts[srvs[0].Source+"\x00"+NameKey(srv.Target)]
		if srv.Port == 0 || len(addresses) == 0 {
			continue
		}
		ttl := min(srvs[0].RR.Header().Ttl, txts[0].RR.Header().Ttl)
		for _, a := range addresses {
			ttl = min(ttl, a.RR.Header().Ttl)
		}
		services[key] = []Answer{withTTL(srvs[0], ttl), withTTL(txts[0], ttl)}
	}
	var view []Answer
	for _, values := range hosts {
		view = append(view, values...)
	}
	for _, values := range services {
		view = append(view, values...)
	}
	for _, a := range evidence {
		ptr, ok := a.RR.(*dns.PTR)
		if !ok {
			continue
		}
		if NameKey(ptr.Hdr.Name) == Enumeration {
			labels := dns.SplitDomainName(NameKey(ptr.Ptr))
			if len(labels) == 3 && strings.HasPrefix(labels[0], "_") && len(labels[0]) > 1 && (labels[1] == "_tcp" || labels[1] == "_udp") && labels[2] == "local" {
				view = append(view, a)
			}
			continue
		}
		if service := services[a.Source+"\x00"+NameKey(ptr.Ptr)]; len(service) > 0 {
			ttl := a.RR.Header().Ttl
			for _, dependency := range service {
				ttl = min(ttl, dependency.RR.Header().Ttl)
			}
			view = append(view, withTTL(a, ttl))
		}
	}
	dedup := make(map[string]Answer)
	for _, a := range view {
		key := a.Key()
		if previous, ok := dedup[key]; !ok || a.RR.Header().Ttl < previous.RR.Header().Ttl {
			dedup[key] = a
		}
	}
	ttls := make(map[RRSet]uint32)
	for _, a := range dedup {
		if ttl, ok := ttls[a.Set()]; !ok || a.RR.Header().Ttl < ttl {
			ttls[a.Set()] = a.RR.Header().Ttl
		}
	}
	result := make([]Answer, 0, len(dedup))
	for _, a := range dedup {
		result = append(result, withTTL(a, ttls[a.Set()]))
	}
	slices.SortFunc(result, func(a, b Answer) int { return strings.Compare(a.Key(), b.Key()) })
	return result
}

// Additionals returns only the answer's same-source service dependencies.
func Additionals(answer Answer, view []Answer) []Answer {
	var result []Answer
	switch rr := answer.RR.(type) {
	case *dns.PTR:
		if NameKey(rr.Hdr.Name) == Enumeration {
			return nil
		}
		for _, a := range view {
			if a.Source == answer.Source && NameKey(a.RR.Header().Name) == NameKey(rr.Ptr) && (a.RR.Header().Rrtype == dns.TypeSRV || a.RR.Header().Rrtype == dns.TypeTXT) {
				result = append(result, a)
				result = append(result, Additionals(a, view)...)
			}
		}
	case *dns.SRV:
		for _, a := range view {
			if a.Source == answer.Source && NameKey(a.RR.Header().Name) == NameKey(rr.Target) && (a.RR.Header().Rrtype == dns.TypeA || a.RR.Header().Rrtype == dns.TypeAAAA) {
				result = append(result, a)
			}
		}
	}
	return result
}
