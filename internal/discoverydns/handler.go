package discoverydns

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/dnswire"
	"github.com/mikenorgate/discovery-bridge/internal/native"
)

// Handler implements authoritative answers only; it never follows public DNS.
type Handler struct {
	settings Config
	zones    []zone
	backend  native.Querier
	clients  []netip.Prefix
	prefixes map[string][]netip.Prefix
	active   atomic.Int32
}

// New validates and copies configuration, then wires the read-only native owner.
func New(settings Config, backend native.Querier) (*Handler, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if backend == nil {
		return nil, errors.New("discovery dns: native query backend required")
	}
	h := &Handler{settings: settings, backend: backend, zones: []zone{}, clients: []netip.Prefix{}, prefixes: make(map[string][]netip.Prefix)}
	h.settings.Listeners = slices.Clone(settings.Listeners)
	h.settings.Clients = slices.Clone(settings.Clients)
	h.settings.Nameservers = slices.Clone(settings.Nameservers)
	h.settings.Links = slices.Clone(settings.Links)
	if settings.SuppressUnusable != nil {
		value := *settings.SuppressUnusable
		h.settings.SuppressUnusable = &value
	}
	for _, raw := range settings.Clients {
		h.clients = append(h.clients, netip.MustParsePrefix(raw))
	}
	for index, link := range h.settings.Links {
		link.Prefixes = slices.Clone(link.Prefixes)
		h.settings.Links[index] = link
		h.zones = append(h.zones, zone{name: link.ServiceDomain, link: index})
		if catalog.NameKey(link.HostDomain) != catalog.NameKey(link.ServiceDomain) {
			h.zones = append(h.zones, zone{name: link.HostDomain, link: index, isHost: true})
		}
		for _, raw := range link.Prefixes {
			prefix := netip.MustParsePrefix(raw)
			h.prefixes[link.Source] = append(h.prefixes[link.Source], prefix)
			reverse, err := dnswire.ReverseZone(prefix)
			if err != nil {
				return nil, err
			}
			h.zones = append(h.zones, zone{name: reverse, link: index, isReverse: true})
		}
	}
	return h, nil
}

func (h *Handler) zone(name string) (zone, bool) {
	for _, candidate := range h.zones {
		if dns.IsSubDomain(candidate.name, name) {
			return candidate, true
		}
	}
	return zone{}, false
}

func (h *Handler) soa(z zone) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{Name: z.name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 10},
		Ns:  h.settings.Nameservers[0], Mbox: h.settings.Mailbox, Serial: 0,
		Refresh: 7200, Retry: 3600, Expire: 86400, Minttl: 10,
	}
}

func (h *Handler) administrative(question dns.Question, z zone) ([]dns.RR, bool) {
	name := catalog.NameKey(question.Name)
	apex := name == catalog.NameKey(z.name)
	if apex {
		result := []dns.RR{}
		if question.Qtype == dns.TypeSOA || question.Qtype == dns.TypeANY {
			result = append(result, h.soa(z))
		}
		if question.Qtype == dns.TypeNS || question.Qtype == dns.TypeANY {
			for _, target := range h.settings.Nameservers {
				result = append(result, &dns.NS{Hdr: dns.RR_Header{Name: z.name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 10}, Ns: target})
			}
		}
		return result, true
	}
	if question.Qtype == dns.TypeSOA || question.Qtype == dns.TypeNS || question.Qtype == dns.TypeDS {
		return nil, true
	}
	for _, service := range []string{
		"_dns-llq._udp.", "_dns-llq._tcp.", "_dns-llq-tls._tcp.", "_dns-push-tls._tcp.",
		"_dns-update._udp.", "_dns-update._tcp.", "_dns-update-tls._tcp.",
	} {
		if name == catalog.NameKey(service+z.name) {
			return nil, true
		}
	}
	if z.isReverse {
		for _, kind := range []string{"b", "db", "lb", "r", "dr"} {
			if name != catalog.NameKey(kind+"._dns-sd._udp."+z.name) {
				continue
			}
			result := []dns.RR{}
			if kind == "r" || kind == "dr" || question.Qtype != dns.TypePTR && question.Qtype != dns.TypeANY {
				return result, true
			}
			for _, link := range h.settings.Links {
				if kind == "db" && link.Source != h.settings.DefaultSource {
					continue
				}
				result = append(result, &dns.PTR{
					Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
					Ptr: link.ServiceDomain,
				})
			}
			return result, true
		}
	}
	return nil, false
}

// Answer returns one authoritative DNS message. Callers provide lifetime and ACLs.
func (h *Handler) Answer(ctx context.Context, request *dns.Msg) *dns.Msg {
	reply := new(dns.Msg)
	reply.SetReply(request)
	reply.RecursionAvailable, reply.AuthenticatedData = false, false
	invalid := request.Response || len(request.Question) != 1 || len(request.Answer) != 0 || len(request.Ns) != 0
	if invalid {
		reply.Rcode = dns.RcodeFormatError
		return reply
	}
	question := request.Question[0]
	z, ok := h.zone(question.Name)
	if !ok || request.Opcode != dns.OpcodeQuery || question.Qtype == dns.TypeAXFR || question.Qtype == dns.TypeIXFR {
		reply.Rcode = dns.RcodeRefused
		return reply
	}
	reply.Authoritative = true
	if question.Qclass != dns.ClassINET && question.Qclass != dns.ClassANY {
		reply.Rcode = dns.RcodeNotImplemented
		return reply
	}
	if opt := request.IsEdns0(); opt != nil && opt.Version() != 0 {
		reply.SetEdns0(1232, false)
		reply.Rcode = dns.RcodeBadVers
		return reply
	}
	if records, administrative := h.administrative(question, z); administrative {
		reply.Answer = records
		if len(records) == 0 {
			reply.Ns = []dns.RR{h.soa(z)}
		}
		return reply
	}
	if h.active.Add(1) > 64 {
		h.active.Add(-1)
		reply.Rcode = dns.RcodeServerFailure
		return reply
	}
	defer h.active.Add(-1)
	bounded, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	link := h.settings.Links[z.link]
	nativeName := question.Name
	if !z.isReverse {
		var err error
		nativeName, err = replaceSuffix(question.Name, z.name, "local.")
		if err != nil {
			reply.Rcode = dns.RcodeFormatError
			return reply
		}
	}
	nativeType := question.Qtype
	if nativeType == dns.TypeNSEC || nativeType == dns.TypeNSEC3 {
		nativeType = dns.TypeANY
	}
	nativeQuestion := native.Question{Source: link.Source, DNS: dns.Question{Name: nativeName, Qtype: nativeType, Qclass: dns.ClassINET}}
	result, err := h.backend.Query(bounded, nativeQuestion)
	if err != nil {
		reply.Rcode = dns.RcodeServerFailure
		return reply
	}
	view, err := h.dependencies(bounded, link, result)
	if err != nil {
		reply.Rcode = dns.RcodeServerFailure
		return reply
	}
	view = h.usable(view, link)
	view = harmonize(view)
	view = dependencyTTLs(view)
	if question.Qtype == dns.TypeNSEC || question.Qtype == dns.TypeNSEC3 {
		if record := h.denial(question, z, nativeName, view); record != nil {
			reply.Answer = []dns.RR{record}
		}
	} else {
		for _, record := range view {
			header := record.Header()
			if catalog.NameKey(header.Name) != catalog.NameKey(nativeName) || header.Rrtype == dns.TypeNSEC || header.Rrtype == dns.TypeNSEC3 {
				continue
			}
			if header.Rrtype != question.Qtype && question.Qtype != dns.TypeANY && header.Rrtype != dns.TypeCNAME {
				continue
			}
			translated, err := h.translate(record, z, view, false)
			if err != nil {
				reply.Rcode = dns.RcodeServerFailure
				reply.Answer = nil
				return reply
			}
			reply.Answer = append(reply.Answer, translated)
		}
	}
	if len(reply.Answer) == 0 {
		reply.Ns = []dns.RR{h.soa(z)}
		return reply
	}
	for _, record := range view {
		if catalog.NameKey(record.Header().Name) == catalog.NameKey(nativeName) {
			continue
		}
		kind := record.Header().Rrtype
		if kind != dns.TypeA && kind != dns.TypeAAAA && kind != dns.TypeSRV && kind != dns.TypeTXT && kind != dns.TypeCNAME {
			continue
		}
		translated, err := h.translate(record, z, view, true)
		if err != nil {
			reply.Rcode = dns.RcodeServerFailure
			reply.Answer, reply.Extra = nil, nil
			return reply
		}
		reply.Extra = append(reply.Extra, translated)
	}
	return reply
}

// replaceSuffix operates on DNS labels, not string substrings or Unicode folding.
func replaceSuffix(name, from, to string) (string, error) {
	if !dnswire.Name(name) || !dnswire.Name(from) || !dnswire.Name(to) {
		return "", errors.New("discovery dns: invalid translated name")
	}
	if !dns.IsSubDomain(catalog.NameKey(from), catalog.NameKey(name)) {
		return name, nil
	}
	labels := dns.SplitDomainName(name)
	count := len(labels) - len(dns.SplitDomainName(from))
	result := strings.Join(labels[:count], ".")
	if result != "" {
		result += "."
	}
	result += to
	if !dnswire.Name(result) {
		return "", errors.New("discovery dns: translated name exceeds dns bounds")
	}
	return result, nil
}

func (h *Handler) translate(record dns.RR, z zone, view []dns.RR, additional bool) (dns.RR, error) {
	rr := dns.Copy(record)
	link := h.settings.Links[z.link]
	ownerDomain := z.name
	if z.isReverse || additional && (rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA) {
		ownerDomain = link.HostDomain
	}
	owner, err := replaceSuffix(rr.Header().Name, "local.", ownerDomain)
	if err != nil {
		return nil, err
	}
	rr.Header().Name, rr.Header().Class, rr.Header().Ttl = owner, dns.ClassINET, min(rr.Header().Ttl, 10)
	for _, field := range dnswire.NameFields(rr) {
		domain := link.ServiceDomain
		isHost := z.isHost || z.isReverse || rr.Header().Rrtype == dns.TypeSRV
		for _, candidate := range view {
			kind := candidate.Header().Rrtype
			if (kind == dns.TypeA || kind == dns.TypeAAAA) && catalog.NameKey(candidate.Header().Name) == catalog.NameKey(*field) {
				isHost = true
			}
		}
		if isHost {
			domain = link.HostDomain
		}
		translated, err := replaceSuffix(*field, "local.", domain)
		if err != nil {
			return nil, err
		}
		*field = translated
	}
	return rr, nil
}

func (h *Handler) dependencies(ctx context.Context, link Link, initial native.Result) ([]dns.RR, error) {
	if initial.Epoch == "" || len(initial.Records) > 256 {
		return nil, native.ErrUnavailable
	}
	view := slices.Clone(initial.Records)
	if h.settings.SuppressUnusable != nil && !*h.settings.SuppressUnusable {
		return view, nil
	}
	queried := make(map[string]bool)
	for range 8 {
		wanted := []string{}
		for _, record := range view {
			var target string
			switch value := record.(type) {
			case *dns.SRV:
				target = value.Target
			case *dns.PTR:
				if serviceInstance(value.Ptr) {
					target = value.Ptr
				}
			}
			if target == "" || !dns.IsSubDomain("local.", target) {
				continue
			}
			key := catalog.NameKey(target)
			known := slices.ContainsFunc(view, func(candidate dns.RR) bool {
				kind := candidate.Header().Rrtype
				return catalog.NameKey(candidate.Header().Name) == key && (kind == dns.TypeA || kind == dns.TypeAAAA || kind == dns.TypeSRV || kind == dns.TypeCNAME || kind == dns.TypeNSEC)
			})
			if !known && !queried[key] {
				queried[key] = true
				wanted = append(wanted, target)
			}
		}
		if len(wanted) == 0 {
			return view, nil
		}
		if len(queried) > 16 {
			return nil, native.ErrBusy
		}
		for _, target := range wanted {
			result, err := h.backend.Query(ctx, native.Question{Source: link.Source, DNS: dns.Question{Name: target, Qtype: dns.TypeANY, Qclass: dns.ClassINET}})
			if err != nil || result.Epoch != initial.Epoch {
				return nil, errors.Join(native.ErrUnavailable, err)
			}
			view = append(view, result.Records...)
			if len(view) > 256 {
				return nil, native.ErrBusy
			}
		}
	}
	return nil, errors.New("discovery dns: service dependency depth exceeded")
}

func serviceInstance(name string) bool {
	labels := dns.SplitDomainName(name)
	return len(labels) >= 4 && strings.HasPrefix(labels[len(labels)-3], "_") &&
		(labels[len(labels)-2] == "_tcp" || labels[len(labels)-2] == "_udp")
}

func (h *Handler) usable(records []dns.RR, link Link) []dns.RR {
	filtered := make([]dns.RR, 0, len(records))
	hosts, services := make(map[string]bool), make(map[string]bool)
	for _, record := range records {
		if record == nil {
			continue
		}
		header := record.Header()
		if header.Class != dns.ClassINET || header.Ttl == 0 || !dnswire.LocalOrReverse(header.Name, h.prefixes[link.Source]) {
			continue
		}
		var address netip.Addr
		switch value := record.(type) {
		case *dns.A:
			address, _ = netip.AddrFromSlice(value.A)
			address = address.Unmap()
		case *dns.AAAA:
			address, _ = netip.AddrFromSlice(value.AAAA)
		}
		if header.Rrtype == dns.TypeA || header.Rrtype == dns.TypeAAAA {
			usable := address.IsValid() && !address.Is4In6() && !address.IsUnspecified() && !address.IsLoopback() && !address.IsMulticast() && !address.IsLinkLocalUnicast()
			matched := slices.ContainsFunc(h.prefixes[link.Source], func(prefix netip.Prefix) bool { return prefix.Contains(address) })
			if !usable || !matched {
				continue
			}
			hosts[catalog.NameKey(header.Name)] = true
		}
		filtered = append(filtered, record)
	}
	if h.settings.SuppressUnusable != nil && !*h.settings.SuppressUnusable {
		return filtered
	}
	for range 8 {
		for _, record := range filtered {
			if alias, ok := record.(*dns.CNAME); ok && hosts[catalog.NameKey(alias.Target)] {
				hosts[catalog.NameKey(alias.Hdr.Name)] = true
			}
		}
	}
	for _, record := range filtered {
		if srv, ok := record.(*dns.SRV); ok && srv.Port != 0 && (hosts[catalog.NameKey(srv.Target)] || !dns.IsSubDomain("local.", srv.Target) && srv.Target != ".") {
			services[catalog.NameKey(srv.Hdr.Name)] = true
		}
	}
	return slices.DeleteFunc(filtered, func(record dns.RR) bool {
		switch value := record.(type) {
		case *dns.SRV:
			return !services[catalog.NameKey(value.Hdr.Name)]
		case *dns.PTR:
			return serviceInstance(value.Ptr) && !services[catalog.NameKey(value.Ptr)]
		}
		return false
	})
}

// harmonize copies and deduplicates records and reports the shortest RRset TTL.
func harmonize(records []dns.RR) []dns.RR {
	identities := make(map[string]dns.RR)
	ttls := make(map[catalog.RRSet]uint32)
	for _, record := range records {
		answer := catalog.Answer{RR: record}
		identity := answer.Key()
		if previous, ok := identities[identity]; !ok || record.Header().Ttl < previous.Header().Ttl {
			identities[identity] = record
		}
		set := answer.Set()
		if ttl, ok := ttls[set]; !ok || record.Header().Ttl < ttl {
			ttls[set] = record.Header().Ttl
		}
	}
	keys := make([]string, 0, len(identities))
	for identity := range identities {
		keys = append(keys, identity)
	}
	slices.Sort(keys)
	result := make([]dns.RR, 0, len(keys))
	for _, identity := range keys {
		record := dns.Copy(identities[identity])
		record.Header().Ttl = ttls[(catalog.Answer{RR: record}).Set()]
		result = append(result, record)
	}
	return result
}

func (h *Handler) denial(question dns.Question, z zone, nativeName string, records []dns.RR) dns.RR {
	types := []uint16{}
	ttl := uint32(10)
	for _, record := range records {
		if catalog.NameKey(record.Header().Name) == catalog.NameKey(nativeName) && record.Header().Rrtype != dns.TypeNSEC && record.Header().Rrtype != dns.TypeNSEC3 {
			types = append(types, record.Header().Rrtype)
			ttl = min(ttl, record.Header().Ttl)
		}
	}
	if len(types) == 0 {
		return nil
	}
	types = append(types, dns.TypeNSEC)
	slices.Sort(types)
	types = slices.Compact(types)
	if question.Qtype == dns.TypeNSEC {
		// The immediate canonical successor narrows the interval to this owner;
		// owner==next would incorrectly assert the rest of the zone is empty.
		next := successor(question.Name)
		if next == "" || !dns.IsSubDomain(z.name, next) {
			return nil
		}
		return &dns.NSEC{
			Hdr:        dns.RR_Header{Name: question.Name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: ttl},
			NextDomain: next, TypeBitMap: types,
		}
	}
	record := narrowNSEC3(question.Name, z.name, types)
	if record != nil {
		record.Header().Ttl = ttl
	}
	return record
}
