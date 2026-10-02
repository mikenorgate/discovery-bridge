package observation

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/dnswire"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
)

// Link identifies an admitted interface generation and its active IP families.
type Link struct {
	Source, Generation string
	Families           []int
}

// Packet metadata must come from kernel UDP receive control messages.
type Packet struct {
	Interface, Family, HopLimit int
	Generation                  string
	Source, Destination         netip.Addr
	SourcePort, DestinationPort int
	Wire                        []byte
}

// Supported reports record types used by mDNS host and service discovery.
func Supported(kind uint16) bool {
	return kind == dns.TypeA || kind == dns.TypeAAAA || kind == dns.TypePTR || kind == dns.TypeSRV || kind == dns.TypeTXT
}

// Parse admits scoped authoritative responses and excludes the bridge's exports.
// Hints and wire records are correlated separately by Cache.
func Parse(packet Packet, links map[int]Link, scopes *policy.SourcePolicy, local map[int][]netip.Addr, owns func(string) (bool, error)) ([]Record, error) {
	link, ok := links[packet.Interface]
	if !ok || packet.Interface < 1 || link.Source == "" || link.Generation == "" || packet.Generation != link.Generation || !slices.Contains(link.Families, packet.Family) || scopes == nil || (packet.Family != 4 && packet.Family != 6) {
		return nil, errors.New("unapproved LAN interface generation or family")
	}
	src, dst := packet.Source, packet.Destination
	if !src.IsValid() || !dst.IsValid() || src.Zone() != "" || dst.Zone() != "" || src.Is4In6() || dst.Is4In6() || src.Is4() != (packet.Family == 4) || dst.Is4() != (packet.Family == 4) {
		return nil, errors.New("LAN address family mismatch")
	}
	if src.IsUnspecified() || src.IsMulticast() || src.IsLoopback() {
		return nil, errors.New("invalid LAN sender")
	}
	for _, addresses := range local {
		if slices.Contains(addresses, src) {
			return nil, nil
		}
	}
	if packet.Family != 6 || !src.IsLinkLocalUnicast() {
		if err := scopes.CheckAddress(link.Source, src); err != nil {
			return nil, err
		}
	}
	group := netip.MustParseAddr("224.0.0.251")
	if packet.Family == 6 {
		group = netip.MustParseAddr("ff02::fb")
	}
	if dst != group && !slices.Contains(local[packet.Interface], dst) {
		return nil, errors.New("mDNS response destination is outside the admitted link")
	}
	if packet.HopLimit != 255 || packet.SourcePort != 5353 || packet.DestinationPort != 5353 {
		return nil, errors.New("mDNS hop limit or UDP ports rejected")
	}
	message, err := dnswire.Decode(packet.Wire, 8952, 16, 256)
	if err != nil {
		return nil, err
	}
	flags := binary.BigEndian.Uint16(packet.Wire[2:4])
	if !message.Response || !message.Authoritative || flags&(0x7800|0x0200|0x000f) != 0 {
		return nil, errors.New("complete authoritative mDNS response required")
	}
	reserved := func(name string) (bool, error) {
		if owns == nil {
			return false, nil
		}
		return owns(name)
	}
	var result []Record
	for _, rr := range append(append(slices.Clone(message.Answer), message.Ns...), message.Extra...) {
		h := rr.Header()
		if h.Class&0x7fff != dns.ClassINET || !Supported(h.Rrtype) || !catalog.LocalName(h.Name) {
			continue
		}
		owned, err := reserved(h.Name)
		if err != nil {
			return nil, err
		}
		if owned {
			continue
		}
		var target string
		var address netip.Addr
		switch value := rr.(type) {
		case *dns.A:
			address, _ = netip.AddrFromSlice(value.A)
			address = address.Unmap()
		case *dns.AAAA:
			address, _ = netip.AddrFromSlice(value.AAAA)
		case *dns.PTR:
			target = value.Ptr
		case *dns.SRV:
			target = value.Target
		}
		if (h.Rrtype == dns.TypeA || h.Rrtype == dns.TypeAAAA) && scopes.CheckAddress(link.Source, address) != nil {
			continue
		}
		if target != "" {
			if !catalog.LocalName(target) {
				continue
			}
			owned, err := reserved(target)
			if err != nil {
				return nil, err
			}
			if owned {
				continue
			}
		}
		flush := h.Class&0x8000 != 0 && h.Rrtype != dns.TypePTR
		h.Class = dns.ClassINET
		result = append(result, Record{Source: link.Source, Generation: link.Generation, Family: packet.Family, RR: rr, Flush: flush})
	}
	return result, nil
}
