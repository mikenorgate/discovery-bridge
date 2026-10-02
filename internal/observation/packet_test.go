package observation

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
)

func TestWholePacketAdmissionAndNativeAddressPolicy(t *testing.T) {
	scopes, err := policy.New(map[string][]string{"lan-a": {"192.0.2.0/24", "2001:db8:1::/64"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	links := map[int]Link{2: {Source: "lan-a", Generation: "link-a", Families: []int{4, 6}}}
	local := map[int][]netip.Addr{2: {netip.MustParseAddr("192.0.2.1")}}
	r := observed(t, "192.0.2.42", 4, 10)
	r.RR.Header().Class |= 0x8000
	message := dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Authoritative: true}, Answer: []dns.RR{r.RR}}
	wire, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	packet := Packet{Interface: 2, Generation: "link-a", Family: 4, Source: netip.MustParseAddr("192.0.2.42"), Destination: netip.MustParseAddr("224.0.0.251"), HopLimit: 255, SourcePort: 5353, DestinationPort: 5353, Wire: wire}
	values, err := Parse(packet, links, scopes, local, nil)
	if err != nil || len(values) != 1 || !values[0].Flush || values[0].RR.Header().Class != dns.ClassINET {
		t.Fatal(values, err)
	}
	for _, mutate := range []func(*Packet){
		func(p *Packet) { p.HopLimit = 254 },
		func(p *Packet) { p.Interface = 3 },
		func(p *Packet) { p.Generation = "old-link" },
		func(p *Packet) { p.SourcePort = 53 },
		func(p *Packet) { p.DestinationPort = 12345 },
		func(p *Packet) { p.Source = netip.MustParseAddr("198.51.100.42") },
		func(p *Packet) { p.Destination = netip.MustParseAddr("192.0.2.5") },
		func(p *Packet) { p.Wire = p.Wire[:len(p.Wire)-1] },
		func(p *Packet) { p.Wire = append(append([]byte{}, p.Wire...), []byte("junk")...) },
	} {
		bad := packet
		mutate(&bad)
		if values, err := Parse(bad, links, scopes, local, nil); err == nil || len(values) != 0 {
			t.Fatal("invalid packet partially installed records", values, err)
		}
	}
	packet.Source = local[2][0]
	if values, err := Parse(packet, links, scopes, local, nil); err != nil || len(values) != 0 {
		t.Fatal("local sender was reimported", values, err)
	}
	packet.Source = netip.MustParseAddr("192.0.2.42")
	if values, err := Parse(packet, links, scopes, local, func(string) (bool, error) { return true, nil }); err != nil || len(values) != 0 {
		t.Fatal("reserved exports were reimported", values, err)
	}
	packet.Family, packet.Source, packet.Destination = 6, netip.MustParseAddr("fe80::42"), netip.MustParseAddr("ff02::fb")
	if values, err := Parse(packet, links, scopes, local, nil); err != nil || len(values) != 1 {
		t.Fatal("IPv6 link-local packet provenance was rejected", values, err)
	}
}
