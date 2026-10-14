package dnswire

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestReverseDelegationsAndSourceAdmission(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, prefix, address, zone string
	}{
		{name: "ipv4", prefix: "192.0.2.0/24", address: "192.0.2.10", zone: "2.0.192.in-addr.arpa."},
		{name: "ipv6", prefix: "2001:db8:1::/64", address: "2001:db8:1::10", zone: "0.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."},
	} {
		t.Run(test.name, func(t *testing.T) {
			prefix := netip.MustParsePrefix(test.prefix)
			zone, err := ReverseZone(prefix)
			if err != nil || zone != test.zone {
				t.Fatalf("zone=%s err=%v", zone, err)
			}
			owner, err := dns.ReverseAddr(test.address)
			if err != nil {
				t.Fatal(err)
			}
			address, err := ReverseIP(owner)
			if err != nil || address.String() != test.address || !LocalOrReverse(owner, []netip.Prefix{prefix}) {
				t.Fatalf("address=%v err=%v", address, err)
			}
		})
	}
	for _, owner := range []string{"example.com.", "2.0.192.in-addr.arpa.", "300.2.0.192.in-addr.arpa.", "10.100.51.198.in-addr.arpa."} {
		if LocalOrReverse(owner, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}) {
			t.Fatal("foreign reverse scope admitted", owner)
		}
	}
}

func FuzzReverseOwner(f *testing.F) {
	f.Add("10.2.0.192.in-addr.arpa.")
	f.Add("\\000.local.")
	f.Fuzz(func(t *testing.T, name string) {
		if !Name(name) {
			return
		}
		address, err := ReverseIP(name)
		if err == nil && !address.IsValid() {
			t.Fatal("reverse parsing created invalid address")
		}
	})
}
