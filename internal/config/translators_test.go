package config

import (
	"net/netip"
	"reflect"
	"testing"
)

func translatorFixture() *Translators {
	return &Translators{
		Translation: Translation{NAT64Prefix: "2001:db8:64::/96", NAT46Pool: "198.51.100.0/24", Reserved: []string{"198.51.100.1"}},
		IP:          []string{"/usr/sbin/ip"}, Systemctl: []string{"/usr/bin/systemctl"},
		NAT46: &Translator{Interface: "xlate46", Unit: "translator46.service", Config: "/etc/translator46.conf", Binary: "/usr/sbin/tayga", IPv4: "198.51.100.1", IPv6: "2001:db8:46:ffff::1", Prefix: "2001:db8:46::/96", DataDirectory: "/var/lib/translator46"},
		NAT64: &Translator{Interface: "xlate64", Unit: "translator64.service", Config: "/etc/translator64.conf", Binary: "/usr/sbin/tayga", IPv4: "203.0.113.1", IPv6: "2001:db8:64:ffff::1", Prefix: "2001:db8:64::/96", DataDirectory: "/var/lib/translator64", DynamicPool: "203.0.113.0/24"},
	}
}

func TestTranslatorAuthorityIsExplicitAndIndependentOfLAN(t *testing.T) {
	for _, change := range []func(*Translators){
		func(c *Translators) { c.IP = []string{"ip"} },
		func(c *Translators) { c.Systemctl = nil },
		func(c *Translators) { c.NAT46, c.NAT64 = nil, nil },
		func(c *Translators) { c.NAT46.Interface = "lan with space" },
		func(c *Translators) { c.NAT46.Unit = "translator46.timer" },
		func(c *Translators) { c.NAT46.Config = "/etc/../tmp/config" },
		func(c *Translators) { c.NAT46.Binary = "tayga" },
		func(c *Translators) { c.NAT46.IPv6 = "fe80::1" },
		func(c *Translators) { c.NAT46.Prefix = c.NAT64Prefix },
		func(c *Translators) { c.Reserved = nil },
		func(c *Translators) { c.NAT46.DynamicPool = "192.0.2.0/24" },
		func(c *Translators) { c.NAT64.DynamicPool = c.NAT46Pool },
		func(c *Translators) { c.NAT64.Prefix = "2001:db8:65::/96" },
		func(c *Translators) { c.NAT64.Interface = c.NAT46.Interface },
		func(c *Translators) { c.NAT64.Config = c.NAT46.Config },
	} {
		c := translatorFixture()
		change(c)
		if err := c.Validate(); err == nil {
			t.Fatal("invalid translator authority accepted", c)
		}
	}
	r := routerFixture()
	r.Translators = translatorFixture()
	r.Sources["lan-a"] = []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"}
	r.Forbidden = make([]string, 0, 8)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	scopes, err := r.Policy()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Forbidden, []string{}) {
		t.Fatal("Policy changed configured exclusions")
	}
	for _, raw := range []string{"198.51.100.42", "203.0.113.42", "2001:db8:46::42", "2001:db8:64::42"} {
		if err := scopes.CheckAddress("lan-a", netip.MustParseAddr(raw)); err == nil {
			t.Fatal("translator address admitted as native", raw)
		}
	}
	r.Translators.NAT46.Interface = r.Interfaces[0].Interface
	if err := r.Validate(); err == nil {
		t.Fatal("translator TUN accepted as discovery LAN")
	}
	r.Translators = nil
	if err := r.Validate(); err != nil {
		t.Fatal("disabled translation changed native router", err)
	}
}
