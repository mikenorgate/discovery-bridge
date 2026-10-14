package discoverydns

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/native"
)

type queryFunc func(context.Context, native.Question) (native.Result, error)

func (f queryFunc) Query(ctx context.Context, question native.Question) (native.Result, error) {
	return f(ctx, question)
}

func testSettings() Config {
	return Config{
		Schema: 1, Enabled: true, Listeners: []config.Endpoint{{Host: "127.0.0.12", Port: 1053}},
		Clients: []string{"127.0.0.1/32", "::1/128"}, NativeSocket: "/run/discovery-bridge/native.sock",
		CollectorUser: "discovery-bridge-collector", Nameservers: []string{"ns.example.test."},
		Mailbox: "hostmaster.example.test.", DefaultSource: "alpha",
		Links: []Link{
			{Source: "alpha", ServiceDomain: "alpha.devices.example.test.", HostDomain: "alpha.devices.example.test.", Prefixes: []string{"192.0.2.0/24", "2001:db8:1::/64"}},
			{Source: "beta", ServiceDomain: "beta.devices.example.test.", HostDomain: "beta.devices.example.test.", Prefixes: []string{"198.51.100.0/24", "2001:db8:2::/64"}},
		},
	}
}

func testRRs(t *testing.T, texts ...string) []dns.RR {
	t.Helper()
	result := make([]dns.RR, 0, len(texts))
	for _, text := range texts {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, rr)
	}
	return result
}

func testHandler(t *testing.T, settings Config, query queryFunc) *Handler {
	t.Helper()
	h, err := New(settings, query)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func ask(t *testing.T, h *Handler, name string, kind uint16) *dns.Msg {
	t.Helper()
	request := new(dns.Msg)
	request.SetQuestion(name, kind)
	reply := h.Answer(t.Context(), request)
	if reply.Id != request.Id || !reply.Response || !reply.Authoritative || reply.AuthenticatedData || reply.RecursionAvailable {
		t.Fatalf("invalid authoritative flags: %s", reply)
	}
	return reply
}

func TestSourceMappingAndNativeAddresses(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, source, owner, address string
		kind                         uint16
	}{
		{name: "alpha ipv4", source: "alpha", owner: "device.alpha.devices.example.test.", address: "192.0.2.10", kind: dns.TypeA},
		{name: "beta ipv4 collision", source: "beta", owner: "device.beta.devices.example.test.", address: "198.51.100.10", kind: dns.TypeA},
		{name: "native ipv6", source: "alpha", owner: "device.alpha.devices.example.test.", address: "2001:db8:1::10", kind: dns.TypeAAAA},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := "device.local. 120 IN " + dns.TypeToString[test.kind] + " " + test.address
			h := testHandler(t, testSettings(), func(_ context.Context, q native.Question) (native.Result, error) {
				if q.Source != test.source || q.DNS.Name != "device.local." || q.DNS.Qtype != test.kind {
					t.Fatalf("wrong native question: %+v", q)
				}
				return native.Result{Epoch: "one", Records: testRRs(t, record)}, nil
			})
			reply := ask(t, h, test.owner, test.kind)
			if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 || reply.Answer[0].Header().Name != test.owner || reply.Answer[0].Header().Ttl != 10 {
				t.Fatal(reply)
			}
			if !strings.Contains(reply.Answer[0].String(), test.address) {
				t.Fatal("address was synthesized or rewritten")
			}
		})
	}
}

func TestAdministrativeAnswersDoNotQueryLAN(t *testing.T) {
	t.Parallel()
	h := testHandler(t, testSettings(), func(context.Context, native.Question) (native.Result, error) {
		t.Error("administrative query reached LAN")
		return native.Result{}, nil
	})
	for _, test := range []struct {
		name, owner string
		kind        uint16
		answers     int
	}{
		{name: "soa apex", owner: "alpha.devices.example.test.", kind: dns.TypeSOA, answers: 1},
		{name: "ns apex", owner: "alpha.devices.example.test.", kind: dns.TypeNS, answers: 1},
		{name: "soa below apex", owner: "x.alpha.devices.example.test.", kind: dns.TypeSOA},
		{name: "ns below apex", owner: "x.alpha.devices.example.test.", kind: dns.TypeNS},
		{name: "ds below apex", owner: "x.alpha.devices.example.test.", kind: dns.TypeDS},
		{name: "unsigned ds apex", owner: "alpha.devices.example.test.", kind: dns.TypeDS},
		{name: "llq udp", owner: "_dns-llq._udp.alpha.devices.example.test.", kind: dns.TypeSRV},
		{name: "llq tcp", owner: "_dns-llq._tcp.alpha.devices.example.test.", kind: dns.TypeSRV},
		{name: "llq tls", owner: "_dns-llq-tls._tcp.alpha.devices.example.test.", kind: dns.TypeSRV},
		{name: "push", owner: "_dns-push-tls._tcp.alpha.devices.example.test.", kind: dns.TypeSRV},
		{name: "update udp", owner: "_dns-update._udp.alpha.devices.example.test.", kind: dns.TypeSRV},
		{name: "update tcp", owner: "_dns-update._tcp.alpha.devices.example.test.", kind: dns.TypeSRV},
		{name: "update tls", owner: "_dns-update-tls._tcp.alpha.devices.example.test.", kind: dns.TypeSRV},
		{name: "reverse browse", owner: "b._dns-sd._udp.2.0.192.in-addr.arpa.", kind: dns.TypePTR, answers: 2},
		{name: "reverse default", owner: "db._dns-sd._udp.2.0.192.in-addr.arpa.", kind: dns.TypePTR, answers: 1},
		{name: "reverse legacy", owner: "lb._dns-sd._udp.2.0.192.in-addr.arpa.", kind: dns.TypePTR, answers: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			reply := ask(t, h, test.owner, test.kind)
			if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != test.answers {
				t.Fatal(reply)
			}
			if test.answers == 0 && (len(reply.Ns) != 1 || reply.Ns[0].Header().Ttl != 10) {
				t.Fatal("negative cache metadata missing")
			}
			if test.kind == dns.TypeSOA && test.answers == 1 {
				soa, ok := reply.Answer[0].(*dns.SOA)
				if !ok || soa.Serial != 0 || soa.Minttl != 10 || soa.Refresh != 7200 || soa.Retry != 3600 || soa.Expire != 86400 {
					t.Fatal("invalid discovery soa")
				}
			}
		})
	}
}

func TestNODATAAndBackendFailureAreDistinct(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		err  error
		code int
	}{
		{name: "no answer", code: dns.RcodeSuccess},
		{name: "busy", err: native.ErrBusy, code: dns.RcodeServerFailure},
		{name: "lost epoch", err: native.ErrUnavailable, code: dns.RcodeServerFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := testHandler(t, testSettings(), func(context.Context, native.Question) (native.Result, error) {
				return native.Result{Epoch: "one", Records: []dns.RR{}}, test.err
			})
			reply := ask(t, h, "absent.alpha.devices.example.test.", dns.TypeAAAA)
			if reply.Rcode != test.code || len(reply.Answer) != 0 {
				t.Fatal(reply)
			}
		})
	}
}

func TestRichDomainsServiceTargetsAndOpaqueTXT(t *testing.T) {
	t.Parallel()
	settings := testSettings()
	settings.Links[0].ServiceDomain = "Building\\032One.devices.example.test."
	settings.Links[0].HostDomain = "bldg-one.devices.example.test."
	records := testRRs(t,
		"_demo._tcp.local. 120 IN PTR Caf\\195\\169\\032Printer._demo._tcp.local.",
		"Caf\\195\\169\\032Printer._demo._tcp.local. 120 IN SRV 0 0 8080 printer.local.",
		"Caf\\195\\169\\032Printer._demo._tcp.local. 120 IN TXT \"adminurl=http://printer.local/\" \"opaque=\\000\\255\"",
		"printer.local. 120 IN A 192.0.2.10",
	)
	h := testHandler(t, settings, func(context.Context, native.Question) (native.Result, error) {
		return native.Result{Epoch: "one", Records: records}, nil
	})
	reply := ask(t, h, "_demo._tcp."+settings.Links[0].ServiceDomain, dns.TypePTR)
	if len(reply.Answer) != 1 || len(reply.Extra) != 3 {
		t.Fatal(reply)
	}
	for _, rr := range reply.Extra {
		switch value := rr.(type) {
		case *dns.SRV:
			if value.Target != "printer.bldg-one.devices.example.test." {
				t.Fatal("srv target did not use host domain")
			}
		case *dns.TXT:
			original, ok := records[2].(*dns.TXT)
			if !ok || !slices.Equal(value.Txt, original.Txt) {
				t.Fatal("opaque txt changed")
			}
		case *dns.A:
			if value.Hdr.Name != "printer.bldg-one.devices.example.test." {
				t.Fatal("additional address used service domain")
			}
		}
	}
}

func TestCNAMEAndReverseTranslation(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, owner, native, target string
		kind                        uint16
		records                     []string
	}{
		{name: "local cname", owner: "alias.alpha.devices.example.test.", native: "alias.local.", target: "device.alpha.devices.example.test.", kind: dns.TypeA,
			records: []string{"alias.local. 120 IN CNAME device.local.", "device.local. 120 IN A 192.0.2.10"}},
		{name: "external cname", owner: "alias.alpha.devices.example.test.", native: "alias.local.", target: "outside.example.test.", kind: dns.TypeA,
			records: []string{"alias.local. 120 IN CNAME outside.example.test."}},
		{name: "reverse", owner: "10.2.0.192.in-addr.arpa.", native: "10.2.0.192.in-addr.arpa.", target: "device.alpha.devices.example.test.", kind: dns.TypePTR,
			records: []string{"10.2.0.192.in-addr.arpa. 120 IN PTR device.local."}},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := testHandler(t, testSettings(), func(_ context.Context, q native.Question) (native.Result, error) {
				if q.DNS.Name != test.native {
					t.Fatal("reverse query name was changed")
				}
				return native.Result{Epoch: "one", Records: testRRs(t, test.records...)}, nil
			})
			reply := ask(t, h, test.owner, test.kind)
			if len(reply.Answer) != 1 || !strings.Contains(reply.Answer[0].String(), test.target) {
				t.Fatal(reply)
			}
		})
	}
}

func TestUnusableAddressesAndServicesAreSuppressed(t *testing.T) {
	t.Parallel()
	records := testRRs(t,
		"host.local. 120 IN A 169.254.10.1",
		"host.local. 120 IN AAAA fe80::1",
		"host.local. 120 IN A 198.51.100.10",
		"host.local. 120 IN A 0.0.0.0",
		"service._demo._tcp.local. 120 IN SRV 0 0 8080 host.local.",
		"_demo._tcp.local. 120 IN PTR service._demo._tcp.local.",
	)
	h := testHandler(t, testSettings(), func(context.Context, native.Question) (native.Result, error) {
		return native.Result{Epoch: "one", Records: records}, nil
	})
	for _, q := range []dns.Question{
		{Name: "host.alpha.devices.example.test.", Qtype: dns.TypeA},
		{Name: "host.alpha.devices.example.test.", Qtype: dns.TypeAAAA},
		{Name: "service._demo._tcp.alpha.devices.example.test.", Qtype: dns.TypeSRV},
		{Name: "_demo._tcp.alpha.devices.example.test.", Qtype: dns.TypePTR},
	} {
		reply := ask(t, h, q.Name, q.Qtype)
		if len(reply.Answer) != 0 || reply.Rcode != dns.RcodeSuccess {
			t.Fatal(reply)
		}
	}
}

func TestNSECAndNSEC3AreGeneratedFromANY(t *testing.T) {
	t.Parallel()
	for _, kind := range []uint16{dns.TypeNSEC, dns.TypeNSEC3} {
		t.Run(dns.TypeToString[kind], func(t *testing.T) {
			h := testHandler(t, testSettings(), func(_ context.Context, q native.Question) (native.Result, error) {
				if q.DNS.Qtype != dns.TypeANY {
					t.Fatal("denial question did not use actual any")
				}
				return native.Result{Epoch: "one", Records: testRRs(t,
					"host.local. 120 IN A 192.0.2.10", "host.local. 120 IN TXT \"x=y\"",
					"host.local. 120 IN NSEC host.local. A TXT",
				)}, nil
			})
			reply := ask(t, h, "host.alpha.devices.example.test.", kind)
			if len(reply.Answer) != 1 || reply.Answer[0].Header().Rrtype != kind {
				t.Fatal(reply)
			}
			switch denial := reply.Answer[0].(type) {
			case *dns.NSEC:
				if denial.NextDomain == denial.Hdr.Name || !slices.Contains(denial.TypeBitMap, dns.TypeNSEC) || strings.HasSuffix(denial.NextDomain, ".local.") {
					t.Fatal("mdns denial was forwarded or asserted an entire zone")
				}
			case *dns.NSEC3:
				if denial.Hash != dns.SHA1 || denial.Iterations != 0 || denial.Salt != "" || strings.HasPrefix(denial.Hdr.Name, denial.NextDomain+".") {
					t.Fatal("invalid narrow nsec3 parameters")
				}
			}
			if _, err := reply.Pack(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOutOfScopeAndTransferQueriesAreRefused(t *testing.T) {
	t.Parallel()
	h := testHandler(t, testSettings(), func(context.Context, native.Question) (native.Result, error) {
		t.Error("refused question reached native backend")
		return native.Result{}, nil
	})
	for _, owner := range []string{"host.local.", "host.devices.example.test.", "host.security.devices.example.test.", "example.com."} {
		request := new(dns.Msg)
		request.SetQuestion(owner, dns.TypeA)
		if reply := h.Answer(t.Context(), request); reply.Rcode != dns.RcodeRefused {
			t.Fatal(reply)
		}
	}
	for _, kind := range []uint16{dns.TypeAXFR, dns.TypeIXFR} {
		request := new(dns.Msg)
		request.SetQuestion("alpha.devices.example.test.", kind)
		if reply := h.Answer(t.Context(), request); reply.Rcode != dns.RcodeRefused {
			t.Fatal(reply)
		}
	}
	update := new(dns.Msg)
	update.SetUpdate("alpha.devices.example.test.")
	if reply := h.Answer(t.Context(), update); reply.Rcode != dns.RcodeRefused {
		t.Fatal(reply)
	}
}

func TestNoAddressSynthesisAndACL(t *testing.T) {
	t.Parallel()
	h := testHandler(t, testSettings(), func(context.Context, native.Question) (native.Result, error) {
		return native.Result{Epoch: "one", Records: testRRs(t, "host.local. 120 IN A 192.0.2.10")}, nil
	})
	if reply := ask(t, h, "host.alpha.devices.example.test.", dns.TypeAAAA); len(reply.Answer) != 0 || reply.Rcode != dns.RcodeSuccess {
		t.Fatal("frontend synthesized an address")
	}
	if !h.admitted(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}) || h.admitted(&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345}) {
		t.Fatal("dns client admission changed")
	}
}

func TestConfigurationRejectsUnsafeAuthority(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		edit func(*Config)
	}{
		{name: "wildcard listener", edit: func(c *Config) { c.Listeners[0].Host = "::" }},
		{name: "nameserver inside zone", edit: func(c *Config) { c.Nameservers = []string{"ns.alpha.devices.example.test."} }},
		{name: "duplicate source", edit: func(c *Config) { c.Links[1].Source = c.Links[0].Source }},
		{name: "overlap", edit: func(c *Config) { c.Links[1].Prefixes = []string{"192.0.2.0/24"} }},
		{name: "nested zone", edit: func(c *Config) { c.Links[1].ServiceDomain = "beta.alpha.devices.example.test." }},
		{name: "absent default", edit: func(c *Config) { c.DefaultSource = "other" }},
		{name: "nonaligned reverse", edit: func(c *Config) { c.Links[1].Prefixes = []string{"198.51.100.0/25"} }},
		{name: "relative zone", edit: func(c *Config) { c.Links[1].ServiceDomain = "relative" }},
		{name: "local zone", edit: func(c *Config) { c.Links[1].ServiceDomain = "alpha.local." }},
	} {
		t.Run(test.name, func(t *testing.T) {
			settings := testSettings()
			test.edit(&settings)
			if settings.Validate() == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func FuzzAuthoritativeQuestion(f *testing.F) {
	request := new(dns.Msg)
	request.SetQuestion("device.alpha.devices.example.test.", dns.TypeA)
	wire, err := request.Pack()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte{0xc0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1232 {
			return
		}
		message := new(dns.Msg)
		if message.Unpack(data) != nil {
			return
		}
		h := testHandler(t, testSettings(), func(context.Context, native.Question) (native.Result, error) {
			return native.Result{}, errors.New("unavailable")
		})
		reply := h.Answer(t.Context(), message)
		if reply.AuthenticatedData || reply.RecursionAvailable {
			t.Fatal("untrusted discovery gained validation or recursion authority")
		}
	})
}
