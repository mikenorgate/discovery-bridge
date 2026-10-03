package translation

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/config"
	"github.com/mikenorgate/discovery-bridge/internal/gateway"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
	"github.com/mikenorgate/discovery-bridge/internal/services"
)

func TestServiceVIPUsesOnlyExistingMappingAndIndependentExpiry(t *testing.T) {
	ctx := context.Background()
	s := fixture(t)
	now := catalog.Now()
	vip := netip.MustParseAddr("2001:db8:ff00::22")
	scopes, err := policy.New(map[string][]string{"kubernetes": {"2001:db8:ff00::/60"}}, []string{s.spaces.Pool.String(), s.spaces.NAT64.String()})
	if err != nil {
		t.Fatal(err)
	}
	intent := services.Intent{Service: config.Service{Namespace: "services", Name: "example", Port: "http", Type: "_http._tcp", Instance: "Example", TXT: map[string]string{}, Subtypes: []string{}}, UID: "service-uid", Addresses: []string{vip.String()}, ServicePort: 80}
	records, err := services.Records([]services.Intent{intent}, now.Wall.Add(services.Lease), "kubernetes", scopes)
	if err != nil {
		t.Fatal(err)
	}
	sample := &readiness{observed: now, maps: map[netip.Addr]netip.Addr{}, generation: 1}
	s.current.Store(sample)
	if len(s.Render(records, now)) != len(records) || len(sample.maps) != 0 {
		t.Fatal("Service discovery allocated an absent mapping")
	}
	// This immutable sample models the already-loaded mapping. The real TUN
	// fixture qualifies the sampler separately from record delivery.
	s.current.Store(&readiness{observed: now, maps: map[netip.Addr]netip.Addr{vip: netip.MustParseAddr("198.51.100.42")}, generation: 2})
	feed, err := gateway.NewFeed(ctx, scopes, filepath.Join(t.TempDir(), "feed"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := feed.Close(); err != nil {
			t.Error(err)
		}
	})
	feed.Render = s.Render
	var answers []catalog.Answer
	for _, record := range records {
		rr, err := record.RR(15)
		if err != nil {
			t.Fatal(err)
		}
		answers = append(answers, catalog.Answer{RR: rr, Source: record.Source})
	}
	if err := feed.Publish(answers, now.Wall, now); err != nil {
		t.Fatal(err)
	}
	node := catalog.NewNodeFeed(scopes, &s.spaces)
	nonce, err := node.BeginRequest()
	if err != nil {
		t.Fatal(err)
	}
	data, err := feed.Read(nonce, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := node.Accept(data, now); err != nil {
		t.Fatal(err)
	}
	view := node.View(now)
	if len(view) != 6 {
		t.Fatal("mapped Service graph absent", view)
	}
	for _, answer := range view {
		if srv, ok := answer.RR.(*dns.SRV); ok {
			if srv.Port != 80 || srv.Hdr.Ttl != 10 {
				t.Fatal("translation changed external port or extended lease", srv)
			}
			found := false
			for _, extra := range catalog.Additionals(answer, view) {
				if a, ok := extra.RR.(*dns.A); ok && a.A.String() == "198.51.100.42" {
					found = true
				}
			}
			if !found {
				t.Fatal("Service SRV omitted its ready translated VIP")
			}
		}
	}
	for _, test := range []struct {
		offset time.Duration
		count  int
	}{{lease, 5}, {services.Lease, 0}} {
		later := catalog.Moment{Wall: now.Wall.Add(test.offset), Mono: now.Mono + test.offset}
		if len(node.View(later)) != test.count {
			t.Fatal("mapping or Service lease renewed by the feed", test.offset, node.View(later))
		}
		for _, answer := range node.View(later) {
			if answer.RR.Header().Rrtype == dns.TypeA {
				t.Fatal("expired Service translation survived")
			}
		}
	}
}
