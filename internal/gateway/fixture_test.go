package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/responder"
)

func TestClientPreservesCompleteDNSSDChainAndOpaqueTXT(t *testing.T) {
	feed, err := NewFeed(context.Background(), testPolicy(t), filepath.Join(t.TempDir(), "generation.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := feed.Close(); err != nil {
			t.Error(err)
		}
	})
	var answers []catalog.Answer
	for _, text := range []string{
		"_services._dns-sd._udp.local. 20 IN PTR _http._tcp.local.",
		"_http._tcp.local. 20 IN PTR Demo._http._tcp.local.",
		"Demo._http._tcp.local. 20 IN SRV 0 0 8080 sensor.local.",
		`Demo._http._tcp.local. 20 IN TXT "opaque=\255\000"`,
		"sensor.local. 20 IN A 192.0.2.42", "sensor.local. 20 IN AAAA 2001:db8:1::42",
	} {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		answers = append(answers, catalog.Answer{RR: rr, Source: "lan-a", Unique: rr.Header().Rrtype == dns.TypeSRV || rr.Header().Rrtype == dns.TypeTXT})
	}
	now := catalog.Now()
	if err := feed.Publish(answers, now.Wall, now); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	lookups := NewLookups(func(_ context.Context, q responder.Question) error {
		if q.Name != "missing.local." || q.Type != dns.TypeAAAA {
			t.Error(q)
		}
		calls.Add(1)
		return nil
	})
	t.Cleanup(lookups.Close)
	endpoint, ctx := startAPI(t, CatalogAPI(feed, lookups), []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	client, err := NewClient(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	node := catalog.NewNodeFeed(testPolicy(t), nil)
	if _, err := client.Refresh(ctx, node); err != nil {
		t.Fatal(err)
	}
	view := node.View(catalog.Now())
	if len(view) != 6 {
		t.Fatal("complete DNS-SD chain was not preserved", view)
	}
	for _, answer := range view {
		if txt, ok := answer.RR.(*dns.TXT); ok {
			message := dns.Msg{Answer: []dns.RR{txt}}
			wire, err := message.Pack()
			if err != nil || !bytes.Contains(wire, []byte("opaque=\xff\x00")) || !answer.Unique {
				t.Fatal("opaque TXT or ownership changed", answer, err)
			}
		}
	}
	value, err := (responder.Query{Questions: []responder.Question{{Name: "missing.local.", Type: dns.TypeAAAA, Class: 1}}}).Lookup()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := client.Post(ctx, "/v1/lookup", data, 202); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("duplicate demand was not coalesced", calls.Load())
	}
	if _, err := client.Post(ctx, "/v1/publications", []byte(`{"schema":1}`), 200); err == nil {
		t.Fatal("node endpoint accepted publication")
	}
	feed.Withdraw()
	if _, err := client.Refresh(ctx, node); err != nil {
		t.Fatal(err)
	}
	if len(node.View(catalog.Now())) != 0 {
		t.Fatal("withdrawn records survived refresh")
	}
}
