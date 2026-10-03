package translation

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/gateway"
	"github.com/mikenorgate/discovery-bridge/internal/policy"
	"github.com/mikenorgate/discovery-bridge/internal/responder"
	"github.com/mikenorgate/discovery-bridge/internal/state"
)

func TestReadyMappingSurvivesFeedAndDNSSDThenWithdraws(t *testing.T) {
	ctx := context.Background()
	s := fixture(t)
	scriptedObserver(t, s)
	value := s.observer.observe(ctx, s.settings, s.spaces, s.lans)
	s.current.Store(&value)
	now := value.observed
	scopes, err := policy.New(map[string][]string{"lan-a": {"192.0.2.0/24", "2001:db8:1::/64"}}, []string{s.spaces.Pool.String(), s.spaces.NAT64.String()})
	if err != nil {
		t.Fatal(err)
	}
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
	var records []catalog.Record
	var answers []catalog.Answer
	for i, fields := range [][3]string{
		{catalog.Enumeration, "PTR", "_example._tcp.local."},
		{"_example._tcp.local.", "PTR", "Sensor._example._tcp.local."},
		{"Sensor._example._tcp.local.", "SRV", "0 0 8080 sensor.local."},
		{"Sensor._example._tcp.local.", "TXT", `"version=1"`},
		{"sensor.local.", "AAAA", "2001:db8:1::42"},
	} {
		r := catalog.Record{ID: string(rune('a' + i)), Name: fields[0], Type: fields[1], Data: fields[2], Source: "lan-a", Expires: now.Wall.Add(30 * time.Second)}
		rr, err := r.RR(30)
		if err != nil {
			t.Fatal(err)
		}
		records, answers = append(records, r), append(answers, catalog.Answer{RR: rr, Source: r.Source})
	}
	if err := feed.Publish(answers, now.Wall, now); err != nil {
		t.Fatal(err)
	}
	node := catalog.NewNodeFeed(scopes, &s.spaces)
	refresh := func(moment catalog.Moment) {
		t.Helper()
		nonce, err := node.BeginRequest()
		if err != nil {
			t.Fatal(err)
		}
		data, err := feed.Read(nonce, moment)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := node.Accept(data, moment); err != nil {
			t.Fatal(err)
		}
	}
	refresh(now)
	r := responder.New()
	for _, question := range []responder.Question{
		{Name: "sensor.local.", Type: dns.TypeA, Class: dns.ClassINET},
		{Name: "_example._tcp.local.", Type: dns.TypePTR, Class: dns.ClassINET},
		{Name: "Sensor._example._tcp.local.", Type: dns.TypeSRV, Class: dns.ClassINET},
	} {
		r = responder.New() // Each question represents an independent listener.
		result, err := r.Build(responder.Query{Questions: []responder.Question{question}, Unicast: []bool{false}}, node.View(now), now.Mono, 5353, 6, 1232, false)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, reply := range result.Replies {
			var message dns.Msg
			if err := message.Unpack(reply.Wire); err != nil {
				t.Fatal(err)
			}
			for _, rr := range append(message.Answer, message.Extra...) {
				if address, ok := rr.(*dns.A); ok && address.A.String() == "198.51.100.42" && address.Hdr.Ttl == 10 && address.Hdr.Name == "sensor.local." {
					found = true
				}
			}
			r.NoteSent(reply, now.Mono)
		}
		if !found {
			t.Fatal("DNS-SD/direct response omitted ready original-name address", question)
		}
	}
	identities, err := state.Open(ctx, filepath.Join(t.TempDir(), "identities.db"), "bridge")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := identities.Close(); err != nil {
			t.Error(err)
		}
	})
	compiled, err := identities.Compile(ctx, s.Render(records, now), now.Wall)
	if err != nil {
		t.Fatal(err)
	}
	alias := false
	for _, answer := range compiled {
		if address, ok := answer.RR.(*dns.A); ok && address.A.String() == "198.51.100.42" && address.Hdr.Name != "sensor.local." {
			alias = true
		}
	}
	if !alias {
		t.Fatal("LAN stable alias compiler omitted ready translation")
	}
	// No new sample, source publication or translation allocation is needed for
	// the node to expire a derived address while keeping its native service.
	later := catalog.Moment{Wall: now.Wall.Add(lease), Mono: now.Mono + lease}
	view := node.View(later)
	if len(view) != 5 {
		t.Fatal("native service did not survive derived expiry", view)
	}
	for _, answer := range view {
		if answer.RR.Header().Rrtype == dns.TypeA {
			t.Fatal("derived mapping lease survived")
		}
	}
	withdrawals, err := r.Withdrawals(view, 6)
	if err != nil {
		t.Fatal(err)
	}
	goodbye := false
	for _, reply := range withdrawals {
		for _, answer := range reply.Records {
			if answer.RR.Header().Rrtype == dns.TypeA && answer.RR.Header().Ttl == 0 {
				goodbye = true
			}
		}
	}
	if !goodbye {
		t.Fatal("derived address omitted from pod goodbyes")
	}
	refresh(later)
	if len(node.View(later)) != 5 {
		t.Fatal("expired sampler renewed address through catalog heartbeat")
	}
}
