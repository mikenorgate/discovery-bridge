package avahi

import (
	"context"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
)

func testBrowser(t *testing.T) *Browser {
	t.Helper()
	b, err := newBrowser(map[int]observation.Link{2: {Source: "lan-a", Generation: "link-a", Families: []int{4, 6}}})
	if err != nil {
		t.Fatal(err)
	}
	b.bus = newBus()
	b.bus.owner = ":1.42"
	query := Query{2, 4, "_example._tcp.local.", dns.TypePTR}
	b.paths["/browser/1"], b.queries[query] = query, "/browser/1"
	return b
}

func itemSignal(t *testing.T, name string, rr dns.RR, flags uint32) *dbus.Signal {
	t.Helper()
	raw, err := rdata(rr)
	if err != nil {
		t.Fatal(err)
	}
	return &dbus.Signal{Sender: ":1.42", Path: "/browser/1", Name: browserInterface + "." + name,
		Body: []any{int32(2), int32(0), rr.Header().Name, uint16(dns.ClassINET), rr.Header().Rrtype, raw, flags}}
}

func TestNameAndRawDataPreserveDNSLabelBytes(t *testing.T) {
	for _, name := range []string{`Office\032Printer._example._tcp.local.`, `Lab\046One._example._tcp.local.`, "Café._example._tcp.local.", `quote\034\092\000.local.`} {
		avahi, err := avahiName(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(avahi, "@ \"é") || catalog.NameKey(name) != catalog.NameKey(avahi) {
			t.Fatalf("label bytes changed: %q -> %q", name, avahi)
		}
	}
	for _, text := range []string{
		"host.local. 10 IN A 192.0.2.42", "host.local. 10 IN AAAA 2001:db8:1::42",
		`_example._tcp.local. 10 IN PTR Office\032Printer._example._tcp.local.`,
		`Office\032Printer._example._tcp.local. 10 IN SRV 0 0 1234 host.local.`,
		`Office\032Printer._example._tcp.local. 10 IN TXT "binary=\000\255" ""`,
	} {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := rdata(rr)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := rawRecord(rr.Header().Name, rr.Header().Rrtype, raw)
		if err != nil || (catalog.Answer{RR: rr}).Key() != (catalog.Answer{RR: decoded}).Key() {
			t.Fatal("Avahi RDATA changed", text, err)
		}
	}
	if _, err := rawRecord("owner.local.", dns.TypePTR, []byte{0xc0, 0}); err == nil {
		t.Fatal("compressed pointer accepted as Avahi RDATA")
	}
	if _, err := avahiName("host.example.org."); err == nil {
		t.Fatal("foreign name accepted")
	}
}

func TestHintScopeFlagsRemovalAndDependencies(t *testing.T) {
	rr, err := dns.NewRR("_example._tcp.local. 120 IN PTR Example._example._tcp.local.")
	if err != nil {
		t.Fatal(err)
	}
	b := testBrowser(t)
	for _, flags := range []uint32{0, 4 | 2, 4 | 8, 4 | 16, 4 | 32} {
		event, admitted, err := b.event(itemSignal(t, "ItemNew", rr, flags))
		if err != nil || admitted {
			t.Fatal(event, admitted, err)
		}
	}
	if _, admitted, err := b.event(itemSignal(t, "ItemRemove", rr, 4)); err != nil || admitted {
		t.Fatal("unseen removal admitted")
	}
	event, admitted, err := b.event(itemSignal(t, "ItemNew", rr, 4|1))
	if err != nil || !admitted || !event.Added || !event.Cached || event.Record.RR.Header().Ttl != 0 || event.Epoch != b.Epoch() {
		t.Fatal(event, admitted, err)
	}
	queries := dependencies(event.Query, event.Record.RR)
	if len(queries) != 2 || queries[0] != (Query{2, 4, "example._example._tcp.local.", dns.TypeSRV}) || queries[1].Type != dns.TypeTXT {
		t.Fatal(queries)
	}
	if _, admitted, err := b.event(itemSignal(t, "ItemRemove", rr, 4)); err != nil || !admitted {
		t.Fatal(err)
	}
	bad := itemSignal(t, "ItemNew", rr, 4)
	bad.Body[0] = int32(3)
	if _, _, err := b.event(bad); err == nil {
		t.Fatal("foreign interface accepted")
	}
	for _, query := range []Query{{99, 4, "host.local.", dns.TypeA}, {2, 5, "host.local.", dns.TypeA}, {2, 4, "foreign.example.org.", dns.TypeA}, {2, 4, "host.local.", dns.TypeCNAME}} {
		if _, err := b.normalize(query); err == nil {
			t.Fatal("invalid query accepted", query)
		}
	}
	canonical, err := b.normalize(Query{2, 4, "HOST.local", dns.TypeAAAA})
	if err != nil || canonical.Name != "host.local." {
		t.Fatal(canonical, err)
	}
}

func TestLocalEnumerationIsOnlyAHint(t *testing.T) {
	b := testBrowser(t)
	query := Query{2, 4, catalog.Enumeration, dns.TypePTR}
	b.paths["/browser/1"] = query
	rr, err := dns.NewRR(catalog.Enumeration + " 120 IN PTR _example._tcp.local.")
	if err != nil {
		t.Fatal(err)
	}
	event, admitted, err := b.event(itemSignal(t, "ItemNew", rr, 4|8))
	if err != nil || !admitted {
		t.Fatal(event, err)
	}
	queries := dependencies(event.Query, event.Record.RR)
	if len(queries) != 1 || queries[0] != (Query{2, 4, "_example._tcp.local.", dns.TypePTR}) {
		t.Fatal(queries)
	}
	cache := observation.New()
	if err := cache.Hint(event.Epoch, event.Record, true); err != nil {
		t.Fatal(err)
	}
	values, err := cache.Records(catalog.Moment{})
	if err != nil || len(values) != 0 {
		t.Fatal("LOCAL enumeration became evidence without remote packet", values, err)
	}
}

func TestOwnerLossOverflowAndFailureDiscardQueuedHints(t *testing.T) {
	rr, err := dns.NewRR("_example._tcp.local. 120 IN PTR Example._example._tcp.local.")
	if err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{"owner", "state", "overflow", "browser"} {
		t.Run(reason, func(t *testing.T) {
			b := testBrowser(t)
			b.bus.DeliverSignal("", "", itemSignal(t, "ItemNew", rr, 4))
			switch reason {
			case "owner":
				b.bus.DeliverSignal("", "", &dbus.Signal{Sender: busInterface, Name: busInterface + ".NameOwnerChanged", Body: []any{service, ":1.42", ":1.43"}})
			case "state":
				b.bus.DeliverSignal("", "", &dbus.Signal{Sender: ":1.42", Path: "/", Name: server + ".StateChanged", Body: []any{int32(3), ""}})
			case "overflow":
				for range cap(b.bus.signals) {
					b.bus.DeliverSignal("", "", itemSignal(t, "ItemNew", rr, 4))
				}
			case "browser":
				// Put the failure first; already returned hints are revoked by epoch loss.
				<-b.bus.signals
				b.bus.DeliverSignal("", "", &dbus.Signal{Sender: ":1.42", Path: "/browser/1", Name: browserInterface + ".Failure", Body: []any{"failed"}})
				b.bus.DeliverSignal("", "", itemSignal(t, "ItemNew", rr, 4))
			}
			if event, err := b.Next(context.Background()); err == nil {
				t.Fatal("failed epoch delivered queued hint", event)
			}
			if b.Err() == nil {
				t.Fatal("epoch remained healthy")
			}
		})
	}
}

func TestLinkConfigurationIsCopiedAndValidated(t *testing.T) {
	for _, links := range []map[int]observation.Link{nil, {0: {Source: "a", Generation: "g", Families: []int{4}}}, {2: {Source: "a", Generation: "g", Families: []int{4, 4}}}, {2: {Source: "a", Generation: "g", Families: []int{7}}}} {
		if _, err := newBrowser(links); err == nil {
			t.Fatal("invalid link accepted")
		}
	}
	links := map[int]observation.Link{2: {Source: "a", Generation: "g", Families: []int{6, 4}}}
	b, err := newBrowser(links)
	if err != nil {
		t.Fatal(err)
	}
	links[2].Families[0] = 7
	delete(links, 2)
	if b.links[2].Families[0] != 4 || b.links[2].Families[1] != 6 {
		t.Fatal("operator link input mutated browser")
	}
}
