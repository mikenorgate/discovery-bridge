package discoverydns

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/dnswire"
	"github.com/mikenorgate/discovery-bridge/internal/native"
)

func TestDependentRecordsDoNotOutliveAddress(t *testing.T) {
	t.Parallel()
	records := testRRs(t,
		"_http._tcp.local. 120 IN PTR Device._http._tcp.local.",
		"Device._http._tcp.local. 120 IN SRV 0 0 80 alias.local.",
		"alias.local. 120 IN CNAME host.local.",
		"host.local. 3 IN A 192.0.2.10")
	h := testHandler(t, testSettings(), func(context.Context, native.Question) (native.Result, error) {
		return native.Result{Epoch: "one", Records: records}, nil
	})
	reply := ask(t, h, "_http._tcp.alpha.devices.example.test.", dns.TypePTR)
	if len(reply.Answer) != 1 || len(reply.Extra) != 3 {
		t.Fatal(reply)
	}
	for _, record := range append(reply.Answer, reply.Extra...) {
		if record.Header().Ttl != 3 {
			t.Fatal("dependent record outlives supporting address", reply)
		}
	}
	if records[0].Header().Ttl != 120 {
		t.Fatal("backend-owned record mutated")
	}
}

func TestNSECSuccessorBounds(t *testing.T) {
	t.Parallel()
	for _, owner := range []string{
		"device.alpha.devices.example.test.",
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61) + ".",
		strings.Repeat("Z", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61) + ".",
	} {
		if !dnswire.Name(owner) {
			t.Fatal("invalid fixture")
		}
		next := successor(owner)
		if !dnswire.Name(next) || next == owner {
			t.Fatal("invalid or whole-zone NSEC interval", next)
		}
		wire := make([]byte, 1024)
		if _, err := dns.PackRR(&dns.NSEC{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 10}, NextDomain: next, TypeBitMap: []uint16{dns.TypeA, dns.TypeNSEC}}, wire, 0, nil, false); err != nil {
			t.Fatal(err)
		}
	}
}
