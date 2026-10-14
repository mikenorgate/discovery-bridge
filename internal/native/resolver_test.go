package native

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/miekg/dns"
	"github.com/mikenorgate/discovery-bridge/internal/catalog"
	"github.com/mikenorgate/discovery-bridge/internal/observation"
)

func fixtureResolver(t *testing.T, start Start) *Resolver {
	t.Helper()
	r, err := New("generation", map[string][]netip.Prefix{
		"alpha": {netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8:1::/64")},
		"beta":  {netip.MustParsePrefix("198.51.100.0/24")},
	}, start)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func ingestFixture(t *testing.T, r *Resolver, source, text string) {
	t.Helper()
	rr, err := dns.NewRR(text)
	if err != nil {
		t.Fatal(err)
	}
	now := catalog.Now().Mono
	if err := r.Ingest([]observation.Record{{Source: source, Generation: "generation", Family: 4, RR: rr}}, now); err != nil {
		t.Fatal(err)
	}
}

func TestCachedAnswerDoesNotQueryAndPreservesSource(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	r := fixtureResolver(t, func(context.Context, Question) (func() error, error) {
		calls.Add(1)
		return nil, errors.New("cache should answer")
	})
	ingestFixture(t, r, "alpha", "Device.local. 120 IN A 192.0.2.10")
	ingestFixture(t, r, "beta", "Device.local. 120 IN A 198.51.100.10")
	for _, source := range []string{"alpha", "beta"} {
		result, err := r.Query(t.Context(), Question{Source: source, DNS: dns.Question{Name: "DEVICE.local.", Qtype: dns.TypeA, Qclass: dns.ClassINET}})
		if err != nil || len(result.Records) != 1 || result.Epoch != "generation" {
			t.Fatalf("source %s: %+v %v", source, result, err)
		}
		address, ok := result.Records[0].(*dns.A)
		if !ok || source == "alpha" && address.A.String() != "192.0.2.10" || source == "beta" && address.A.String() != "198.51.100.10" {
			t.Fatal("answer crossed source boundary")
		}
		result.Records[0].Header().Ttl = 999
	}
	if calls.Load() != 0 {
		t.Fatal("cached answer caused multicast")
	}
}

func TestQueryOvertakingQueuedIngestDoesNotInvalidateEpoch(t *testing.T) {
	r := fixtureResolver(t, func(context.Context, Question) (func() error, error) {
		return nil, errors.New("cached answers must not start multicast")
	})
	ingestFixture(t, r, "alpha", "existing.local. 120 IN A 192.0.2.10")
	received := catalog.Now().Mono
	question := Question{Source: "alpha", DNS: dns.Question{Name: "existing.local.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	if _, err := r.Query(t.Context(), question); err != nil {
		t.Fatal(err)
	}
	// The caller sampled time before a query obtained the cache lock. This is
	// normal scheduling, not a backwards jump of the monotonic clock.
	rr, err := dns.NewRR("queued.local. 10 IN A 192.0.2.11")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Ingest([]observation.Record{{Source: "alpha", Generation: "generation", Family: 4, RR: rr}}, received); err != nil {
		t.Fatal("queued ingest invalidated a healthy epoch:", err)
	}
	question.DNS.Name = "queued.local."
	result, err := r.Query(t.Context(), question)
	if err != nil || len(result.Records) != 1 || result.Records[0].Header().Ttl > 10 {
		t.Fatalf("queued observation lost or lifetime extended: %+v %v", result, err)
	}
}

func TestColdLookupTimingAndRetransmission(t *testing.T) {
	for _, test := range []struct {
		name  string
		kind  uint16
		calls int32
	}{
		{name: "typed avahi interest", kind: dns.TypeA, calls: 1},
		{name: "genuine any at zero one three", kind: dns.TypeANY, calls: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls, releases atomic.Int32
				r := fixtureResolver(t, func(context.Context, Question) (func() error, error) {
					calls.Add(1)
					return func() error { releases.Add(1); return nil }, nil
				})
				began := time.Now()
				result, err := r.Query(t.Context(), Question{Source: "alpha", DNS: dns.Question{Name: "absent.local.", Qtype: test.kind, Qclass: dns.ClassINET}})
				synctest.Wait()
				if err != nil || len(result.Records) != 0 || result.Epoch != "generation" || time.Since(began) != 6*time.Second {
					t.Fatalf("cold result=%+v err=%v elapsed=%v", result, err, time.Since(began))
				}
				if calls.Load() != test.calls || releases.Load() != test.calls {
					t.Fatalf("calls=%d releases=%d", calls.Load(), releases.Load())
				}
			})
		})
	}
}

func TestCoalescedCallerCancellationDoesNotWithdrawOther(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls, released atomic.Int32
		r := fixtureResolver(t, func(context.Context, Question) (func() error, error) {
			calls.Add(1)
			return func() error { released.Add(1); return nil }, nil
		})
		question := Question{Source: "alpha", DNS: dns.Question{Name: "device.local.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
		first, cancel := context.WithCancel(t.Context())
		defer cancel()
		var group sync.WaitGroup
		var firstErr, secondErr error
		var second Result
		group.Go(func() { _, firstErr = r.Query(first, question) })
		group.Go(func() { second, secondErr = r.Query(t.Context(), question) })
		synctest.Wait()
		cancel()
		synctest.Wait()
		ingestFixture(t, r, "alpha", "device.local. 120 IN A 192.0.2.10")
		group.Wait()
		synctest.Wait()
		if !errors.Is(firstErr, context.Canceled) || secondErr != nil || len(second.Records) != 1 {
			t.Fatalf("first=%v second=%+v %v", firstErr, second, secondErr)
		}
		if calls.Load() != 1 || released.Load() != 1 {
			t.Fatal("coalesced query did not own exactly one interest")
		}
	})
}

func TestNewCallerDoesNotJoinAbandonedInterest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cleanupStarted, releaseCleanup := make(chan struct{}), make(chan struct{})
		var calls atomic.Int32
		r := fixtureResolver(t, func(context.Context, Question) (func() error, error) {
			if calls.Add(1) == 1 {
				return func() error { close(cleanupStarted); <-releaseCleanup; return nil }, nil
			}
			return nil, nil
		})
		question := Question{Source: "alpha", DNS: dns.Question{Name: "host.local.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
		first, cancel := context.WithCancel(t.Context())
		firstDone := make(chan error, 1)
		go func() { _, err := r.Query(first, question); firstDone <- err }()
		synctest.Wait()
		cancel()
		if err := <-firstDone; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		<-cleanupStarted
		secondDone := make(chan error, 1)
		go func() { _, err := r.Query(t.Context(), question); secondDone <- err }()
		synctest.Wait()
		if calls.Load() != 1 {
			t.Error("new interest started before abandoned cleanup joined")
		}
		close(releaseCleanup)
		synctest.Wait()
		ingestFixture(t, r, "alpha", "host.local. 120 IN A 192.0.2.10")
		if err := <-secondDone; err != nil || calls.Load() != 2 {
			t.Fatalf("new caller inherited abandoned result: %v calls=%d", err, calls.Load())
		}
	})
}

func TestNativeAdmission(t *testing.T) {
	t.Parallel()
	r := fixtureResolver(t, func(context.Context, Question) (func() error, error) {
		t.Error("unapproved query reached multicast owner")
		return nil, nil
	})
	for _, test := range []struct {
		name, source, owner string
		kind                uint16
	}{
		{name: "unknown source", source: "other", owner: "host.local.", kind: dns.TypeA},
		{name: "unicast name", source: "alpha", owner: "host.example.test.", kind: dns.TypeA},
		{name: "foreign reverse", source: "alpha", owner: "10.100.51.198.in-addr.arpa.", kind: dns.TypePTR},
		{name: "zone transfer", source: "alpha", owner: "host.local.", kind: dns.TypeAXFR},
		{name: "invalid type", source: "alpha", owner: "host.local.", kind: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := r.Query(t.Context(), Question{Source: test.source, DNS: dns.Question{Name: test.owner, Qtype: test.kind, Qclass: dns.ClassINET}})
			if err == nil {
				t.Fatal("invalid question admitted")
			}
		})
	}
}

func TestEpochWithdrawalAndCapacity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := fixtureResolver(t, func(context.Context, Question) (func() error, error) { return nil, nil })
		var workers sync.WaitGroup
		var unavailable atomic.Int32
		for index := range 16 {
			workers.Go(func() {
				owner := string(rune('a'+index)) + ".local."
				_, err := r.Query(t.Context(), Question{Source: "alpha", DNS: dns.Question{Name: owner, Qtype: dns.TypeA, Qclass: dns.ClassINET}})
				if errors.Is(err, ErrUnavailable) {
					unavailable.Add(1)
				}
			})
		}
		synctest.Wait()
		question := Question{Source: "alpha", DNS: dns.Question{Name: "overflow.local.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
		if _, err := r.Query(t.Context(), question); !errors.Is(err, ErrBusy) {
			t.Fatalf("capacity returned %v", err)
		}
		r.Close()
		workers.Wait()
		if unavailable.Load() != 16 {
			t.Fatalf("withdrawal lost %d query owners", 16-unavailable.Load())
		}
		if _, err := r.Query(t.Context(), question); !errors.Is(err, ErrUnavailable) {
			t.Fatal("closed epoch retained authority")
		}
	})
}

func TestNativeNSECNegativeAndReverse(t *testing.T) {
	t.Parallel()
	r := fixtureResolver(t, func(context.Context, Question) (func() error, error) {
		t.Error("fresh denial or reverse cache caused multicast")
		return nil, nil
	})
	ingestFixture(t, r, "alpha", "device.local. 120 IN NSEC device.local. A TXT")
	ingestFixture(t, r, "alpha", "10.2.0.192.in-addr.arpa. 120 IN PTR device.local.")
	for _, q := range []dns.Question{
		{Name: "device.local.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		{Name: "10.2.0.192.in-addr.arpa.", Qtype: dns.TypePTR, Qclass: dns.ClassINET},
	} {
		result, err := r.Query(t.Context(), Question{Source: "alpha", DNS: q})
		if err != nil || len(result.Records) < 1 {
			t.Fatalf("query=%+v result=%+v err=%v", q, result, err)
		}
	}
}
